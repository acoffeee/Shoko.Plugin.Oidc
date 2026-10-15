using System;
using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Shoko.Plugin.Oidc.Services;

namespace Shoko.Plugin.Oidc.Pages;

/// <summary>
///   The small server-rendered pages a login passes through.
/// </summary>
public static class HtmlPages
{
    private const string Style = """
        :root { color-scheme: light dark; --bg: #f4f5f7; --card: #fff; --text: #1d2024; --muted: #5d636b; --border: #d9dce1; --accent: #2f6fde; --danger: #c93838; }
        @media (prefers-color-scheme: dark) { :root { --bg: #16181c; --card: #1f2227; --text: #e6e8eb; --muted: #9aa1aa; --border: #33373e; --accent: #5b8ff0; --danger: #e05d5d; } }
        * { box-sizing: border-box; }
        body { margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 1rem; background: var(--bg); color: var(--text); font: 15px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }
        main { width: 100%; max-width: 30rem; background: var(--card); border: 1px solid var(--border); border-radius: 0.75rem; padding: 1.75rem; }
        h1 { margin: 0 0 0.75rem; font-size: 1.25rem; }
        p { margin: 0 0 1rem; color: var(--muted); }
        p strong, dd { color: var(--text); }
        code { display: block; padding: 0.6rem 0.75rem; border: 1px solid var(--border); border-radius: 0.4rem; background: var(--bg); color: var(--text); font: 0.85rem ui-monospace, monospace; word-break: break-all; user-select: all; }
        dl { display: grid; grid-template-columns: auto 1fr; gap: 0.35rem 1rem; margin: 0 0 1.25rem; }
        dt { color: var(--muted); } dd { margin: 0; word-break: break-word; }
        .actions { display: flex; gap: 0.75rem; flex-wrap: wrap; }
        a.button, button { display: inline-block; padding: 0.55rem 1.1rem; border: 1px solid var(--border); border-radius: 0.4rem; background: var(--card); color: var(--text); font: inherit; text-decoration: none; cursor: pointer; }
        .primary { background: var(--accent); border-color: var(--accent); color: #fff; }
        .danger { color: var(--danger); }
        .warning { padding: 0.6rem 0.75rem; border-left: 3px solid var(--danger); background: var(--bg); color: var(--text); }
        input { width: 100%; padding: 0.55rem 0.75rem; margin-bottom: 1rem; border: 1px solid var(--border); border-radius: 0.4rem; background: var(--bg); color: var(--text); font: 1.25rem ui-monospace, monospace; letter-spacing: 0.15em; text-transform: uppercase; text-align: center; }
        """;

    /// <summary>
    ///   Encodes text for HTML.
    /// </summary>
    public static string Encode(string? value)
        => HtmlEncoder.Default.Encode(value ?? string.Empty);

    /// <summary>
    ///   Renders a page with the headers every page of the plugin carries: no
    ///   caching, no referrer (the callback URL holds the authorization code),
    ///   and a content security policy only letting in its own script.
    /// </summary>
    public static ContentResult Render(HttpResponse response, string title, string body, string? script = null, int statusCode = StatusCodes.Status200OK)
    {
        var nonce = OidcClient.CreateRandomValue(16);
        ApplySecurityHeaders(response, nonce);
        var scriptTag = script is null ? string.Empty : $"<script nonce=\"{nonce}\">{script}</script>";
        return new()
        {
            StatusCode = statusCode,
            ContentType = "text/html; charset=utf-8",
            Content = $"""
                <!doctype html>
                <html lang="en">
                <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <meta name="referrer" content="no-referrer">
                <title>{Encode(title)} | Shoko</title>
                <style nonce="{nonce}">{Style}</style>
                </head>
                <body>
                <main>
                <h1>{Encode(title)}</h1>
                {body}
                </main>
                {scriptTag}
                </body>
                </html>
                """,
        };
    }

    /// <summary>
    ///   Sets the headers every page of the plugin carries.
    /// </summary>
    public static void ApplySecurityHeaders(HttpResponse response, string nonce)
    {
        response.Headers.CacheControl = "no-store";
        response.Headers.Pragma = "no-cache";
        response.Headers["Referrer-Policy"] = "no-referrer";
        response.Headers["X-Content-Type-Options"] = "nosniff";
        response.Headers.ContentSecurityPolicy =
            $"default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'self'";
    }

    /// <summary>
    ///   A login that went wrong.
    /// </summary>
    public static ContentResult Error(HttpResponse response, string message, string? retryUrl = null, int statusCode = StatusCodes.Status400BadRequest)
        => Render(response, "Could not sign in", $"""
            <p>{Encode(message)}</p>
            {(retryUrl is null ? string.Empty : $"<div class=\"actions\"><a class=\"button primary\" href=\"{Encode(retryUrl)}\">Try again</a></div>")}
            """, statusCode: statusCode);

    /// <summary>
    ///   A subject the identity provider vouched for that is not mapped to a
    ///   Shoko user.
    /// </summary>
    public static ContentResult Unmapped(HttpResponse response, OidcIdentity identity, bool mappedUserMissing)
        => Render(response, "Not linked to a Shoko user", $"""
            <p>
              You signed in{(identity.PreferredUsername is { } name ? $" as <strong>{Encode(name)}</strong>" : string.Empty)},
              but {(mappedUserMissing ? "the Shoko user your account is linked to no longer exists" : "your account is not linked to a Shoko user yet")}.
              Ask an admin to link it on the plugin's <strong>User Mappings</strong> page, where it is now listed. Your subject is:
            </p>
            <p><code>{Encode(identity.Subject)}</code></p>
            """, statusCode: StatusCodes.Status403Forbidden);

    /// <summary>
    ///   Hands a freshly minted API key to the Web UI, the way its own login
    ///   form would have stored it, then opens the Web UI.
    /// </summary>
    /// <remarks>
    ///   The Web UI reads its session from <c>sessionStorage["state"]</c>
    ///   first and from <c>localStorage["apiSession"]</c> when a remembered
    ///   login is all there is. A version that does not match its own only
    ///   resets the other slices of its state, never the session.
    /// </remarks>
    public static ContentResult WebUIHandoff(HttpResponse response, string apiKey, string username, bool remember, string redirectTo)
    {
        var session = JsonSerializer.Serialize(new { apikey = apiKey, username, rememberUser = remember });
        var target = JsonSerializer.Serialize(redirectTo);
        return Render(response, "Signing in", """
            <p id="status">Opening the Web UI…</p>
            """, $$"""
            (function () {
              var session = {{session}};
              try {
                var state = {};
                try { state = JSON.parse(sessionStorage.getItem('state') || '{}') || {}; } catch (e) { state = {}; }
                var stored = {};
                try { stored = JSON.parse(localStorage.getItem('apiSession') || '{}') || {}; } catch (e) { stored = {}; }
                session.version = (state.apiSession && state.apiSession.version) || stored.version || 'oidc';
                state.apiSession = session;
                sessionStorage.setItem('state', JSON.stringify(state));
                if (session.rememberUser) localStorage.setItem('apiSession', JSON.stringify(session));
                else localStorage.removeItem('apiSession');
              } catch (e) {
                document.getElementById('status').textContent = 'Your browser did not let the Web UI store its session. Allow site data for this site and try again.';
                return;
              }
              location.replace({{target}});
            })();
            """);
    }

    /// <summary>
    ///   Asks for the code a device shows.
    /// </summary>
    public static ContentResult PairEnterCode(HttpResponse response, string? error = null)
        => Render(response, "Pair a device", $"""
            <p>Enter the code your device shows. You will be asked to sign in before the device is given access.</p>
            {(error is null ? string.Empty : $"<p class=\"warning\">{Encode(error)}</p>")}
            <form method="get" action="{Constants.ApprovalPath}">
              <input name="code" autocomplete="off" autocapitalize="characters" spellcheck="false" placeholder="XXXX-XXXX" maxlength="16" required autofocus>
              <div class="actions"><button class="primary" type="submit">Continue</button></div>
            </form>
            """, statusCode: error is null ? StatusCodes.Status200OK : StatusCodes.Status400BadRequest);

    /// <summary>
    ///   Asks the signed-in user to approve or deny a device.
    /// </summary>
    public static ContentResult PairConfirm(HttpResponse response, PairingInfo pairing, string username, string ticket)
        => Render(response, "Approve this device?", $"""
            <dl>
              <dt>Device</dt><dd>{Encode(pairing.DeviceName)}</dd>
              <dt>Code</dt><dd>{Encode(pairing.Code)}</dd>
              <dt>Requested from</dt><dd>{Encode(pairing.RequestedFrom ?? "unknown")}</dd>
              <dt>Shoko user</dt><dd>{Encode(username)}</dd>
            </dl>
            <p class="warning">Only approve a device you are holding yourself. The device gets full access to Shoko as <strong>{Encode(username)}</strong>.</p>
            <form method="post" action="{Constants.ApprovalPath}/confirm">
              <input type="hidden" name="ticket" value="{Encode(ticket)}">
              <div class="actions">
                <button class="primary" type="submit" name="decision" value="approve">Approve</button>
                <button class="danger" type="submit" name="decision" value="deny">Deny</button>
              </div>
            </form>
            """);

    /// <summary>
    ///   Tells the user how answering a pairing request went.
    /// </summary>
    public static ContentResult PairResult(HttpResponse response, string title, string message, int statusCode = StatusCodes.Status200OK)
        => Render(response, title, $"<p>{Encode(message)}</p>", statusCode: statusCode);
}
