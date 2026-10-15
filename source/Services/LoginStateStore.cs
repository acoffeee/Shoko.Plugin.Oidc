using System;
using System.Collections.Concurrent;
using System.Linq;

namespace Shoko.Plugin.Oidc.Services;

/// <summary>
///   What a login has to remember between sending the browser to the
///   identity provider and the browser coming back, and the tickets that let
///   a signed-in user answer a pairing request.
/// </summary>
/// <remarks>
///   Kept in memory: a restart only costs a login in flight a retry.
/// </remarks>
public sealed class LoginStateStore
{
    /// <summary>
    ///   How long a browser has to come back from the identity provider.
    /// </summary>
    public static readonly TimeSpan LoginLifetime = TimeSpan.FromMinutes(10);

    /// <summary>
    ///   How long a signed-in user has to answer a pairing request.
    /// </summary>
    public static readonly TimeSpan TicketLifetime = TimeSpan.FromMinutes(5);

    // Logins can be started without signing in, so there is a ceiling on how
    // many can be in flight before new ones are turned away.
    private const int MaxPendingLogins = 1000;

    private readonly ConcurrentDictionary<string, PendingLogin> _logins = new(StringComparer.Ordinal);

    private readonly ConcurrentDictionary<string, ApprovalTicket> _tickets = new(StringComparer.Ordinal);

    /// <summary>
    ///   Remembers a login that is about to be sent to the identity provider.
    /// </summary>
    /// <returns>The login, or <c>null</c> when too many are in flight.</returns>
    public PendingLogin? Begin(LoginPurpose purpose, string redirectUri, string bindingHash, string? returnTo, string? pairingCode, DateTime now)
    {
        if (_logins.Count >= MaxPendingLogins)
        {
            Sweep(now);
            if (_logins.Count >= MaxPendingLogins)
                return null;
        }

        var login = new PendingLogin(
            OidcClient.CreateRandomValue(),
            OidcClient.CreateRandomValue(),
            OidcClient.CreateRandomValue(),
            redirectUri,
            bindingHash,
            purpose,
            returnTo,
            pairingCode,
            now + LoginLifetime
        );
        _logins[login.State] = login;
        return login;
    }

    /// <summary>
    ///   Takes a login out by its state, so a state is only ever used once.
    /// </summary>
    /// <returns>The login, or <c>null</c> when it is unknown or expired.</returns>
    public PendingLogin? Take(string state, DateTime now)
        => _logins.TryRemove(state, out var login) && login.ExpiresAt > now ? login : null;

    /// <summary>
    ///   Issues a single-use ticket letting a signed-in user answer one
    ///   pairing request from the browser they signed in with.
    /// </summary>
    public string IssueTicket(string pairingCode, int userID, string bindingHash, DateTime now)
    {
        var ticket = new ApprovalTicket(OidcClient.CreateRandomValue(), pairingCode, userID, bindingHash, now + TicketLifetime);
        _tickets[ticket.Ticket] = ticket;
        return ticket.Ticket;
    }

    /// <summary>
    ///   Takes a ticket out, so it is only ever used once.
    /// </summary>
    /// <returns>The ticket, or <c>null</c> when it is unknown or expired.</returns>
    public ApprovalTicket? TakeTicket(string ticket, DateTime now)
        => _tickets.TryRemove(ticket, out var value) && value.ExpiresAt > now ? value : null;

    /// <summary>
    ///   Forgets the logins and tickets that have expired.
    /// </summary>
    public void Sweep(DateTime now)
    {
        foreach (var login in _logins.Values.Where(login => login.ExpiresAt <= now))
            _logins.TryRemove(login.State, out _);
        foreach (var ticket in _tickets.Values.Where(ticket => ticket.ExpiresAt <= now))
            _tickets.TryRemove(ticket.Ticket, out _);
    }
}

/// <summary>
///   Why a login was started, and so what happens once it succeeds.
/// </summary>
public enum LoginPurpose
{
    /// <summary>
    ///   Sign in to the Web UI.
    /// </summary>
    WebUI,

    /// <summary>
    ///   Answer a device's pairing request.
    /// </summary>
    Pairing,
}

/// <summary>
///   A login waiting for the browser to come back from the identity provider.
/// </summary>
/// <param name="State">The <c>state</c> parameter, which finds the login again.</param>
/// <param name="Nonce">The <c>nonce</c> the ID token has to carry.</param>
/// <param name="CodeVerifier">The PKCE code verifier.</param>
/// <param name="RedirectUri">The redirect URI, which the code exchange has to repeat.</param>
/// <param name="BindingHash">The hash of the cookie of the browser that started the login.</param>
/// <param name="Purpose">Why the login was started.</param>
/// <param name="ReturnTo">Where in the Web UI to go after a Web UI login.</param>
/// <param name="PairingCode">The pairing code being answered, for a pairing login.</param>
/// <param name="ExpiresAt">When the login is forgotten.</param>
public sealed record PendingLogin(
    string State,
    string Nonce,
    string CodeVerifier,
    string RedirectUri,
    string BindingHash,
    LoginPurpose Purpose,
    string? ReturnTo,
    string? PairingCode,
    DateTime ExpiresAt
);

/// <summary>
///   Lets a signed-in user answer one pairing request.
/// </summary>
/// <param name="Ticket">The ticket itself, handed out in the confirmation form.</param>
/// <param name="PairingCode">The pairing code it answers.</param>
/// <param name="UserID">The Shoko user who signed in.</param>
/// <param name="BindingHash">The hash of the cookie of the browser that signed in.</param>
/// <param name="ExpiresAt">When the ticket is forgotten.</param>
public sealed record ApprovalTicket(string Ticket, string PairingCode, int UserID, string BindingHash, DateTime ExpiresAt);
