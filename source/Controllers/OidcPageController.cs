using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Shoko.Abstractions.User.Services;
using Shoko.Plugin.Oidc.Pages;
using Shoko.Plugin.Oidc.Services;

namespace Shoko.Plugin.Oidc.Controllers;

/// <summary>
///   The pages a browser passes through: the start of a login, the callback
///   from the identity provider, the device approval, and the admin page.
/// </summary>
[AllowAnonymous]
[ApiExplorerSettings(IgnoreApi = true)]
[Route(Constants.PagePath)]
public class OidcPageController(
    OidcLoginService loginService,
    LoginStateStore loginStateStore,
    PairingStore pairingStore,
    IUserService userService,
    ILogger<OidcPageController> logger
) : Controller
{
    /// <summary>
    ///   Starts a Web UI login.
    /// </summary>
    [HttpGet]
    public Task<IActionResult> Index([FromQuery] string? redirectTo, CancellationToken cancellationToken)
        => Login(redirectTo, cancellationToken);

    /// <summary>
    ///   Starts a Web UI login.
    /// </summary>
    /// <param name="redirectTo">Where in the Web UI to go afterwards.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    [HttpGet("login")]
    public async Task<IActionResult> Login([FromQuery] string? redirectTo, CancellationToken cancellationToken)
    {
        try
        {
            var config = loginService.LoadConfiguration();
            var url = await loginService.BeginLogin(HttpContext, LoginPurpose.WebUI, SanitizeReturnTo(redirectTo, config.WebUIPath), null, cancellationToken);
            return Redirect(url);
        }
        catch (OidcException ex)
        {
            logger.LogWarning(ex.InnerException, "Could not start a login: {Message}", ex.Message);
            return HtmlPages.Error(Response, ex.Message, statusCode: StatusCodes.Status503ServiceUnavailable);
        }
    }

    /// <summary>
    ///   Where the identity provider sends the browser back to.
    /// </summary>
    [HttpGet("callback")]
    public async Task<IActionResult> Callback(
        [FromQuery] string? state,
        [FromQuery] string? code,
        [FromQuery] string? error,
        [FromQuery(Name = "error_description")] string? errorDescription,
        CancellationToken cancellationToken
    )
    {
        CompletedLogin result;
        try
        {
            result = await loginService.CompleteLogin(HttpContext, state, code, error, errorDescription, cancellationToken);
        }
        catch (OidcException ex)
        {
            logger.LogWarning(ex.InnerException, "A login failed: {Message}", ex.Message);
            return HtmlPages.Error(Response, ex.Message, Constants.LoginPath);
        }

        if (result.User is not { } user)
            return HtmlPages.Unmapped(Response, result.Identity, result.MappedUserMissing);

        var config = loginService.LoadConfiguration();
        switch (result.Login.Purpose)
        {
            case LoginPurpose.WebUI:
            {
                var token = await loginService.MintWebSession(user);
                return HtmlPages.WebUIHandoff(Response, token.Token, user.Username, config.RememberLogin, result.Login.ReturnTo ?? config.WebUIPath);
            }

            case LoginPurpose.Pairing:
            {
                if (!config.EnableDevicePairing)
                    return HtmlPages.PairResult(Response, "Device pairing is off", "An admin turned device pairing off.", StatusCodes.Status404NotFound);
                if (result.Login.PairingCode is not { } pairingCode || pairingStore.Find(pairingCode, DateTime.UtcNow) is not { Status: PairingStatus.Pending } pairing)
                    return HtmlPages.PairEnterCode(Response, "That code has expired or was already answered. Start pairing again on the device.");

                var ticket = loginStateStore.IssueTicket(pairingCode, user.LocalID, result.Login.BindingHash, DateTime.UtcNow);
                return HtmlPages.PairConfirm(Response, pairing, user.Username, ticket);
            }

            default:
                return HtmlPages.Error(Response, "This login was started for something the plugin does not know.");
        }
    }

    /// <summary>
    ///   Asks for a device's code, or, given one, signs the user in to
    ///   approve it.
    /// </summary>
    [HttpGet("pair")]
    public async Task<IActionResult> Pair([FromQuery] string? code, CancellationToken cancellationToken)
    {
        if (!loginService.LoadConfiguration().EnableDevicePairing)
            return HtmlPages.PairResult(Response, "Device pairing is off", "An admin turned device pairing off.", StatusCodes.Status404NotFound);
        if (string.IsNullOrWhiteSpace(code))
            return HtmlPages.PairEnterCode(Response);

        var normalized = PairingStore.NormalizeCode(code);
        if (pairingStore.Find(normalized, DateTime.UtcNow) is not { Status: PairingStatus.Pending })
            return HtmlPages.PairEnterCode(Response, "That code is unknown, expired, or was already answered.");

        try
        {
            var url = await loginService.BeginLogin(HttpContext, LoginPurpose.Pairing, null, normalized, cancellationToken);
            return Redirect(url);
        }
        catch (OidcException ex)
        {
            logger.LogWarning(ex.InnerException, "Could not start a login: {Message}", ex.Message);
            return HtmlPages.Error(Response, ex.Message, statusCode: StatusCodes.Status503ServiceUnavailable);
        }
    }

    /// <summary>
    ///   Approves or denies a device, for the user who just signed in.
    /// </summary>
    /// <param name="ticket">The single-use ticket from the confirmation form.</param>
    /// <param name="decision"><c>approve</c> or <c>deny</c>.</param>
    [HttpPost("pair/confirm")]
    public async Task<IActionResult> ConfirmPair([FromForm] string? ticket, [FromForm] string? decision)
    {
        var now = DateTime.UtcNow;
        // The ticket only came out of the confirmation page, which only the
        // browser that signed in got to see, so it doubles as the CSRF token.
        if (string.IsNullOrEmpty(ticket) || loginStateStore.TakeTicket(ticket, now) is not { } approval || !OidcLoginService.BindingMatches(HttpContext, approval.BindingHash))
            return HtmlPages.PairResult(Response, "Could not answer the device", "This confirmation expired or was already used. Start again from the device's code.", StatusCodes.Status400BadRequest);

        if (decision == "deny")
        {
            return pairingStore.Deny(approval.PairingCode, now)
                ? HtmlPages.PairResult(Response, "Device denied", "The device was not given access. You can close this page.")
                : HtmlPages.PairResult(Response, "Could not answer the device", "The code expired or was already answered.", StatusCodes.Status409Conflict);
        }

        if (decision != "approve")
            return HtmlPages.PairResult(Response, "Could not answer the device", "Pick approve or deny.", StatusCodes.Status400BadRequest);

        if (userService.GetUserByID(approval.UserID) is not { } user)
            return HtmlPages.PairResult(Response, "Could not answer the device", "Your Shoko user no longer exists.", StatusCodes.Status403Forbidden);
        if (pairingStore.Find(approval.PairingCode, now) is not { } pairing || !pairingStore.TryBeginApproval(approval.PairingCode, now))
            return HtmlPages.PairResult(Response, "Could not answer the device", "The code expired or was already answered.", StatusCodes.Status409Conflict);

        try
        {
            var (token, minted) = await loginService.MintDeviceKey(user, pairing.DeviceName);
            if (!await pairingStore.CompleteApproval(approval.PairingCode, token.Token, user.Username, minted, DateTime.UtcNow))
                return HtmlPages.PairResult(Response, "Could not answer the device", "The code expired while it was being approved.", StatusCodes.Status409Conflict);
        }
        catch (Exception ex)
        {
            pairingStore.AbortApproval(approval.PairingCode);
            logger.LogError(ex, "Could not mint a key for device {DeviceName}", pairing.DeviceName);
            return HtmlPages.PairResult(Response, "Could not answer the device", "Shoko could not create a key for the device.", StatusCodes.Status500InternalServerError);
        }

        return HtmlPages.PairResult(Response, "Device approved", $"{pairing.DeviceName} is signed in as {user.Username}. You can close this page.");
    }

    /// <summary>
    ///   The admin page for mapping subjects to Shoko users. It talks to the
    ///   admin API with the Web UI's own API key.
    /// </summary>
    [HttpGet("admin")]
    public IActionResult Admin()
    {
        using var stream = typeof(OidcPageController).Assembly.GetManifestResourceStream("Shoko.Plugin.Oidc.Pages.admin.html");
        if (stream is null)
            return NotFound();

        using var reader = new StreamReader(stream);
        var nonce = OidcClient.CreateRandomValue(16);
        HtmlPages.ApplySecurityHeaders(Response, nonce);
        return Content(reader.ReadToEnd().Replace("{{nonce}}", nonce, StringComparison.Ordinal), "text/html; charset=utf-8");
    }

    /// <summary>
    ///   Only lets a login return to a path inside the Web UI, so the login
    ///   link cannot be used to send someone elsewhere.
    /// </summary>
    private static string? SanitizeReturnTo(string? redirectTo, string webUIPath)
    {
        if (string.IsNullOrWhiteSpace(redirectTo))
            return null;

        redirectTo = redirectTo.Trim();
        var root = webUIPath.TrimEnd('/');
        if (!redirectTo.StartsWith('/') || redirectTo.StartsWith("//") || redirectTo.Contains('\\') || !Uri.TryCreate(redirectTo, UriKind.Relative, out _))
            return null;
        if (redirectTo != root && !redirectTo.StartsWith(root + "/", StringComparison.Ordinal) && !redirectTo.StartsWith(root + "?", StringComparison.Ordinal))
            return null;
        return redirectTo;
    }
}
