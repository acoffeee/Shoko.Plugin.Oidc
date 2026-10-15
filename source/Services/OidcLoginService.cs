using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Shoko.Abstractions.Config;
using Shoko.Abstractions.User;
using Shoko.Abstractions.User.Services;
using Shoko.Plugin.Oidc.Configuration;

namespace Shoko.Plugin.Oidc.Services;

/// <summary>
///   Runs a login from start to end: sends the browser to the identity
///   provider, checks what comes back, and finds the Shoko user the subject
///   is mapped to. Shoko stays the source of truth for users; the provider
///   only vouches for who is at the keyboard.
/// </summary>
public sealed class OidcLoginService(
    ConfigurationProvider<OidcPluginConfiguration> configurationProvider,
    OidcClient oidcClient,
    LoginStateStore loginStateStore,
    UnmappedSubjectTracker unmappedSubjects,
    IUserService userService,
    ILogger<OidcLoginService> logger
)
{
    /// <summary>
    ///   Gets the current configuration.
    /// </summary>
    public OidcPluginConfiguration LoadConfiguration()
        => configurationProvider.Load();

    /// <summary>
    ///   Gets the URL browsers reach Shoko on, without a trailing slash.
    /// </summary>
    public static string GetBaseUrl(OidcPluginConfiguration config, HttpRequest request)
        => !string.IsNullOrWhiteSpace(config.PublicUrl)
            ? config.PublicUrl.Trim().TrimEnd('/')
            : $"{request.Scheme}://{request.Host}{request.PathBase}";

    /// <summary>
    ///   Gets the redirect URI to register with the identity provider.
    /// </summary>
    public static string GetRedirectUri(OidcPluginConfiguration config, HttpRequest request)
        => GetBaseUrl(config, request) + Constants.CallbackPath;

    /// <summary>
    ///   Starts a login, and returns where to send the browser.
    /// </summary>
    /// <param name="context">The request starting the login.</param>
    /// <param name="purpose">Why the login is started.</param>
    /// <param name="returnTo">Where in the Web UI to go after a Web UI login.</param>
    /// <param name="pairingCode">The pairing code being answered, for a pairing login.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The authorization URL.</returns>
    public async Task<string> BeginLogin(HttpContext context, LoginPurpose purpose, string? returnTo, string? pairingCode, CancellationToken cancellationToken)
    {
        var config = configurationProvider.Load();
        if (!config.IsConfigured())
            throw new OidcException("Single sign-on is not set up yet. An admin has to set the issuer URL and client ID in the plugin's settings.");

        var metadata = await oidcClient.GetMetadata(config.Issuer!, cancellationToken).ConfigureAwait(false);
        var binding = GetOrCreateBinding(context, config);
        var login = loginStateStore.Begin(purpose, GetRedirectUri(config, context.Request), OidcClient.Hash(binding), returnTo, pairingCode, DateTime.UtcNow)
            ?? throw new OidcException("Too many logins are in progress. Try again in a few minutes.");
        return OidcClient.BuildAuthorizationUrl(metadata, config, login.RedirectUri, login.State, login.Nonce, login.CodeVerifier);
    }

    /// <summary>
    ///   Finishes a login when the browser comes back from the identity
    ///   provider.
    /// </summary>
    /// <param name="context">The callback request.</param>
    /// <param name="state">The <c>state</c> parameter.</param>
    /// <param name="code">The <c>code</c> parameter.</param>
    /// <param name="error">The <c>error</c> parameter.</param>
    /// <param name="errorDescription">The <c>error_description</c> parameter.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The login, who signed in, and the Shoko user they are mapped to, if any.</returns>
    public async Task<CompletedLogin> CompleteLogin(HttpContext context, string? state, string? code, string? error, string? errorDescription, CancellationToken cancellationToken)
    {
        var now = DateTime.UtcNow;
        if (string.IsNullOrEmpty(state) || loginStateStore.Take(state, now) is not { } login)
            throw new OidcException("This login is unknown or took too long. Start again.");

        // The login has to finish in the browser that started it. Otherwise
        // someone could sign in themselves and hand the callback link to a
        // victim, whose browser would end up signed in as them.
        if (!BindingMatches(context, login.BindingHash))
            throw new OidcException("This login was started in another browser. Start again from this one.");

        if (!string.IsNullOrEmpty(error))
            throw new OidcException(error == "access_denied"
                ? "The login was cancelled or denied at the identity provider."
                : $"The identity provider refused the login: {error}{(string.IsNullOrEmpty(errorDescription) ? string.Empty : $" ({errorDescription})")}.");

        if (string.IsNullOrEmpty(code))
            throw new OidcException("The identity provider sent the browser back without a code.");

        var config = configurationProvider.Load();
        if (!config.IsConfigured())
            throw new OidcException("Single sign-on is not set up.");

        var identity = await oidcClient.CompleteLogin(config, code, login.RedirectUri, login.CodeVerifier, login.Nonce, cancellationToken).ConfigureAwait(false);
        var mapping = config.FindMapping(identity.Subject);
        var user = mapping is null ? null : userService.GetUserByID(mapping.UserID);
        if (user is null)
        {
            unmappedSubjects.Record(identity, now);
            if (mapping is null)
                logger.LogInformation("Subject {Subject} ({PreferredUsername}) signed in, but is not mapped to a Shoko user", identity.Subject, identity.PreferredUsername);
            else
                logger.LogWarning("Subject {Subject} is mapped to Shoko user {UserID}, which does not exist", identity.Subject, mapping.UserID);
        }
        else
        {
            logger.LogInformation("Subject {Subject} signed in as Shoko user {Username}", identity.Subject, user.Username);
        }

        return new(login, identity, user, mapping is not null && user is null);
    }

    /// <summary>
    ///   Mints the API key for a Web UI session.
    /// </summary>
    public Task<ApiToken> MintWebSession(IUser user)
    {
        var config = configurationProvider.Load();
        var device = config.WebUIDeviceName.Trim();
        return config.SessionLifetimeDays > 0
            ? userService.GenerateApiTokenForUser(user, device, DateTime.UtcNow.AddDays(config.SessionLifetimeDays))
            : userService.GenerateApiTokenForUser(user, device);
    }

    /// <summary>
    ///   Mints the API key for a paired device.
    /// </summary>
    /// <returns>The key, and whether it is new rather than one the device already had.</returns>
    public async Task<(ApiToken Token, bool Minted)> MintDeviceKey(IUser user, string deviceName)
    {
        var config = configurationProvider.Load();
        if (config.PairedDeviceLifetimeDays > 0)
            return (await userService.GenerateApiTokenForUser(user, deviceName, DateTime.UtcNow.AddDays(config.PairedDeviceLifetimeDays)).ConfigureAwait(false), true);

        // A non-expiring key is shared by every login of the same device
        // name, so one that already existed was not ours to revoke.
        var existed = userService.GetApiTokensForUser(user).Any(token => token.Device == deviceName && token.ExpiresAt is null);
        return (await userService.GenerateApiTokenForUser(user, deviceName).ConfigureAwait(false), !existed);
    }

    /// <summary>
    ///   Checks that the request comes from the browser a login or ticket was
    ///   handed to.
    /// </summary>
    public static bool BindingMatches(HttpContext context, string bindingHash)
        => context.Request.Cookies.TryGetValue(Constants.BindingCookieName, out var binding) && !string.IsNullOrEmpty(binding) &&
            CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(OidcClient.Hash(binding)), Encoding.ASCII.GetBytes(bindingHash));

    /// <summary>
    ///   Gets the hash of the browser's binding cookie.
    /// </summary>
    public static string? GetBindingHash(HttpContext context)
        => context.Request.Cookies.TryGetValue(Constants.BindingCookieName, out var binding) && !string.IsNullOrEmpty(binding) ? OidcClient.Hash(binding) : null;

    private static string GetOrCreateBinding(HttpContext context, OidcPluginConfiguration config)
    {
        if (context.Request.Cookies.TryGetValue(Constants.BindingCookieName, out var binding) && binding is { Length: >= 32 })
            return binding;

        binding = OidcClient.CreateRandomValue();
        context.Response.Cookies.Append(Constants.BindingCookieName, binding, new CookieOptions
        {
            HttpOnly = true,
            // Lax, so the cookie comes along on the top-level redirect back
            // from the identity provider.
            SameSite = SameSiteMode.Lax,
            Secure = GetBaseUrl(config, context.Request).StartsWith("https://", StringComparison.OrdinalIgnoreCase),
            Path = Constants.PagePath,
            IsEssential = true,
        });
        return binding;
    }
}

/// <summary>
///   A login the identity provider vouched for.
/// </summary>
/// <param name="Login">The login, as it was started.</param>
/// <param name="Identity">Who signed in.</param>
/// <param name="User">The Shoko user the subject is mapped to, or <c>null</c> when it is not.</param>
/// <param name="MappedUserMissing">Whether the subject is mapped to a Shoko user that no longer exists.</param>
public sealed record CompletedLogin(PendingLogin Login, OidcIdentity Identity, IUser? User, bool MappedUserMissing);
