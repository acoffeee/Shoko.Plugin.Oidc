using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using Shoko.Abstractions.Config;
using Shoko.Abstractions.Config.Attributes;
using Shoko.Abstractions.Config.Services;
using Shoko.Abstractions.Plugin;

namespace Shoko.Plugin.Oidc.Configuration;

/// <summary>
///   How the plugin reaches the identity provider, and which of its
///   subjects may sign in as which Shoko user.
/// </summary>
[Display(Name = "OpenID Connect")]
public class OidcPluginConfiguration : IConfiguration, IConfigurationWithCustomValidation<OidcPluginConfiguration>
{
    /// <summary>
    ///   The issuer URL of the identity provider.
    /// </summary>
    [Display(Name = "Issuer URL", Description = """
        The issuer of the identity provider, e.g. `https://auth.example.com` for Authelia.
        The discovery document is read from `<issuer>/.well-known/openid-configuration`.
        """)]
    [EnvironmentVariable("SHOKO_OIDC_ISSUER", AllowOverride = true)]
    public string? Issuer { get; set; }

    /// <summary>
    ///   The client ID registered with the identity provider.
    /// </summary>
    [Display(Name = "Client ID")]
    [EnvironmentVariable("SHOKO_OIDC_CLIENT_ID", AllowOverride = true)]
    public string? ClientID { get; set; }

    /// <summary>
    ///   The client secret registered with the identity provider.
    /// </summary>
    [Display(Name = "Client Secret", Description = """
        The plain-text client secret. Leave empty for a public client, which
        Authelia only accepts with `public: true` and
        `token_endpoint_auth_method: 'none'`.
        """)]
    [DataType(DataType.Password)]
    [EnvironmentVariable("SHOKO_OIDC_CLIENT_SECRET", AllowOverride = true)]
    public string? ClientSecret { get; set; }

    /// <summary>
    ///   How the client authenticates at the token endpoint.
    /// </summary>
    [Display(Name = "Token Endpoint Auth Method", Description = """
        Has to match `token_endpoint_auth_method` on the Authelia client.
        Ignored for a public client.
        """)]
    [DefaultValue(TokenEndpointAuthMethod.ClientSecretBasic)]
    public TokenEndpointAuthMethod TokenEndpointAuthMethod { get; set; } = TokenEndpointAuthMethod.ClientSecretBasic;

    /// <summary>
    ///   The scopes to request.
    /// </summary>
    [Display(Name = "Scopes", Description = """
        Space-separated. `openid` is always added. `profile` and `email` are
        only used to show who an unmapped subject is.
        """)]
    [DefaultValue("openid profile email")]
    public string Scopes { get; set; } = "openid profile email";

    /// <summary>
    ///   The public URL Shoko is reached on.
    /// </summary>
    [Display(Name = "Public URL", Description = """
        The URL browsers reach Shoko on, e.g. `https://shoko.example.com`.
        The redirect URI sent to the provider is built from it, so set it
        when Shoko is behind a reverse proxy. When empty, the URL of the
        incoming request is used.
        """)]
    [EnvironmentVariable("SHOKO_OIDC_PUBLIC_URL", AllowOverride = true)]
    public string? PublicUrl { get; set; }

    /// <summary>
    ///   How long a Web UI session lasts.
    /// </summary>
    [Display(Name = "Web UI Session Lifetime (Days)", Description = """
        How long an API key handed to the Web UI after a login stays valid.
        Every login mints a new key. Set to 0 for keys that never expire,
        which are then shared by every login of the same user, like a
        password login's are.
        """)]
    [Range(0, 3650)]
    [DefaultValue(30)]
    public int SessionLifetimeDays { get; set; } = 30;

    /// <summary>
    ///   The device name Web UI sessions are minted under.
    /// </summary>
    [Display(Name = "Web UI Device Name", Description = "The device name the API keys of Web UI logins are listed under.")]
    [DefaultValue("web-ui (oidc)")]
    public string WebUIDeviceName { get; set; } = "web-ui (oidc)";

    /// <summary>
    ///   Whether the Web UI should remember the login across browser restarts.
    /// </summary>
    [Display(Name = "Remember Login", Description = """
        Keep the Web UI logged in after the browser is closed, as the
        "Remember Me" box on the login page does.
        """)]
    [DefaultValue(true)]
    public bool RememberLogin { get; set; } = true;

    /// <summary>
    ///   Where the Web UI is served from.
    /// </summary>
    [Display(Name = "Web UI Path", Description = "The path the Web UI is served from. Match the server's Web UI public path.")]
    [DefaultValue("/webui")]
    public string WebUIPath { get; set; } = "/webui";

    /// <summary>
    ///   Whether devices can ask to be paired.
    /// </summary>
    [Display(Name = "Enable Device Pairing", Description = """
        Let a device ask for an API key, which a user then approves in a
        browser after signing in with the identity provider.
        """)]
    [DefaultValue(true)]
    public bool EnableDevicePairing { get; set; } = true;

    /// <summary>
    ///   How long a pairing request waits for approval.
    /// </summary>
    [Display(Name = "Pairing Window (Minutes)", Description = "How long a device's pairing code can be approved for.")]
    [Range(1, 60)]
    [DefaultValue(10)]
    public int PairingWindowMinutes { get; set; } = 10;

    /// <summary>
    ///   How long a paired device's key lasts.
    /// </summary>
    [Display(Name = "Paired Device Key Lifetime (Days)", Description = """
        How long the API key handed to a paired device stays valid. Set to 0
        for keys that never expire.
        """)]
    [Range(0, 3650)]
    [DefaultValue(0)]
    public int PairedDeviceLifetimeDays { get; set; }

    /// <summary>
    ///   Which subject signs in as which Shoko user.
    /// </summary>
    [Display(Name = "User Mappings", Description = """
        Which subject (`sub` claim) of the identity provider signs in as
        which Shoko user. A subject that is not listed here cannot sign in.
        The "User Mappings" plugin page lists the subjects that tried, and
        the Shoko users to pick from.
        """)]
    public List<UserMapping> UserMappings { get; set; } = [];

    /// <summary>
    ///   Whether enough is set to start a login.
    /// </summary>
    public bool IsConfigured() => !string.IsNullOrWhiteSpace(Issuer) && !string.IsNullOrWhiteSpace(ClientID);

    /// <inheritdoc/>
    public static IReadOnlyDictionary<string, IReadOnlyList<string>> Validate(OidcPluginConfiguration config, IConfigurationService configurationService, IPluginManager pluginManager)
    {
        var errors = new Dictionary<string, IReadOnlyList<string>>();
        if (!string.IsNullOrWhiteSpace(config.Issuer) && !IsHttpUrl(config.Issuer))
            errors[nameof(Issuer)] = ["Has to be an absolute http or https URL."];
        if (!string.IsNullOrWhiteSpace(config.PublicUrl) && !IsHttpUrl(config.PublicUrl))
            errors[nameof(PublicUrl)] = ["Has to be an absolute http or https URL."];
        if (string.IsNullOrWhiteSpace(config.WebUIPath) || !config.WebUIPath.StartsWith('/') || config.WebUIPath.StartsWith("//"))
            errors[nameof(WebUIPath)] = ["Has to be an absolute path, e.g. /webui."];
        if (string.IsNullOrWhiteSpace(config.WebUIDeviceName))
            errors[nameof(WebUIDeviceName)] = ["Cannot be empty."];

        // Whether each user ID exists is not checked here: validation also
        // runs on load, which can happen before the users are.
        var seen = new HashSet<string>(StringComparer.Ordinal);
        for (var index = 0; index < config.UserMappings.Count; index++)
        {
            var mapping = config.UserMappings[index];
            var path = $"{nameof(UserMappings)}[{index}]";
            if (string.IsNullOrWhiteSpace(mapping.Subject))
                errors[$"{path}.{nameof(UserMapping.Subject)}"] = ["Cannot be empty."];
            else if (!seen.Add(mapping.Subject.Trim()))
                errors[$"{path}.{nameof(UserMapping.Subject)}"] = ["This subject is already mapped."];
        }

        return errors;
    }

    private static bool IsHttpUrl(string value)
        => Uri.TryCreate(value.Trim(), UriKind.Absolute, out var uri) && (uri.Scheme == Uri.UriSchemeHttps || uri.Scheme == Uri.UriSchemeHttp);

    /// <summary>
    ///   Finds the mapping for a subject.
    /// </summary>
    /// <param name="subject">The <c>sub</c> claim.</param>
    /// <returns>The mapping, or <c>null</c> when the subject is not mapped.</returns>
    public UserMapping? FindMapping(string subject)
        => UserMappings.FirstOrDefault(mapping => string.Equals(mapping.Subject.Trim(), subject, StringComparison.Ordinal));
}

/// <summary>
///   One subject of the identity provider, signing in as one Shoko user.
/// </summary>
public class UserMapping
{
    /// <summary>
    ///   The <c>sub</c> claim of the identity provider.
    /// </summary>
    [Display(Name = "Subject", Description = "The `sub` claim. For Authelia, an opaque UUID per user.")]
    [Required]
    public string Subject { get; set; } = string.Empty;

    /// <summary>
    ///   The ID of the Shoko user the subject signs in as.
    /// </summary>
    [Display(Name = "Shoko User ID")]
    [Range(1, int.MaxValue)]
    public int UserID { get; set; }

    /// <summary>
    ///   A note for the admin, e.g. who the subject is.
    /// </summary>
    [Display(Name = "Note", Description = "Who the subject is, for your own reference.")]
    public string? Note { get; set; }
}

/// <summary>
///   How the client authenticates at the token endpoint.
/// </summary>
public enum TokenEndpointAuthMethod
{
    /// <summary>
    ///   HTTP basic authentication, <c>client_secret_basic</c>.
    /// </summary>
    ClientSecretBasic = 0,

    /// <summary>
    ///   In the request body, <c>client_secret_post</c>.
    /// </summary>
    ClientSecretPost = 1,
}
