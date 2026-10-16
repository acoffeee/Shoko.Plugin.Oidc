using System;

namespace Shoko.Plugin.Oidc;

/// <summary>
///   Identity and routes shared across the plugin.
/// </summary>
public static class Constants
{
    /// <summary>
    ///   The plugin's ID. Has to match <c>id</c> in <c>manifest.json</c>.
    /// </summary>
    public static readonly Guid PluginGuid = new("c7dbd592-a764-438b-8a17-6fddd45f4c26");

    /// <summary>
    ///   The plugin's friendly name.
    /// </summary>
    public const string PluginName = "OpenID Connect";

    /// <summary>
    ///   The namespace every route of the plugin lives under.
    /// </summary>
    public const string RouteNamespace = "OIDC";

    /// <summary>
    ///   The base path of the plugin's pages.
    /// </summary>
    public const string PagePath = "/plugin/" + RouteNamespace;

    /// <summary>
    ///   The base path of the plugin's API.
    /// </summary>
    public const string ApiPath = "/api/plugin/" + RouteNamespace;

    /// <summary>
    ///   Where a browser starts a Web UI login.
    /// </summary>
    public const string LoginPath = PagePath + "/login";

    /// <summary>
    ///   Where the identity provider sends the browser back to. This is the
    ///   redirect URI to register with the provider.
    /// </summary>
    public const string CallbackPath = PagePath + "/callback";

    /// <summary>
    ///   Where a user approves a device that asked to be paired.
    /// </summary>
    public const string ApprovalPath = PagePath + "/pair";

    /// <summary>
    ///   The admin page for mapping subjects to Shoko users.
    /// </summary>
    public const string AdminPath = PagePath + "/admin";

    /// <summary>
    ///   The name of the HTTP client used to talk to the identity provider.
    /// </summary>
    public const string HttpClientName = "Shoko.Plugin.Oidc";

    /// <summary>
    ///   The cookie that ties a login back to the browser that started it.
    /// </summary>
    public const string BindingCookieName = "shoko-oidc-binding";
}
