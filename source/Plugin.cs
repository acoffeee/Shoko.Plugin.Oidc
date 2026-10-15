using System;
using System.Collections.Generic;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json.Linq;
using Shoko.Abstractions.Config;
using Shoko.Abstractions.Plugin;
using Shoko.Abstractions.Plugin.Enums;
using Shoko.Abstractions.Plugin.Models;
using Shoko.Abstractions.User.Services;
using Shoko.Plugin.Oidc.Configuration;
using Shoko.Plugin.Oidc.Services;

namespace Shoko.Plugin.Oidc;

/// <inheritdoc/>
public class Plugin : IPlugin, IPluginServiceRegistration
{
    private ConfigurationProvider<OidcPluginConfiguration>? _configurationProvider;

    /// <inheritdoc/>
    public Guid ID { get; private init; } = Constants.PluginGuid;

    /// <inheritdoc/>
    public string Name { get; private set; } = Constants.PluginName;

    /// <inheritdoc/>
    public string? Description { get; private set; } = """
        Kinda oidc by mapping users from the idp to a shoko user so not truely in the sense that like the idp is the source of truth but like enough you feel me.
        Mainly useful if you have passkeys set up so you can get that sweet passwordless login flow
    """;

    /// <inheritdoc/>
    public void Setup(IServiceProvider serviceProvider)
        => _configurationProvider = serviceProvider.GetRequiredService<ConfigurationProvider<OidcPluginConfiguration>>();

    /// <inheritdoc/>
    public IReadOnlyList<PluginPage> GetPages() =>
    [
        new()
        {
            Name = "User Mappings",
            Url = Constants.AdminPath,
        },
        new()
        {
            Name = "Pair a device",
            Url = Constants.ApprovalPath,
            // The identity provider will not render in a frame.
            CanEmbed = false,
        },
    ];

    /// <inheritdoc/>
    public IReadOnlyList<PluginFeature> GetFeatures()
    {
        if (_configurationProvider?.Load() is not { } config || !config.IsConfigured())
            return [];

        // Anonymous, so a login page can offer the button before anyone has
        // signed in.
        return
        [
            new()
            {
                Name = "oidc-login",
                Visibility = PluginFeatureVisibility.Anonymous,
                Metadata = JObject.FromObject(new { loginUrl = Constants.LoginPath }),
            },
            .. config.EnableDevicePairing
                ? new PluginFeature[]
                {
                    new()
                    {
                        Name = "oidc-device-pairing",
                        Visibility = PluginFeatureVisibility.Anonymous,
                        Metadata = JObject.FromObject(new { startUrl = Constants.ApiPath + "/Pair", pollUrl = Constants.ApiPath + "/Pair/Poll", approvalUrl = Constants.ApprovalPath }),
                    },
                }
                : [],
        ];
    }

    /// <inheritdoc/>
    public static void RegisterServices(IServiceCollection serviceCollection, IApplicationPaths applicationPaths)
    {
        serviceCollection.AddHttpClient(Constants.HttpClientName, client =>
        {
            client.Timeout = TimeSpan.FromSeconds(15);
            client.DefaultRequestHeaders.UserAgent.ParseAdd("Shoko.Plugin.Oidc/1.0");
        });
        serviceCollection.AddSingleton<OidcClient>();
        serviceCollection.AddSingleton<LoginStateStore>();
        serviceCollection.AddSingleton<UnmappedSubjectTracker>();
        serviceCollection.AddSingleton<OidcLoginService>();

        // The store is handed a revoke callback rather than the user
        // service, so the state machine has no host in it and can be tested
        // without one. The only thing it revokes is a key it caused to be
        // minted and that nobody collected.
        serviceCollection.AddSingleton(provider => new PairingStore(
            provider.GetRequiredService<ILogger<PairingStore>>(),
            apiKey => provider.GetRequiredService<IUserService>().InvalidateApiToken(apiKey)));

        serviceCollection.AddHostedService<HousekeepingService>();
    }
}
