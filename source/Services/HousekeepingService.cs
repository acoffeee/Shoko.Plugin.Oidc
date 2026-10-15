using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Shoko.Plugin.Oidc.Services;

/// <summary>
///   Sweeps the logins and pairing requests that ran out of time, so that a
///   key nobody collected is revoked even when nobody asks about it again.
/// </summary>
public sealed class HousekeepingService(LoginStateStore loginStateStore, PairingStore pairingStore, ILogger<HousekeepingService> logger) : BackgroundService
{
    private static readonly TimeSpan _interval = TimeSpan.FromSeconds(30);

    /// <inheritdoc/>
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(_interval);
        while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
        {
            try
            {
                var now = DateTime.UtcNow;
                loginStateStore.Sweep(now);
                await pairingStore.Sweep(now).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Sweeping expired logins and pairing requests failed");
            }
        }
    }
}
