using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Shoko.Plugin.Oidc.Services;

/// <summary>
///   The device pairing state machine. A device asks to be paired and gets a
///   short code to show and a long secret to keep; a user signs in, approves
///   the code, and the API key minted for them waits here until the device
///   collects it with its secret.
/// </summary>
/// <remarks>
///   <code>
///   Pending ──approve──▶ Approving ──minted──▶ Approved ──poll──▶ (collected)
///      │                     └──failed──▶ Pending
///      └──deny──▶ Denied ──poll──▶ (gone)
///   </code>
///   Anything not finished in time is swept. A key that was minted and never
///   collected is revoked, but only when the store caused it to be minted: a
///   key handed back because the device already had one is left alone.
/// </remarks>
/// <param name="logger">The logger.</param>
/// <param name="revokeApiKey">Revokes a key that was minted and never collected.</param>
public sealed class PairingStore(ILogger<PairingStore> logger, Func<string, Task> revokeApiKey)
{
    /// <summary>
    ///   The characters of a pairing code: no vowels, so no words, and nothing
    ///   that is easily mistaken for something else. From RFC 8628 section 6.1.
    /// </summary>
    private const string CodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ";

    private const int CodeLength = 8;

    // Pairing can be started without signing in, so there is a ceiling on how
    // many requests can wait at once.
    private const int MaxPairings = 100;

    /// <summary>
    ///   How long an approved key waits for its device to collect it.
    /// </summary>
    public static readonly TimeSpan CollectWindow = TimeSpan.FromMinutes(5);

    /// <summary>
    ///   How often a device is asked to poll, in seconds.
    /// </summary>
    public const int PollIntervalSeconds = 5;

    private readonly object _lock = new();

    private readonly Dictionary<string, Pairing> _byCode = new(StringComparer.Ordinal);

    private readonly Dictionary<string, Pairing> _bySecretHash = new(StringComparer.Ordinal);

    /// <summary>
    ///   Starts a pairing request.
    /// </summary>
    /// <param name="deviceName">The device name the key will be minted under.</param>
    /// <param name="requestedFrom">Where the request came from, shown to the approving user.</param>
    /// <param name="window">How long the code can be approved for.</param>
    /// <param name="now">The current time.</param>
    /// <returns>The code and secret, or <c>null</c> when too many requests are waiting.</returns>
    public PairingRequest? Start(string deviceName, string? requestedFrom, TimeSpan window, DateTime now)
    {
        var secret = OidcClient.CreateRandomValue();
        lock (_lock)
        {
            if (_byCode.Count >= MaxPairings)
                return null;

            string code;
            do
                code = RandomNumberGenerator.GetString(CodeAlphabet, CodeLength);
            while (_byCode.ContainsKey(code));

            var pairing = new Pairing(code, OidcClient.Hash(secret), deviceName, requestedFrom, now + window);
            _byCode[code] = pairing;
            _bySecretHash[pairing.SecretHash] = pairing;
            logger.LogInformation("Device {DeviceName} asked to be paired from {RequestedFrom}", deviceName, requestedFrom);
            return new(FormatCode(code), secret, pairing.ExpiresAt);
        }
    }

    /// <summary>
    ///   Looks up a pairing request by the code its device shows.
    /// </summary>
    /// <returns>The request, or <c>null</c> when the code is unknown or expired.</returns>
    public PairingInfo? Find(string code, DateTime now)
    {
        lock (_lock)
        {
            if (!_byCode.TryGetValue(NormalizeCode(code), out var pairing) || IsExpired(pairing, now))
                return null;
            return new(FormatCode(pairing.Code), pairing.DeviceName, pairing.RequestedFrom, pairing.ExpiresAt, pairing.Status);
        }
    }

    /// <summary>
    ///   Moves a pending request to approving, so only one approval can mint a
    ///   key for it.
    /// </summary>
    public bool TryBeginApproval(string code, DateTime now)
    {
        lock (_lock)
        {
            if (!_byCode.TryGetValue(NormalizeCode(code), out var pairing) || IsExpired(pairing, now) || pairing.Status is not PairingStatus.Pending)
                return false;
            pairing.Status = PairingStatus.Approving;
            return true;
        }
    }

    /// <summary>
    ///   Puts the minted key in place for the device to collect.
    /// </summary>
    /// <param name="code">The pairing code.</param>
    /// <param name="apiKey">The minted key.</param>
    /// <param name="username">The Shoko user the key belongs to.</param>
    /// <param name="mintedByUs">Whether the key was newly minted, rather than one the device already had.</param>
    /// <param name="now">The current time.</param>
    /// <returns><c>false</c> when the request was swept while the key was minted, which revokes the key again.</returns>
    public async Task<bool> CompleteApproval(string code, string apiKey, string username, bool mintedByUs, DateTime now)
    {
        lock (_lock)
        {
            if (_byCode.TryGetValue(NormalizeCode(code), out var pairing) && pairing.Status is PairingStatus.Approving)
            {
                pairing.Status = PairingStatus.Approved;
                pairing.ApiKey = apiKey;
                pairing.Username = username;
                pairing.MintedByUs = mintedByUs;
                pairing.ExpiresAt = now + CollectWindow;
                logger.LogInformation("Device {DeviceName} was approved for user {Username}", pairing.DeviceName, username);
                return true;
            }
        }

        if (mintedByUs)
            await Revoke(apiKey).ConfigureAwait(false);
        return false;
    }

    /// <summary>
    ///   Puts a request back to pending after minting its key failed.
    /// </summary>
    public void AbortApproval(string code)
    {
        lock (_lock)
        {
            if (_byCode.TryGetValue(NormalizeCode(code), out var pairing) && pairing.Status is PairingStatus.Approving)
                pairing.Status = PairingStatus.Pending;
        }
    }

    /// <summary>
    ///   Denies a pending request.
    /// </summary>
    public bool Deny(string code, DateTime now)
    {
        lock (_lock)
        {
            if (!_byCode.TryGetValue(NormalizeCode(code), out var pairing) || IsExpired(pairing, now) || pairing.Status is not PairingStatus.Pending)
                return false;
            pairing.Status = PairingStatus.Denied;
            logger.LogInformation("Device {DeviceName} was denied", pairing.DeviceName);
            return true;
        }
    }

    /// <summary>
    ///   Answers a device asking how its request is going, and hands over the
    ///   key once it is approved. A finished request is forgotten once its
    ///   device has been told.
    /// </summary>
    public PollResult Poll(string secret, DateTime now)
    {
        lock (_lock)
        {
            if (!_bySecretHash.TryGetValue(OidcClient.Hash(secret), out var pairing) || IsExpired(pairing, now))
                return new(PairingStatus.Expired, null, null);

            switch (pairing.Status)
            {
                case PairingStatus.Approved:
                    Remove(pairing);
                    logger.LogInformation("Device {DeviceName} collected its key", pairing.DeviceName);
                    return new(PairingStatus.Approved, pairing.ApiKey, pairing.Username);
                case PairingStatus.Denied:
                    Remove(pairing);
                    return new(PairingStatus.Denied, null, null);
                default:
                    // Approving reads as pending; the key is on its way.
                    return new(PairingStatus.Pending, null, null);
            }
        }
    }

    /// <summary>
    ///   Forgets the requests that ran out of time, and revokes any key the
    ///   store minted that was never collected.
    /// </summary>
    public async Task Sweep(DateTime now)
    {
        var toRevoke = new List<string>();
        lock (_lock)
        {
            // A request in the middle of being approved is left for
            // CompleteApproval, which revokes the key itself if it is late.
            foreach (var pairing in _byCode.Values.Where(pairing => IsExpired(pairing, now) && pairing.Status is not PairingStatus.Approving).ToList())
            {
                Remove(pairing);
                if (pairing.Status is PairingStatus.Approved && pairing.MintedByUs && pairing.ApiKey is { } apiKey)
                {
                    logger.LogInformation("Device {DeviceName} never collected its key, revoking it", pairing.DeviceName);
                    toRevoke.Add(apiKey);
                }
            }
        }

        foreach (var apiKey in toRevoke)
            await Revoke(apiKey).ConfigureAwait(false);
    }

    private async Task Revoke(string apiKey)
    {
        try
        {
            await revokeApiKey(apiKey).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Could not revoke an uncollected API key");
        }
    }

    private void Remove(Pairing pairing)
    {
        _byCode.Remove(pairing.Code);
        _bySecretHash.Remove(pairing.SecretHash);
    }

    private static bool IsExpired(Pairing pairing, DateTime now)
        => pairing.ExpiresAt <= now && pairing.Status is not PairingStatus.Approving;

    /// <summary>
    ///   Turns what a user typed into the code as stored: upper case, with
    ///   the dash and any spaces left out.
    /// </summary>
    public static string NormalizeCode(string code)
        => new(code.Where(char.IsLetterOrDigit).Select(char.ToUpperInvariant).ToArray());

    private static string FormatCode(string code)
        => $"{code[..(CodeLength / 2)]}-{code[(CodeLength / 2)..]}";

    private sealed class Pairing(string code, string secretHash, string deviceName, string? requestedFrom, DateTime expiresAt)
    {
        public string Code { get; } = code;

        public string SecretHash { get; } = secretHash;

        public string DeviceName { get; } = deviceName;

        public string? RequestedFrom { get; } = requestedFrom;

        public DateTime ExpiresAt { get; set; } = expiresAt;

        public PairingStatus Status { get; set; } = PairingStatus.Pending;

        public string? ApiKey { get; set; }

        public string? Username { get; set; }

        public bool MintedByUs { get; set; }
    }
}

/// <summary>
///   Where a pairing request stands.
/// </summary>
public enum PairingStatus
{
    /// <summary>
    ///   Waiting for a user to approve or deny it.
    /// </summary>
    Pending,

    /// <summary>
    ///   Approved, with the key being minted.
    /// </summary>
    Approving,

    /// <summary>
    ///   Approved, with the key waiting for the device.
    /// </summary>
    Approved,

    /// <summary>
    ///   Denied by the user.
    /// </summary>
    Denied,

    /// <summary>
    ///   Unknown, expired, or already collected.
    /// </summary>
    Expired,
}

/// <summary>
///   What a device gets back when it asks to be paired.
/// </summary>
/// <param name="Code">The code to show the user.</param>
/// <param name="Secret">The secret to poll with. Never shown to the user.</param>
/// <param name="ExpiresAt">When the code stops working.</param>
public sealed record PairingRequest(string Code, string Secret, DateTime ExpiresAt);

/// <summary>
///   A pairing request, as shown to the user approving it.
/// </summary>
public sealed record PairingInfo(string Code, string DeviceName, string? RequestedFrom, DateTime ExpiresAt, PairingStatus Status);

/// <summary>
///   The answer to a device polling.
/// </summary>
/// <param name="Status">Where the request stands.</param>
/// <param name="ApiKey">The key, once approved.</param>
/// <param name="Username">The Shoko user the key belongs to, once approved.</param>
public sealed record PollResult(PairingStatus Status, string? ApiKey, string? Username);
