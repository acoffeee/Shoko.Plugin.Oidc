using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Shoko.Abstractions.Config;
using Shoko.Abstractions.Config.Exceptions;
using Shoko.Abstractions.User.Services;
using Shoko.Plugin.Oidc.Configuration;
using Shoko.Plugin.Oidc.Services;

namespace Shoko.Plugin.Oidc.Controllers;

/// <summary>
///   The plugin's API: device pairing for devices, and subject mapping for
///   admins.
/// </summary>
[ApiController]
[Route(Constants.ApiPath)]
public class OidcApiController(
    ConfigurationProvider<OidcPluginConfiguration> configurationProvider,
    PairingStore pairingStore,
    UnmappedSubjectTracker unmappedSubjects,
    IUserService userService
) : ControllerBase
{
    #region Pairing

    /// <summary>
    ///   Asks to pair a device. Show the user <c>Code</c> and
    ///   <c>VerificationUri</c> (or <c>VerificationUriComplete</c> as a link
    ///   or QR code), keep <c>Secret</c> to yourself, and poll with it every
    ///   <c>Interval</c> seconds until the request is answered.
    /// </summary>
    /// <param name="body">The device asking.</param>
    [AllowAnonymous]
    [HttpPost("Pair")]
    [ProducesResponseType<PairStartResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status429TooManyRequests)]
    public ActionResult<PairStartResponse> StartPairing([FromBody] PairStartBody body)
    {
        var config = configurationProvider.Load();
        if (!config.EnableDevicePairing || !config.IsConfigured())
            return NotFound("Device pairing is not available.");

        var deviceName = body.DeviceName.Trim();
        if (deviceName.Length == 0)
            return ValidationProblem("The device name cannot be empty.");

        var requestedFrom = HttpContext.Connection.RemoteIpAddress?.ToString();
        var request = pairingStore.Start(deviceName, requestedFrom, TimeSpan.FromMinutes(config.PairingWindowMinutes), DateTime.UtcNow);
        if (request is null)
            return StatusCode(StatusCodes.Status429TooManyRequests, "Too many devices are waiting to be paired. Try again in a few minutes.");

        var verificationUri = OidcLoginService.GetBaseUrl(config, Request) + Constants.ApprovalPath;
        return new PairStartResponse(
            request.Code,
            request.Secret,
            verificationUri,
            $"{verificationUri}?code={Uri.EscapeDataString(request.Code)}",
            request.ExpiresAt,
            PairingStore.PollIntervalSeconds
        );
    }

    /// <summary>
    ///   Asks how a pairing request is going. Once it is approved, the answer
    ///   carries the API key, and only that one answer does.
    /// </summary>
    /// <param name="body">The secret from <see cref="StartPairing"/>.</param>
    [AllowAnonymous]
    [HttpPost("Pair/Poll")]
    [ProducesResponseType<PairPollResponse>(StatusCodes.Status200OK)]
    public ActionResult<PairPollResponse> PollPairing([FromBody] PairPollBody body)
    {
        var result = pairingStore.Poll(body.Secret, DateTime.UtcNow);
        return new PairPollResponse(result.Status.ToString(), result.ApiKey, result.Username);
    }

    #endregion

    #region Admin

    /// <summary>
    ///   Gets everything the admin page shows: the mappings, the Shoko users
    ///   to map to, the subjects that tried to sign in without a mapping, and
    ///   what to register with the identity provider.
    /// </summary>
    [Authorize("admin")]
    [HttpGet("Admin")]
    public ActionResult<AdminState> GetAdminState()
    {
        var config = configurationProvider.Load();
        var users = userService.GetUsers()
            .OrderBy(user => user.Username, StringComparer.OrdinalIgnoreCase)
            .Select(user => new AdminUser(user.LocalID, user.Username, user.IsAdmin))
            .ToList();
        var mappedSubjects = config.UserMappings.Select(mapping => mapping.Subject.Trim()).ToHashSet(StringComparer.Ordinal);
        return new AdminState(
            config.IsConfigured(),
            config.Issuer,
            config.ClientID,
            // Named as the provider's client has to name it. A client that is
            // set up but has no secret is a public one.
            string.IsNullOrEmpty(config.ClientSecret) && config.IsConfigured()
                ? "none"
                : config.TokenEndpointAuthMethod is TokenEndpointAuthMethod.ClientSecretPost ? "client_secret_post" : "client_secret_basic",
            OidcLoginService.GetRedirectUri(config, Request),
            OidcLoginService.GetBaseUrl(config, Request) + Constants.LoginPath,
            string.IsNullOrWhiteSpace(config.PublicUrl),
            config.UserMappings.Select(mapping => new AdminMapping(mapping.Subject, mapping.UserID, mapping.Note)).ToList(),
            users,
            unmappedSubjects.GetAll().Where(entry => !mappedSubjects.Contains(entry.Subject)).ToList()
        );
    }

    /// <summary>
    ///   Maps a subject to a Shoko user, or changes the user it is mapped to.
    /// </summary>
    [Authorize("admin")]
    [HttpPut("Admin/Mapping")]
    public ActionResult<AdminMapping> SaveMapping([FromBody] AdminMapping body)
    {
        var subject = body.Subject.Trim();
        if (subject.Length == 0)
            return ValidationProblem("The subject cannot be empty.");
        if (userService.GetUserByID(body.UserID) is null)
            return ValidationProblem($"There is no Shoko user with ID {body.UserID}.");

        var config = configurationProvider.Load(copy: true);
        var note = string.IsNullOrWhiteSpace(body.Note) ? null : body.Note.Trim();
        if (config.FindMapping(subject) is { } existing)
        {
            existing.UserID = body.UserID;
            existing.Note = note;
        }
        else
        {
            config.UserMappings.Add(new() { Subject = subject, UserID = body.UserID, Note = note });
        }

        if (Save(config) is { } problem)
            return problem;

        unmappedSubjects.Remove(subject);
        return new AdminMapping(subject, body.UserID, note);
    }

    /// <summary>
    ///   Removes a subject's mapping. API keys it already got stay valid until
    ///   they expire or are revoked.
    /// </summary>
    [Authorize("admin")]
    [HttpDelete("Admin/Mapping")]
    public ActionResult RemoveMapping([FromQuery, Required] string subject)
    {
        var config = configurationProvider.Load(copy: true);
        if (config.FindMapping(subject.Trim()) is not { } existing)
            return NotFound();

        config.UserMappings.Remove(existing);
        return Save(config) ?? (ActionResult)NoContent();
    }

    /// <summary>
    ///   Forgets a subject that tried to sign in without a mapping.
    /// </summary>
    [Authorize("admin")]
    [HttpDelete("Admin/Unmapped")]
    public ActionResult DismissUnmapped([FromQuery, Required] string subject)
        => unmappedSubjects.Remove(subject) ? NoContent() : NotFound();

    private ActionResult? Save(OidcPluginConfiguration config)
    {
        try
        {
            configurationProvider.Save(config);
            return null;
        }
        catch (ConfigurationValidationException ex)
        {
            return ValidationProblem(string.Join(" ", ex.ValidationErrors.SelectMany(pair => pair.Value.Select(message => $"{pair.Key}: {message}"))));
        }
    }

    #endregion
}

/// <summary>
///   A device asking to be paired.
/// </summary>
/// <param name="DeviceName">The device name its API key is minted under.</param>
public sealed record PairStartBody([Required, MaxLength(64)] string DeviceName);

/// <summary>
///   An answer to a device asking to be paired.
/// </summary>
/// <param name="Code">The code to show the user.</param>
/// <param name="Secret">The secret to poll with. Never show it to the user.</param>
/// <param name="VerificationUri">Where the user enters the code.</param>
/// <param name="VerificationUriComplete">Where the user approves this code without typing it.</param>
/// <param name="ExpiresAt">When the code stops working.</param>
/// <param name="Interval">How many seconds to wait between polls.</param>
public sealed record PairStartResponse(string Code, string Secret, string VerificationUri, string VerificationUriComplete, DateTime ExpiresAt, int Interval);

/// <summary>
///   A device polling.
/// </summary>
/// <param name="Secret">The secret it was given.</param>
public sealed record PairPollBody([Required, MaxLength(128)] string Secret);

/// <summary>
///   Where a pairing request stands.
/// </summary>
/// <param name="Status"><c>Pending</c>, <c>Approved</c>, <c>Denied</c> or <c>Expired</c>.</param>
/// <param name="ApiKey">The key, when approved.</param>
/// <param name="Username">The Shoko user the key belongs to, when approved.</param>
public sealed record PairPollResponse(string Status, string? ApiKey, string? Username);

/// <summary>
///   What the admin page shows.
/// </summary>
public sealed record AdminState(
    bool IsConfigured,
    string? Issuer,
    string? ClientID,
    string TokenEndpointAuthMethod,
    string RedirectUri,
    string LoginUrl,
    bool RedirectUriFromRequest,
    IReadOnlyList<AdminMapping> Mappings,
    IReadOnlyList<AdminUser> Users,
    IReadOnlyList<UnmappedSubject> Unmapped
);

/// <summary>
///   A subject mapped to a Shoko user.
/// </summary>
public sealed record AdminMapping([Required] string Subject, int UserID, string? Note);

/// <summary>
///   A Shoko user to map to.
/// </summary>
public sealed record AdminUser(int ID, string Username, bool IsAdmin);
