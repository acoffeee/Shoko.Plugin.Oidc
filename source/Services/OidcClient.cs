using System;
using System.Buffers.Text;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Shoko.Plugin.Oidc.Configuration;

namespace Shoko.Plugin.Oidc.Services;

/// <summary>
///   The relying party side of the OpenID Connect authorization code flow,
///   with PKCE: discovery, the authorization URL, the code exchange, and the
///   validation of the ID token, its signature included.
/// </summary>
/// <remarks>
///   Written against the base class library alone, so the plugin ships no
///   assemblies that could clash with the ones the server already loads.
/// </remarks>
public sealed class OidcClient(IHttpClientFactory httpClientFactory, ILogger<OidcClient> logger)
{
    private static readonly TimeSpan _metadataLifetime = TimeSpan.FromHours(1);

    // ID tokens only ever come from our own call to the token endpoint, so
    // this only keeps a misbehaving provider from being asked in a loop.
    private static readonly TimeSpan _minimumKeyRefreshInterval = TimeSpan.FromSeconds(10);

    private static readonly TimeSpan _clockSkew = TimeSpan.FromMinutes(2);

    private static readonly HashSet<string> _supportedAlgorithms = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"];

    private readonly SemaphoreSlim _lock = new(1, 1);

    private ProviderMetadata? _metadata;

    /// <summary>
    ///   Gets the provider's discovery document and signing keys, cached for
    ///   an hour.
    /// </summary>
    /// <param name="configuredIssuer">The issuer from the configuration.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The provider metadata.</returns>
    public async Task<ProviderMetadata> GetMetadata(string configuredIssuer, CancellationToken cancellationToken)
    {
        configuredIssuer = configuredIssuer.Trim().TrimEnd('/');
        if (_metadata is { } cached && cached.ConfiguredIssuer == configuredIssuer && DateTime.UtcNow - cached.FetchedAt < _metadataLifetime)
            return cached;

        await _lock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_metadata is { } cached2 && cached2.ConfiguredIssuer == configuredIssuer && DateTime.UtcNow - cached2.FetchedAt < _metadataLifetime)
                return cached2;

            var metadata = await FetchMetadata(configuredIssuer, cancellationToken).ConfigureAwait(false);
            _metadata = metadata;
            return metadata;
        }
        finally
        {
            _lock.Release();
        }
    }

    private async Task<ProviderMetadata> FetchMetadata(string configuredIssuer, CancellationToken cancellationToken)
    {
        var client = httpClientFactory.CreateClient(Constants.HttpClientName);
        var discoveryUrl = $"{configuredIssuer}/.well-known/openid-configuration";
        logger.LogDebug("Fetching the discovery document from {Url}", discoveryUrl);

        DiscoveryDocument? document;
        try
        {
            document = await client.GetFromJsonAsync<DiscoveryDocument>(discoveryUrl, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is HttpRequestException or JsonException or TaskCanceledException)
        {
            throw new OidcException($"Could not read the identity provider's discovery document at {discoveryUrl}.", ex);
        }

        if (document is null || string.IsNullOrEmpty(document.Issuer) || string.IsNullOrEmpty(document.AuthorizationEndpoint) ||
            string.IsNullOrEmpty(document.TokenEndpoint) || string.IsNullOrEmpty(document.JwksUri))
            throw new OidcException($"The discovery document at {discoveryUrl} is missing the issuer or one of the endpoints.");

        // The issuer the provider claims has to be the one we were told to
        // trust, or anyone able to answer the discovery request could name
        // themselves the issuer of the tokens we accept.
        if (!string.Equals(document.Issuer.TrimEnd('/'), configuredIssuer, StringComparison.Ordinal))
            throw new OidcException($"The discovery document names the issuer \"{document.Issuer}\", not \"{configuredIssuer}\". Set the issuer URL to the one the provider uses.");

        var keys = await FetchKeys(client, document.JwksUri, cancellationToken).ConfigureAwait(false);
        return new(configuredIssuer, document.Issuer, document.AuthorizationEndpoint, document.TokenEndpoint, document.UserInfoEndpoint, document.JwksUri, keys, DateTime.UtcNow);
    }

    private static async Task<IReadOnlyList<JsonWebKey>> FetchKeys(HttpClient client, string jwksUri, CancellationToken cancellationToken)
    {
        try
        {
            var keySet = await client.GetFromJsonAsync<JsonWebKeySet>(jwksUri, cancellationToken).ConfigureAwait(false);
            return keySet?.Keys ?? [];
        }
        catch (Exception ex) when (ex is HttpRequestException or JsonException or TaskCanceledException)
        {
            throw new OidcException($"Could not read the identity provider's signing keys at {jwksUri}.", ex);
        }
    }

    /// <summary>
    ///   Builds the URL to send the browser to.
    /// </summary>
    public static string BuildAuthorizationUrl(ProviderMetadata metadata, OidcPluginConfiguration config, string redirectUri, string state, string nonce, string codeVerifier)
    {
        var scopes = (config.Scopes ?? string.Empty)
            .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Prepend("openid")
            .Distinct(StringComparer.Ordinal);
        var query = new Dictionary<string, string>
        {
            ["response_type"] = "code",
            ["client_id"] = config.ClientID!.Trim(),
            ["redirect_uri"] = redirectUri,
            ["scope"] = string.Join(' ', scopes),
            ["state"] = state,
            ["nonce"] = nonce,
            ["code_challenge"] = CreateCodeChallenge(codeVerifier),
            ["code_challenge_method"] = "S256",
        };
        var separator = metadata.AuthorizationEndpoint.Contains('?') ? '&' : '?';
        return metadata.AuthorizationEndpoint + separator + string.Join('&', query.Select(pair => $"{Uri.EscapeDataString(pair.Key)}={Uri.EscapeDataString(pair.Value)}"));
    }

    /// <summary>
    ///   Creates a random, URL-safe value, for a state, a nonce, a code
    ///   verifier or a secret.
    /// </summary>
    public static string CreateRandomValue(int byteCount = 32)
        => Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(byteCount));

    /// <summary>
    ///   Hashes a value for storage, so that what is kept in memory cannot be
    ///   replayed as the value itself.
    /// </summary>
    public static string Hash(string value)
        => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    private static string CreateCodeChallenge(string codeVerifier)
        => Base64Url.EncodeToString(SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier)));

    /// <summary>
    ///   Exchanges an authorization code for tokens, validates the ID token,
    ///   and returns who signed in.
    /// </summary>
    public async Task<OidcIdentity> CompleteLogin(OidcPluginConfiguration config, string code, string redirectUri, string codeVerifier, string nonce, CancellationToken cancellationToken)
    {
        var metadata = await GetMetadata(config.Issuer!, cancellationToken).ConfigureAwait(false);
        var tokens = await ExchangeCode(metadata, config, code, redirectUri, codeVerifier, cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrEmpty(tokens.IdToken))
            throw new OidcException("The identity provider did not return an ID token. Make sure the client is allowed the openid scope.");

        var claims = await ValidateIdToken(metadata, config.ClientID!.Trim(), tokens.IdToken, nonce, cancellationToken).ConfigureAwait(false);
        var subject = GetString(claims, "sub")!;
        var identity = new OidcIdentity(subject, GetString(claims, "preferred_username"), GetString(claims, "name"), GetString(claims, "email"));

        // Authelia keeps the profile claims out of the ID token by default
        // and serves them from the user info endpoint. They are only ever
        // shown to an admin, so a failure here is not a failed login.
        if ((identity.PreferredUsername is null || identity.Email is null) && !string.IsNullOrEmpty(metadata.UserInfoEndpoint) && !string.IsNullOrEmpty(tokens.AccessToken))
            identity = await AddUserInfo(metadata.UserInfoEndpoint, tokens.AccessToken, identity, cancellationToken).ConfigureAwait(false);

        return identity;
    }

    private async Task<TokenResponse> ExchangeCode(ProviderMetadata metadata, OidcPluginConfiguration config, string code, string redirectUri, string codeVerifier, CancellationToken cancellationToken)
    {
        var clientID = config.ClientID!.Trim();
        var clientSecret = string.IsNullOrEmpty(config.ClientSecret) ? null : config.ClientSecret;
        var body = new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = redirectUri,
            ["code_verifier"] = codeVerifier,
        };

        using var request = new HttpRequestMessage(HttpMethod.Post, metadata.TokenEndpoint);
        if (clientSecret is not null && config.TokenEndpointAuthMethod is TokenEndpointAuthMethod.ClientSecretBasic)
        {
            // RFC 6749 section 2.3.1: both halves are form-encoded first.
            var credentials = $"{WebUtility.UrlEncode(clientID)}:{WebUtility.UrlEncode(clientSecret)}";
            request.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(credentials)));
        }
        else
        {
            body["client_id"] = clientID;
            if (clientSecret is not null)
                body["client_secret"] = clientSecret;
        }

        request.Content = new FormUrlEncodedContent(body);
        request.Headers.Accept.Add(new("application/json"));

        var client = httpClientFactory.CreateClient(Constants.HttpClientName);
        HttpResponseMessage response;
        try
        {
            response = await client.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            throw new OidcException("Could not reach the identity provider's token endpoint.", ex);
        }

        using (response)
        {
            var content = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                var error = TryDeserialize<TokenErrorResponse>(content);
                logger.LogWarning("The token endpoint answered {StatusCode}: {Error} {Description}", (int)response.StatusCode, error?.Error, error?.ErrorDescription);
                throw new OidcException(error?.Error is { } code2
                    ? $"The identity provider refused the login: {code2}{(error.ErrorDescription is { } description ? $" ({description})" : string.Empty)}."
                    : $"The identity provider's token endpoint answered {(int)response.StatusCode}.");
            }

            return TryDeserialize<TokenResponse>(content) ?? throw new OidcException("The identity provider's token response could not be read.");
        }
    }

    private async Task<IReadOnlyDictionary<string, JsonElement>> ValidateIdToken(ProviderMetadata metadata, string clientID, string idToken, string nonce, CancellationToken cancellationToken)
    {
        var parts = idToken.Split('.');
        if (parts.Length != 3)
            throw new OidcException("The ID token is not a signed JWT.");

        JwtHeader header;
        Dictionary<string, JsonElement> claims;
        byte[] signature;
        try
        {
            header = JsonSerializer.Deserialize<JwtHeader>(Base64Url.DecodeFromChars(parts[0])) ?? throw new JsonException();
            claims = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(Base64Url.DecodeFromChars(parts[1])) ?? throw new JsonException();
            signature = Base64Url.DecodeFromChars(parts[2]);
        }
        catch (Exception ex) when (ex is JsonException or FormatException)
        {
            throw new OidcException("The ID token could not be read.", ex);
        }

        if (header.Algorithm is null || !_supportedAlgorithms.Contains(header.Algorithm))
            throw new OidcException($"The ID token is signed with \"{header.Algorithm ?? "none"}\", which is not supported. Use RS256 or ES256.");

        var signedData = Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}");
        if (!VerifySignature(metadata.Keys, header, signedData, signature))
        {
            // The provider may have rotated its keys since they were read.
            var refreshed = await RefreshKeys(metadata, cancellationToken).ConfigureAwait(false);
            if (refreshed is null || !VerifySignature(refreshed.Keys, header, signedData, signature))
                throw new OidcException("The ID token's signature could not be verified against the identity provider's keys.");
        }

        if (GetString(claims, "iss") != metadata.Issuer)
            throw new OidcException("The ID token was issued by someone else.");

        var audiences = GetStrings(claims, "aud");
        if (!audiences.Contains(clientID, StringComparer.Ordinal))
            throw new OidcException("The ID token was issued to another client.");
        if (audiences.Count > 1 && GetString(claims, "azp") is { } authorizedParty && authorizedParty != clientID)
            throw new OidcException("The ID token was issued to another client.");

        var now = DateTimeOffset.UtcNow;
        if (GetNumber(claims, "exp") is not { } expiresAt || DateTimeOffset.FromUnixTimeSeconds(expiresAt) < now - _clockSkew)
            throw new OidcException("The ID token has expired. Check that the clocks of Shoko and the identity provider agree.");
        if (GetNumber(claims, "iat") is { } issuedAt && DateTimeOffset.FromUnixTimeSeconds(issuedAt) > now + _clockSkew)
            throw new OidcException("The ID token was issued in the future. Check that the clocks of Shoko and the identity provider agree.");

        if (GetString(claims, "nonce") is not { } tokenNonce || !CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(tokenNonce), Encoding.UTF8.GetBytes(nonce)))
            throw new OidcException("The ID token does not belong to this login.");

        if (string.IsNullOrEmpty(GetString(claims, "sub")))
            throw new OidcException("The ID token does not name a subject.");

        return claims;
    }

    private async Task<ProviderMetadata?> RefreshKeys(ProviderMetadata metadata, CancellationToken cancellationToken)
    {
        await _lock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var current = _metadata ?? metadata;
            if (current != metadata && current.ConfiguredIssuer == metadata.ConfiguredIssuer)
                return current;
            if (DateTime.UtcNow - metadata.KeysFetchedAt < _minimumKeyRefreshInterval)
                return null;

            var client = httpClientFactory.CreateClient(Constants.HttpClientName);
            var keys = await FetchKeys(client, metadata.JwksUri, cancellationToken).ConfigureAwait(false);
            var refreshed = metadata with { Keys = keys, KeysFetchedAt = DateTime.UtcNow };
            _metadata = refreshed;
            return refreshed;
        }
        finally
        {
            _lock.Release();
        }
    }

    private static bool VerifySignature(IReadOnlyList<JsonWebKey> keys, JwtHeader header, byte[] data, byte[] signature)
    {
        var algorithm = header.Algorithm!;
        var keyType = algorithm[0] == 'E' ? "EC" : "RSA";
        var candidates = keys.Where(key =>
            key.KeyType == keyType &&
            key.Use is null or "sig" &&
            (key.Algorithm is null || key.Algorithm == algorithm) &&
            (header.KeyID is null || key.KeyID == header.KeyID));

        var hashAlgorithm = algorithm[2..] switch
        {
            "256" => HashAlgorithmName.SHA256,
            "384" => HashAlgorithmName.SHA384,
            _ => HashAlgorithmName.SHA512,
        };
        foreach (var key in candidates)
        {
            try
            {
                if (keyType == "RSA")
                {
                    if (key.Modulus is null || key.Exponent is null)
                        continue;
                    using var rsa = RSA.Create(new RSAParameters
                    {
                        Modulus = Base64Url.DecodeFromChars(key.Modulus),
                        Exponent = Base64Url.DecodeFromChars(key.Exponent),
                    });
                    var padding = algorithm[0] == 'P' ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;
                    if (rsa.VerifyData(data, signature, hashAlgorithm, padding))
                        return true;
                }
                else
                {
                    if (key.X is null || key.Y is null)
                        continue;
                    var curve = key.Curve switch
                    {
                        "P-256" => ECCurve.NamedCurves.nistP256,
                        "P-384" => ECCurve.NamedCurves.nistP384,
                        "P-521" => ECCurve.NamedCurves.nistP521,
                        _ => (ECCurve?)null,
                    };
                    if (curve is null)
                        continue;
                    using var ecdsa = ECDsa.Create(new ECParameters
                    {
                        Curve = curve.Value,
                        Q = new() { X = Base64Url.DecodeFromChars(key.X), Y = Base64Url.DecodeFromChars(key.Y) },
                    });
                    if (ecdsa.VerifyData(data, signature, hashAlgorithm, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
                        return true;
                }
            }
            catch (Exception ex) when (ex is CryptographicException or FormatException)
            {
                // A malformed key is skipped, the others may still verify.
            }
        }

        return false;
    }

    private async Task<OidcIdentity> AddUserInfo(string userInfoEndpoint, string accessToken, OidcIdentity identity, CancellationToken cancellationToken)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, userInfoEndpoint);
            request.Headers.Authorization = new("Bearer", accessToken);
            request.Headers.Accept.Add(new("application/json"));
            var client = httpClientFactory.CreateClient(Constants.HttpClientName);
            using var response = await client.SendAsync(request, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode || response.Content.Headers.ContentType?.MediaType != "application/json")
                return identity;

            var claims = await response.Content.ReadFromJsonAsync<Dictionary<string, JsonElement>>(cancellationToken).ConfigureAwait(false);
            // OpenID Connect Core 5.3.2: the user info is only about the
            // ID token's subject if it says so.
            if (claims is null || GetString(claims, "sub") != identity.Subject)
                return identity;

            return identity with
            {
                PreferredUsername = identity.PreferredUsername ?? GetString(claims, "preferred_username"),
                Name = identity.Name ?? GetString(claims, "name"),
                Email = identity.Email ?? GetString(claims, "email"),
            };
        }
        catch (Exception ex) when (ex is HttpRequestException or JsonException or TaskCanceledException)
        {
            logger.LogDebug(ex, "Could not read the user info for subject {Subject}", identity.Subject);
            return identity;
        }
    }

    private static T? TryDeserialize<T>(string content) where T : class
    {
        try
        {
            return JsonSerializer.Deserialize<T>(content);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static string? GetString(IReadOnlyDictionary<string, JsonElement> claims, string name)
        => claims.TryGetValue(name, out var value) && value.ValueKind is JsonValueKind.String ? value.GetString() : null;

    private static long? GetNumber(IReadOnlyDictionary<string, JsonElement> claims, string name)
        => claims.TryGetValue(name, out var value) && value.ValueKind is JsonValueKind.Number && value.TryGetInt64(out var number) ? number : null;

    private static IReadOnlyList<string> GetStrings(IReadOnlyDictionary<string, JsonElement> claims, string name)
    {
        if (!claims.TryGetValue(name, out var value))
            return [];
        if (value.ValueKind is JsonValueKind.String)
            return [value.GetString()!];
        if (value.ValueKind is JsonValueKind.Array)
            return value.EnumerateArray().Where(item => item.ValueKind is JsonValueKind.String).Select(item => item.GetString()!).ToList();
        return [];
    }

    private sealed record DiscoveryDocument(
        [property: JsonPropertyName("issuer")] string? Issuer,
        [property: JsonPropertyName("authorization_endpoint")] string? AuthorizationEndpoint,
        [property: JsonPropertyName("token_endpoint")] string? TokenEndpoint,
        [property: JsonPropertyName("userinfo_endpoint")] string? UserInfoEndpoint,
        [property: JsonPropertyName("jwks_uri")] string? JwksUri
    );

    private sealed record JsonWebKeySet([property: JsonPropertyName("keys")] List<JsonWebKey>? Keys);

    private sealed record TokenResponse(
        [property: JsonPropertyName("access_token")] string? AccessToken,
        [property: JsonPropertyName("id_token")] string? IdToken
    );

    private sealed record TokenErrorResponse(
        [property: JsonPropertyName("error")] string? Error,
        [property: JsonPropertyName("error_description")] string? ErrorDescription
    );

    private sealed record JwtHeader(
        [property: JsonPropertyName("alg")] string? Algorithm,
        [property: JsonPropertyName("kid")] string? KeyID
    );
}

/// <summary>
///   What the plugin uses of the provider's discovery document.
/// </summary>
public sealed record ProviderMetadata(
    string ConfiguredIssuer,
    string Issuer,
    string AuthorizationEndpoint,
    string TokenEndpoint,
    string? UserInfoEndpoint,
    string JwksUri,
    IReadOnlyList<JsonWebKey> Keys,
    DateTime FetchedAt
)
{
    /// <summary>
    ///   When the signing keys were last read.
    /// </summary>
    public DateTime KeysFetchedAt { get; init; } = FetchedAt;
}

/// <summary>
///   One public key of the provider, as much of RFC 7517 as is needed to
///   check a signature.
/// </summary>
public sealed record JsonWebKey(
    [property: JsonPropertyName("kty")] string? KeyType,
    [property: JsonPropertyName("kid")] string? KeyID,
    [property: JsonPropertyName("use")] string? Use,
    [property: JsonPropertyName("alg")] string? Algorithm,
    [property: JsonPropertyName("n")] string? Modulus,
    [property: JsonPropertyName("e")] string? Exponent,
    [property: JsonPropertyName("crv")] string? Curve,
    [property: JsonPropertyName("x")] string? X,
    [property: JsonPropertyName("y")] string? Y
);

/// <summary>
///   Who signed in at the identity provider.
/// </summary>
/// <param name="Subject">The <c>sub</c> claim, the only one used to decide who the user is.</param>
/// <param name="PreferredUsername">The <c>preferred_username</c> claim, for display.</param>
/// <param name="Name">The <c>name</c> claim, for display.</param>
/// <param name="Email">The <c>email</c> claim, for display.</param>
public sealed record OidcIdentity(string Subject, string? PreferredUsername, string? Name, string? Email);

/// <summary>
///   A login that failed, with a message that is safe to show the user.
/// </summary>
public sealed class OidcException(string message, Exception? innerException = null) : Exception(message, innerException);
