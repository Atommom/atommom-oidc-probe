using System.Text.Json;
using OpenIdProbe.Protocol.Http;

namespace OpenIdProbe.Protocol.Jwks;

/// <summary>
/// Client for fetching JSON Web Key Sets.
/// </summary>
public interface IJwksClient
{
    /// <summary>
    /// Fetches a JWKS from a URL.
    /// </summary>
    /// <param name="jwksUri">The JWKS URI.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The JWKS result.</returns>
    Task<JwksResult> GetJwksAsync(
        string jwksUri,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Result of fetching a JWKS.
/// </summary>
public sealed record JwksResult
{
    public bool IsSuccess { get; init; }
    public JsonWebKeySet? Jwks { get; init; }
    public string? Error { get; init; }
    public TimeSpan Duration { get; init; }

    public static JwksResult Success(JsonWebKeySet jwks, TimeSpan duration) =>
        new() { IsSuccess = true, Jwks = jwks, Duration = duration };

    public static JwksResult Failure(string error, TimeSpan duration) =>
        new() { IsSuccess = false, Error = error, Duration = duration };
}

/// <summary>
/// Default implementation of <see cref="IJwksClient"/>.
/// </summary>
public sealed class JwksClient : IJwksClient
{
    private readonly HttpClient _httpClient;
    private readonly IUrlSafetyValidator _urlValidator;
    private readonly ProbeHttpOptions _options;

    public JwksClient(
        HttpClient httpClient,
        IUrlSafetyValidator urlValidator,
        ProbeHttpOptions options)
    {
        _httpClient = httpClient;
        _urlValidator = urlValidator;
        _options = options;
    }

    public async Task<JwksResult> GetJwksAsync(
        string jwksUri,
        CancellationToken cancellationToken = default)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();

        try
        {
            // Validate URL safety
            var validation = _urlValidator.Validate(jwksUri, _options);
            if (!validation.IsValid)
            {
                return JwksResult.Failure(validation.Error!, sw.Elapsed);
            }

            // Fetch JWKS
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(_options.Timeout);

            using var response = await _httpClient.GetAsync(jwksUri, cts.Token);

            if (!response.IsSuccessStatusCode)
            {
                return JwksResult.Failure(
                    $"HTTP {(int)response.StatusCode} {response.ReasonPhrase}",
                    sw.Elapsed);
            }

            // Check content length
            if (response.Content.Headers.ContentLength > _options.MaxResponseSize)
            {
                return JwksResult.Failure(
                    $"Response too large: {response.Content.Headers.ContentLength} bytes",
                    sw.Elapsed);
            }

            var json = await response.Content.ReadAsStringAsync(cts.Token);

            // Parse JWKS
            var jwks = JsonWebKeySet.Parse(json);
            return JwksResult.Success(jwks, sw.Elapsed);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return JwksResult.Failure("Request timed out", sw.Elapsed);
        }
        catch (HttpRequestException ex)
        {
            return JwksResult.Failure($"HTTP error: {ex.Message}", sw.Elapsed);
        }
        catch (JwksParseException ex)
        {
            return JwksResult.Failure($"Parse error: {ex.Message}", sw.Elapsed);
        }
        catch (JsonException ex)
        {
            return JwksResult.Failure($"Invalid JSON: {ex.Message}", sw.Elapsed);
        }
    }
}
