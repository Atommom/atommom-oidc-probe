using System.Text.Json;
using OpenIdProbe.Protocol.Http;

namespace OpenIdProbe.Protocol.Discovery;

/// <summary>
/// Client for fetching OpenID Connect discovery documents.
/// </summary>
public interface IDiscoveryClient
{
    /// <summary>
    /// Fetches the discovery document for an issuer.
    /// </summary>
    /// <param name="issuer">The issuer URL.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The discovery document.</returns>
    Task<DiscoveryDocumentResult> GetDiscoveryDocumentAsync(
        string issuer,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Result of fetching a discovery document.
/// </summary>
public sealed record DiscoveryDocumentResult
{
    public bool IsSuccess { get; init; }
    public DiscoveryDocument? Document { get; init; }
    public string? Error { get; init; }
    public TimeSpan Duration { get; init; }

    public static DiscoveryDocumentResult Success(DiscoveryDocument document, TimeSpan duration) =>
        new() { IsSuccess = true, Document = document, Duration = duration };

    public static DiscoveryDocumentResult Failure(string error, TimeSpan duration) =>
        new() { IsSuccess = false, Error = error, Duration = duration };
}

/// <summary>
/// Default implementation of <see cref="IDiscoveryClient"/>.
/// </summary>
public sealed class DiscoveryClient : IDiscoveryClient
{
    private readonly HttpClient _httpClient;
    private readonly IUrlSafetyValidator _urlValidator;
    private readonly ProbeHttpOptions _options;

    private const string WellKnownPath = "/.well-known/openid-configuration";

    public DiscoveryClient(
        HttpClient httpClient,
        IUrlSafetyValidator urlValidator,
        ProbeHttpOptions options)
    {
        _httpClient = httpClient;
        _urlValidator = urlValidator;
        _options = options;
    }

    public async Task<DiscoveryDocumentResult> GetDiscoveryDocumentAsync(
        string issuer,
        CancellationToken cancellationToken = default)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();

        try
        {
            // Build discovery URL
            var discoveryUrl = BuildDiscoveryUrl(issuer);

            // Validate URL safety
            var validation = _urlValidator.Validate(discoveryUrl, _options);
            if (!validation.IsValid)
            {
                return DiscoveryDocumentResult.Failure(validation.Error!, sw.Elapsed);
            }

            // Fetch document
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(_options.Timeout);

            using var response = await _httpClient.GetAsync(discoveryUrl, cts.Token);

            if (!response.IsSuccessStatusCode)
            {
                return DiscoveryDocumentResult.Failure(
                    $"HTTP {(int)response.StatusCode} {response.ReasonPhrase}",
                    sw.Elapsed);
            }

            // Check content length
            if (response.Content.Headers.ContentLength > _options.MaxResponseSize)
            {
                return DiscoveryDocumentResult.Failure(
                    $"Response too large: {response.Content.Headers.ContentLength} bytes",
                    sw.Elapsed);
            }

            var json = await response.Content.ReadAsStringAsync(cts.Token);

            // Parse and validate
            var document = DiscoveryDocument.Parse(json);
            return DiscoveryDocumentResult.Success(document, sw.Elapsed);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return DiscoveryDocumentResult.Failure("Request timed out", sw.Elapsed);
        }
        catch (HttpRequestException ex)
        {
            return DiscoveryDocumentResult.Failure($"HTTP error: {ex.Message}", sw.Elapsed);
        }
        catch (DiscoveryDocumentParseException ex)
        {
            return DiscoveryDocumentResult.Failure($"Parse error: {ex.Message}", sw.Elapsed);
        }
        catch (JsonException ex)
        {
            return DiscoveryDocumentResult.Failure($"Invalid JSON: {ex.Message}", sw.Elapsed);
        }
    }

    private static string BuildDiscoveryUrl(string issuer)
    {
        var baseUrl = issuer.TrimEnd('/');
        return baseUrl + WellKnownPath;
    }
}
