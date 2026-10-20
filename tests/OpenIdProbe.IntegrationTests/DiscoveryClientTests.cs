using OpenIdProbe.Protocol.Discovery;
using OpenIdProbe.Protocol.Http;

namespace OpenIdProbe.IntegrationTests;

public class DiscoveryClientTests
{
    private const string ValidDiscoveryJson = """
        {
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/authorize",
            "token_endpoint": "https://example.com/token",
            "jwks_uri": "https://example.com/.well-known/jwks.json",
            "response_types_supported": ["code", "token"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "scopes_supported": ["openid", "profile", "email"],
            "code_challenge_methods_supported": ["S256"]
        }
        """;

    [Fact]
    public async Task GetDiscoveryDocumentAsync_ValidResponse_ReturnsSuccess()
    {
        var mockHandler = new MockHttpMessageHandler();
        mockHandler.SetResponse(
            "https://example.com/.well-known/openid-configuration",
            ValidDiscoveryJson);

        var httpClient = new HttpClient(mockHandler);
        var options = new ProbeHttpOptions { AllowPrivateNetwork = true };
        var urlValidator = new UrlSafetyValidator();
        var client = new DiscoveryClient(httpClient, urlValidator, options);

        var result = await client.GetDiscoveryDocumentAsync("https://example.com");

        result.IsSuccess.Should().BeTrue();
        result.Document.Should().NotBeNull();
        result.Document!.Issuer.Should().Be("https://example.com");
        result.Document.AuthorizationEndpoint.Should().Be("https://example.com/authorize");
        result.Document.JwksUri.Should().Be("https://example.com/.well-known/jwks.json");
    }

    [Fact]
    public async Task GetDiscoveryDocumentAsync_NotFound_ReturnsFailure()
    {
        var mockHandler = new MockHttpMessageHandler();
        // No response configured = 404

        var httpClient = new HttpClient(mockHandler);
        var options = new ProbeHttpOptions { AllowPrivateNetwork = true };
        var urlValidator = new UrlSafetyValidator();
        var client = new DiscoveryClient(httpClient, urlValidator, options);

        var result = await client.GetDiscoveryDocumentAsync("https://example.com");

        result.IsSuccess.Should().BeFalse();
        result.Error.Should().Contain("404");
    }

    [Fact]
    public async Task GetDiscoveryDocumentAsync_InvalidJson_ReturnsFailure()
    {
        var mockHandler = new MockHttpMessageHandler();
        mockHandler.SetResponse(
            "https://example.com/.well-known/openid-configuration",
            "not valid json");

        var httpClient = new HttpClient(mockHandler);
        var options = new ProbeHttpOptions { AllowPrivateNetwork = true };
        var urlValidator = new UrlSafetyValidator();
        var client = new DiscoveryClient(httpClient, urlValidator, options);

        var result = await client.GetDiscoveryDocumentAsync("https://example.com");

        result.IsSuccess.Should().BeFalse();
        result.Error.Should().Contain("Parse error");
    }

    [Fact]
    public async Task GetDiscoveryDocumentAsync_HttpNotAllowed_ReturnsFailure()
    {
        var mockHandler = new MockHttpMessageHandler();
        mockHandler.SetResponse(
            "http://example.com/.well-known/openid-configuration",
            ValidDiscoveryJson);

        var httpClient = new HttpClient(mockHandler);
        var options = new ProbeHttpOptions { AllowInsecure = false };
        var urlValidator = new UrlSafetyValidator();
        var client = new DiscoveryClient(httpClient, urlValidator, options);

        var result = await client.GetDiscoveryDocumentAsync("http://example.com");

        result.IsSuccess.Should().BeFalse();
        result.Error.Should().Contain("allow-insecure");
    }
}
