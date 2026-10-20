using OpenIdProbe.Protocol.Http;
using OpenIdProbe.Protocol.Jwks;

namespace OpenIdProbe.IntegrationTests;

public class JwksClientTests
{
    private const string ValidJwksJson = """
        {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "kid": "key-1",
                    "alg": "RS256",
                    "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                    "e": "AQAB"
                }
            ]
        }
        """;

    [Fact]
    public async Task GetJwksAsync_ValidResponse_ReturnsSuccess()
    {
        var mockHandler = new MockHttpMessageHandler();
        mockHandler.SetResponse(
            "https://example.com/.well-known/jwks.json",
            ValidJwksJson);

        var httpClient = new HttpClient(mockHandler);
        var options = new ProbeHttpOptions { AllowPrivateNetwork = true };
        var urlValidator = new UrlSafetyValidator();
        var client = new JwksClient(httpClient, urlValidator, options);

        var result = await client.GetJwksAsync("https://example.com/.well-known/jwks.json");

        result.IsSuccess.Should().BeTrue();
        result.Jwks.Should().NotBeNull();
        result.Jwks!.Keys.Should().HaveCount(1);
        result.Jwks.Keys[0].KeyId.Should().Be("key-1");
    }

    [Fact]
    public async Task GetJwksAsync_InvalidJwks_ReturnsFailure()
    {
        var mockHandler = new MockHttpMessageHandler();
        mockHandler.SetResponse(
            "https://example.com/.well-known/jwks.json",
            """{ "notkeys": [] }""");

        var httpClient = new HttpClient(mockHandler);
        var options = new ProbeHttpOptions { AllowPrivateNetwork = true };
        var urlValidator = new UrlSafetyValidator();
        var client = new JwksClient(httpClient, urlValidator, options);

        var result = await client.GetJwksAsync("https://example.com/.well-known/jwks.json");

        result.IsSuccess.Should().BeFalse();
        result.Error.Should().Contain("keys");
    }
}
