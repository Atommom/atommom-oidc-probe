using System.Net;
using System.Text.Json;
using OpenIdProbe.Protocol.OAuth;

namespace OpenIdProbe.Protocol.Tests;

public class TokenClientTests
{
    [Fact]
    public async Task ExchangeCodeAsync_SendsCorrectRequest()
    {
        string? capturedContent = null;

        var handler = new MockHttpHandler((request, ct) =>
        {
            capturedContent = request.Content?.ReadAsStringAsync(ct).Result;
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(JsonSerializer.Serialize(new
                {
                    access_token = "access-token-123",
                    token_type = "Bearer",
                    expires_in = 3600,
                    id_token = "id-token-123"
                }), System.Text.Encoding.UTF8, "application/json")
            };
        });

        var httpClient = new HttpClient(handler);
        var client = new TokenClient(httpClient);

        var request = new TokenExchangeRequest
        {
            TokenEndpoint = "https://auth.example.com/token",
            Code = "auth-code",
            CodeVerifier = "test-verifier",
            ClientId = "test-client",
            RedirectUri = "http://127.0.0.1:8400/callback"
        };

        await client.ExchangeCodeAsync(request, CancellationToken.None);

        capturedContent.Should().Contain("grant_type=authorization_code");
        capturedContent.Should().Contain("code=auth-code");
        capturedContent.Should().Contain("code_verifier=test-verifier");
        capturedContent.Should().Contain("client_id=test-client");
        capturedContent.Should().Contain("redirect_uri=http%3A%2F%2F127.0.0.1%3A8400%2Fcallback");
    }

    [Fact]
    public async Task ExchangeCodeAsync_ReturnsTokenResponse()
    {
        var handler = new MockHttpHandler((_, _) => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(JsonSerializer.Serialize(new
            {
                access_token = "access-token-123",
                token_type = "Bearer",
                expires_in = 3600,
                id_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature",
                refresh_token = "refresh-token-456"
            }), System.Text.Encoding.UTF8, "application/json")
        });

        var httpClient = new HttpClient(handler);
        var client = new TokenClient(httpClient);

        var request = new TokenExchangeRequest
        {
            TokenEndpoint = "https://auth.example.com/token",
            Code = "auth-code",
            CodeVerifier = "test-verifier",
            ClientId = "test-client",
            RedirectUri = "http://127.0.0.1:8400/callback"
        };

        var response = await client.ExchangeCodeAsync(request, CancellationToken.None);

        response.IsSuccess.Should().BeTrue();
        response.AccessToken.Should().Be("access-token-123");
        response.TokenType.Should().Be("Bearer");
        response.ExpiresIn.Should().Be(3600);
        response.IdToken.Should().StartWith("eyJ");
        response.RefreshToken.Should().Be("refresh-token-456");
    }

    [Fact]
    public async Task ExchangeCodeAsync_ReturnsError_OnOAuthError()
    {
        var handler = new MockHttpHandler((_, _) => new HttpResponseMessage(HttpStatusCode.BadRequest)
        {
            Content = new StringContent(JsonSerializer.Serialize(new
            {
                error = "invalid_grant",
                error_description = "Authorization code has expired"
            }), System.Text.Encoding.UTF8, "application/json")
        });

        var httpClient = new HttpClient(handler);
        var client = new TokenClient(httpClient);

        var request = new TokenExchangeRequest
        {
            TokenEndpoint = "https://auth.example.com/token",
            Code = "expired-code",
            CodeVerifier = "test-verifier",
            ClientId = "test-client",
            RedirectUri = "http://127.0.0.1:8400/callback"
        };

        var response = await client.ExchangeCodeAsync(request, CancellationToken.None);

        response.IsSuccess.Should().BeFalse();
        response.Error.Should().Be("invalid_grant");
        response.ErrorDescription.Should().Be("Authorization code has expired");
    }

    [Fact]
    public async Task ExchangeCodeAsync_ReturnsError_OnHttpFailure()
    {
        var handler = new MockHttpHandler((_, _) => new HttpResponseMessage(HttpStatusCode.InternalServerError)
        {
            Content = new StringContent("Internal Server Error")
        });

        var httpClient = new HttpClient(handler);
        var client = new TokenClient(httpClient);

        var request = new TokenExchangeRequest
        {
            TokenEndpoint = "https://auth.example.com/token",
            Code = "auth-code",
            CodeVerifier = "test-verifier",
            ClientId = "test-client",
            RedirectUri = "http://127.0.0.1:8400/callback"
        };

        var response = await client.ExchangeCodeAsync(request, CancellationToken.None);

        response.IsSuccess.Should().BeFalse();
        response.Error.Should().NotBeNullOrEmpty();
    }

    private sealed class MockHttpHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, CancellationToken, HttpResponseMessage> _handler;

        public MockHttpHandler(Func<HttpRequestMessage, CancellationToken, HttpResponseMessage> handler)
        {
            _handler = handler;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            return Task.FromResult(_handler(request, cancellationToken));
        }
    }
}
