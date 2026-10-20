using System.Net;
using System.Text.Json;
using OpenIdProbe.Protocol.OAuth;

namespace OpenIdProbe.Protocol.Tests;

public class UserInfoClientTests
{
    [Fact]
    public async Task GetUserInfoAsync_SendsAuthorizationHeader()
    {
        string? authHeader = null;

        var handler = new MockHttpHandler((request, _) =>
        {
            authHeader = request.Headers.Authorization?.ToString();
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(JsonSerializer.Serialize(new
                {
                    sub = "user-123",
                    name = "Test User",
                    email = "test@example.com"
                }), System.Text.Encoding.UTF8, "application/json")
            };
        });

        var httpClient = new HttpClient(handler);
        var client = new UserInfoClient(httpClient);

        await client.GetUserInfoAsync("https://auth.example.com/userinfo", "access-token-123", CancellationToken.None);

        authHeader.Should().Be("Bearer access-token-123");
    }

    [Fact]
    public async Task GetUserInfoAsync_ReturnsUserInfoClaims()
    {
        var handler = new MockHttpHandler((_, _) => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(JsonSerializer.Serialize(new
            {
                sub = "user-123",
                name = "Test User",
                email = "test@example.com",
                email_verified = true,
                picture = "https://example.com/photo.jpg"
            }), System.Text.Encoding.UTF8, "application/json")
        });

        var httpClient = new HttpClient(handler);
        var client = new UserInfoClient(httpClient);

        var result = await client.GetUserInfoAsync("https://auth.example.com/userinfo", "token", CancellationToken.None);

        result.IsSuccess.Should().BeTrue();
        result.Subject.Should().Be("user-123");
        result.Name.Should().Be("Test User");
        result.Email.Should().Be("test@example.com");
        result.EmailVerified.Should().BeTrue();
        result.Picture.Should().Be("https://example.com/photo.jpg");
    }

    [Fact]
    public async Task GetUserInfoAsync_ReturnsError_On401()
    {
        var handler = new MockHttpHandler((_, _) => new HttpResponseMessage(HttpStatusCode.Unauthorized)
        {
            Content = new StringContent("Unauthorized")
        });

        var httpClient = new HttpClient(handler);
        var client = new UserInfoClient(httpClient);

        var result = await client.GetUserInfoAsync("https://auth.example.com/userinfo", "invalid-token", CancellationToken.None);

        result.IsSuccess.Should().BeFalse();
        result.Error.Should().Contain("401");
    }

    [Fact]
    public async Task GetUserInfoAsync_ReturnsError_OnInvalidJson()
    {
        var handler = new MockHttpHandler((_, _) => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("not valid json", System.Text.Encoding.UTF8, "application/json")
        });

        var httpClient = new HttpClient(handler);
        var client = new UserInfoClient(httpClient);

        var result = await client.GetUserInfoAsync("https://auth.example.com/userinfo", "token", CancellationToken.None);

        result.IsSuccess.Should().BeFalse();
        result.Error.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task GetUserInfoAsync_HandlesMissingSub()
    {
        var handler = new MockHttpHandler((_, _) => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(JsonSerializer.Serialize(new
            {
                name = "Test User"
                // Missing required 'sub' claim
            }), System.Text.Encoding.UTF8, "application/json")
        });

        var httpClient = new HttpClient(handler);
        var client = new UserInfoClient(httpClient);

        var result = await client.GetUserInfoAsync("https://auth.example.com/userinfo", "token", CancellationToken.None);

        result.IsSuccess.Should().BeFalse();
        result.Error.Should().Contain("sub");
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
