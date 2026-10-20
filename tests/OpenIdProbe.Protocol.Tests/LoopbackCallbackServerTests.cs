using System.Net;
using System.Net.Http;
using OpenIdProbe.Protocol.OAuth;

namespace OpenIdProbe.Protocol.Tests;

public class LoopbackCallbackServerTests : IAsyncDisposable
{
    private LoopbackCallbackServer? _server;

    [Fact]
    public async Task Start_ListensOnSpecifiedPort()
    {
        _server = new LoopbackCallbackServer("http://127.0.0.1:8401/callback");
        await _server.StartAsync();

        using var client = new HttpClient();
        var response = await client.GetAsync("http://127.0.0.1:8401/callback?code=test&state=test");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task WaitForCallback_ReturnsCodeAndState()
    {
        _server = new LoopbackCallbackServer("http://127.0.0.1:8402/callback");
        await _server.StartAsync();

        // Simulate callback in background
        _ = Task.Run(async () =>
        {
            await Task.Delay(100);
            using var client = new HttpClient();
            await client.GetAsync("http://127.0.0.1:8402/callback?code=auth-code-123&state=state-456");
        });

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var result = await _server.WaitForCallbackAsync(cts.Token);

        result.Code.Should().Be("auth-code-123");
        result.State.Should().Be("state-456");
        result.Error.Should().BeNull();
    }

    [Fact]
    public async Task WaitForCallback_ReturnsErrorWhenPresent()
    {
        _server = new LoopbackCallbackServer("http://127.0.0.1:8403/callback");
        await _server.StartAsync();

        // Simulate error callback
        _ = Task.Run(async () =>
        {
            await Task.Delay(100);
            using var client = new HttpClient();
            await client.GetAsync("http://127.0.0.1:8403/callback?error=access_denied&error_description=User+denied+access&state=state-789");
        });

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var result = await _server.WaitForCallbackAsync(cts.Token);

        result.Code.Should().BeNull();
        result.Error.Should().Be("access_denied");
        result.ErrorDescription.Should().Be("User denied access");
        result.State.Should().Be("state-789");
    }

    [Fact]
    public async Task WaitForCallback_ThrowsOnCancellation()
    {
        _server = new LoopbackCallbackServer("http://127.0.0.1:8404/callback");
        await _server.StartAsync();

        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));

        // TaskCanceledException inherits from OperationCanceledException
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => _server.WaitForCallbackAsync(cts.Token));
    }

    [Fact]
    public async Task Callback_ReturnsSuccessHtmlPage()
    {
        _server = new LoopbackCallbackServer("http://127.0.0.1:8405/callback");
        await _server.StartAsync();

        using var client = new HttpClient();
        var response = await client.GetAsync("http://127.0.0.1:8405/callback?code=test&state=test");
        var content = await response.Content.ReadAsStringAsync();

        content.Should().Contain("html");
        content.Should().Contain("Authentication successful");
    }

    public async ValueTask DisposeAsync()
    {
        if (_server != null)
        {
            await _server.DisposeAsync();
        }
        GC.SuppressFinalize(this);
    }
}
