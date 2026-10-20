using System.Net;
using System.Web;

namespace OpenIdProbe.Protocol.OAuth;

/// <summary>
/// A lightweight HTTP server to receive OAuth callbacks on a loopback address.
/// </summary>
public sealed class LoopbackCallbackServer : IAsyncDisposable
{
    private readonly string _redirectUri;
    private readonly HttpListener _listener;
    private readonly TaskCompletionSource<CallbackResult> _callbackReceived = new();

    public LoopbackCallbackServer(string redirectUri)
    {
        _redirectUri = redirectUri;

        var uri = new Uri(redirectUri);
        var prefix = $"http://{uri.Host}:{uri.Port}/";

        _listener = new HttpListener();
        _listener.Prefixes.Add(prefix);
    }

    public Task StartAsync()
    {
        _listener.Start();
        _ = ProcessRequestsAsync();
        return Task.CompletedTask;
    }

    public async Task<CallbackResult> WaitForCallbackAsync(CancellationToken cancellationToken)
    {
        using var registration = cancellationToken.Register(() =>
            _callbackReceived.TrySetCanceled(cancellationToken));

        return await _callbackReceived.Task;
    }

    private async Task ProcessRequestsAsync()
    {
        try
        {
            while (_listener.IsListening)
            {
                var context = await _listener.GetContextAsync();
                await HandleRequestAsync(context);
            }
        }
        catch (HttpListenerException)
        {
            // Listener was stopped
        }
        catch (ObjectDisposedException)
        {
            // Listener was disposed
        }
    }

    private async Task HandleRequestAsync(HttpListenerContext context)
    {
        var request = context.Request;
        var response = context.Response;

        try
        {
            var query = HttpUtility.ParseQueryString(request.Url?.Query ?? string.Empty);

            var code = query["code"];
            var state = query["state"];
            var error = query["error"];
            var errorDescription = query["error_description"];

            var result = new CallbackResult(code, state, error, errorDescription);

            // Send response to browser
            var html = error != null
                ? GetErrorHtml(error, errorDescription)
                : GetSuccessHtml();

            var buffer = System.Text.Encoding.UTF8.GetBytes(html);
            response.ContentType = "text/html; charset=utf-8";
            response.ContentLength64 = buffer.Length;
            await response.OutputStream.WriteAsync(buffer);
            response.Close();

            _callbackReceived.TrySetResult(result);
        }
        catch (Exception ex)
        {
            _callbackReceived.TrySetException(ex);
        }
    }

    private static string GetSuccessHtml() => """
        <!DOCTYPE html>
        <html>
        <head>
            <title>OpenID Probe - Authentication successful</title>
            <style>
                body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                       display: flex; justify-content: center; align-items: center;
                       min-height: 100vh; margin: 0; background: #f5f5f5; }
                .container { text-align: center; background: white; padding: 3rem;
                            border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                h1 { color: #2e7d32; margin-bottom: 1rem; }
                p { color: #666; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>✓ Authentication successful</h1>
                <p>You can close this window and return to the terminal.</p>
            </div>
        </body>
        </html>
        """;

    private static string GetErrorHtml(string error, string? description)
    {
        var descriptionHtml = description != null
            ? $"<strong>Description:</strong> {WebUtility.HtmlEncode(description)}"
            : "";

        return $$"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>OpenID Probe - Authentication failed</title>
                <style>
                    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                           display: flex; justify-content: center; align-items: center;
                           min-height: 100vh; margin: 0; background: #f5f5f5; }
                    .container { text-align: center; background: white; padding: 3rem;
                                border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                    h1 { color: #c62828; margin-bottom: 1rem; }
                    p { color: #666; }
                    .error { font-family: monospace; background: #fafafa; padding: 1rem;
                             border-radius: 4px; margin-top: 1rem; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>✗ Authentication failed</h1>
                    <p>An error occurred during authentication.</p>
                    <div class="error">
                        <strong>Error:</strong> {{WebUtility.HtmlEncode(error)}}<br/>
                        {{descriptionHtml}}
                    </div>
                    <p>You can close this window and return to the terminal.</p>
                </div>
            </body>
            </html>
            """;
    }

    public async ValueTask DisposeAsync()
    {
        _listener.Stop();
        _listener.Close();
        await Task.CompletedTask;
    }
}

/// <summary>
/// Result of an OAuth callback.
/// </summary>
public sealed record CallbackResult(
    string? Code,
    string? State,
    string? Error,
    string? ErrorDescription);
