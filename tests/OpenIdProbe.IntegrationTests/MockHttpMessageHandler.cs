using System.Net;
using System.Text;

namespace OpenIdProbe.IntegrationTests;

/// <summary>
/// A mock HTTP message handler for testing.
/// </summary>
public sealed class MockHttpMessageHandler : HttpMessageHandler
{
    private readonly Dictionary<string, (HttpStatusCode StatusCode, string Content)> _responses = new();

    public void SetResponse(string url, string content, HttpStatusCode statusCode = HttpStatusCode.OK)
    {
        _responses[url] = (statusCode, content);
    }

    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        var url = request.RequestUri?.ToString() ?? "";

        if (_responses.TryGetValue(url, out var response))
        {
            return Task.FromResult(new HttpResponseMessage(response.StatusCode)
            {
                Content = new StringContent(response.Content, Encoding.UTF8, "application/json")
            });
        }

        return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound)
        {
            Content = new StringContent("Not found")
        });
    }
}
