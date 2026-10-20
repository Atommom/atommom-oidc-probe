namespace OpenIdProbe.Protocol.Http;

/// <summary>
/// Configuration options for HTTP requests.
/// </summary>
public sealed class ProbeHttpOptions
{
    /// <summary>Request timeout.</summary>
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>Maximum response size in bytes.</summary>
    public long MaxResponseSize { get; init; } = 1024 * 1024; // 1 MB

    /// <summary>Maximum number of redirects to follow.</summary>
    public int MaxRedirects { get; init; } = 5;

    /// <summary>Allow HTTP (non-HTTPS) requests.</summary>
    public bool AllowInsecure { get; init; }

    /// <summary>Allow requests to private network addresses.</summary>
    public bool AllowPrivateNetwork { get; init; }

    /// <summary>User agent string.</summary>
    public string UserAgent { get; init; } = "OpenIdProbe/1.0";
}
