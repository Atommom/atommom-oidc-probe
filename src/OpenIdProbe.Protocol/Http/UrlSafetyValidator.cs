using System.Net;
using System.Net.Sockets;

namespace OpenIdProbe.Protocol.Http;

/// <summary>
/// Validates URLs for safety against SSRF and other attacks.
/// </summary>
public interface IUrlSafetyValidator
{
    /// <summary>
    /// Validates a URL for safety.
    /// </summary>
    /// <param name="url">The URL to validate.</param>
    /// <param name="options">HTTP options controlling what is allowed.</param>
    /// <returns>A validation result.</returns>
    UrlValidationResult Validate(string url, ProbeHttpOptions options);
}

/// <summary>
/// Result of URL validation.
/// </summary>
public sealed record UrlValidationResult(bool IsValid, string? Error = null)
{
    public static UrlValidationResult Valid() => new(true);
    public static UrlValidationResult Invalid(string error) => new(false, error);
}

/// <summary>
/// Default implementation of URL safety validation.
/// </summary>
public sealed class UrlSafetyValidator : IUrlSafetyValidator
{
    private static readonly HashSet<string> PrivateHostnames =
    [
        "localhost",
        "localhost.localdomain",
        "local"
    ];

    public UrlValidationResult Validate(string url, ProbeHttpOptions options)
    {
        if (string.IsNullOrWhiteSpace(url))
        {
            return UrlValidationResult.Invalid("URL is empty");
        }

        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return UrlValidationResult.Invalid("URL is not a valid absolute URI");
        }

        // Scheme validation
        if (!options.AllowInsecure && uri.Scheme != "https")
        {
            return UrlValidationResult.Invalid(
                $"URL scheme '{uri.Scheme}' is not allowed; use --allow-insecure to permit HTTP");
        }

        if (uri.Scheme != "http" && uri.Scheme != "https")
        {
            return UrlValidationResult.Invalid($"URL scheme '{uri.Scheme}' is not supported");
        }

        // Fragment validation
        if (!string.IsNullOrEmpty(uri.Fragment))
        {
            return UrlValidationResult.Invalid("URL must not contain a fragment");
        }

        // Private network validation
        if (!options.AllowPrivateNetwork)
        {
            var privateCheck = CheckPrivateNetwork(uri);
            if (!privateCheck.IsValid)
            {
                return privateCheck;
            }
        }

        return UrlValidationResult.Valid();
    }

    private static UrlValidationResult CheckPrivateNetwork(Uri uri)
    {
        var host = uri.Host.ToLowerInvariant();

        // Check for common private hostnames
        if (PrivateHostnames.Contains(host))
        {
            return UrlValidationResult.Invalid(
                $"Host '{host}' is a private hostname; use --allow-private-network to permit");
        }

        // Check for IP addresses
        if (IPAddress.TryParse(host, out var ip))
        {
            if (IsPrivateAddress(ip))
            {
                return UrlValidationResult.Invalid(
                    $"IP address '{ip}' is a private address; use --allow-private-network to permit");
            }
        }

        // Try to resolve hostname and check resolved addresses
        try
        {
            var addresses = Dns.GetHostAddresses(host);
            foreach (var address in addresses)
            {
                if (IsPrivateAddress(address))
                {
                    return UrlValidationResult.Invalid(
                        $"Host '{host}' resolves to private address {address}; use --allow-private-network to permit");
                }
            }
        }
        catch (SocketException)
        {
            // DNS resolution failed - we'll let the HTTP client handle this
        }

        return UrlValidationResult.Valid();
    }

    private static bool IsPrivateAddress(IPAddress address)
    {
        // Loopback (127.0.0.0/8, ::1)
        if (IPAddress.IsLoopback(address))
        {
            return true;
        }

        var bytes = address.GetAddressBytes();

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            // IPv4 private ranges
            // 10.0.0.0/8
            if (bytes[0] == 10)
            {
                return true;
            }

            // 172.16.0.0/12
            if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
            {
                return true;
            }

            // 192.168.0.0/16
            if (bytes[0] == 192 && bytes[1] == 168)
            {
                return true;
            }

            // 169.254.0.0/16 (link-local)
            if (bytes[0] == 169 && bytes[1] == 254)
            {
                return true;
            }

            // 0.0.0.0/8
            if (bytes[0] == 0)
            {
                return true;
            }
        }
        else if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            // IPv6 link-local (fe80::/10)
            if (bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80)
            {
                return true;
            }

            // IPv6 unique local (fc00::/7)
            if ((bytes[0] & 0xfe) == 0xfc)
            {
                return true;
            }
        }

        return false;
    }
}
