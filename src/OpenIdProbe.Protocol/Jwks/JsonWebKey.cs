using System.Text.Json.Serialization;

namespace OpenIdProbe.Protocol.Jwks;

/// <summary>
/// Represents a JSON Web Key (JWK) as defined in RFC 7517.
/// </summary>
public sealed class JsonWebKey
{
    /// <summary>Key type (e.g., "RSA", "EC").</summary>
    [JsonPropertyName("kty")]
    public string KeyType { get; init; } = string.Empty;

    /// <summary>Public key use (e.g., "sig", "enc").</summary>
    [JsonPropertyName("use")]
    public string? Use { get; init; }

    /// <summary>Key operations.</summary>
    [JsonPropertyName("key_ops")]
    public IReadOnlyList<string>? KeyOperations { get; init; }

    /// <summary>Algorithm intended for use with the key.</summary>
    [JsonPropertyName("alg")]
    public string? Algorithm { get; init; }

    /// <summary>Key ID.</summary>
    [JsonPropertyName("kid")]
    public string? KeyId { get; init; }

    /// <summary>X.509 URL.</summary>
    [JsonPropertyName("x5u")]
    public string? X509Url { get; init; }

    /// <summary>X.509 certificate chain.</summary>
    [JsonPropertyName("x5c")]
    public IReadOnlyList<string>? X509CertificateChain { get; init; }

    /// <summary>X.509 certificate SHA-1 thumbprint.</summary>
    [JsonPropertyName("x5t")]
    public string? X509Thumbprint { get; init; }

    /// <summary>X.509 certificate SHA-256 thumbprint.</summary>
    [JsonPropertyName("x5t#S256")]
    public string? X509ThumbprintS256 { get; init; }

    // RSA-specific parameters
    /// <summary>RSA modulus (Base64url encoded).</summary>
    [JsonPropertyName("n")]
    public string? Modulus { get; init; }

    /// <summary>RSA exponent (Base64url encoded).</summary>
    [JsonPropertyName("e")]
    public string? Exponent { get; init; }

    // EC-specific parameters
    /// <summary>EC curve name.</summary>
    [JsonPropertyName("crv")]
    public string? Curve { get; init; }

    /// <summary>EC X coordinate (Base64url encoded).</summary>
    [JsonPropertyName("x")]
    public string? X { get; init; }

    /// <summary>EC Y coordinate (Base64url encoded).</summary>
    [JsonPropertyName("y")]
    public string? Y { get; init; }

    /// <summary>
    /// Gets whether this key is an RSA key.
    /// </summary>
    [JsonIgnore]
    public bool IsRsa => string.Equals(KeyType, "RSA", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Gets whether this key is an EC key.
    /// </summary>
    [JsonIgnore]
    public bool IsEc => string.Equals(KeyType, "EC", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Gets whether this key is intended for signing.
    /// </summary>
    [JsonIgnore]
    public bool IsSigningKey => Use == null || string.Equals(Use, "sig", StringComparison.OrdinalIgnoreCase);
}
