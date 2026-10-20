using Microsoft.IdentityModel.Tokens;

namespace OpenIdProbe.Protocol.Tokens;

/// <summary>
/// Options for validating ID tokens.
/// </summary>
public sealed class IdTokenValidationOptions
{
    /// <summary>Expected issuer.</summary>
    public required string Issuer { get; init; }

    /// <summary>Expected audience (client ID).</summary>
    public required string Audience { get; init; }

    /// <summary>Expected nonce (if used in authorization request).</summary>
    public string? Nonce { get; init; }

    /// <summary>Signing keys for signature validation.</summary>
    public required IReadOnlyList<JsonWebKey> SigningKeys { get; init; }

    /// <summary>Allowed clock skew for time validation.</summary>
    public TimeSpan ClockSkew { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>Require auth_time claim.</summary>
    public bool RequireAuthTime { get; init; }

    /// <summary>Allowed signing algorithms. If empty, RS256 and ES256 are allowed.</summary>
    public IReadOnlyList<string> AllowedAlgorithms { get; init; } = ["RS256", "ES256", "RS384", "ES384", "RS512", "ES512"];
}
