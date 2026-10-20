using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using OpenIdProbe.Core;

namespace OpenIdProbe.Protocol.Tokens;

/// <summary>
/// Validates ID tokens according to OpenID Connect Core 1.0.
/// </summary>
public interface IIdTokenValidator
{
    /// <summary>
    /// Validates an ID token.
    /// </summary>
    /// <param name="token">The ID token string.</param>
    /// <param name="options">Validation options.</param>
    /// <returns>Validation results.</returns>
    IReadOnlyList<TestResult> Validate(string token, IdTokenValidationOptions options);
}

/// <summary>
/// Default implementation of <see cref="IIdTokenValidator"/>.
/// </summary>
public sealed class IdTokenValidator : IIdTokenValidator
{
    private const string SpecReference = "OpenID Connect Core 1.0";

    public IReadOnlyList<TestResult> Validate(string token, IdTokenValidationOptions options)
    {
        var results = new List<TestResult>();

        // First, try to parse the token
        var parseResult = TryParseToken(token);
        results.Add(parseResult.Result);

        if (!parseResult.Success || parseResult.Token == null)
        {
            return results;
        }

        var jwt = parseResult.Token;

        // Validate signature
        results.Add(ValidateSignature(token, options));

        // Validate issuer
        results.Add(ValidateIssuer(jwt, options));

        // Validate audience
        results.Add(ValidateAudience(jwt, options));

        // Validate authorized party (azp)
        results.Add(ValidateAuthorizedParty(jwt, options));

        // Validate expiration
        results.Add(ValidateExpiration(jwt, options));

        // Validate issued at
        results.Add(ValidateIssuedAt(jwt, options));

        // Validate nonce
        if (options.Nonce != null)
        {
            results.Add(ValidateNoncePresent(jwt, options));
            results.Add(ValidateNonceMatch(jwt, options));
        }

        // Validate subject
        results.Add(ValidateSubject(jwt));

        // Validate auth_time if required
        if (options.RequireAuthTime)
        {
            results.Add(ValidateAuthTime(jwt));
        }

        // Validate algorithm
        results.Add(ValidateAlgorithm(jwt, options));

        return results;
    }

    private static (bool Success, JwtSecurityToken? Token, TestResult Result) TryParseToken(string token)
    {
        var sw = Stopwatch.StartNew();

        try
        {
            var handler = new JwtSecurityTokenHandler();
            if (!handler.CanReadToken(token))
            {
                return (false, null, new TestResult(
                    TestId: "TOKEN-000",
                    Description: "Token is well-formed JWT",
                    Outcome: TestOutcome.Fail,
                    Duration: sw.Elapsed,
                    SpecReference: "RFC 7519",
                    FailureReason: "Token is not a valid JWT format",
                    Remediation: "Ensure the token is a properly encoded JWT with header.payload.signature"));
            }

            var jwt = handler.ReadJwtToken(token);
            return (true, jwt, new TestResult(
                TestId: "TOKEN-000",
                Description: "Token is well-formed JWT",
                Outcome: TestOutcome.Pass,
                Duration: sw.Elapsed,
                SpecReference: "RFC 7519"));
        }
        catch (Exception ex)
        {
            return (false, null, new TestResult(
                TestId: "TOKEN-000",
                Description: "Token is well-formed JWT",
                Outcome: TestOutcome.Fail,
                Duration: sw.Elapsed,
                SpecReference: "RFC 7519",
                FailureReason: $"Failed to parse token: {ex.Message}",
                Remediation: "Ensure the token is a properly encoded JWT"));
        }
    }

    private static TestResult ValidateSignature(string token, IdTokenValidationOptions options)
    {
        var sw = Stopwatch.StartNew();

        try
        {
            var handler = new JwtSecurityTokenHandler();

            var securityKeys = options.SigningKeys
                .Select(CreateSecurityKey)
                .Where(k => k != null)
                .Cast<SecurityKey>()
                .ToList();

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKeys = securityKeys,
                RequireSignedTokens = true
            };

            handler.ValidateToken(token, validationParameters, out _);

            return new TestResult(
                TestId: "TOKEN-001",
                Description: "Token signature is valid",
                Outcome: TestOutcome.Pass,
                Duration: sw.Elapsed,
                SpecReference: $"{SpecReference}, Section 3.1.3.7");
        }
        catch (SecurityTokenSignatureKeyNotFoundException)
        {
            return new TestResult(
                TestId: "TOKEN-001",
                Description: "Token signature is valid",
                Outcome: TestOutcome.Fail,
                Duration: sw.Elapsed,
                SpecReference: $"{SpecReference}, Section 3.1.3.7",
                FailureReason: "No matching signing key found for token",
                Remediation: "Ensure the JWKS contains the key referenced by the token's kid header");
        }
        catch (SecurityTokenInvalidSignatureException)
        {
            return new TestResult(
                TestId: "TOKEN-001",
                Description: "Token signature is valid",
                Outcome: TestOutcome.Fail,
                Duration: sw.Elapsed,
                SpecReference: $"{SpecReference}, Section 3.1.3.7",
                FailureReason: "Token signature validation failed",
                Remediation: "The token signature does not match the signing key");
        }
        catch (Exception ex)
        {
            return new TestResult(
                TestId: "TOKEN-001",
                Description: "Token signature is valid",
                Outcome: TestOutcome.Fail,
                Duration: sw.Elapsed,
                SpecReference: $"{SpecReference}, Section 3.1.3.7",
                FailureReason: $"Signature validation error: {ex.Message}");
        }
    }

    private static SecurityKey? CreateSecurityKey(JsonWebKey jwk)
    {
        try
        {
            if (jwk.Kty == "RSA" && !string.IsNullOrEmpty(jwk.N) && !string.IsNullOrEmpty(jwk.E))
            {
                var rsa = System.Security.Cryptography.RSA.Create();
                rsa.ImportParameters(new System.Security.Cryptography.RSAParameters
                {
                    Modulus = Base64UrlEncoder.DecodeBytes(jwk.N),
                    Exponent = Base64UrlEncoder.DecodeBytes(jwk.E)
                });
                return new RsaSecurityKey(rsa) { KeyId = jwk.Kid };
            }

            if (jwk.Kty == "EC" && !string.IsNullOrEmpty(jwk.X) && !string.IsNullOrEmpty(jwk.Y) && !string.IsNullOrEmpty(jwk.Crv))
            {
                var curve = jwk.Crv switch
                {
                    "P-256" => System.Security.Cryptography.ECCurve.NamedCurves.nistP256,
                    "P-384" => System.Security.Cryptography.ECCurve.NamedCurves.nistP384,
                    "P-521" => System.Security.Cryptography.ECCurve.NamedCurves.nistP521,
                    _ => throw new NotSupportedException($"Unsupported curve: {jwk.Crv}")
                };

                var ecdsa = System.Security.Cryptography.ECDsa.Create(new System.Security.Cryptography.ECParameters
                {
                    Curve = curve,
                    Q = new System.Security.Cryptography.ECPoint
                    {
                        X = Base64UrlEncoder.DecodeBytes(jwk.X),
                        Y = Base64UrlEncoder.DecodeBytes(jwk.Y)
                    }
                });
                return new ECDsaSecurityKey(ecdsa) { KeyId = jwk.Kid };
            }

            return null;
        }
        catch
        {
            return null;
        }
    }

    private static TestResult ValidateIssuer(JwtSecurityToken jwt, IdTokenValidationOptions options)
    {
        var sw = Stopwatch.StartNew();
        var matches = string.Equals(jwt.Issuer, options.Issuer, StringComparison.Ordinal);

        return new TestResult(
            TestId: "TOKEN-010",
            Description: "Token issuer matches expected value",
            Outcome: matches ? TestOutcome.Pass : TestOutcome.Fail,
            Duration: sw.Elapsed,
            SpecReference: $"{SpecReference}, Section 3.1.3.7",
            Evidence: $"Expected: {options.Issuer}, Actual: {jwt.Issuer}",
            FailureReason: matches ? null : "Issuer mismatch",
            Remediation: matches ? null : "Ensure the token is from the expected identity provider");
    }

    private static TestResult ValidateAudience(JwtSecurityToken jwt, IdTokenValidationOptions options)
    {
        var sw = Stopwatch.StartNew();
        var audiences = jwt.Audiences.ToList();
        var matches = audiences.Contains(options.Audience, StringComparer.Ordinal);

        return new TestResult(
            TestId: "TOKEN-011",
            Description: "Token audience includes expected client ID",
            Outcome: matches ? TestOutcome.Pass : TestOutcome.Fail,
            Duration: sw.Elapsed,
            SpecReference: $"{SpecReference}, Section 3.1.3.7",
            Evidence: $"Expected: {options.Audience}, Actual: [{string.Join(", ", audiences)}]",
            FailureReason: matches ? null : "Audience mismatch",
            Remediation: matches ? null : "Ensure the token was issued for your client ID");
    }

    private static TestResult ValidateAuthorizedParty(JwtSecurityToken jwt, IdTokenValidationOptions options)
    {
        var sw = Stopwatch.StartNew();
        var azp = jwt.Claims.FirstOrDefault(c => c.Type == "azp")?.Value;

        if (azp == null)
        {
            // azp is only required when there are multiple audiences
            var hasMultipleAudiences = jwt.Audiences.Count() > 1;
            return new TestResult(
                TestId: "TOKEN-012",
                Description: "Authorized party (azp) is valid",
                Outcome: hasMultipleAudiences ? TestOutcome.Warn : TestOutcome.Pass,
                Duration: sw.Elapsed,
                SpecReference: $"{SpecReference}, Section 3.1.3.7",
                Evidence: "azp: (not present)",
                FailureReason: hasMultipleAudiences ? "azp should be present when multiple audiences exist" : null);
        }

        var matches = string.Equals(azp, options.Audience, StringComparison.Ordinal);

        return new TestResult(
            TestId: "TOKEN-012",
            Description: "Authorized party (azp) is valid",
            Outcome: matches ? TestOutcome.Pass : TestOutcome.Fail,
            Duration: sw.Elapsed,
            SpecReference: $"{SpecReference}, Section 3.1.3.7",
            Evidence: $"Expected: {options.Audience}, Actual azp: {azp}",
            FailureReason: matches ? null : "Authorized party does not match client ID",
            Remediation: matches ? null : "The azp claim must match the client ID");
    }

    private static TestResult ValidateExpiration(JwtSecurityToken jwt, IdTokenValidationOptions options)
    {
        var sw = Stopwatch.StartNew();
        var now = DateTime.UtcNow;
        var expirationWithSkew = jwt.ValidTo.Add(options.ClockSkew);
        var isValid = now <= expirationWithSkew;

        return new TestResult(
            TestId: "TOKEN-020",
            Description: "Token is not expired",
            Outcome: isValid ? TestOutcome.Pass : TestOutcome.Fail,
            Duration: sw.Elapsed,
            SpecReference: $"{SpecReference}, Section 3.1.3.7",
            Evidence: $"exp: {jwt.ValidTo:O}, now: {now:O}, skew: {options.ClockSkew}",
            FailureReason: isValid ? null : "Token has expired",
            Remediation: isValid ? null : "Obtain a fresh token from the identity provider");
    }

    private static TestResult ValidateIssuedAt(JwtSecurityToken jwt, IdTokenValidationOptions options)
    {
        var sw = Stopwatch.StartNew();
        var now = DateTime.UtcNow;
        var issuedAtWithSkew = jwt.IssuedAt.Subtract(options.ClockSkew);
        var isValid = now >= issuedAtWithSkew;

        return new TestResult(
            TestId: "TOKEN-021",
            Description: "Token issued-at time is valid",
            Outcome: isValid ? TestOutcome.Pass : TestOutcome.Fail,
            Duration: sw.Elapsed,
            SpecReference: $"{SpecReference}, Section 3.1.3.7",
            Evidence: $"iat: {jwt.IssuedAt:O}, now: {now:O}",
            FailureReason: isValid ? null : "Token was issued in the future",
            Remediation: isValid ? null : "Check clock synchronization between systems");
    }

    private static TestResult ValidateNoncePresent(JwtSecurityToken jwt, IdTokenValidationOptions options)
    {
        var sw = Stopwatch.StartNew();
        var nonce = jwt.Claims.FirstOrDefault(c => c.Type == "nonce")?.Value;
        var hasNonce = !string.IsNullOrEmpty(nonce);

        return new TestResult(
            TestId: "TOKEN-030",
            Description: "Nonce claim is present",
            Outcome: hasNonce ? TestOutcome.Pass : TestOutcome.Fail,
            Duration: sw.Elapsed,
            SpecReference: $"{SpecReference}, Section 3.1.3.7",
            Evidence: hasNonce ? $"nonce: {nonce}" : "nonce: (missing)",
            FailureReason: hasNonce ? null : "Token is missing required nonce claim",
            Remediation: hasNonce ? null : "Ensure the authorization request included a nonce parameter");
    }

    private static TestResult ValidateNonceMatch(JwtSecurityToken jwt, IdTokenValidationOptions options)
    {
        var sw = Stopwatch.StartNew();
        var nonce = jwt.Claims.FirstOrDefault(c => c.Type == "nonce")?.Value;

        if (string.IsNullOrEmpty(nonce))
        {
            return new TestResult(
                TestId: "TOKEN-031",
                Description: "Nonce matches expected value",
                Outcome: TestOutcome.Skip,
                Duration: sw.Elapsed,
                SpecReference: $"{SpecReference}, Section 3.1.3.7",
                FailureReason: "Cannot validate: nonce claim is missing");
        }

        var matches = string.Equals(nonce, options.Nonce, StringComparison.Ordinal);

        return new TestResult(
            TestId: "TOKEN-031",
            Description: "Nonce matches expected value",
            Outcome: matches ? TestOutcome.Pass : TestOutcome.Fail,
            Duration: sw.Elapsed,
            SpecReference: $"{SpecReference}, Section 3.1.3.7",
            Evidence: $"Expected: {options.Nonce}, Actual: {nonce}",
            FailureReason: matches ? null : "Nonce mismatch - possible replay attack",
            Remediation: matches ? null : "The nonce in the token must match the nonce sent in the authorization request");
    }

    private static TestResult ValidateSubject(JwtSecurityToken jwt)
    {
        var sw = Stopwatch.StartNew();
        var sub = jwt.Subject;
        var hasSub = !string.IsNullOrEmpty(sub);

        return new TestResult(
            TestId: "TOKEN-040",
            Description: "Subject (sub) claim is present",
            Outcome: hasSub ? TestOutcome.Pass : TestOutcome.Warn,
            Duration: sw.Elapsed,
            SpecReference: $"{SpecReference}, Section 2",
            Evidence: hasSub ? $"sub: {sub}" : "sub: (missing)",
            FailureReason: hasSub ? null : "Subject claim is missing or empty");
    }

    private static TestResult ValidateAuthTime(JwtSecurityToken jwt)
    {
        var sw = Stopwatch.StartNew();
        var authTime = jwt.Claims.FirstOrDefault(c => c.Type == "auth_time")?.Value;
        var hasAuthTime = !string.IsNullOrEmpty(authTime);

        return new TestResult(
            TestId: "TOKEN-050",
            Description: "Authentication time (auth_time) is present",
            Outcome: hasAuthTime ? TestOutcome.Pass : TestOutcome.Fail,
            Duration: sw.Elapsed,
            SpecReference: $"{SpecReference}, Section 2",
            Evidence: hasAuthTime ? $"auth_time: {authTime}" : "auth_time: (missing)",
            FailureReason: hasAuthTime ? null : "Required auth_time claim is missing");
    }

    private static TestResult ValidateAlgorithm(JwtSecurityToken jwt, IdTokenValidationOptions options)
    {
        var sw = Stopwatch.StartNew();
        var alg = jwt.Header.Alg;

        if (string.Equals(alg, "none", StringComparison.OrdinalIgnoreCase))
        {
            return new TestResult(
                TestId: "TOKEN-002",
                Description: "Token uses secure signing algorithm",
                Outcome: TestOutcome.Fail,
                Duration: sw.Elapsed,
                SpecReference: $"{SpecReference}, Section 3.1.3.7",
                Evidence: $"alg: {alg}",
                FailureReason: "Token uses 'none' algorithm - unsigned tokens are not secure",
                Remediation: "Tokens must be signed with a cryptographic algorithm");
        }

        var isAllowed = options.AllowedAlgorithms.Contains(alg, StringComparer.OrdinalIgnoreCase);

        return new TestResult(
            TestId: "TOKEN-002",
            Description: "Token uses secure signing algorithm",
            Outcome: isAllowed ? TestOutcome.Pass : TestOutcome.Warn,
            Duration: sw.Elapsed,
            SpecReference: $"{SpecReference}, Section 3.1.3.7",
            Evidence: $"alg: {alg}",
            FailureReason: isAllowed ? null : $"Algorithm '{alg}' is not in the allowed list");
    }
}
