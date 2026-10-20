using System.Diagnostics;
using OpenIdProbe.Core;

namespace OpenIdProbe.Protocol.Jwks;

/// <summary>
/// Validates a JSON Web Key Set against best practices and specifications.
/// </summary>
public interface IJwksValidator
{
    IReadOnlyList<TestResult> Validate(JsonWebKeySet jwks);
}

/// <summary>
/// Default implementation of <see cref="IJwksValidator"/>.
/// </summary>
public sealed class JwksValidator : IJwksValidator
{
    private const string SpecReference = "RFC 7517 (JSON Web Key)";

    private static readonly HashSet<string> SupportedKeyTypes = ["RSA", "EC"];
    private static readonly HashSet<string> SupportedEcCurves = ["P-256", "P-384", "P-521"];

    public IReadOnlyList<TestResult> Validate(JsonWebKeySet jwks)
    {
        var results = new List<TestResult>();

        results.Add(ValidateHasKeys(jwks));
        results.Add(ValidateHasSigningKeys(jwks));
        results.Add(ValidateNoDuplicateKeyIds(jwks));
        results.Add(ValidateAllKeysHaveKeyId(jwks));
        results.Add(ValidateSupportedKeyTypes(jwks));

        // Per-key validation
        foreach (var key in jwks.Keys)
        {
            if (key.IsRsa)
            {
                results.Add(ValidateRsaKeyStructure(key));
            }
            else if (key.IsEc)
            {
                results.Add(ValidateEcKeyStructure(key));
            }
        }

        return results;
    }

    private static TestResult ValidateHasKeys(JsonWebKeySet jwks)
    {
        var sw = Stopwatch.StartNew();
        var hasKeys = jwks.Keys.Count > 0;

        return new TestResult(
            TestId: "JWKS-001",
            Description: "JWKS contains at least one key",
            Outcome: hasKeys ? TestOutcome.Pass : TestOutcome.Fail,
            Duration: sw.Elapsed,
            SpecReference: SpecReference,
            Evidence: $"Key count: {jwks.Keys.Count}",
            FailureReason: hasKeys ? null : "JWKS is empty; at least one signing key is required",
            Remediation: hasKeys ? null : "Add at least one signing key to the JWKS");
    }

    private static TestResult ValidateHasSigningKeys(JsonWebKeySet jwks)
    {
        var sw = Stopwatch.StartNew();
        var signingKeys = jwks.GetSigningKeys().ToList();
        var hasSigningKeys = signingKeys.Count > 0;

        return new TestResult(
            TestId: "JWKS-002",
            Description: "JWKS contains signing keys",
            Outcome: hasSigningKeys ? TestOutcome.Pass : TestOutcome.Fail,
            Duration: sw.Elapsed,
            SpecReference: SpecReference,
            Evidence: $"Signing key count: {signingKeys.Count}",
            FailureReason: hasSigningKeys ? null : "No signing keys found (keys with use='sig' or no use specified)",
            Remediation: hasSigningKeys ? null : "Add at least one key with use='sig' or without a use restriction");
    }

    private static TestResult ValidateNoDuplicateKeyIds(JsonWebKeySet jwks)
    {
        var sw = Stopwatch.StartNew();
        var keyIds = jwks.Keys
            .Where(k => !string.IsNullOrEmpty(k.KeyId))
            .Select(k => k.KeyId!)
            .ToList();

        var duplicates = keyIds
            .GroupBy(id => id)
            .Where(g => g.Count() > 1)
            .Select(g => g.Key)
            .ToList();

        var hasDuplicates = duplicates.Count > 0;

        return new TestResult(
            TestId: "JWKS-003",
            Description: "No duplicate key IDs",
            Outcome: hasDuplicates ? TestOutcome.Fail : TestOutcome.Pass,
            Duration: sw.Elapsed,
            SpecReference: SpecReference,
            Evidence: hasDuplicates ? $"Duplicate key IDs: {string.Join(", ", duplicates)}" : "All key IDs are unique",
            FailureReason: hasDuplicates ? "Duplicate key IDs can cause key selection ambiguity" : null,
            Remediation: hasDuplicates ? "Ensure each key has a unique key ID (kid)" : null);
    }

    private static TestResult ValidateAllKeysHaveKeyId(JsonWebKeySet jwks)
    {
        var sw = Stopwatch.StartNew();
        var keysWithoutId = jwks.Keys.Count(k => string.IsNullOrEmpty(k.KeyId));
        var allHaveIds = keysWithoutId == 0;

        return new TestResult(
            TestId: "JWKS-004",
            Description: "All keys have key IDs",
            Outcome: allHaveIds ? TestOutcome.Pass : TestOutcome.Warn,
            Duration: sw.Elapsed,
            SpecReference: SpecReference,
            Evidence: allHaveIds ? "All keys have kid" : $"{keysWithoutId} key(s) missing kid",
            FailureReason: allHaveIds ? null : "Keys without key IDs make key selection difficult",
            Remediation: allHaveIds ? null : "Add a unique kid to each key for proper key selection");
    }

    private static TestResult ValidateSupportedKeyTypes(JsonWebKeySet jwks)
    {
        var sw = Stopwatch.StartNew();
        var unsupportedTypes = jwks.Keys
            .Select(k => k.KeyType)
            .Where(t => !SupportedKeyTypes.Contains(t))
            .Distinct()
            .ToList();

        var allSupported = unsupportedTypes.Count == 0;

        return new TestResult(
            TestId: "JWKS-005",
            Description: "All keys use supported key types",
            Outcome: allSupported ? TestOutcome.Pass : TestOutcome.Warn,
            Duration: sw.Elapsed,
            SpecReference: SpecReference,
            Evidence: allSupported
                ? $"Key types: {string.Join(", ", jwks.Keys.Select(k => k.KeyType).Distinct())}"
                : $"Unsupported key types: {string.Join(", ", unsupportedTypes)}",
            FailureReason: allSupported ? null : "Some key types may not be widely supported",
            Remediation: allSupported ? null : "Consider using RSA or EC keys for maximum compatibility");
    }

    private static TestResult ValidateRsaKeyStructure(JsonWebKey key)
    {
        var sw = Stopwatch.StartNew();
        var hasModulus = !string.IsNullOrEmpty(key.Modulus);
        var hasExponent = !string.IsNullOrEmpty(key.Exponent);
        var isValid = hasModulus && hasExponent;

        var keyIdentifier = key.KeyId ?? "(no kid)";

        return new TestResult(
            TestId: "JWKS-010",
            Description: $"RSA key '{keyIdentifier}' has valid structure",
            Outcome: isValid ? TestOutcome.Pass : TestOutcome.Fail,
            Duration: sw.Elapsed,
            SpecReference: "RFC 7518, Section 6.3",
            Evidence: $"n: {(hasModulus ? "present" : "missing")}, e: {(hasExponent ? "present" : "missing")}",
            FailureReason: isValid ? null : "RSA key missing required parameters (n and/or e)",
            Remediation: isValid ? null : "Ensure RSA keys include both modulus (n) and exponent (e)");
    }

    private static TestResult ValidateEcKeyStructure(JsonWebKey key)
    {
        var sw = Stopwatch.StartNew();
        var hasCurve = !string.IsNullOrEmpty(key.Curve);
        var hasX = !string.IsNullOrEmpty(key.X);
        var hasY = !string.IsNullOrEmpty(key.Y);
        var validCurve = hasCurve && SupportedEcCurves.Contains(key.Curve!);
        var isValid = hasCurve && hasX && hasY;

        var keyIdentifier = key.KeyId ?? "(no kid)";

        var outcome = TestOutcome.Pass;
        string? failureReason = null;

        if (!hasCurve || !hasX || !hasY)
        {
            outcome = TestOutcome.Fail;
            failureReason = "EC key missing required parameters";
        }
        else if (!validCurve)
        {
            outcome = TestOutcome.Warn;
            failureReason = $"EC curve '{key.Curve}' may not be widely supported";
        }

        return new TestResult(
            TestId: "JWKS-011",
            Description: $"EC key '{keyIdentifier}' has valid structure",
            Outcome: outcome,
            Duration: sw.Elapsed,
            SpecReference: "RFC 7518, Section 6.2",
            Evidence: $"crv: {key.Curve ?? "missing"}, x: {(hasX ? "present" : "missing")}, y: {(hasY ? "present" : "missing")}",
            FailureReason: failureReason,
            Remediation: outcome == TestOutcome.Fail
                ? "Ensure EC keys include curve (crv), x, and y parameters"
                : null);
    }
}
