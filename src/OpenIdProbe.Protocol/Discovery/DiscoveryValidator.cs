using System.Diagnostics;
using OpenIdProbe.Core;

namespace OpenIdProbe.Protocol.Discovery;

/// <summary>
/// Validates an OpenID Connect discovery document against the specification.
/// </summary>
public interface IDiscoveryValidator
{
    /// <summary>
    /// Validates a discovery document.
    /// </summary>
    /// <param name="document">The discovery document to validate.</param>
    /// <param name="expectedIssuer">The expected issuer URL.</param>
    /// <returns>A list of test results.</returns>
    IReadOnlyList<TestResult> Validate(DiscoveryDocument document, string expectedIssuer);
}

/// <summary>
/// Default implementation of <see cref="IDiscoveryValidator"/>.
/// </summary>
public sealed class DiscoveryValidator : IDiscoveryValidator
{
    private const string SpecReference = "OpenID Connect Discovery 1.0";

    /// <inheritdoc />
    public IReadOnlyList<TestResult> Validate(DiscoveryDocument document, string expectedIssuer)
    {
        var results = new List<TestResult>();

        // Issuer validation
        results.Add(ValidateIssuerMatch(document, expectedIssuer));
        results.Add(ValidateIssuerNoTrailingSlash(document));
        results.Add(ValidateIssuerNoFragment(document));
        results.Add(ValidateIssuerNoQueryString(document));
        results.Add(ValidateIssuerHttps(document));

        // Endpoint validation
        results.Add(ValidateAuthorizationEndpoint(document));
        results.Add(ValidateAuthorizationEndpointHttps(document));
        results.Add(ValidateTokenEndpoint(document));
        results.Add(ValidateJwksUri(document));
        results.Add(ValidateJwksUriHttps(document));

        // Required arrays
        results.Add(ValidateResponseTypesSupported(document));
        results.Add(ValidateSubjectTypesSupported(document));
        results.Add(ValidateIdTokenSigningAlgValuesSupported(document));
        results.Add(ValidateNoOnlyNoneAlgorithm(document));

        // PKCE
        results.Add(ValidatePkceSupported(document));
        results.Add(ValidatePkceS256(document));

        return results;
    }

    private static TestResult ValidateIssuerMatch(DiscoveryDocument doc, string expectedIssuer)
    {
        var sw = Stopwatch.StartNew();
        var matches = string.Equals(doc.Issuer, expectedIssuer, StringComparison.Ordinal);

        return new TestResult(
            TestId: "DISC-001",
            Description: "Issuer matches expected value",
            Outcome: matches ? TestOutcome.Pass : TestOutcome.Fail,
            Duration: sw.Elapsed,
            SpecReference: $"{SpecReference}, Section 3",
            Evidence: $"Expected: {expectedIssuer}, Actual: {doc.Issuer}",
            FailureReason: matches ? null : "Issuer mismatch: the discovery document issuer does not match the expected issuer",
            Remediation: matches ? null : "Ensure the issuer claim in the discovery document exactly matches the URL used to retrieve it");
    }

    private static TestResult ValidateIssuerNoTrailingSlash(DiscoveryDocument doc)
    {
        var sw = Stopwatch.StartNew();
        var hasTrailingSlash = doc.Issuer.EndsWith('/');

        return new TestResult(
            TestId: "DISC-002",
            Description: "Issuer has no trailing slash",
            Outcome: hasTrailingSlash ? TestOutcome.Fail : TestOutcome.Pass,
            Duration: sw.Elapsed,
            SpecReference: $"{SpecReference}, Section 3",
            Evidence: $"Issuer: {doc.Issuer}",
            FailureReason: hasTrailingSlash ? "Issuer must not have a trailing slash" : null,
            Remediation: hasTrailingSlash ? "Remove the trailing slash from the issuer URL" : null);
    }

    private static TestResult ValidateIssuerNoFragment(DiscoveryDocument doc)
    {
        var sw = Stopwatch.StartNew();
        var hasFragment = doc.Issuer.Contains('#');

        return new TestResult(
            TestId: "DISC-003",
            Description: "Issuer has no fragment component",
            Outcome: hasFragment ? TestOutcome.Fail : TestOutcome.Pass,
            Duration: sw.Elapsed,
            SpecReference: $"{SpecReference}, Section 3",
            Evidence: $"Issuer: {doc.Issuer}",
            FailureReason: hasFragment ? "Issuer must not contain a fragment component" : null,
            Remediation: hasFragment ? "Remove the fragment from the issuer URL" : null);
    }

    private static TestResult ValidateIssuerNoQueryString(DiscoveryDocument doc)
    {
        var sw = Stopwatch.StartNew();
        var hasQuery = doc.Issuer.Contains('?');

        return new TestResult(
            TestId: "DISC-004",
            Description: "Issuer has no query component",
            Outcome: hasQuery ? TestOutcome.Fail : TestOutcome.Pass,
            Duration: sw.Elapsed,
            SpecReference: $"{SpecReference}, Section 3",
            Evidence: $"Issuer: {doc.Issuer}",
            FailureReason: hasQuery ? "Issuer must not contain a query component" : null,
            Remediation: hasQuery ? "Remove the query string from the issuer URL" : null);
    }

    private static TestResult ValidateIssuerHttps(DiscoveryDocument doc)
    {
        var sw = Stopwatch.StartNew();
        var isHttps = doc.Issuer.StartsWith("https://", StringComparison.OrdinalIgnoreCase);

        return new TestResult(
            TestId: "DISC-005",
            Description: "Issuer uses HTTPS",
            Outcome: isHttps ? TestOutcome.Pass : TestOutcome.Fail,
            Duration: sw.Elapsed,
            SpecReference: $"{SpecReference}, Section 3",
            Evidence: $"Issuer: {doc.Issuer}",
            FailureReason: isHttps ? null : "Issuer must use the HTTPS scheme",
            Remediation: isHttps ? null : "Configure the identity provider to use HTTPS");
    }

    private static TestResult ValidateAuthorizationEndpoint(DiscoveryDocument doc)
    {
        var sw = Stopwatch.StartNew();
        var hasEndpoint = !string.IsNullOrWhiteSpace(doc.AuthorizationEndpoint);

        return new TestResult(
            TestId: "DISC-010",
            Description: "Authorization endpoint is present",
            Outcome: hasEndpoint ? TestOutcome.Pass : TestOutcome.Fail,
            Duration: sw.Elapsed,
            SpecReference: $"{SpecReference}, Section 3",
            Evidence: hasEndpoint ? $"authorization_endpoint: {doc.AuthorizationEndpoint}" : "authorization_endpoint: (missing)",
            FailureReason: hasEndpoint ? null : "Missing required field: authorization_endpoint",
            Remediation: hasEndpoint ? null : "Add the authorization_endpoint to the discovery document");
    }

    private static TestResult ValidateAuthorizationEndpointHttps(DiscoveryDocument doc)
    {
        var sw = Stopwatch.StartNew();
        if (string.IsNullOrWhiteSpace(doc.AuthorizationEndpoint))
        {
            return new TestResult(
                TestId: "DISC-011",
                Description: "Authorization endpoint uses HTTPS",
                Outcome: TestOutcome.Skip,
                Duration: sw.Elapsed,
                SpecReference: $"{SpecReference}, Section 3",
                FailureReason: "Cannot validate: authorization_endpoint is missing");
        }

        var isHttps = doc.AuthorizationEndpoint.StartsWith("https://", StringComparison.OrdinalIgnoreCase);

        return new TestResult(
            TestId: "DISC-011",
            Description: "Authorization endpoint uses HTTPS",
            Outcome: isHttps ? TestOutcome.Pass : TestOutcome.Fail,
            Duration: sw.Elapsed,
            SpecReference: $"{SpecReference}, Section 3",
            Evidence: $"authorization_endpoint: {doc.AuthorizationEndpoint}",
            FailureReason: isHttps ? null : "Authorization endpoint must use HTTPS",
            Remediation: isHttps ? null : "Configure the authorization endpoint to use HTTPS");
    }

    private static TestResult ValidateTokenEndpoint(DiscoveryDocument doc)
    {
        var sw = Stopwatch.StartNew();
        var hasEndpoint = !string.IsNullOrWhiteSpace(doc.TokenEndpoint);

        // Token endpoint is required for most grant types but technically optional
        // if only implicit flow is supported
        return new TestResult(
            TestId: "DISC-015",
            Description: "Token endpoint is present",
            Outcome: hasEndpoint ? TestOutcome.Pass : TestOutcome.Warn,
            Duration: sw.Elapsed,
            SpecReference: $"{SpecReference}, Section 3",
            Evidence: hasEndpoint ? $"token_endpoint: {doc.TokenEndpoint}" : "token_endpoint: (missing)",
            FailureReason: hasEndpoint ? null : "Token endpoint is recommended for authorization code flow");
    }

    private static TestResult ValidateJwksUri(DiscoveryDocument doc)
    {
        var sw = Stopwatch.StartNew();
        var hasUri = !string.IsNullOrWhiteSpace(doc.JwksUri);

        return new TestResult(
            TestId: "DISC-020",
            Description: "JWKS URI is present",
            Outcome: hasUri ? TestOutcome.Pass : TestOutcome.Fail,
            Duration: sw.Elapsed,
            SpecReference: $"{SpecReference}, Section 3",
            Evidence: hasUri ? $"jwks_uri: {doc.JwksUri}" : "jwks_uri: (missing)",
            FailureReason: hasUri ? null : "Missing required field: jwks_uri",
            Remediation: hasUri ? null : "Add the jwks_uri to the discovery document");
    }

    private static TestResult ValidateJwksUriHttps(DiscoveryDocument doc)
    {
        var sw = Stopwatch.StartNew();
        if (string.IsNullOrWhiteSpace(doc.JwksUri))
        {
            return new TestResult(
                TestId: "DISC-021",
                Description: "JWKS URI uses HTTPS",
                Outcome: TestOutcome.Skip,
                Duration: sw.Elapsed,
                SpecReference: $"{SpecReference}, Section 3",
                FailureReason: "Cannot validate: jwks_uri is missing");
        }

        var isHttps = doc.JwksUri.StartsWith("https://", StringComparison.OrdinalIgnoreCase);

        return new TestResult(
            TestId: "DISC-021",
            Description: "JWKS URI uses HTTPS",
            Outcome: isHttps ? TestOutcome.Pass : TestOutcome.Fail,
            Duration: sw.Elapsed,
            SpecReference: $"{SpecReference}, Section 3",
            Evidence: $"jwks_uri: {doc.JwksUri}",
            FailureReason: isHttps ? null : "JWKS URI must use HTTPS",
            Remediation: isHttps ? null : "Configure the JWKS endpoint to use HTTPS");
    }

    private static TestResult ValidateResponseTypesSupported(DiscoveryDocument doc)
    {
        var sw = Stopwatch.StartNew();
        var hasTypes = doc.ResponseTypesSupported.Count > 0;

        return new TestResult(
            TestId: "DISC-030",
            Description: "Response types supported is present and non-empty",
            Outcome: hasTypes ? TestOutcome.Pass : TestOutcome.Fail,
            Duration: sw.Elapsed,
            SpecReference: $"{SpecReference}, Section 3",
            Evidence: hasTypes ? $"response_types_supported: [{string.Join(", ", doc.ResponseTypesSupported)}]" : "response_types_supported: []",
            FailureReason: hasTypes ? null : "Missing required field: response_types_supported",
            Remediation: hasTypes ? null : "Add supported response types to the discovery document");
    }

    private static TestResult ValidateSubjectTypesSupported(DiscoveryDocument doc)
    {
        var sw = Stopwatch.StartNew();
        var hasTypes = doc.SubjectTypesSupported.Count > 0;

        return new TestResult(
            TestId: "DISC-031",
            Description: "Subject types supported is present and non-empty",
            Outcome: hasTypes ? TestOutcome.Pass : TestOutcome.Fail,
            Duration: sw.Elapsed,
            SpecReference: $"{SpecReference}, Section 3",
            Evidence: hasTypes ? $"subject_types_supported: [{string.Join(", ", doc.SubjectTypesSupported)}]" : "subject_types_supported: []",
            FailureReason: hasTypes ? null : "Missing required field: subject_types_supported",
            Remediation: hasTypes ? null : "Add supported subject types to the discovery document");
    }

    private static TestResult ValidateIdTokenSigningAlgValuesSupported(DiscoveryDocument doc)
    {
        var sw = Stopwatch.StartNew();
        var hasAlgs = doc.IdTokenSigningAlgValuesSupported.Count > 0;

        return new TestResult(
            TestId: "DISC-032",
            Description: "ID token signing algorithms is present and non-empty",
            Outcome: hasAlgs ? TestOutcome.Pass : TestOutcome.Fail,
            Duration: sw.Elapsed,
            SpecReference: $"{SpecReference}, Section 3",
            Evidence: hasAlgs ? $"id_token_signing_alg_values_supported: [{string.Join(", ", doc.IdTokenSigningAlgValuesSupported)}]" : "id_token_signing_alg_values_supported: []",
            FailureReason: hasAlgs ? null : "Missing required field: id_token_signing_alg_values_supported",
            Remediation: hasAlgs ? null : "Add supported ID token signing algorithms to the discovery document");
    }

    private static TestResult ValidateNoOnlyNoneAlgorithm(DiscoveryDocument doc)
    {
        var sw = Stopwatch.StartNew();
        var onlyNone = doc.IdTokenSigningAlgValuesSupported.Count == 1 &&
                       doc.IdTokenSigningAlgValuesSupported[0].Equals("none", StringComparison.OrdinalIgnoreCase);

        return new TestResult(
            TestId: "DISC-033",
            Description: "ID token signing supports algorithms other than 'none'",
            Outcome: onlyNone ? TestOutcome.Warn : TestOutcome.Pass,
            Duration: sw.Elapsed,
            SpecReference: "OpenID Connect Core 1.0, Section 3.1.3.7",
            Evidence: $"id_token_signing_alg_values_supported: [{string.Join(", ", doc.IdTokenSigningAlgValuesSupported)}]",
            FailureReason: onlyNone ? "Supporting only 'none' algorithm is insecure" : null,
            Remediation: onlyNone ? "Add cryptographic signing algorithms like RS256 or ES256" : null);
    }

    private static TestResult ValidatePkceSupported(DiscoveryDocument doc)
    {
        var sw = Stopwatch.StartNew();
        var hasPkce = doc.CodeChallengeMethodsSupported.Count > 0;

        return new TestResult(
            TestId: "DISC-040",
            Description: "PKCE is advertised",
            Outcome: hasPkce ? TestOutcome.Pass : TestOutcome.Warn,
            Duration: sw.Elapsed,
            SpecReference: "RFC 7636 (PKCE)",
            Evidence: hasPkce ? $"code_challenge_methods_supported: [{string.Join(", ", doc.CodeChallengeMethodsSupported)}]" : "code_challenge_methods_supported: (not advertised)",
            FailureReason: hasPkce ? null : "PKCE support is not advertised; PKCE is recommended for all OAuth clients",
            Remediation: hasPkce ? null : "Enable PKCE and advertise supported code challenge methods");
    }

    private static TestResult ValidatePkceS256(DiscoveryDocument doc)
    {
        var sw = Stopwatch.StartNew();
        if (doc.CodeChallengeMethodsSupported.Count == 0)
        {
            return new TestResult(
                TestId: "DISC-041",
                Description: "PKCE S256 method is supported",
                Outcome: TestOutcome.Skip,
                Duration: sw.Elapsed,
                SpecReference: "RFC 7636, Section 4.2",
                FailureReason: "Cannot validate: code_challenge_methods_supported is not advertised");
        }

        var hasS256 = doc.CodeChallengeMethodsSupported.Any(m =>
            m.Equals("S256", StringComparison.OrdinalIgnoreCase));
        var onlyPlain = doc.CodeChallengeMethodsSupported.All(m =>
            m.Equals("plain", StringComparison.OrdinalIgnoreCase));

        var outcome = hasS256 ? TestOutcome.Pass : (onlyPlain ? TestOutcome.Warn : TestOutcome.Pass);

        return new TestResult(
            TestId: "DISC-041",
            Description: "PKCE S256 method is supported",
            Outcome: outcome,
            Duration: sw.Elapsed,
            SpecReference: "RFC 7636, Section 4.2",
            Evidence: $"code_challenge_methods_supported: [{string.Join(", ", doc.CodeChallengeMethodsSupported)}]",
            FailureReason: onlyPlain ? "Only 'plain' method is supported; S256 is more secure" : null,
            Remediation: onlyPlain ? "Add support for the S256 code challenge method" : null);
    }
}
