using OpenIdProbe.Core;
using OpenIdProbe.Protocol.Discovery;

namespace OpenIdProbe.Protocol.Tests;

public class DiscoveryValidatorTests
{
    private readonly DiscoveryValidator _validator = new();

    [Fact]
    public void Validate_ValidDocument_ReturnsAllPassing()
    {
        var doc = CreateValidDocument();

        var results = _validator.Validate(doc, "https://example.com");

        results.Should().NotBeEmpty();
        results.Should().OnlyContain(r => r.Outcome == TestOutcome.Pass);
    }

    [Fact]
    public void Validate_IssuerMismatch_ReturnsFail()
    {
        var doc = CreateValidDocument();

        var results = _validator.Validate(doc, "https://different.com");

        results.Should().Contain(r =>
            r.TestId == "DISC-001" &&
            r.Outcome == TestOutcome.Fail &&
            r.FailureReason!.Contains("mismatch", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Validate_IssuerWithTrailingSlash_ReturnsFail()
    {
        var doc = CreateValidDocument(issuer: "https://example.com/");

        var results = _validator.Validate(doc, "https://example.com");

        results.Should().Contain(r =>
            r.TestId == "DISC-002" &&
            r.Outcome == TestOutcome.Fail &&
            r.FailureReason!.Contains("trailing slash", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Validate_IssuerWithFragment_ReturnsFail()
    {
        var doc = CreateValidDocument(issuer: "https://example.com#fragment");

        var results = _validator.Validate(doc, "https://example.com#fragment");

        results.Should().Contain(r =>
            r.TestId == "DISC-003" &&
            r.Outcome == TestOutcome.Fail);
    }

    [Fact]
    public void Validate_IssuerWithQueryString_ReturnsFail()
    {
        var doc = CreateValidDocument(issuer: "https://example.com?query=value");

        var results = _validator.Validate(doc, "https://example.com?query=value");

        results.Should().Contain(r =>
            r.TestId == "DISC-004" &&
            r.Outcome == TestOutcome.Fail);
    }

    [Fact]
    public void Validate_HttpIssuer_ReturnsFail()
    {
        var doc = CreateValidDocument(issuer: "http://example.com");

        var results = _validator.Validate(doc, "http://example.com");

        results.Should().Contain(r =>
            r.TestId == "DISC-005" &&
            r.Outcome == TestOutcome.Fail);
    }

    [Fact]
    public void Validate_MissingAuthorizationEndpoint_ReturnsFail()
    {
        var doc = CreateValidDocument(authorizationEndpoint: "");

        var results = _validator.Validate(doc, "https://example.com");

        results.Should().Contain(r =>
            r.TestId == "DISC-010" &&
            r.Outcome == TestOutcome.Fail);
    }

    [Fact]
    public void Validate_HttpAuthorizationEndpoint_ReturnsFail()
    {
        var doc = CreateValidDocument(authorizationEndpoint: "http://example.com/auth");

        var results = _validator.Validate(doc, "https://example.com");

        results.Should().Contain(r =>
            r.TestId == "DISC-011" &&
            r.Outcome == TestOutcome.Fail);
    }

    [Fact]
    public void Validate_MissingJwksUri_ReturnsFail()
    {
        var doc = CreateValidDocument(jwksUri: "");

        var results = _validator.Validate(doc, "https://example.com");

        results.Should().Contain(r =>
            r.TestId == "DISC-020" &&
            r.Outcome == TestOutcome.Fail);
    }

    [Fact]
    public void Validate_EmptyResponseTypesSupported_ReturnsFail()
    {
        var doc = CreateValidDocument(responseTypesSupported: []);

        var results = _validator.Validate(doc, "https://example.com");

        results.Should().Contain(r =>
            r.TestId == "DISC-030" &&
            r.Outcome == TestOutcome.Fail);
    }

    [Fact]
    public void Validate_EmptySubjectTypesSupported_ReturnsFail()
    {
        var doc = CreateValidDocument(subjectTypesSupported: []);

        var results = _validator.Validate(doc, "https://example.com");

        results.Should().Contain(r =>
            r.TestId == "DISC-031" &&
            r.Outcome == TestOutcome.Fail);
    }

    [Fact]
    public void Validate_EmptyIdTokenSigningAlgValuesSupported_ReturnsFail()
    {
        var doc = CreateValidDocument(idTokenSigningAlgValuesSupported: []);

        var results = _validator.Validate(doc, "https://example.com");

        results.Should().Contain(r =>
            r.TestId == "DISC-032" &&
            r.Outcome == TestOutcome.Fail);
    }

    [Fact]
    public void Validate_OnlyNoneAlgorithm_ReturnsWarn()
    {
        var doc = CreateValidDocument(idTokenSigningAlgValuesSupported: ["none"]);

        var results = _validator.Validate(doc, "https://example.com");

        results.Should().Contain(r =>
            r.TestId == "DISC-033" &&
            r.Outcome == TestOutcome.Warn);
    }

    [Fact]
    public void Validate_PkceSupported_ReturnsPass()
    {
        var doc = CreateValidDocument(codeChallengeMethodsSupported: ["S256"]);

        var results = _validator.Validate(doc, "https://example.com");

        results.Should().Contain(r =>
            r.TestId == "DISC-040" &&
            r.Outcome == TestOutcome.Pass);
    }

    [Fact]
    public void Validate_PkceNotAdvertised_ReturnsWarn()
    {
        var doc = CreateValidDocument(codeChallengeMethodsSupported: []);

        var results = _validator.Validate(doc, "https://example.com");

        results.Should().Contain(r =>
            r.TestId == "DISC-040" &&
            r.Outcome == TestOutcome.Warn);
    }

    [Fact]
    public void Validate_OnlyPlainPkce_ReturnsWarn()
    {
        var doc = CreateValidDocument(codeChallengeMethodsSupported: ["plain"]);

        var results = _validator.Validate(doc, "https://example.com");

        results.Should().Contain(r =>
            r.TestId == "DISC-041" &&
            r.Outcome == TestOutcome.Warn);
    }

    private static DiscoveryDocument CreateValidDocument(
        string issuer = "https://example.com",
        string authorizationEndpoint = "https://example.com/authorize",
        string tokenEndpoint = "https://example.com/token",
        string jwksUri = "https://example.com/.well-known/jwks.json",
        IReadOnlyList<string>? responseTypesSupported = null,
        IReadOnlyList<string>? subjectTypesSupported = null,
        IReadOnlyList<string>? idTokenSigningAlgValuesSupported = null,
        IReadOnlyList<string>? codeChallengeMethodsSupported = null) => new()
    {
        Issuer = issuer,
        AuthorizationEndpoint = authorizationEndpoint,
        TokenEndpoint = tokenEndpoint,
        JwksUri = jwksUri,
        ResponseTypesSupported = responseTypesSupported ?? ["code"],
        SubjectTypesSupported = subjectTypesSupported ?? ["public"],
        IdTokenSigningAlgValuesSupported = idTokenSigningAlgValuesSupported ?? ["RS256"],
        CodeChallengeMethodsSupported = codeChallengeMethodsSupported ?? ["S256"]
    };
}
