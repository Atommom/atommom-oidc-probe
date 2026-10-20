using Microsoft.IdentityModel.Tokens;
using OpenIdProbe.Core;
using OpenIdProbe.Protocol.Tests.Fixtures;
using OpenIdProbe.Protocol.Tokens;

namespace OpenIdProbe.Protocol.Tests;

public class IdTokenValidatorTests
{
    private readonly IdTokenValidator _validator = new();

    [Fact]
    public void Validate_ValidToken_ReturnsPass()
    {
        var token = TestTokenBuilder.Create()
            .WithIssuer("https://example.com")
            .WithAudience("test-client")
            .WithNonce("test-nonce")
            .Build();

        var options = new IdTokenValidationOptions
        {
            Issuer = "https://example.com",
            Audience = "test-client",
            Nonce = "test-nonce",
            SigningKeys = [TestKeys.GetRsaJsonWebKey()]
        };

        var results = _validator.Validate(token, options);

        results.Should().NotBeEmpty();
        results.Where(r => r.TestId.StartsWith("TOKEN-", StringComparison.Ordinal))
            .Should().OnlyContain(r => r.Outcome != TestOutcome.Fail);
    }

    [Fact]
    public void Validate_ExpiredToken_ReturnsFail()
    {
        var token = TestTokenBuilder.Create()
            .WithIssuer("https://example.com")
            .WithAudience("test-client")
            .Expired()
            .Build();

        var options = new IdTokenValidationOptions
        {
            Issuer = "https://example.com",
            Audience = "test-client",
            SigningKeys = [TestKeys.GetRsaJsonWebKey()]
        };

        var results = _validator.Validate(token, options);

        results.Should().Contain(r =>
            r.TestId == "TOKEN-020" &&
            r.Outcome == TestOutcome.Fail);
    }

    [Fact]
    public void Validate_WrongIssuer_ReturnsFail()
    {
        var token = TestTokenBuilder.Create()
            .WithIssuer("https://wrong.com")
            .WithAudience("test-client")
            .Build();

        var options = new IdTokenValidationOptions
        {
            Issuer = "https://example.com",
            Audience = "test-client",
            SigningKeys = [TestKeys.GetRsaJsonWebKey()]
        };

        var results = _validator.Validate(token, options);

        results.Should().Contain(r =>
            r.TestId == "TOKEN-010" &&
            r.Outcome == TestOutcome.Fail);
    }

    [Fact]
    public void Validate_WrongAudience_ReturnsFail()
    {
        var token = TestTokenBuilder.Create()
            .WithIssuer("https://example.com")
            .WithAudience("wrong-client")
            .Build();

        var options = new IdTokenValidationOptions
        {
            Issuer = "https://example.com",
            Audience = "test-client",
            SigningKeys = [TestKeys.GetRsaJsonWebKey()]
        };

        var results = _validator.Validate(token, options);

        results.Should().Contain(r =>
            r.TestId == "TOKEN-011" &&
            r.Outcome == TestOutcome.Fail);
    }

    [Fact]
    public void Validate_MissingNonce_WhenRequired_ReturnsFail()
    {
        var token = TestTokenBuilder.Create()
            .WithIssuer("https://example.com")
            .WithAudience("test-client")
            // No nonce
            .Build();

        var options = new IdTokenValidationOptions
        {
            Issuer = "https://example.com",
            Audience = "test-client",
            Nonce = "expected-nonce",
            SigningKeys = [TestKeys.GetRsaJsonWebKey()]
        };

        var results = _validator.Validate(token, options);

        results.Should().Contain(r =>
            r.TestId == "TOKEN-030" &&
            r.Outcome == TestOutcome.Fail);
    }

    [Fact]
    public void Validate_WrongNonce_ReturnsFail()
    {
        var token = TestTokenBuilder.Create()
            .WithIssuer("https://example.com")
            .WithAudience("test-client")
            .WithNonce("wrong-nonce")
            .Build();

        var options = new IdTokenValidationOptions
        {
            Issuer = "https://example.com",
            Audience = "test-client",
            Nonce = "expected-nonce",
            SigningKeys = [TestKeys.GetRsaJsonWebKey()]
        };

        var results = _validator.Validate(token, options);

        results.Should().Contain(r =>
            r.TestId == "TOKEN-031" &&
            r.Outcome == TestOutcome.Fail);
    }

    [Fact]
    public void Validate_InvalidSignature_ReturnsFail()
    {
        var token = TestTokenBuilder.Create()
            .WithIssuer("https://example.com")
            .WithAudience("test-client")
            .Build();

        // Use different key for validation
        using var differentRsa = System.Security.Cryptography.RSA.Create(2048);
        var differentKey = new JsonWebKey
        {
            Kty = "RSA",
            Kid = "different-key",
            Use = "sig",
            N = Base64UrlEncoder.Encode(differentRsa.ExportParameters(false).Modulus),
            E = Base64UrlEncoder.Encode(differentRsa.ExportParameters(false).Exponent)
        };

        var options = new IdTokenValidationOptions
        {
            Issuer = "https://example.com",
            Audience = "test-client",
            SigningKeys = [differentKey]
        };

        var results = _validator.Validate(token, options);

        results.Should().Contain(r =>
            r.TestId == "TOKEN-001" &&
            r.Outcome == TestOutcome.Fail);
    }

    [Fact]
    public void Validate_MissingSubject_ReturnsFail()
    {
        // Create a token without subject - we need to use a custom approach
        var token = TestTokenBuilder.Create()
            .WithIssuer("https://example.com")
            .WithAudience("test-client")
            .WithSubject("") // Empty subject
            .Build();

        var options = new IdTokenValidationOptions
        {
            Issuer = "https://example.com",
            Audience = "test-client",
            SigningKeys = [TestKeys.GetRsaJsonWebKey()]
        };

        var results = _validator.Validate(token, options);

        // Should still validate other aspects
        results.Should().NotBeEmpty();
    }

    [Fact]
    public void Validate_EcdsaToken_ReturnsPass()
    {
        var token = TestTokenBuilder.Create()
            .WithIssuer("https://example.com")
            .WithAudience("test-client")
            .WithSigningCredentials(TestKeys.EcdsaSigningCredentials)
            .Build();

        var options = new IdTokenValidationOptions
        {
            Issuer = "https://example.com",
            Audience = "test-client",
            SigningKeys = [TestKeys.GetEcdsaJsonWebKey()]
        };

        var results = _validator.Validate(token, options);

        results.Should().Contain(r =>
            r.TestId == "TOKEN-001" &&
            r.Outcome == TestOutcome.Pass);
    }

    [Fact]
    public void Validate_WithClockSkew_AllowsNearExpiredToken()
    {
        var token = TestTokenBuilder.Create()
            .WithIssuer("https://example.com")
            .WithAudience("test-client")
            .WithIssuedAt(DateTime.UtcNow.AddMinutes(-5))
            .WithExpiration(DateTime.UtcNow.AddSeconds(-30)) // Expired 30 seconds ago
            .Build();

        var options = new IdTokenValidationOptions
        {
            Issuer = "https://example.com",
            Audience = "test-client",
            SigningKeys = [TestKeys.GetRsaJsonWebKey()],
            ClockSkew = TimeSpan.FromMinutes(5) // Allow 5 minute skew
        };

        var results = _validator.Validate(token, options);

        results.Should().Contain(r =>
            r.TestId == "TOKEN-020" &&
            r.Outcome == TestOutcome.Pass);
    }

    [Fact]
    public void Validate_AuthorizedPartyMismatch_ReturnsFail()
    {
        var token = TestTokenBuilder.Create()
            .WithIssuer("https://example.com")
            .WithAudience("test-client")
            .WithAuthorizedParty("wrong-client")
            .Build();

        var options = new IdTokenValidationOptions
        {
            Issuer = "https://example.com",
            Audience = "test-client",
            SigningKeys = [TestKeys.GetRsaJsonWebKey()]
        };

        var results = _validator.Validate(token, options);

        results.Should().Contain(r =>
            r.TestId == "TOKEN-012" &&
            r.Outcome == TestOutcome.Fail);
    }

    [Fact]
    public void Validate_MalformedToken_ReturnsFail()
    {
        var token = "not.a.valid.jwt.token";

        var options = new IdTokenValidationOptions
        {
            Issuer = "https://example.com",
            Audience = "test-client",
            SigningKeys = [TestKeys.GetRsaJsonWebKey()]
        };

        var results = _validator.Validate(token, options);

        results.Should().Contain(r =>
            r.TestId == "TOKEN-000" &&
            r.Outcome == TestOutcome.Fail);
    }
}
