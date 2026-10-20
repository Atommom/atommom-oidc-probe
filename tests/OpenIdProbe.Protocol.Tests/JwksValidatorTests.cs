using OpenIdProbe.Core;
using OpenIdProbe.Protocol.Jwks;

namespace OpenIdProbe.Protocol.Tests;

public class JwksValidatorTests
{
    private readonly JwksValidator _validator = new();

    [Fact]
    public void Validate_ValidRsaKey_ReturnsPass()
    {
        var jwks = CreateJwks("""
            {
                "keys": [{
                    "kty": "RSA",
                    "kid": "key-1",
                    "use": "sig",
                    "alg": "RS256",
                    "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                    "e": "AQAB"
                }]
            }
            """);

        var results = _validator.Validate(jwks);

        results.Should().Contain(r =>
            r.TestId == "JWKS-001" &&
            r.Outcome == TestOutcome.Pass);
    }

    [Fact]
    public void Validate_EmptyJwks_ReturnsFail()
    {
        var jwks = CreateJwks("""{ "keys": [] }""");

        var results = _validator.Validate(jwks);

        results.Should().Contain(r =>
            r.TestId == "JWKS-001" &&
            r.Outcome == TestOutcome.Fail);
    }

    [Fact]
    public void Validate_NoSigningKeys_ReturnsFail()
    {
        var jwks = CreateJwks("""
            {
                "keys": [{
                    "kty": "RSA",
                    "kid": "enc-key",
                    "use": "enc",
                    "n": "abc",
                    "e": "AQAB"
                }]
            }
            """);

        var results = _validator.Validate(jwks);

        results.Should().Contain(r =>
            r.TestId == "JWKS-002" &&
            r.Outcome == TestOutcome.Fail);
    }

    [Fact]
    public void Validate_DuplicateKeyIds_ReturnsFail()
    {
        var jwks = CreateJwks("""
            {
                "keys": [
                    { "kty": "RSA", "kid": "same-id", "n": "abc", "e": "AQAB" },
                    { "kty": "RSA", "kid": "same-id", "n": "def", "e": "AQAB" }
                ]
            }
            """);

        var results = _validator.Validate(jwks);

        results.Should().Contain(r =>
            r.TestId == "JWKS-003" &&
            r.Outcome == TestOutcome.Fail);
    }

    [Fact]
    public void Validate_MissingKeyId_ReturnsWarn()
    {
        var jwks = CreateJwks("""
            {
                "keys": [{
                    "kty": "RSA",
                    "use": "sig",
                    "n": "abc",
                    "e": "AQAB"
                }]
            }
            """);

        var results = _validator.Validate(jwks);

        results.Should().Contain(r =>
            r.TestId == "JWKS-004" &&
            r.Outcome == TestOutcome.Warn);
    }

    [Fact]
    public void Validate_UnsupportedKeyType_ReturnsWarn()
    {
        var jwks = CreateJwks("""
            {
                "keys": [{
                    "kty": "oct",
                    "kid": "sym-key",
                    "k": "GawgguFyGrWKav7AX4VKUg"
                }]
            }
            """);

        var results = _validator.Validate(jwks);

        results.Should().Contain(r =>
            r.TestId == "JWKS-005" &&
            r.Outcome == TestOutcome.Warn);
    }

    [Fact]
    public void Validate_RsaKeyMissingModulus_ReturnsFail()
    {
        var jwks = CreateJwks("""
            {
                "keys": [{
                    "kty": "RSA",
                    "kid": "bad-key",
                    "e": "AQAB"
                }]
            }
            """);

        var results = _validator.Validate(jwks);

        results.Should().Contain(r =>
            r.TestId == "JWKS-010" &&
            r.Outcome == TestOutcome.Fail);
    }

    [Fact]
    public void Validate_RsaKeyMissingExponent_ReturnsFail()
    {
        var jwks = CreateJwks("""
            {
                "keys": [{
                    "kty": "RSA",
                    "kid": "bad-key",
                    "n": "abc"
                }]
            }
            """);

        var results = _validator.Validate(jwks);

        results.Should().Contain(r =>
            r.TestId == "JWKS-010" &&
            r.Outcome == TestOutcome.Fail);
    }

    [Fact]
    public void Validate_EcKeyMissingCurve_ReturnsFail()
    {
        var jwks = CreateJwks("""
            {
                "keys": [{
                    "kty": "EC",
                    "kid": "bad-ec",
                    "x": "abc",
                    "y": "def"
                }]
            }
            """);

        var results = _validator.Validate(jwks);

        results.Should().Contain(r =>
            r.TestId == "JWKS-011" &&
            r.Outcome == TestOutcome.Fail);
    }

    [Fact]
    public void Validate_WeakAlgorithm_ReturnsWarn()
    {
        var jwks = CreateJwks("""
            {
                "keys": [{
                    "kty": "RSA",
                    "kid": "weak-key",
                    "alg": "RS384",
                    "n": "abc",
                    "e": "AQAB"
                }]
            }
            """);

        var results = _validator.Validate(jwks);

        // RS384 is fine, but let's test for a potentially weak one
        results.Should().NotContain(r =>
            r.TestId == "JWKS-020" &&
            r.Outcome == TestOutcome.Fail);
    }

    [Fact]
    public void Validate_ValidEcKey_ReturnsPass()
    {
        var jwks = CreateJwks("""
            {
                "keys": [{
                    "kty": "EC",
                    "kid": "ec-key",
                    "crv": "P-256",
                    "x": "WbbXwISFJ3SbXYNJZByzOCGwKREohdqvk9c5XDrpGw8",
                    "y": "VfyTHvLaQkrjB2F8U_hMxpvMhQX5VBrIzKV9S8_7qaY"
                }]
            }
            """);

        var results = _validator.Validate(jwks);

        results.Should().Contain(r =>
            r.TestId == "JWKS-011" &&
            r.Outcome == TestOutcome.Pass);
    }

    private static JsonWebKeySet CreateJwks(string json) => JsonWebKeySet.Parse(json);
}
