using OpenIdProbe.Protocol.Jwks;

namespace OpenIdProbe.Protocol.Tests;

public class JsonWebKeySetTests
{
    [Fact]
    public void Parse_ValidRsaKey_ParsesCorrectly()
    {
        var json = """
        {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "kid": "key-1",
                    "alg": "RS256",
                    "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                    "e": "AQAB"
                }
            ]
        }
        """;

        var jwks = JsonWebKeySet.Parse(json);

        jwks.Keys.Should().HaveCount(1);
        var key = jwks.Keys[0];
        key.KeyType.Should().Be("RSA");
        key.Use.Should().Be("sig");
        key.KeyId.Should().Be("key-1");
        key.Algorithm.Should().Be("RS256");
    }

    [Fact]
    public void Parse_ValidEcKey_ParsesCorrectly()
    {
        var json = """
        {
            "keys": [
                {
                    "kty": "EC",
                    "use": "sig",
                    "kid": "ec-key-1",
                    "alg": "ES256",
                    "crv": "P-256",
                    "x": "WbbXwISFJ3SbXYNJZByzOCGwKREohdqvk9c5XDrpGw8",
                    "y": "VfyTHvLaQkrjB2F8U_hMxpvMhQX5VBrIzKV9S8_7qaY"
                }
            ]
        }
        """;

        var jwks = JsonWebKeySet.Parse(json);

        jwks.Keys.Should().HaveCount(1);
        var key = jwks.Keys[0];
        key.KeyType.Should().Be("EC");
        key.Curve.Should().Be("P-256");
    }

    [Fact]
    public void Parse_MultipleKeys_ParsesAll()
    {
        var json = """
        {
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "key-1",
                    "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                    "e": "AQAB"
                },
                {
                    "kty": "RSA",
                    "kid": "key-2",
                    "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                    "e": "AQAB"
                }
            ]
        }
        """;

        var jwks = JsonWebKeySet.Parse(json);

        jwks.Keys.Should().HaveCount(2);
        jwks.Keys[0].KeyId.Should().Be("key-1");
        jwks.Keys[1].KeyId.Should().Be("key-2");
    }

    [Fact]
    public void Parse_EmptyKeys_ReturnsEmptySet()
    {
        var json = """{ "keys": [] }""";

        var jwks = JsonWebKeySet.Parse(json);

        jwks.Keys.Should().BeEmpty();
    }

    [Fact]
    public void Parse_InvalidJson_ThrowsException()
    {
        var json = "not valid json";

        var act = () => JsonWebKeySet.Parse(json);

        act.Should().Throw<JwksParseException>();
    }

    [Fact]
    public void Parse_MissingKeysArray_ThrowsException()
    {
        var json = """{ "notkeys": [] }""";

        var act = () => JsonWebKeySet.Parse(json);

        act.Should().Throw<JwksParseException>()
            .WithMessage("*keys*");
    }

    [Fact]
    public void FindKey_ByKeyId_ReturnsCorrectKey()
    {
        var json = """
        {
            "keys": [
                { "kty": "RSA", "kid": "key-1", "n": "abc", "e": "AQAB" },
                { "kty": "RSA", "kid": "key-2", "n": "def", "e": "AQAB" }
            ]
        }
        """;

        var jwks = JsonWebKeySet.Parse(json);
        var key = jwks.FindKey("key-2");

        key.Should().NotBeNull();
        key!.KeyId.Should().Be("key-2");
    }

    [Fact]
    public void FindKey_NotFound_ReturnsNull()
    {
        var json = """
        {
            "keys": [
                { "kty": "RSA", "kid": "key-1", "n": "abc", "e": "AQAB" }
            ]
        }
        """;

        var jwks = JsonWebKeySet.Parse(json);
        var key = jwks.FindKey("nonexistent");

        key.Should().BeNull();
    }
}
