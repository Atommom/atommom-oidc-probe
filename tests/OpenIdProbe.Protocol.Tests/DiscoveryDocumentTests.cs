using OpenIdProbe.Protocol.Discovery;

namespace OpenIdProbe.Protocol.Tests;

public class DiscoveryDocumentTests
{
    [Fact]
    public void Deserialize_ValidDocument_ParsesRequiredFields()
    {
        var json = """
        {
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/authorize",
            "token_endpoint": "https://example.com/token",
            "jwks_uri": "https://example.com/.well-known/jwks.json",
            "response_types_supported": ["code", "token"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"]
        }
        """;

        var doc = DiscoveryDocument.Parse(json);

        doc.Issuer.Should().Be("https://example.com");
        doc.AuthorizationEndpoint.Should().Be("https://example.com/authorize");
        doc.TokenEndpoint.Should().Be("https://example.com/token");
        doc.JwksUri.Should().Be("https://example.com/.well-known/jwks.json");
        doc.ResponseTypesSupported.Should().BeEquivalentTo(["code", "token"]);
        doc.SubjectTypesSupported.Should().BeEquivalentTo(["public"]);
        doc.IdTokenSigningAlgValuesSupported.Should().BeEquivalentTo(["RS256"]);
    }

    [Fact]
    public void Deserialize_ValidDocument_ParsesOptionalFields()
    {
        var json = """
        {
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/authorize",
            "token_endpoint": "https://example.com/token",
            "jwks_uri": "https://example.com/.well-known/jwks.json",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "userinfo_endpoint": "https://example.com/userinfo",
            "registration_endpoint": "https://example.com/register",
            "scopes_supported": ["openid", "profile", "email"],
            "claims_supported": ["sub", "name", "email"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
            "code_challenge_methods_supported": ["S256"],
            "end_session_endpoint": "https://example.com/logout",
            "revocation_endpoint": "https://example.com/revoke",
            "introspection_endpoint": "https://example.com/introspect"
        }
        """;

        var doc = DiscoveryDocument.Parse(json);

        doc.UserinfoEndpoint.Should().Be("https://example.com/userinfo");
        doc.RegistrationEndpoint.Should().Be("https://example.com/register");
        doc.ScopesSupported.Should().BeEquivalentTo(["openid", "profile", "email"]);
        doc.ClaimsSupported.Should().BeEquivalentTo(["sub", "name", "email"]);
        doc.GrantTypesSupported.Should().BeEquivalentTo(["authorization_code", "refresh_token"]);
        doc.TokenEndpointAuthMethodsSupported.Should().BeEquivalentTo(["client_secret_basic", "client_secret_post"]);
        doc.CodeChallengeMethodsSupported.Should().BeEquivalentTo(["S256"]);
        doc.EndSessionEndpoint.Should().Be("https://example.com/logout");
        doc.RevocationEndpoint.Should().Be("https://example.com/revoke");
        doc.IntrospectionEndpoint.Should().Be("https://example.com/introspect");
    }

    [Fact]
    public void Deserialize_MissingOptionalFields_ReturnsNullOrEmpty()
    {
        var json = """
        {
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/authorize",
            "token_endpoint": "https://example.com/token",
            "jwks_uri": "https://example.com/.well-known/jwks.json",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"]
        }
        """;

        var doc = DiscoveryDocument.Parse(json);

        doc.UserinfoEndpoint.Should().BeNull();
        doc.ScopesSupported.Should().BeEmpty();
        doc.ClaimsSupported.Should().BeEmpty();
        doc.GrantTypesSupported.Should().BeEmpty();
        doc.CodeChallengeMethodsSupported.Should().BeEmpty();
    }

    [Fact]
    public void Parse_InvalidJson_ThrowsException()
    {
        var json = "not valid json";

        var act = () => DiscoveryDocument.Parse(json);

        act.Should().Throw<DiscoveryDocumentParseException>();
    }

    [Fact]
    public void Parse_EmptyJson_ThrowsException()
    {
        var json = "{}";

        var act = () => DiscoveryDocument.Parse(json);

        act.Should().Throw<DiscoveryDocumentParseException>()
            .WithMessage("*issuer*");
    }
}
