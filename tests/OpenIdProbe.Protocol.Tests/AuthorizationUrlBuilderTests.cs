using OpenIdProbe.Protocol.OAuth;

namespace OpenIdProbe.Protocol.Tests;

public class AuthorizationUrlBuilderTests
{
    [Fact]
    public void Build_IncludesAllRequiredParameters()
    {
        var url = new AuthorizationUrlBuilder("https://auth.example.com/authorize")
            .WithClientId("test-client")
            .WithRedirectUri("http://127.0.0.1:8400/callback")
            .WithCodeChallenge("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
            .WithState("test-state")
            .WithNonce("test-nonce")
            .WithScopes("openid profile email")
            .Build();

        url.Should().Contain("response_type=code");
        url.Should().Contain("client_id=test-client");
        url.Should().Contain("redirect_uri=");
        url.Should().Contain("127.0.0.1");
        url.Should().Contain("code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
        url.Should().Contain("code_challenge_method=S256");
        url.Should().Contain("state=test-state");
        url.Should().Contain("nonce=test-nonce");
        url.Should().Contain("scope=openid");
    }

    [Fact]
    public void Build_StartsWithAuthorizationEndpoint()
    {
        var url = new AuthorizationUrlBuilder("https://auth.example.com/authorize")
            .WithClientId("test-client")
            .WithRedirectUri("http://127.0.0.1:8400/callback")
            .WithCodeChallenge("test-challenge")
            .WithState("test-state")
            .Build();

        url.Should().StartWith("https://auth.example.com");
        url.Should().Contain("/authorize?");
    }

    [Fact]
    public void Build_UrlEncodesSpecialCharacters()
    {
        var url = new AuthorizationUrlBuilder("https://auth.example.com/authorize")
            .WithClientId("client+with+special")
            .WithRedirectUri("http://127.0.0.1:8400/callback")
            .WithCodeChallenge("test-challenge")
            .WithState("state&with=special")
            .Build();

        // URL encoding may use lowercase hex digits
        url.ToUpperInvariant().Should().Contain("CLIENT_ID=CLIENT%2BWITH%2BSPECIAL");
        url.ToUpperInvariant().Should().Contain("STATE=STATE%26WITH%3DSPECIAL");
    }

    [Fact]
    public void Build_WithoutScopes_DefaultsToOpenId()
    {
        var url = new AuthorizationUrlBuilder("https://auth.example.com/authorize")
            .WithClientId("test-client")
            .WithRedirectUri("http://127.0.0.1:8400/callback")
            .WithCodeChallenge("test-challenge")
            .WithState("test-state")
            .Build();

        url.Should().Contain("scope=openid");
    }

    [Fact]
    public void Build_WithPrompt_IncludesPromptParameter()
    {
        var url = new AuthorizationUrlBuilder("https://auth.example.com/authorize")
            .WithClientId("test-client")
            .WithRedirectUri("http://127.0.0.1:8400/callback")
            .WithCodeChallenge("test-challenge")
            .WithState("test-state")
            .WithPrompt("consent")
            .Build();

        url.Should().Contain("prompt=consent");
    }

    [Fact]
    public void Build_PreservesExistingQueryParameters()
    {
        var url = new AuthorizationUrlBuilder("https://auth.example.com/authorize?existing=param")
            .WithClientId("test-client")
            .WithRedirectUri("http://127.0.0.1:8400/callback")
            .WithCodeChallenge("test-challenge")
            .WithState("test-state")
            .Build();

        url.Should().Contain("existing=param");
    }
}
