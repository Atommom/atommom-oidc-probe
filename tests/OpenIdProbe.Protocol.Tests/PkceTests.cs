using System.Security.Cryptography;
using System.Text;
using OpenIdProbe.Protocol.OAuth;

namespace OpenIdProbe.Protocol.Tests;

public class PkceTests
{
    [Fact]
    public void GenerateCodeVerifier_Returns43To128Characters()
    {
        var verifier = Pkce.GenerateCodeVerifier();

        verifier.Length.Should().BeInRange(43, 128);
    }

    [Fact]
    public void GenerateCodeVerifier_UsesOnlyAllowedCharacters()
    {
        var verifier = Pkce.GenerateCodeVerifier();

        // RFC 7636: unreserved characters [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
        verifier.Should().MatchRegex(@"^[A-Za-z0-9\-._~]+$");
    }

    [Fact]
    public void GenerateCodeVerifier_ReturnsUniqueValues()
    {
        var verifiers = Enumerable.Range(0, 100)
            .Select(_ => Pkce.GenerateCodeVerifier())
            .ToList();

        verifiers.Distinct().Count().Should().Be(100);
    }

    [Fact]
    public void ComputeCodeChallenge_ReturnsBase64UrlEncodedSha256()
    {
        // Test vector from RFC 7636 Appendix B
        var verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        var expectedChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        var challenge = Pkce.ComputeCodeChallenge(verifier);

        challenge.Should().Be(expectedChallenge);
    }

    [Fact]
    public void ComputeCodeChallenge_UsesBase64UrlEncoding()
    {
        var verifier = Pkce.GenerateCodeVerifier();
        var challenge = Pkce.ComputeCodeChallenge(verifier);

        // Base64url encoding should not contain + or / or =
        challenge.Should().NotContain("+");
        challenge.Should().NotContain("/");
        challenge.Should().NotContain("=");
    }

    [Fact]
    public void ComputeCodeChallenge_Returns43Characters()
    {
        var verifier = Pkce.GenerateCodeVerifier();
        var challenge = Pkce.ComputeCodeChallenge(verifier);

        // SHA-256 produces 32 bytes, Base64url encoded = 43 characters
        challenge.Length.Should().Be(43);
    }

    [Fact]
    public void GenerateState_Returns32Characters()
    {
        var state = Pkce.GenerateState();

        state.Length.Should().Be(32);
    }

    [Fact]
    public void GenerateState_ReturnsUniqueValues()
    {
        var states = Enumerable.Range(0, 100)
            .Select(_ => Pkce.GenerateState())
            .ToList();

        states.Distinct().Count().Should().Be(100);
    }

    [Fact]
    public void GenerateNonce_Returns32Characters()
    {
        var nonce = Pkce.GenerateNonce();

        nonce.Length.Should().Be(32);
    }

    [Fact]
    public void GenerateNonce_ReturnsUniqueValues()
    {
        var nonces = Enumerable.Range(0, 100)
            .Select(_ => Pkce.GenerateNonce())
            .ToList();

        nonces.Distinct().Count().Should().Be(100);
    }
}
