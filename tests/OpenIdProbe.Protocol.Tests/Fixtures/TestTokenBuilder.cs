using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;

namespace OpenIdProbe.Protocol.Tests.Fixtures;

/// <summary>
/// Builder for creating test ID tokens.
/// </summary>
public sealed class TestTokenBuilder
{
    private string _issuer = "https://example.com";
    private string _audience = "test-client";
    private string _subject = "user-123";
    private string? _nonce;
    private DateTime _issuedAt = DateTime.UtcNow;
    private DateTime _expiration = DateTime.UtcNow.AddHours(1);
    private DateTime? _authTime;
    private string? _azp;
    private SigningCredentials _signingCredentials = TestKeys.RsaSigningCredentials;
    private readonly List<Claim> _additionalClaims = [];

    public TestTokenBuilder WithIssuer(string issuer)
    {
        _issuer = issuer;
        return this;
    }

    public TestTokenBuilder WithAudience(string audience)
    {
        _audience = audience;
        return this;
    }

    public TestTokenBuilder WithSubject(string subject)
    {
        _subject = subject;
        return this;
    }

    public TestTokenBuilder WithNonce(string nonce)
    {
        _nonce = nonce;
        return this;
    }

    public TestTokenBuilder WithIssuedAt(DateTime issuedAt)
    {
        _issuedAt = issuedAt;
        return this;
    }

    public TestTokenBuilder WithExpiration(DateTime expiration)
    {
        _expiration = expiration;
        return this;
    }

    public TestTokenBuilder WithAuthTime(DateTime authTime)
    {
        _authTime = authTime;
        return this;
    }

    public TestTokenBuilder WithAuthorizedParty(string azp)
    {
        _azp = azp;
        return this;
    }

    public TestTokenBuilder WithSigningCredentials(SigningCredentials credentials)
    {
        _signingCredentials = credentials;
        return this;
    }

    public TestTokenBuilder WithClaim(string type, string value)
    {
        _additionalClaims.Add(new Claim(type, value));
        return this;
    }

    public TestTokenBuilder Expired()
    {
        _issuedAt = DateTime.UtcNow.AddHours(-2);
        _expiration = DateTime.UtcNow.AddHours(-1);
        return this;
    }

    public TestTokenBuilder NotYetValid()
    {
        _issuedAt = DateTime.UtcNow.AddHours(1);
        _expiration = DateTime.UtcNow.AddHours(2);
        return this;
    }

    public string Build()
    {
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, _subject),
            new(JwtRegisteredClaimNames.Iat, new DateTimeOffset(_issuedAt).ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture), ClaimValueTypes.Integer64)
        };

        if (_nonce != null)
        {
            claims.Add(new Claim("nonce", _nonce));
        }

        if (_authTime.HasValue)
        {
            claims.Add(new Claim("auth_time", new DateTimeOffset(_authTime.Value).ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture), ClaimValueTypes.Integer64));
        }

        if (_azp != null)
        {
            claims.Add(new Claim("azp", _azp));
        }

        claims.AddRange(_additionalClaims);

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Issuer = _issuer,
            Audience = _audience,
            Subject = new ClaimsIdentity(claims),
            NotBefore = _issuedAt,
            Expires = _expiration,
            IssuedAt = _issuedAt,
            SigningCredentials = _signingCredentials
        };

        var handler = new JwtSecurityTokenHandler();
        var token = handler.CreateToken(tokenDescriptor);
        return handler.WriteToken(token);
    }

    public static TestTokenBuilder Create() => new();
}
