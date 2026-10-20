using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace OpenIdProbe.Protocol.Tests.Fixtures;

/// <summary>
/// Test RSA keys for token signing/verification tests.
/// </summary>
public static class TestKeys
{
    private static readonly Lazy<RSA> LazyRsa = new(() =>
    {
        var rsa = RSA.Create(2048);
        return rsa;
    });

    private static readonly Lazy<ECDsa> LazyEcdsa = new(() =>
    {
        var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return ecdsa;
    });

    public static RSA Rsa => LazyRsa.Value;
    public static ECDsa Ecdsa => LazyEcdsa.Value;

    public static RsaSecurityKey RsaSecurityKey => new(Rsa) { KeyId = "test-rsa-key" };
    public static ECDsaSecurityKey EcdsaSecurityKey => new(Ecdsa) { KeyId = "test-ec-key" };

    public static SigningCredentials RsaSigningCredentials =>
        new(RsaSecurityKey, SecurityAlgorithms.RsaSha256);

    public static SigningCredentials EcdsaSigningCredentials =>
        new(EcdsaSecurityKey, SecurityAlgorithms.EcdsaSha256);

    public static JsonWebKey GetRsaJsonWebKey()
    {
        var parameters = Rsa.ExportParameters(false);
        return new JsonWebKey
        {
            Kty = "RSA",
            Kid = "test-rsa-key",
            Use = "sig",
            Alg = "RS256",
            N = Base64UrlEncoder.Encode(parameters.Modulus),
            E = Base64UrlEncoder.Encode(parameters.Exponent)
        };
    }

    public static JsonWebKey GetEcdsaJsonWebKey()
    {
        var parameters = Ecdsa.ExportParameters(false);
        return new JsonWebKey
        {
            Kty = "EC",
            Kid = "test-ec-key",
            Use = "sig",
            Alg = "ES256",
            Crv = "P-256",
            X = Base64UrlEncoder.Encode(parameters.Q.X),
            Y = Base64UrlEncoder.Encode(parameters.Q.Y)
        };
    }
}
