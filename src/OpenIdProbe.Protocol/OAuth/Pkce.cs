using System.Security.Cryptography;
using System.Text;

namespace OpenIdProbe.Protocol.OAuth;

/// <summary>
/// PKCE (Proof Key for Code Exchange) utilities per RFC 7636.
/// </summary>
public static class Pkce
{
    // RFC 7636 unreserved characters
    private const string UnreservedCharacters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";

    /// <summary>
    /// Generates a cryptographically random code verifier.
    /// </summary>
    /// <returns>A code verifier string between 43 and 128 characters.</returns>
    public static string GenerateCodeVerifier()
    {
        // Use 32 bytes which will produce 43 base64url characters
        var bytes = RandomNumberGenerator.GetBytes(32);
        return Base64UrlEncode(bytes);
    }

    /// <summary>
    /// Computes the S256 code challenge from the code verifier.
    /// </summary>
    /// <param name="codeVerifier">The code verifier.</param>
    /// <returns>The Base64url-encoded SHA-256 hash of the code verifier.</returns>
    public static string ComputeCodeChallenge(string codeVerifier)
    {
        var bytes = Encoding.ASCII.GetBytes(codeVerifier);
        var hash = SHA256.HashData(bytes);
        return Base64UrlEncode(hash);
    }

    /// <summary>
    /// Generates a cryptographically random state parameter.
    /// </summary>
    /// <returns>A 32-character state string.</returns>
    public static string GenerateState()
    {
        return GenerateRandomString(32);
    }

    /// <summary>
    /// Generates a cryptographically random nonce.
    /// </summary>
    /// <returns>A 32-character nonce string.</returns>
    public static string GenerateNonce()
    {
        return GenerateRandomString(32);
    }

    private static string GenerateRandomString(int length)
    {
        var bytes = RandomNumberGenerator.GetBytes(length);
        var chars = new char[length];

        for (var i = 0; i < length; i++)
        {
            chars[i] = UnreservedCharacters[bytes[i] % UnreservedCharacters.Length];
        }

        return new string(chars);
    }

    private static string Base64UrlEncode(byte[] bytes)
    {
        return Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }
}
