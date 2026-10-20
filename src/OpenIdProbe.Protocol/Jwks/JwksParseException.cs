namespace OpenIdProbe.Protocol.Jwks;

/// <summary>
/// Exception thrown when parsing a JWKS fails.
/// </summary>
public sealed class JwksParseException : Exception
{
    public JwksParseException(string message)
        : base(message)
    {
    }

    public JwksParseException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
