namespace OpenIdProbe.Protocol.Discovery;

/// <summary>
/// Exception thrown when parsing a discovery document fails.
/// </summary>
public sealed class DiscoveryDocumentParseException : Exception
{
    public DiscoveryDocumentParseException(string message)
        : base(message)
    {
    }

    public DiscoveryDocumentParseException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
