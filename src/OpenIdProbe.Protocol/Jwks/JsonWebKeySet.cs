using System.Text.Json;
using System.Text.Json.Serialization;

namespace OpenIdProbe.Protocol.Jwks;

/// <summary>
/// Represents a JSON Web Key Set (JWKS) as defined in RFC 7517.
/// </summary>
public sealed class JsonWebKeySet
{
    /// <summary>The keys in the set.</summary>
    [JsonPropertyName("keys")]
    public IReadOnlyList<JsonWebKey> Keys { get; init; } = [];

    /// <summary>
    /// The raw JSON source of the document.
    /// </summary>
    [JsonIgnore]
    public string? RawJson { get; private set; }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = false,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true
    };

    /// <summary>
    /// Parses a JWKS from JSON.
    /// </summary>
    /// <param name="json">The JSON string to parse.</param>
    /// <returns>The parsed JWKS.</returns>
    /// <exception cref="JwksParseException">Thrown when parsing fails.</exception>
    public static JsonWebKeySet Parse(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("keys", out _))
            {
                throw new JwksParseException("Missing required field: keys");
            }

            var jwks = JsonSerializer.Deserialize<JsonWebKeySet>(json, JsonOptions)
                ?? throw new JwksParseException("Failed to deserialize JWKS");

            jwks.RawJson = json;
            return jwks;
        }
        catch (JsonException ex)
        {
            throw new JwksParseException("Invalid JSON in JWKS", ex);
        }
    }

    /// <summary>
    /// Finds a key by its key ID.
    /// </summary>
    /// <param name="keyId">The key ID to search for.</param>
    /// <returns>The matching key, or null if not found.</returns>
    public JsonWebKey? FindKey(string keyId)
    {
        return Keys.FirstOrDefault(k =>
            string.Equals(k.KeyId, keyId, StringComparison.Ordinal));
    }

    /// <summary>
    /// Gets all signing keys in the set.
    /// </summary>
    /// <returns>The signing keys.</returns>
    public IEnumerable<JsonWebKey> GetSigningKeys()
    {
        return Keys.Where(k => k.IsSigningKey);
    }
}
