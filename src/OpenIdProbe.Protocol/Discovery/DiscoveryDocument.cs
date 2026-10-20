using System.Text.Json;
using System.Text.Json.Serialization;

namespace OpenIdProbe.Protocol.Discovery;

/// <summary>
/// Represents an OpenID Connect Discovery document.
/// See: https://openid.net/specs/openid-connect-discovery-1_0.html
/// </summary>
public sealed class DiscoveryDocument
{
    // Required fields per OIDC Discovery 1.0, Section 3
    [JsonPropertyName("issuer")]
    public string Issuer { get; init; } = string.Empty;

    [JsonPropertyName("authorization_endpoint")]
    public string AuthorizationEndpoint { get; init; } = string.Empty;

    [JsonPropertyName("token_endpoint")]
    public string? TokenEndpoint { get; init; }

    [JsonPropertyName("jwks_uri")]
    public string JwksUri { get; init; } = string.Empty;

    [JsonPropertyName("response_types_supported")]
    public IReadOnlyList<string> ResponseTypesSupported { get; init; } = [];

    [JsonPropertyName("subject_types_supported")]
    public IReadOnlyList<string> SubjectTypesSupported { get; init; } = [];

    [JsonPropertyName("id_token_signing_alg_values_supported")]
    public IReadOnlyList<string> IdTokenSigningAlgValuesSupported { get; init; } = [];

    // Optional fields
    [JsonPropertyName("userinfo_endpoint")]
    public string? UserinfoEndpoint { get; init; }

    [JsonPropertyName("registration_endpoint")]
    public string? RegistrationEndpoint { get; init; }

    [JsonPropertyName("scopes_supported")]
    public IReadOnlyList<string> ScopesSupported { get; init; } = [];

    [JsonPropertyName("claims_supported")]
    public IReadOnlyList<string> ClaimsSupported { get; init; } = [];

    [JsonPropertyName("grant_types_supported")]
    public IReadOnlyList<string> GrantTypesSupported { get; init; } = [];

    [JsonPropertyName("response_modes_supported")]
    public IReadOnlyList<string> ResponseModesSupported { get; init; } = [];

    [JsonPropertyName("token_endpoint_auth_methods_supported")]
    public IReadOnlyList<string> TokenEndpointAuthMethodsSupported { get; init; } = [];

    [JsonPropertyName("token_endpoint_auth_signing_alg_values_supported")]
    public IReadOnlyList<string> TokenEndpointAuthSigningAlgValuesSupported { get; init; } = [];

    [JsonPropertyName("code_challenge_methods_supported")]
    public IReadOnlyList<string> CodeChallengeMethodsSupported { get; init; } = [];

    [JsonPropertyName("end_session_endpoint")]
    public string? EndSessionEndpoint { get; init; }

    [JsonPropertyName("revocation_endpoint")]
    public string? RevocationEndpoint { get; init; }

    [JsonPropertyName("introspection_endpoint")]
    public string? IntrospectionEndpoint { get; init; }

    [JsonPropertyName("pushed_authorization_request_endpoint")]
    public string? PushedAuthorizationRequestEndpoint { get; init; }

    [JsonPropertyName("backchannel_logout_supported")]
    public bool? BackchannelLogoutSupported { get; init; }

    [JsonPropertyName("backchannel_logout_session_supported")]
    public bool? BackchannelLogoutSessionSupported { get; init; }

    [JsonPropertyName("frontchannel_logout_supported")]
    public bool? FrontchannelLogoutSupported { get; init; }

    [JsonPropertyName("frontchannel_logout_session_supported")]
    public bool? FrontchannelLogoutSessionSupported { get; init; }

    [JsonPropertyName("claims_parameter_supported")]
    public bool? ClaimsParameterSupported { get; init; }

    [JsonPropertyName("request_parameter_supported")]
    public bool? RequestParameterSupported { get; init; }

    [JsonPropertyName("request_uri_parameter_supported")]
    public bool? RequestUriParameterSupported { get; init; }

    [JsonPropertyName("require_request_uri_registration")]
    public bool? RequireRequestUriRegistration { get; init; }

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
    /// Parses a discovery document from JSON.
    /// </summary>
    /// <param name="json">The JSON string to parse.</param>
    /// <returns>The parsed discovery document.</returns>
    /// <exception cref="DiscoveryDocumentParseException">Thrown when parsing fails.</exception>
    public static DiscoveryDocument Parse(string json)
    {
        try
        {
            var doc = JsonSerializer.Deserialize<DiscoveryDocument>(json, JsonOptions)
                ?? throw new DiscoveryDocumentParseException("Failed to deserialize discovery document");

            // Validate required fields
            if (string.IsNullOrWhiteSpace(doc.Issuer))
            {
                throw new DiscoveryDocumentParseException("Missing required field: issuer");
            }

            doc.RawJson = json;
            return doc;
        }
        catch (JsonException ex)
        {
            throw new DiscoveryDocumentParseException("Invalid JSON in discovery document", ex);
        }
    }
}
