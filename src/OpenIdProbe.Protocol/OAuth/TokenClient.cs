using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace OpenIdProbe.Protocol.OAuth;

/// <summary>
/// Client for exchanging authorization codes for tokens.
/// </summary>
public sealed class TokenClient
{
    private readonly HttpClient _httpClient;

    public TokenClient(HttpClient httpClient)
    {
        _httpClient = httpClient;
    }

    public async Task<TokenExchangeResponse> ExchangeCodeAsync(
        TokenExchangeRequest request,
        CancellationToken cancellationToken)
    {
        var formContent = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = request.Code,
            ["code_verifier"] = request.CodeVerifier,
            ["client_id"] = request.ClientId,
            ["redirect_uri"] = request.RedirectUri
        });

        HttpResponseMessage response;
        try
        {
            response = await _httpClient.PostAsync(request.TokenEndpoint, formContent, cancellationToken);
        }
        catch (Exception ex)
        {
            return TokenExchangeResponse.FromError("request_failed", ex.Message);
        }

        var content = await response.Content.ReadAsStringAsync(cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            try
            {
                var errorResponse = JsonSerializer.Deserialize<OAuthErrorResponse>(content);
                return TokenExchangeResponse.FromError(
                    errorResponse?.Error ?? "http_error",
                    errorResponse?.ErrorDescription ?? $"HTTP {(int)response.StatusCode}");
            }
            catch
            {
                return TokenExchangeResponse.FromError("http_error", $"HTTP {(int)response.StatusCode}: {content}");
            }
        }

        try
        {
            var tokenResponse = JsonSerializer.Deserialize<OAuthTokenResponse>(content);
            if (tokenResponse == null)
            {
                return TokenExchangeResponse.FromError("parse_error", "Failed to parse token response");
            }

            return TokenExchangeResponse.FromSuccess(
                tokenResponse.AccessToken,
                tokenResponse.TokenType,
                tokenResponse.ExpiresIn,
                tokenResponse.IdToken,
                tokenResponse.RefreshToken);
        }
        catch (JsonException ex)
        {
            return TokenExchangeResponse.FromError("parse_error", ex.Message);
        }
    }

    private sealed class OAuthTokenResponse
    {
        [JsonPropertyName("access_token")]
        public string AccessToken { get; set; } = string.Empty;

        [JsonPropertyName("token_type")]
        public string TokenType { get; set; } = string.Empty;

        [JsonPropertyName("expires_in")]
        public int? ExpiresIn { get; set; }

        [JsonPropertyName("id_token")]
        public string? IdToken { get; set; }

        [JsonPropertyName("refresh_token")]
        public string? RefreshToken { get; set; }
    }

    private sealed class OAuthErrorResponse
    {
        [JsonPropertyName("error")]
        public string? Error { get; set; }

        [JsonPropertyName("error_description")]
        public string? ErrorDescription { get; set; }
    }
}

/// <summary>
/// Request parameters for token exchange.
/// </summary>
public sealed class TokenExchangeRequest
{
    public required string TokenEndpoint { get; init; }
    public required string Code { get; init; }
    public required string CodeVerifier { get; init; }
    public required string ClientId { get; init; }
    public required string RedirectUri { get; init; }
}

/// <summary>
/// Response from token exchange.
/// </summary>
public sealed class TokenExchangeResponse
{
    public bool IsSuccess { get; private init; }
    public string? AccessToken { get; private init; }
    public string? TokenType { get; private init; }
    public int? ExpiresIn { get; private init; }
    public string? IdToken { get; private init; }
    public string? RefreshToken { get; private init; }
    public string? Error { get; private init; }
    public string? ErrorDescription { get; private init; }

    public static TokenExchangeResponse FromSuccess(
        string accessToken,
        string tokenType,
        int? expiresIn,
        string? idToken,
        string? refreshToken) => new()
    {
        IsSuccess = true,
        AccessToken = accessToken,
        TokenType = tokenType,
        ExpiresIn = expiresIn,
        IdToken = idToken,
        RefreshToken = refreshToken
    };

    public static TokenExchangeResponse FromError(string error, string? description) => new()
    {
        IsSuccess = false,
        Error = error,
        ErrorDescription = description
    };
}
