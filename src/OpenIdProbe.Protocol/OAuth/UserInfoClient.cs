using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace OpenIdProbe.Protocol.OAuth;

/// <summary>
/// Client for fetching user information from the UserInfo endpoint.
/// </summary>
public sealed class UserInfoClient
{
    private readonly HttpClient _httpClient;

    public UserInfoClient(HttpClient httpClient)
    {
        _httpClient = httpClient;
    }

    public async Task<UserInfoResponse> GetUserInfoAsync(
        string userInfoEndpoint,
        string accessToken,
        CancellationToken cancellationToken)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, userInfoEndpoint);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

        HttpResponseMessage response;
        try
        {
            response = await _httpClient.SendAsync(request, cancellationToken);
        }
        catch (Exception ex)
        {
            return UserInfoResponse.FromError($"Request failed: {ex.Message}");
        }

        var content = await response.Content.ReadAsStringAsync(cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            return UserInfoResponse.FromError($"HTTP {(int)response.StatusCode}: {content}");
        }

        try
        {
            var claims = JsonSerializer.Deserialize<UserInfoClaims>(content);
            if (claims == null)
            {
                return UserInfoResponse.FromError("Failed to parse userinfo response");
            }

            if (string.IsNullOrEmpty(claims.Subject))
            {
                return UserInfoResponse.FromError("UserInfo response missing required 'sub' claim");
            }

            return UserInfoResponse.FromSuccess(claims);
        }
        catch (JsonException ex)
        {
            return UserInfoResponse.FromError($"Failed to parse JSON: {ex.Message}");
        }
    }
}

/// <summary>
/// Standard OpenID Connect UserInfo claims.
/// </summary>
public sealed class UserInfoClaims
{
    [JsonPropertyName("sub")]
    public string? Subject { get; set; }

    [JsonPropertyName("name")]
    public string? Name { get; set; }

    [JsonPropertyName("given_name")]
    public string? GivenName { get; set; }

    [JsonPropertyName("family_name")]
    public string? FamilyName { get; set; }

    [JsonPropertyName("middle_name")]
    public string? MiddleName { get; set; }

    [JsonPropertyName("nickname")]
    public string? Nickname { get; set; }

    [JsonPropertyName("preferred_username")]
    public string? PreferredUsername { get; set; }

    [JsonPropertyName("profile")]
    public string? Profile { get; set; }

    [JsonPropertyName("picture")]
    public string? Picture { get; set; }

    [JsonPropertyName("website")]
    public string? Website { get; set; }

    [JsonPropertyName("email")]
    public string? Email { get; set; }

    [JsonPropertyName("email_verified")]
    public bool? EmailVerified { get; set; }

    [JsonPropertyName("gender")]
    public string? Gender { get; set; }

    [JsonPropertyName("birthdate")]
    public string? Birthdate { get; set; }

    [JsonPropertyName("zoneinfo")]
    public string? Zoneinfo { get; set; }

    [JsonPropertyName("locale")]
    public string? Locale { get; set; }

    [JsonPropertyName("phone_number")]
    public string? PhoneNumber { get; set; }

    [JsonPropertyName("phone_number_verified")]
    public bool? PhoneNumberVerified { get; set; }

    [JsonPropertyName("updated_at")]
    public long? UpdatedAt { get; set; }
}

/// <summary>
/// Response from the UserInfo endpoint.
/// </summary>
public sealed class UserInfoResponse
{
    public bool IsSuccess { get; private init; }
    public string? Subject { get; private init; }
    public string? Name { get; private init; }
    public string? Email { get; private init; }
    public bool? EmailVerified { get; private init; }
    public string? Picture { get; private init; }
    public UserInfoClaims? Claims { get; private init; }
    public string? Error { get; private init; }

    public static UserInfoResponse FromSuccess(UserInfoClaims claims) => new()
    {
        IsSuccess = true,
        Subject = claims.Subject,
        Name = claims.Name,
        Email = claims.Email,
        EmailVerified = claims.EmailVerified,
        Picture = claims.Picture,
        Claims = claims
    };

    public static UserInfoResponse FromError(string error) => new()
    {
        IsSuccess = false,
        Error = error
    };
}
