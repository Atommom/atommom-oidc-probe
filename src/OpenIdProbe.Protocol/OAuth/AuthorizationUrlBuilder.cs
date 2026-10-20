using System.Text;
using System.Web;

namespace OpenIdProbe.Protocol.OAuth;

/// <summary>
/// Builds OAuth 2.0 authorization URLs with PKCE support.
/// </summary>
public sealed class AuthorizationUrlBuilder
{
    private readonly string _authorizationEndpoint;
    private string? _clientId;
    private string? _redirectUri;
    private string? _codeChallenge;
    private string? _state;
    private string? _nonce;
    private string _scopes = "openid";
    private string? _prompt;

    public AuthorizationUrlBuilder(string authorizationEndpoint)
    {
        _authorizationEndpoint = authorizationEndpoint;
    }

    public AuthorizationUrlBuilder WithClientId(string clientId)
    {
        _clientId = clientId;
        return this;
    }

    public AuthorizationUrlBuilder WithRedirectUri(string redirectUri)
    {
        _redirectUri = redirectUri;
        return this;
    }

    public AuthorizationUrlBuilder WithCodeChallenge(string codeChallenge)
    {
        _codeChallenge = codeChallenge;
        return this;
    }

    public AuthorizationUrlBuilder WithState(string state)
    {
        _state = state;
        return this;
    }

    public AuthorizationUrlBuilder WithNonce(string nonce)
    {
        _nonce = nonce;
        return this;
    }

    public AuthorizationUrlBuilder WithScopes(string scopes)
    {
        _scopes = scopes;
        return this;
    }

    public AuthorizationUrlBuilder WithPrompt(string prompt)
    {
        _prompt = prompt;
        return this;
    }

    public string Build()
    {
        var uri = new UriBuilder(_authorizationEndpoint);
        var query = HttpUtility.ParseQueryString(uri.Query);

        query["response_type"] = "code";
        query["client_id"] = _clientId;
        query["redirect_uri"] = _redirectUri;
        query["code_challenge"] = _codeChallenge;
        query["code_challenge_method"] = "S256";
        query["state"] = _state;
        query["scope"] = _scopes;

        if (_nonce != null)
        {
            query["nonce"] = _nonce;
        }

        if (_prompt != null)
        {
            query["prompt"] = _prompt;
        }

        uri.Query = query.ToString();
        return uri.ToString();
    }
}
