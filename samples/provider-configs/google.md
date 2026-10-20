# Google OIDC Provider

Google's OpenID Connect implementation is one of the most widely used.

## Issuer URL

```
https://accounts.google.com
```

## Discovery Endpoint

```
https://accounts.google.com/.well-known/openid-configuration
```

## Testing

```bash
# Validate discovery
openid-probe discover --issuer https://accounts.google.com

# Validate JWKS
openid-probe jwks --issuer https://accounts.google.com

# Run all tests
openid-probe test --issuer https://accounts.google.com --suite all
```

## Notes

- Google requires client registration through the Google Cloud Console
- Supports authorization code flow with PKCE
- Supports refresh tokens
- Uses RS256 for ID token signing
