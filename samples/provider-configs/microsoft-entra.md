# Microsoft Entra ID (Azure AD) OIDC Provider

Microsoft Entra ID supports OpenID Connect for enterprise identity scenarios.

## Issuer URLs

### Common (Multi-tenant)

```
https://login.microsoftonline.com/common/v2.0
```

### Single Tenant

```
https://login.microsoftonline.com/{tenant-id}/v2.0
```

## Discovery Endpoint

```
https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration
```

## Testing

```bash
# Validate discovery (common endpoint)
openid-probe discover --issuer https://login.microsoftonline.com/common/v2.0

# Validate JWKS
openid-probe jwks --issuer https://login.microsoftonline.com/common/v2.0

# Run all tests
openid-probe test --issuer https://login.microsoftonline.com/common/v2.0 --suite all
```

## Notes

- Microsoft uses multiple signing keys for rotation
- Supports RS256 signing
- Token lifetimes are configurable per application
- Supports various OAuth 2.0 grant types
