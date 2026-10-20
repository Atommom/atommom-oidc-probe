# Keycloak OIDC Provider

Keycloak is an open-source identity and access management solution.

## Issuer URL

```
https://{keycloak-host}/realms/{realm-name}
```

## Discovery Endpoint

```
https://{keycloak-host}/realms/{realm-name}/.well-known/openid-configuration
```

## Testing

```bash
# Validate discovery
openid-probe discover --issuer https://keycloak.example.com/realms/myrealm

# Validate JWKS
openid-probe jwks --issuer https://keycloak.example.com/realms/myrealm

# Run all tests
openid-probe test --issuer https://keycloak.example.com/realms/myrealm --suite all
```

## Local Development

For local Keycloak instances:

```bash
# Allow private network and insecure connections
openid-probe discover \
  --issuer http://localhost:8080/realms/master \
  --allow-insecure \
  --allow-private-network
```

## Notes

- Each realm has its own OIDC configuration
- Supports RS256, ES256, and other algorithms
- Highly configurable through admin console
- Supports PKCE, refresh tokens, and all standard flows
