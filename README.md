# OpenID Probe

A developer-focused CLI and testing library that evaluates OpenID Connect providers for interoperability, protocol correctness, and selected security behaviors.

> **Note:** This tool is not an official OpenID Foundation certification suite. Test results should not be interpreted as proof of certification or complete standards compliance.

## Features

- **Discovery Validation** - Fetch and validate OpenID Connect discovery documents
- **JWKS Validation** - Validate JSON Web Key Sets for structure and security
- **Protocol Compliance Testing** - Test providers against OIDC specifications
- **Multiple Output Formats** - Console, JSON reporting
- **Security-First Design** - SSRF protection, TLS enforcement, secure defaults

## Quick Start

### Prerequisites

- [.NET 10 SDK](https://dotnet.microsoft.com/download)

### Build

```bash
git clone https://github.com/yourusername/openid-probe.git
cd openid-probe
dotnet build
```

### Run Tests

```bash
dotnet test
```

### Basic Usage

```bash
# Validate a discovery document
dotnet run --project src/OpenIdProbe.Cli -- discover --issuer https://accounts.google.com

# Validate a JWKS
dotnet run --project src/OpenIdProbe.Cli -- jwks --issuer https://accounts.google.com

# Run all tests
dotnet run --project src/OpenIdProbe.Cli -- test --issuer https://accounts.google.com --suite all
```

## CLI Reference

### Global Options

| Option | Description |
|--------|-------------|
| `-v, --verbose` | Show detailed output |
| `-f, --format <format>` | Output format: `console` (default), `json` |
| `-o, --output <file>` | Write output to file |
| `--allow-insecure` | Allow HTTP connections (not recommended) |
| `--allow-private-network` | Allow connections to private network addresses |

### Commands

#### `discover`

Fetch and validate an OIDC discovery document.

```bash
openid-probe discover --issuer https://idp.example.com
```

| Option | Description |
|--------|-------------|
| `-i, --issuer <url>` | The issuer URL (required) |

#### `jwks`

Fetch and validate a JWKS document.

```bash
openid-probe jwks --issuer https://idp.example.com
# or directly:
openid-probe jwks --uri https://idp.example.com/.well-known/jwks.json
```

| Option | Description |
|--------|-------------|
| `-i, --issuer <url>` | The issuer URL (fetches discovery first) |
| `-u, --uri <url>` | The JWKS URI directly |

#### `test`

Run a test suite against an OIDC provider.

```bash
openid-probe test --issuer https://idp.example.com --suite all
```

| Option | Description |
|--------|-------------|
| `-i, --issuer <url>` | The issuer URL (required) |
| `-s, --suite <suite>` | Test suite: `discovery` (default), `jwks`, `all` |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success (all tests passed) |
| 1 | Failure (one or more tests failed) |
| 2 | Error (invalid arguments or runtime error) |

## Test Coverage

### Discovery Tests

| Test ID | Description | Spec Reference |
|---------|-------------|----------------|
| DISC-001 | Issuer matches expected value | OIDC Discovery 1.0 §3 |
| DISC-002 | Issuer has no trailing slash | OIDC Discovery 1.0 §3 |
| DISC-003 | Issuer has no fragment | OIDC Discovery 1.0 §3 |
| DISC-004 | Issuer has no query string | OIDC Discovery 1.0 §3 |
| DISC-005 | Issuer uses HTTPS | OIDC Discovery 1.0 §3 |
| DISC-010 | Authorization endpoint present | OIDC Discovery 1.0 §3 |
| DISC-011 | Authorization endpoint uses HTTPS | OIDC Discovery 1.0 §3 |
| DISC-015 | Token endpoint present | OIDC Discovery 1.0 §3 |
| DISC-020 | JWKS URI present | OIDC Discovery 1.0 §3 |
| DISC-021 | JWKS URI uses HTTPS | OIDC Discovery 1.0 §3 |
| DISC-030 | Response types supported | OIDC Discovery 1.0 §3 |
| DISC-031 | Subject types supported | OIDC Discovery 1.0 §3 |
| DISC-032 | ID token signing algorithms | OIDC Discovery 1.0 §3 |
| DISC-033 | Secure signing algorithms | OIDC Core 1.0 §3.1.3.7 |
| DISC-040 | PKCE advertised | RFC 7636 |
| DISC-041 | PKCE S256 supported | RFC 7636 §4.2 |

### JWKS Tests

| Test ID | Description | Spec Reference |
|---------|-------------|----------------|
| JWKS-001 | JWKS contains keys | RFC 7517 |
| JWKS-002 | Signing keys present | RFC 7517 |
| JWKS-003 | No duplicate key IDs | RFC 7517 |
| JWKS-004 | All keys have key IDs | RFC 7517 |
| JWKS-005 | Supported key types | RFC 7517 |
| JWKS-010 | RSA key structure valid | RFC 7518 §6.3 |
| JWKS-011 | EC key structure valid | RFC 7518 §6.2 |

## Security Model

OpenID Probe is designed with security as a priority:

- **HTTPS by default** - HTTP connections require explicit `--allow-insecure` flag
- **SSRF protection** - Private network addresses blocked by default
- **Request timeouts** - 30-second timeout prevents hanging
- **Response size limits** - 1MB limit prevents memory exhaustion
- **No secret logging** - Tokens and credentials are never logged
- **TLS validation** - Certificate validation is always enabled

## Provider Compatibility

OpenID Probe works with any standards-compliant OIDC provider, including:

- Google
- Microsoft Entra ID (Azure AD)
- Auth0
- Okta
- Keycloak
- authentik
- Custom identity providers

## Project Structure

```
openid-probe/
├── src/
│   ├── OpenIdProbe.Core/       # Domain models, interfaces
│   ├── OpenIdProbe.Protocol/   # Discovery, JWKS, HTTP clients
│   ├── OpenIdProbe.Reporting/  # Output formatters
│   └── OpenIdProbe.Cli/        # Command-line interface
├── tests/
│   ├── OpenIdProbe.Core.Tests/
│   ├── OpenIdProbe.Protocol.Tests/
│   └── OpenIdProbe.IntegrationTests/
├── samples/
│   └── provider-configs/       # Example configurations
└── docs/
```

## Roadmap

### Milestone 1 ✅ (Current)
- Discovery document validation
- JWKS validation
- Console and JSON reporting
- CLI interface

### Milestone 2 (Planned)
- ID token signature validation
- Claims validation
- Negative test fixtures

### Milestone 3 (Planned)
- Interactive authorization code flow
- PKCE verification
- Browser integration

### Milestone 4 (Planned)
- Refresh token testing
- UserInfo endpoint testing
- Logout testing

### Milestone 5 (Planned)
- HTML reports
- JUnit XML output
- Docker packaging

## Contributing

Contributions are welcome! Please read our contributing guidelines before submitting a pull request.

### Development Setup

1. Clone the repository
2. Install .NET 10 SDK
3. Run `dotnet restore`
4. Run `dotnet build`
5. Run `dotnet test`

## License

MIT License - see [LICENSE](LICENSE) for details.

## Specifications

This tool validates against the following specifications:

- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
- [RFC 7517 - JSON Web Key (JWK)](https://tools.ietf.org/html/rfc7517)
- [RFC 7518 - JSON Web Algorithms (JWA)](https://tools.ietf.org/html/rfc7518)
- [RFC 7636 - PKCE](https://tools.ietf.org/html/rfc7636)
- [RFC 6749 - OAuth 2.0](https://tools.ietf.org/html/rfc6749)
