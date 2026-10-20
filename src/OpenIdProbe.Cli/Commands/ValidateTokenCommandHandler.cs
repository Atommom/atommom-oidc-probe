using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using OpenIdProbe.Core;
using OpenIdProbe.Protocol.Discovery;
using OpenIdProbe.Protocol.Jwks;
using OpenIdProbe.Protocol.Tokens;
using OpenIdProbe.Reporting;

namespace OpenIdProbe.Cli.Commands;

public sealed class ValidateTokenCommandHandler
{
    private readonly IServiceProvider _services;
    private readonly bool _verbose;
    private readonly string _format;

    public ValidateTokenCommandHandler(IServiceProvider services, bool verbose, string format)
    {
        _services = services;
        _verbose = verbose;
        _format = format;
    }

    public async Task<int> ExecuteAsync(
        string issuer,
        string audience,
        string tokenFilePath,
        string? nonce,
        FileInfo? outputFile,
        CancellationToken cancellationToken)
    {
        // Read token from file
        if (!File.Exists(tokenFilePath))
        {
            Console.Error.WriteLine($"Error: Token file not found: {tokenFilePath}");
            return 2;
        }

        var token = (await File.ReadAllTextAsync(tokenFilePath, cancellationToken)).Trim();

        if (string.IsNullOrEmpty(token))
        {
            Console.Error.WriteLine("Error: Token file is empty");
            return 2;
        }

        // Redact token in output
        var redactedToken = token.Length > 20
            ? $"{token[..10]}...{token[^10..]}"
            : "[redacted]";
        Console.WriteLine($"Validating token: {redactedToken}");

        // Fetch discovery and JWKS
        var discoveryClient = _services.GetRequiredService<IDiscoveryClient>();
        var jwksClient = _services.GetRequiredService<IJwksClient>();

        Console.WriteLine($"Fetching discovery document from: {issuer}");

        var discoveryResult = await discoveryClient.GetDiscoveryDocumentAsync(issuer, cancellationToken);

        if (!discoveryResult.IsSuccess)
        {
            Console.Error.WriteLine($"Error fetching discovery: {discoveryResult.Error}");
            return 2;
        }

        if (string.IsNullOrEmpty(discoveryResult.Document!.JwksUri))
        {
            Console.Error.WriteLine("Error: Discovery document does not contain jwks_uri");
            return 2;
        }

        Console.WriteLine($"Fetching JWKS from: {discoveryResult.Document.JwksUri}");

        var jwksResult = await jwksClient.GetJwksAsync(discoveryResult.Document.JwksUri, cancellationToken);

        if (!jwksResult.IsSuccess)
        {
            Console.Error.WriteLine($"Error fetching JWKS: {jwksResult.Error}");
            return 2;
        }

        // Convert to Microsoft.IdentityModel.Tokens JsonWebKey
        var signingKeys = jwksResult.Jwks!.Keys
            .Where(k => k.IsSigningKey)
            .Select(ConvertToMsftJwk)
            .ToList();

        Console.WriteLine($"Validating against {signingKeys.Count} signing key(s)");

        // Validate token
        var validator = new IdTokenValidator();
        var options = new IdTokenValidationOptions
        {
            Issuer = issuer,
            Audience = audience,
            Nonce = nonce,
            SigningKeys = signingKeys
        };

        var results = validator.Validate(token, options);

        var testRun = new TestRunResult(issuer, "token-validation", results);

        var formatter = GetFormatter();
        var output = formatter.FormatReport(testRun);

        if (outputFile != null)
        {
            await File.WriteAllTextAsync(outputFile.FullName, output, cancellationToken);
            Console.WriteLine($"Report written to: {outputFile.FullName}");
        }
        else
        {
            Console.Write(output);
        }

        return testRun.HasFailures ? 1 : 0;
    }

    private static Microsoft.IdentityModel.Tokens.JsonWebKey ConvertToMsftJwk(Protocol.Jwks.JsonWebKey jwk)
    {
        var msftJwk = new Microsoft.IdentityModel.Tokens.JsonWebKey
        {
            Kty = jwk.KeyType,
            Kid = jwk.KeyId,
            Use = jwk.Use,
            Alg = jwk.Algorithm
        };

        if (jwk.IsRsa)
        {
            msftJwk.N = jwk.Modulus;
            msftJwk.E = jwk.Exponent;
        }
        else if (jwk.IsEc)
        {
            msftJwk.Crv = jwk.Curve;
            msftJwk.X = jwk.X;
            msftJwk.Y = jwk.Y;
        }

        return msftJwk;
    }

    private IReportFormatter GetFormatter() => _format.ToLowerInvariant() switch
    {
        "json" => new JsonReportFormatter(),
        _ => new ConsoleReportFormatter(_verbose)
    };
}
