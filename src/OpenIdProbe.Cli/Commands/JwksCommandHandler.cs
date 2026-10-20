using Microsoft.Extensions.DependencyInjection;
using OpenIdProbe.Core;
using OpenIdProbe.Protocol.Discovery;
using OpenIdProbe.Protocol.Jwks;
using OpenIdProbe.Reporting;

namespace OpenIdProbe.Cli.Commands;

public sealed class JwksCommandHandler
{
    private readonly IServiceProvider _services;
    private readonly bool _verbose;
    private readonly string _format;

    public JwksCommandHandler(IServiceProvider services, bool verbose, string format)
    {
        _services = services;
        _verbose = verbose;
        _format = format;
    }

    public async Task<int> ExecuteAsync(
        string? issuer,
        string? jwksUri,
        FileInfo? outputFile,
        CancellationToken cancellationToken)
    {
        var jwksClient = _services.GetRequiredService<IJwksClient>();
        var validator = _services.GetRequiredService<IJwksValidator>();

        string actualJwksUri;
        string effectiveIssuer;

        if (!string.IsNullOrEmpty(jwksUri))
        {
            actualJwksUri = jwksUri;
            effectiveIssuer = jwksUri;
        }
        else
        {
            // Fetch discovery first to get JWKS URI
            var discoveryClient = _services.GetRequiredService<IDiscoveryClient>();

            Console.WriteLine($"Fetching discovery document from: {issuer}");

            var discoveryResult = await discoveryClient.GetDiscoveryDocumentAsync(issuer!, cancellationToken);

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

            actualJwksUri = discoveryResult.Document.JwksUri;
            effectiveIssuer = issuer!;
            Console.WriteLine($"JWKS URI: {actualJwksUri}");
        }

        Console.WriteLine($"Fetching JWKS from: {actualJwksUri}");

        var result = await jwksClient.GetJwksAsync(actualJwksUri, cancellationToken);

        if (!result.IsSuccess)
        {
            Console.Error.WriteLine($"Error: {result.Error}");
            return 2;
        }

        Console.WriteLine($"JWKS fetched in {result.Duration.TotalMilliseconds:F0}ms");
        Console.WriteLine($"Keys found: {result.Jwks!.Keys.Count}");

        var validationResults = validator.Validate(result.Jwks);

        var testRun = new TestRunResult(effectiveIssuer, "jwks", validationResults);

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

    private IReportFormatter GetFormatter() => _format.ToLowerInvariant() switch
    {
        "json" => new JsonReportFormatter(),
        _ => new ConsoleReportFormatter(_verbose)
    };
}
