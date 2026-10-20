using Microsoft.Extensions.DependencyInjection;
using OpenIdProbe.Core;
using OpenIdProbe.Protocol.Discovery;
using OpenIdProbe.Protocol.Jwks;
using OpenIdProbe.Reporting;

namespace OpenIdProbe.Cli.Commands;

public sealed class TestCommandHandler
{
    private readonly IServiceProvider _services;
    private readonly bool _verbose;
    private readonly string _format;

    public TestCommandHandler(IServiceProvider services, bool verbose, string format)
    {
        _services = services;
        _verbose = verbose;
        _format = format;
    }

    public async Task<int> ExecuteAsync(
        string issuer,
        string suite,
        FileInfo? outputFile,
        CancellationToken cancellationToken)
    {
        var allResults = new List<TestResult>();
        var suiteName = suite.ToLowerInvariant();

        var runDiscovery = suiteName is "discovery" or "all";
        var runJwks = suiteName is "jwks" or "all";

        DiscoveryDocument? discoveryDoc = null;

        // Discovery tests
        if (runDiscovery || runJwks)
        {
            var discoveryClient = _services.GetRequiredService<IDiscoveryClient>();
            var discoveryValidator = _services.GetRequiredService<IDiscoveryValidator>();

            Console.WriteLine($"Fetching discovery document from: {issuer}");

            var discoveryResult = await discoveryClient.GetDiscoveryDocumentAsync(issuer, cancellationToken);

            if (!discoveryResult.IsSuccess)
            {
                Console.Error.WriteLine($"Error fetching discovery: {discoveryResult.Error}");
                return 2;
            }

            discoveryDoc = discoveryResult.Document;
            Console.WriteLine($"Discovery document fetched in {discoveryResult.Duration.TotalMilliseconds:F0}ms");

            if (runDiscovery)
            {
                var validationResults = discoveryValidator.Validate(discoveryDoc!, issuer);
                allResults.AddRange(validationResults);
            }
        }

        // JWKS tests
        if (runJwks && discoveryDoc != null)
        {
            var jwksClient = _services.GetRequiredService<IJwksClient>();
            var jwksValidator = _services.GetRequiredService<IJwksValidator>();

            if (string.IsNullOrEmpty(discoveryDoc.JwksUri))
            {
                allResults.Add(new TestResult(
                    "JWKS-000",
                    "JWKS URI available",
                    TestOutcome.Fail,
                    TimeSpan.Zero,
                    FailureReason: "Discovery document does not contain jwks_uri"));
            }
            else
            {
                Console.WriteLine($"Fetching JWKS from: {discoveryDoc.JwksUri}");

                var jwksResult = await jwksClient.GetJwksAsync(discoveryDoc.JwksUri, cancellationToken);

                if (!jwksResult.IsSuccess)
                {
                    allResults.Add(new TestResult(
                        "JWKS-000",
                        "JWKS fetch successful",
                        TestOutcome.Fail,
                        jwksResult.Duration,
                        FailureReason: jwksResult.Error));
                }
                else
                {
                    Console.WriteLine($"JWKS fetched in {jwksResult.Duration.TotalMilliseconds:F0}ms");
                    Console.WriteLine($"Keys found: {jwksResult.Jwks!.Keys.Count}");

                    var validationResults = jwksValidator.Validate(jwksResult.Jwks);
                    allResults.AddRange(validationResults);
                }
            }
        }

        var testRun = new TestRunResult(issuer, suite, allResults);

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
