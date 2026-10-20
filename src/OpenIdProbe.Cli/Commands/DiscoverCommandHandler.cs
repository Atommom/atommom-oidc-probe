using Microsoft.Extensions.DependencyInjection;
using OpenIdProbe.Core;
using OpenIdProbe.Protocol.Discovery;
using OpenIdProbe.Reporting;

namespace OpenIdProbe.Cli.Commands;

public sealed class DiscoverCommandHandler
{
    private readonly IServiceProvider _services;
    private readonly bool _verbose;
    private readonly string _format;

    public DiscoverCommandHandler(IServiceProvider services, bool verbose, string format)
    {
        _services = services;
        _verbose = verbose;
        _format = format;
    }

    public async Task<int> ExecuteAsync(string issuer, FileInfo? outputFile, CancellationToken cancellationToken)
    {
        var discoveryClient = _services.GetRequiredService<IDiscoveryClient>();
        var validator = _services.GetRequiredService<IDiscoveryValidator>();

        Console.WriteLine($"Fetching discovery document from: {issuer}");

        var result = await discoveryClient.GetDiscoveryDocumentAsync(issuer, cancellationToken);

        if (!result.IsSuccess)
        {
            Console.Error.WriteLine($"Error: {result.Error}");
            return 2;
        }

        Console.WriteLine($"Discovery document fetched in {result.Duration.TotalMilliseconds:F0}ms");

        var validationResults = validator.Validate(result.Document!, issuer);

        var testRun = new TestRunResult(issuer, "discovery", validationResults);

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
