using System.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using OpenIdProbe.Core;
using OpenIdProbe.Protocol.Discovery;
using OpenIdProbe.Protocol.OAuth;
using OpenIdProbe.Reporting;

namespace OpenIdProbe.Cli.Commands;

public sealed class UserInfoCommandHandler
{
    private readonly IServiceProvider _services;
    private readonly bool _verbose;
    private readonly string _format;

    public UserInfoCommandHandler(IServiceProvider services, bool verbose, string format)
    {
        _services = services;
        _verbose = verbose;
        _format = format;
    }

    public async Task<int> ExecuteAsync(
        string issuer,
        string accessToken,
        string? expectedSubject,
        FileInfo? outputFile,
        CancellationToken cancellationToken)
    {
        var results = new List<TestResult>();
        var stopwatch = Stopwatch.StartNew();

        Console.WriteLine("Fetching UserInfo...");
        Console.WriteLine($"Issuer: {issuer}");
        Console.WriteLine();

        // Fetch discovery to get userinfo_endpoint
        Console.WriteLine("Fetching discovery document...");
        var discoveryClient = _services.GetRequiredService<IDiscoveryClient>();
        var discoveryResult = await discoveryClient.GetDiscoveryDocumentAsync(issuer, cancellationToken);

        if (!discoveryResult.IsSuccess)
        {
            Console.Error.WriteLine($"Error: Failed to fetch discovery document: {discoveryResult.Error}");
            results.Add(new TestResult(
                "USERINFO-FETCH-001",
                "Fetch discovery document",
                TestOutcome.Fail,
                stopwatch.Elapsed,
                FailureReason: discoveryResult.Error));
            return OutputResults(results, issuer, outputFile);
        }

        var discovery = discoveryResult.Document!;

        if (string.IsNullOrEmpty(discovery.UserinfoEndpoint))
        {
            Console.Error.WriteLine("Error: Discovery document does not contain userinfo_endpoint");
            results.Add(new TestResult(
                "USERINFO-FETCH-002",
                "Discovery has userinfo_endpoint",
                TestOutcome.Fail,
                stopwatch.Elapsed,
                FailureReason: "userinfo_endpoint is required"));
            return OutputResults(results, issuer, outputFile);
        }

        results.Add(new TestResult(
            "USERINFO-FETCH-001",
            "Fetch discovery document",
            TestOutcome.Pass,
            stopwatch.Elapsed));

        results.Add(new TestResult(
            "USERINFO-FETCH-002",
            "Discovery has userinfo_endpoint",
            TestOutcome.Pass,
            stopwatch.Elapsed));

        Console.WriteLine($"UserInfo endpoint: {discovery.UserinfoEndpoint}");

        // Fetch UserInfo
        Console.WriteLine("Fetching user information...");
        var userInfoClient = new UserInfoClient(new HttpClient());
        var userInfoResult = await userInfoClient.GetUserInfoAsync(
            discovery.UserinfoEndpoint,
            accessToken,
            cancellationToken);

        if (!userInfoResult.IsSuccess)
        {
            Console.Error.WriteLine($"Error: Failed to fetch UserInfo: {userInfoResult.Error}");
            results.Add(new TestResult(
                "USERINFO-FETCH-003",
                "Fetch UserInfo response",
                TestOutcome.Fail,
                stopwatch.Elapsed,
                FailureReason: userInfoResult.Error));
            return OutputResults(results, issuer, outputFile);
        }

        results.Add(new TestResult(
            "USERINFO-FETCH-003",
            "Fetch UserInfo response",
            TestOutcome.Pass,
            stopwatch.Elapsed));

        Console.WriteLine("UserInfo fetched successfully!");
        Console.WriteLine();

        if (_verbose && userInfoResult.Claims != null)
        {
            Console.WriteLine("Claims:");
            Console.WriteLine($"  sub: {userInfoResult.Subject}");
            if (userInfoResult.Name != null) Console.WriteLine($"  name: {userInfoResult.Name}");
            if (userInfoResult.Email != null) Console.WriteLine($"  email: {userInfoResult.Email}");
            if (userInfoResult.EmailVerified != null) Console.WriteLine($"  email_verified: {userInfoResult.EmailVerified}");
            if (userInfoResult.Picture != null) Console.WriteLine($"  picture: {userInfoResult.Picture}");
            Console.WriteLine();
        }

        // Validate UserInfo
        Console.WriteLine("Validating UserInfo response...");
        var validationResults = UserInfoValidator.Validate(userInfoResult.Claims!, expectedSubject);
        results.AddRange(validationResults);

        return OutputResults(results, issuer, outputFile);
    }

    private int OutputResults(List<TestResult> results, string issuer, FileInfo? outputFile)
    {
        var testRun = new TestRunResult(issuer, "userinfo", results);

        var formatter = GetFormatter();
        var output = formatter.FormatReport(testRun);

        if (outputFile != null)
        {
            File.WriteAllText(outputFile.FullName, output);
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
