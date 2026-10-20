using System.Text.Json;
using System.Text.Json.Serialization;
using OpenIdProbe.Core;

namespace OpenIdProbe.Reporting;

/// <summary>
/// Formats test results as JSON.
/// </summary>
public sealed class JsonReportFormatter : IReportFormatter
{
    public string Format => "json";

    private readonly bool _indented;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) }
    };

    private static readonly JsonSerializerOptions CompactJsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) }
    };

    public JsonReportFormatter(bool indented = true)
    {
        _indented = indented;
    }

    public string FormatReport(TestRunResult result)
    {
        var report = new JsonReport
        {
            Issuer = result.Issuer,
            Suite = result.Suite,
            ExecutedAt = result.ExecutedAt,
            DurationMs = result.TotalDuration.TotalMilliseconds,
            Summary = new JsonReportSummary
            {
                Total = result.Results.Count,
                Passed = result.PassCount,
                Failed = result.FailCount,
                Warnings = result.WarnCount,
                Skipped = result.SkipCount,
                Inconclusive = result.InconclusiveCount,
                HasFailures = result.HasFailures
            },
            Results = result.Results.Select(r => new JsonTestResult
            {
                TestId = r.TestId,
                Description = r.Description,
                Outcome = r.Outcome.ToString().ToLowerInvariant(),
                DurationMs = r.Duration.TotalMilliseconds,
                SpecReference = r.SpecReference,
                Evidence = r.Evidence,
                FailureReason = r.FailureReason,
                Remediation = r.Remediation
            }).ToList()
        };

        var options = _indented ? JsonOptions : CompactJsonOptions;
        return JsonSerializer.Serialize(report, options);
    }

    private sealed class JsonReport
    {
        public required string Issuer { get; init; }
        public required string Suite { get; init; }
        public required DateTimeOffset ExecutedAt { get; init; }
        public required double DurationMs { get; init; }
        public required JsonReportSummary Summary { get; init; }
        public required IReadOnlyList<JsonTestResult> Results { get; init; }
    }

    private sealed class JsonReportSummary
    {
        public required int Total { get; init; }
        public required int Passed { get; init; }
        public required int Failed { get; init; }
        public required int Warnings { get; init; }
        public required int Skipped { get; init; }
        public required int Inconclusive { get; init; }
        public required bool HasFailures { get; init; }
    }

    private sealed class JsonTestResult
    {
        public required string TestId { get; init; }
        public required string Description { get; init; }
        public required string Outcome { get; init; }
        public required double DurationMs { get; init; }
        public string? SpecReference { get; init; }
        public string? Evidence { get; init; }
        public string? FailureReason { get; init; }
        public string? Remediation { get; init; }
    }
}
