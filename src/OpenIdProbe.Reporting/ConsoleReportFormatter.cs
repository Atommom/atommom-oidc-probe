using System.Text;
using OpenIdProbe.Core;

namespace OpenIdProbe.Reporting;

/// <summary>
/// Formats test results for console output.
/// </summary>
public sealed class ConsoleReportFormatter : IReportFormatter
{
    public string Format => "console";

    private readonly bool _verbose;

    public ConsoleReportFormatter(bool verbose = false)
    {
        _verbose = verbose;
    }

    public string FormatReport(TestRunResult result)
    {
        var sb = new StringBuilder();

        // Header
        sb.AppendLine();
        sb.AppendLine("═══════════════════════════════════════════════════════════════════");
        sb.AppendLine($"  OpenID Probe Test Report");
        sb.AppendLine("═══════════════════════════════════════════════════════════════════");
        sb.AppendLine();
        sb.AppendLine($"  Issuer:    {result.Issuer}");
        sb.AppendLine($"  Suite:     {result.Suite}");
        sb.AppendLine($"  Executed:  {result.ExecutedAt:yyyy-MM-dd HH:mm:ss} UTC");
        sb.AppendLine($"  Duration:  {result.TotalDuration.TotalMilliseconds:F0}ms");
        sb.AppendLine();

        // Results
        sb.AppendLine("───────────────────────────────────────────────────────────────────");
        sb.AppendLine("  Test Results");
        sb.AppendLine("───────────────────────────────────────────────────────────────────");
        sb.AppendLine();

        foreach (var test in result.Results)
        {
            var symbol = GetOutcomeSymbol(test.Outcome);
            var color = GetOutcomeColor(test.Outcome);

            sb.AppendLine($"  {symbol} [{test.TestId}] {test.Description}");

            if (_verbose || test.Outcome == TestOutcome.Fail)
            {
                if (!string.IsNullOrEmpty(test.Evidence))
                {
                    sb.AppendLine($"      Evidence: {test.Evidence}");
                }

                if (!string.IsNullOrEmpty(test.FailureReason))
                {
                    sb.AppendLine($"      Reason: {test.FailureReason}");
                }

                if (!string.IsNullOrEmpty(test.Remediation))
                {
                    sb.AppendLine($"      Fix: {test.Remediation}");
                }

                if (!string.IsNullOrEmpty(test.SpecReference))
                {
                    sb.AppendLine($"      Spec: {test.SpecReference}");
                }
            }
        }

        // Summary
        sb.AppendLine();
        sb.AppendLine("───────────────────────────────────────────────────────────────────");
        sb.AppendLine("  Summary");
        sb.AppendLine("───────────────────────────────────────────────────────────────────");
        sb.AppendLine();
        sb.AppendLine($"  ✓ Passed:       {result.PassCount}");
        sb.AppendLine($"  ✗ Failed:       {result.FailCount}");
        sb.AppendLine($"  ⚠ Warnings:     {result.WarnCount}");
        sb.AppendLine($"  ○ Skipped:      {result.SkipCount}");
        sb.AppendLine($"  ? Inconclusive: {result.InconclusiveCount}");
        sb.AppendLine();

        if (result.HasFailures)
        {
            sb.AppendLine("  ✗ TESTS FAILED");
        }
        else if (result.WarnCount > 0)
        {
            sb.AppendLine("  ⚠ TESTS PASSED WITH WARNINGS");
        }
        else
        {
            sb.AppendLine("  ✓ ALL TESTS PASSED");
        }

        sb.AppendLine();
        sb.AppendLine("═══════════════════════════════════════════════════════════════════");
        sb.AppendLine();

        return sb.ToString();
    }

    private static string GetOutcomeSymbol(TestOutcome outcome) => outcome switch
    {
        TestOutcome.Pass => "✓",
        TestOutcome.Fail => "✗",
        TestOutcome.Warn => "⚠",
        TestOutcome.Skip => "○",
        TestOutcome.Inconclusive => "?",
        _ => " "
    };

    private static string GetOutcomeColor(TestOutcome outcome) => outcome switch
    {
        TestOutcome.Pass => "green",
        TestOutcome.Fail => "red",
        TestOutcome.Warn => "yellow",
        _ => "default"
    };
}
