namespace OpenIdProbe.Core;

/// <summary>
/// Represents the aggregated results of a test run.
/// </summary>
public sealed class TestRunResult
{
    public TestRunResult(string issuer, string suite, IReadOnlyList<TestResult> results)
    {
        Issuer = issuer;
        Suite = suite;
        Results = results;
        ExecutedAt = DateTimeOffset.UtcNow;
    }

    /// <summary>The issuer URL that was tested.</summary>
    public string Issuer { get; }

    /// <summary>The test suite that was executed.</summary>
    public string Suite { get; }

    /// <summary>When the test run was executed.</summary>
    public DateTimeOffset ExecutedAt { get; init; }

    /// <summary>Individual test results.</summary>
    public IReadOnlyList<TestResult> Results { get; }

    /// <summary>Number of passing tests.</summary>
    public int PassCount => Results.Count(r => r.Outcome == TestOutcome.Pass);

    /// <summary>Number of failing tests.</summary>
    public int FailCount => Results.Count(r => r.Outcome == TestOutcome.Fail);

    /// <summary>Number of tests with warnings.</summary>
    public int WarnCount => Results.Count(r => r.Outcome == TestOutcome.Warn);

    /// <summary>Number of skipped tests.</summary>
    public int SkipCount => Results.Count(r => r.Outcome == TestOutcome.Skip);

    /// <summary>Number of inconclusive tests.</summary>
    public int InconclusiveCount => Results.Count(r => r.Outcome == TestOutcome.Inconclusive);

    /// <summary>Total duration of all tests.</summary>
    public TimeSpan TotalDuration => Results.Aggregate(
        TimeSpan.Zero,
        (acc, r) => acc + r.Duration);

    /// <summary>Whether any tests failed.</summary>
    public bool HasFailures => FailCount > 0;
}
