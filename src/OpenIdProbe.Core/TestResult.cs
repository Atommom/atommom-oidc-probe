namespace OpenIdProbe.Core;

/// <summary>
/// Represents the result of an individual test.
/// </summary>
/// <param name="TestId">Unique identifier for the test.</param>
/// <param name="Description">Human-readable description of what was tested.</param>
/// <param name="Outcome">The test outcome.</param>
/// <param name="Duration">How long the test took to execute.</param>
/// <param name="SpecReference">Reference to the relevant specification section.</param>
/// <param name="Evidence">Evidence collected during the test (redacted of secrets).</param>
/// <param name="FailureReason">Explanation of why the test failed.</param>
/// <param name="Remediation">Suggested fix for the failure.</param>
public sealed record TestResult(
    string TestId,
    string Description,
    TestOutcome Outcome,
    TimeSpan Duration,
    string? SpecReference = null,
    string? Evidence = null,
    string? FailureReason = null,
    string? Remediation = null)
{
    /// <summary>
    /// Gets whether this result represents a failure.
    /// </summary>
    public bool IsFailure => Outcome == TestOutcome.Fail;

    /// <summary>
    /// Gets whether this result represents a success (Pass or Warn).
    /// </summary>
    public bool IsSuccess => Outcome is TestOutcome.Pass or TestOutcome.Warn;
}
