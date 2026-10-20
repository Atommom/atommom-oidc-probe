namespace OpenIdProbe.Core;

/// <summary>
/// Represents the outcome of an individual test.
/// </summary>
public enum TestOutcome
{
    /// <summary>Test passed successfully.</summary>
    Pass,

    /// <summary>Test failed.</summary>
    Fail,

    /// <summary>Test passed with warnings.</summary>
    Warn,

    /// <summary>Test was skipped.</summary>
    Skip,

    /// <summary>Test result could not be determined.</summary>
    Inconclusive
}
