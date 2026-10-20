using OpenIdProbe.Core;

namespace OpenIdProbe.Reporting;

/// <summary>
/// Formats test results for output.
/// </summary>
public interface IReportFormatter
{
    /// <summary>
    /// Gets the format name.
    /// </summary>
    string Format { get; }

    /// <summary>
    /// Formats a test run result.
    /// </summary>
    /// <param name="result">The test run result.</param>
    /// <returns>The formatted output.</returns>
    string FormatReport(TestRunResult result);
}
