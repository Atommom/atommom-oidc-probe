using System.Diagnostics;
using System.Text.RegularExpressions;
using OpenIdProbe.Core;

namespace OpenIdProbe.Protocol.OAuth;

/// <summary>
/// Validates UserInfo endpoint responses per OpenID Connect Core 1.0.
/// </summary>
public sealed partial class UserInfoValidator
{
    public static IReadOnlyList<TestResult> Validate(UserInfoClaims claims, string? expectedSubject)
    {
        var results = new List<TestResult>();
        var stopwatch = Stopwatch.StartNew();

        // USERINFO-001: Subject claim present
        results.Add(new TestResult(
            "USERINFO-001",
            "UserInfo response contains sub claim",
            string.IsNullOrEmpty(claims.Subject) ? TestOutcome.Fail : TestOutcome.Pass,
            stopwatch.Elapsed,
            SpecReference: "OpenID Connect Core 1.0 Section 5.3.2",
            FailureReason: string.IsNullOrEmpty(claims.Subject) ? "sub claim is required" : null));

        // USERINFO-002: Subject matches ID token (if expected subject provided)
        if (expectedSubject != null)
        {
            var subjectMatches = claims.Subject == expectedSubject;
            results.Add(new TestResult(
                "USERINFO-002",
                "UserInfo sub matches ID token sub",
                subjectMatches ? TestOutcome.Pass : TestOutcome.Fail,
                stopwatch.Elapsed,
                SpecReference: "OpenID Connect Core 1.0 Section 5.3.2",
                FailureReason: subjectMatches ? null : $"Expected '{expectedSubject}', got '{claims.Subject}'",
                Remediation: subjectMatches ? null : "The sub claim in UserInfo must match the sub in the ID token"));
        }

        // USERINFO-010: Email format validation (if present)
        if (!string.IsNullOrEmpty(claims.Email))
        {
            var emailValid = EmailRegex().IsMatch(claims.Email);
            results.Add(new TestResult(
                "USERINFO-010",
                "Email claim has valid format",
                emailValid ? TestOutcome.Pass : TestOutcome.Warn,
                stopwatch.Elapsed,
                FailureReason: emailValid ? null : $"Email '{claims.Email}' does not appear to be valid"));
        }

        // USERINFO-011: Picture URL validation (if present)
        if (!string.IsNullOrEmpty(claims.Picture))
        {
            var isValidUrl = Uri.TryCreate(claims.Picture, UriKind.Absolute, out var pictureUri);
            results.Add(new TestResult(
                "USERINFO-011",
                "Picture claim is a valid URL",
                isValidUrl ? TestOutcome.Pass : TestOutcome.Warn,
                stopwatch.Elapsed,
                FailureReason: isValidUrl ? null : $"Picture '{claims.Picture}' is not a valid URL"));

            // USERINFO-012: Picture uses HTTPS
            if (isValidUrl && pictureUri != null)
            {
                var isHttps = pictureUri.Scheme == "https";
                results.Add(new TestResult(
                    "USERINFO-012",
                    "Picture URL uses HTTPS",
                    isHttps ? TestOutcome.Pass : TestOutcome.Warn,
                    stopwatch.Elapsed,
                    FailureReason: isHttps ? null : "Picture URL should use HTTPS for security"));
            }
        }

        // USERINFO-020: Profile URL validation (if present)
        if (!string.IsNullOrEmpty(claims.Profile))
        {
            var isValidUrl = Uri.TryCreate(claims.Profile, UriKind.Absolute, out _);
            results.Add(new TestResult(
                "USERINFO-020",
                "Profile claim is a valid URL",
                isValidUrl ? TestOutcome.Pass : TestOutcome.Warn,
                stopwatch.Elapsed,
                FailureReason: isValidUrl ? null : $"Profile '{claims.Profile}' is not a valid URL"));
        }

        // USERINFO-021: Website URL validation (if present)
        if (!string.IsNullOrEmpty(claims.Website))
        {
            var isValidUrl = Uri.TryCreate(claims.Website, UriKind.Absolute, out _);
            results.Add(new TestResult(
                "USERINFO-021",
                "Website claim is a valid URL",
                isValidUrl ? TestOutcome.Pass : TestOutcome.Warn,
                stopwatch.Elapsed,
                FailureReason: isValidUrl ? null : $"Website '{claims.Website}' is not a valid URL"));
        }

        return results;
    }

    [GeneratedRegex(@"^[^@\s]+@[^@\s]+\.[^@\s]+$", RegexOptions.Compiled)]
    private static partial Regex EmailRegex();
}
