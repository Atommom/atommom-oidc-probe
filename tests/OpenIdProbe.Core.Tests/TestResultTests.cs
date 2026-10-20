namespace OpenIdProbe.Core.Tests;

public class TestResultTests
{
    [Fact]
    public void Create_WithRequiredValues_SetsProperties()
    {
        var result = new TestResult(
            TestId: "DISC-001",
            Description: "Issuer URL is valid HTTPS URL",
            Outcome: TestOutcome.Pass,
            Duration: TimeSpan.FromMilliseconds(150));

        result.TestId.Should().Be("DISC-001");
        result.Description.Should().Be("Issuer URL is valid HTTPS URL");
        result.Outcome.Should().Be(TestOutcome.Pass);
        result.Duration.Should().Be(TimeSpan.FromMilliseconds(150));
    }

    [Fact]
    public void Create_WithAllValues_SetsAllProperties()
    {
        var result = new TestResult(
            TestId: "DISC-002",
            Description: "Authorization endpoint uses HTTPS",
            Outcome: TestOutcome.Fail,
            Duration: TimeSpan.FromMilliseconds(50),
            SpecReference: "OpenID Connect Discovery 1.0, Section 3",
            Evidence: "authorization_endpoint: http://example.com/auth",
            FailureReason: "Authorization endpoint must use HTTPS",
            Remediation: "Configure the authorization endpoint to use HTTPS");

        result.SpecReference.Should().Be("OpenID Connect Discovery 1.0, Section 3");
        result.Evidence.Should().Be("authorization_endpoint: http://example.com/auth");
        result.FailureReason.Should().Be("Authorization endpoint must use HTTPS");
        result.Remediation.Should().Be("Configure the authorization endpoint to use HTTPS");
    }

    [Fact]
    public void TestOutcome_HasExpectedValues()
    {
        Enum.GetValues<TestOutcome>().Should().BeEquivalentTo([
            TestOutcome.Pass,
            TestOutcome.Fail,
            TestOutcome.Warn,
            TestOutcome.Skip,
            TestOutcome.Inconclusive
        ]);
    }

    [Theory]
    [InlineData(TestOutcome.Pass, false)]
    [InlineData(TestOutcome.Fail, true)]
    [InlineData(TestOutcome.Warn, false)]
    [InlineData(TestOutcome.Skip, false)]
    [InlineData(TestOutcome.Inconclusive, false)]
    public void IsFailure_ReturnsExpectedValue(TestOutcome outcome, bool expectedIsFailure)
    {
        var result = new TestResult("TEST-001", "Test", outcome, TimeSpan.Zero);

        result.IsFailure.Should().Be(expectedIsFailure);
    }

    [Theory]
    [InlineData(TestOutcome.Pass, true)]
    [InlineData(TestOutcome.Fail, false)]
    [InlineData(TestOutcome.Warn, true)]
    [InlineData(TestOutcome.Skip, false)]
    [InlineData(TestOutcome.Inconclusive, false)]
    public void IsSuccess_ReturnsExpectedValue(TestOutcome outcome, bool expectedIsSuccess)
    {
        var result = new TestResult("TEST-001", "Test", outcome, TimeSpan.Zero);

        result.IsSuccess.Should().Be(expectedIsSuccess);
    }
}
