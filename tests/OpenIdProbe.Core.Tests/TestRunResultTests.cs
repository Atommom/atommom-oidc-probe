namespace OpenIdProbe.Core.Tests;

public class TestRunResultTests
{
    [Fact]
    public void Create_WithResults_CalculatesSummary()
    {
        var results = new[]
        {
            new TestResult("T1", "Test 1", TestOutcome.Pass, TimeSpan.FromMilliseconds(10)),
            new TestResult("T2", "Test 2", TestOutcome.Pass, TimeSpan.FromMilliseconds(20)),
            new TestResult("T3", "Test 3", TestOutcome.Fail, TimeSpan.FromMilliseconds(15)),
            new TestResult("T4", "Test 4", TestOutcome.Warn, TimeSpan.FromMilliseconds(5)),
            new TestResult("T5", "Test 5", TestOutcome.Skip, TimeSpan.FromMilliseconds(1)),
        };

        var run = new TestRunResult("https://example.com", "discovery", results);

        run.Issuer.Should().Be("https://example.com");
        run.Suite.Should().Be("discovery");
        run.Results.Should().HaveCount(5);
        run.PassCount.Should().Be(2);
        run.FailCount.Should().Be(1);
        run.WarnCount.Should().Be(1);
        run.SkipCount.Should().Be(1);
        run.InconclusiveCount.Should().Be(0);
        run.TotalDuration.Should().Be(TimeSpan.FromMilliseconds(51));
    }

    [Fact]
    public void HasFailures_WhenNoFailures_ReturnsFalse()
    {
        var results = new[]
        {
            new TestResult("T1", "Test 1", TestOutcome.Pass, TimeSpan.Zero),
            new TestResult("T2", "Test 2", TestOutcome.Warn, TimeSpan.Zero),
        };

        var run = new TestRunResult("https://example.com", "discovery", results);

        run.HasFailures.Should().BeFalse();
    }

    [Fact]
    public void HasFailures_WhenHasFailures_ReturnsTrue()
    {
        var results = new[]
        {
            new TestResult("T1", "Test 1", TestOutcome.Pass, TimeSpan.Zero),
            new TestResult("T2", "Test 2", TestOutcome.Fail, TimeSpan.Zero),
        };

        var run = new TestRunResult("https://example.com", "discovery", results);

        run.HasFailures.Should().BeTrue();
    }

    [Fact]
    public void Empty_Results_HasZeroCounts()
    {
        var run = new TestRunResult("https://example.com", "discovery", []);

        run.PassCount.Should().Be(0);
        run.FailCount.Should().Be(0);
        run.TotalDuration.Should().Be(TimeSpan.Zero);
        run.HasFailures.Should().BeFalse();
    }
}
