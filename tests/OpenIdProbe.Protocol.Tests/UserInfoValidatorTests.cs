using OpenIdProbe.Core;
using OpenIdProbe.Protocol.OAuth;

namespace OpenIdProbe.Protocol.Tests;

public class UserInfoValidatorTests
{
    [Fact]
    public void Validate_ValidResponse_ReturnsPass()
    {
        var claims = new UserInfoClaims
        {
            Subject = "user-123",
            Name = "Test User",
            Email = "test@example.com"
        };

        var results = UserInfoValidator.Validate(claims, expectedSubject: "user-123");

        results.Should().Contain(r =>
            r.TestId == "USERINFO-001" &&
            r.Outcome == TestOutcome.Pass);
    }

    [Fact]
    public void Validate_SubjectMismatch_ReturnsFail()
    {
        var claims = new UserInfoClaims
        {
            Subject = "user-123"
        };

        var results = UserInfoValidator.Validate(claims, expectedSubject: "different-user");

        results.Should().Contain(r =>
            r.TestId == "USERINFO-002" &&
            r.Outcome == TestOutcome.Fail);
    }

    [Fact]
    public void Validate_WithoutExpectedSubject_SkipsSubjectMatch()
    {
        var claims = new UserInfoClaims
        {
            Subject = "user-123"
        };

        var results = UserInfoValidator.Validate(claims, expectedSubject: null);

        results.Should().NotContain(r => r.TestId == "USERINFO-002");
    }

    [Fact]
    public void Validate_InvalidEmailFormat_ReturnsWarn()
    {
        var claims = new UserInfoClaims
        {
            Subject = "user-123",
            Email = "not-an-email"
        };

        var results = UserInfoValidator.Validate(claims, expectedSubject: null);

        results.Should().Contain(r =>
            r.TestId == "USERINFO-010" &&
            r.Outcome == TestOutcome.Warn);
    }

    [Fact]
    public void Validate_ValidEmail_ReturnsPass()
    {
        var claims = new UserInfoClaims
        {
            Subject = "user-123",
            Email = "test@example.com"
        };

        var results = UserInfoValidator.Validate(claims, expectedSubject: null);

        results.Should().Contain(r =>
            r.TestId == "USERINFO-010" &&
            r.Outcome == TestOutcome.Pass);
    }

    [Fact]
    public void Validate_InvalidPictureUrl_ReturnsWarn()
    {
        var claims = new UserInfoClaims
        {
            Subject = "user-123",
            Picture = "not-a-url"
        };

        var results = UserInfoValidator.Validate(claims, expectedSubject: null);

        results.Should().Contain(r =>
            r.TestId == "USERINFO-011" &&
            r.Outcome == TestOutcome.Warn);
    }

    [Fact]
    public void Validate_HttpPictureUrl_ReturnsWarn()
    {
        var claims = new UserInfoClaims
        {
            Subject = "user-123",
            Picture = "http://example.com/photo.jpg"
        };

        var results = UserInfoValidator.Validate(claims, expectedSubject: null);

        results.Should().Contain(r =>
            r.TestId == "USERINFO-012" &&
            r.Outcome == TestOutcome.Warn);
    }

    [Fact]
    public void Validate_HttpsPictureUrl_ReturnsPass()
    {
        var claims = new UserInfoClaims
        {
            Subject = "user-123",
            Picture = "https://example.com/photo.jpg"
        };

        var results = UserInfoValidator.Validate(claims, expectedSubject: null);

        results.Should().Contain(r =>
            r.TestId == "USERINFO-011" &&
            r.Outcome == TestOutcome.Pass);
    }
}
