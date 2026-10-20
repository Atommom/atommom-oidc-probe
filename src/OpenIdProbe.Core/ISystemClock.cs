namespace OpenIdProbe.Core;

/// <summary>
/// Abstraction over system time for testability.
/// </summary>
public interface ISystemClock
{
    /// <summary>
    /// Gets the current UTC time.
    /// </summary>
    DateTimeOffset UtcNow { get; }
}

/// <summary>
/// Default implementation using actual system time.
/// </summary>
public sealed class SystemClock : ISystemClock
{
    public static readonly SystemClock Instance = new();

    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;
}
