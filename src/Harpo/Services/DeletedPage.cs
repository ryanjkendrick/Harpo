namespace Harpo.Services;

/// <summary>Where the next page of a recovery list starts: the last row already shown.</summary>
public sealed record DeletedCursor(DateTime UpdatedAtUtc, Guid Id);

/// <summary>
/// One page of tombstones (newest first) plus the true number of tombstones, so the UI can say
/// "Recently deleted (51)" while showing 50 and offering "Show older".
/// </summary>
public sealed record DeletedPage<T>(List<T> Items, int Total);
