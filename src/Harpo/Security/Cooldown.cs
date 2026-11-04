using System.Collections.Concurrent;

namespace Harpo.Security;

/// <summary>
/// Lets each key through once per interval. Keys whose interval has passed are
/// dropped from time to time, so these live as long as the process without growing.
/// </summary>
public sealed class Cooldown<TKey>(TimeProvider time) where TKey : notnull
{
    private static readonly TimeSpan PruneEvery = TimeSpan.FromMinutes(10);

    private readonly ConcurrentDictionary<TKey, DateTimeOffset> _last = new();
    private long _lastPruneTicks;

    internal int Tracked => _last.Count;

    public bool TryAcquire(TKey key, TimeSpan minInterval, out TimeSpan retryAfter)
    {
        var now = time.GetUtcNow();
        PruneIfDue(now, minInterval);
        var granted = false;
        var updated = _last.AddOrUpdate(
            key,
            _ => { granted = true; return now; },
            (_, last) =>
            {
                if (now - last >= minInterval)
                {
                    granted = true;
                    return now;
                }
                return last;
            });
        retryAfter = granted ? TimeSpan.Zero : minInterval - (now - updated);
        return granted;
    }

    private void PruneIfDue(DateTimeOffset now, TimeSpan minInterval)
    {
        var last = Interlocked.Read(ref _lastPruneTicks);
        if (now.UtcTicks - last < PruneEvery.Ticks
            || Interlocked.CompareExchange(ref _lastPruneTicks, now.UtcTicks, last) != last)
        {
            return;
        }
        foreach (var entry in _last)
        {
            if (now - entry.Value >= minInterval)
            {
                // Only if it has not been renewed since it was read.
                _last.TryRemove(entry);
            }
        }
    }
}
