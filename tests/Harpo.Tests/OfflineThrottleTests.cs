using Harpo.Offline;

namespace Harpo.Tests;

public class OfflineThrottleTests
{
    [Fact]
    public void Snapshot_throttle_enforces_per_user_cooldown()
    {
        var time = new ManualTime();
        var throttle = new OfflineSnapshotThrottle(time);
        var interval = TimeSpan.FromSeconds(30);

        Assert.True(throttle.TryAcquire("alice", interval, out _));
        Assert.False(throttle.TryAcquire("alice", interval, out var retryAfter));
        Assert.True(retryAfter > TimeSpan.Zero && retryAfter <= interval);

        // A different user is unaffected.
        Assert.True(throttle.TryAcquire("bob", interval, out _));

        // After the cooldown, alice may sync again.
        time.Advance(TimeSpan.FromSeconds(31));
        Assert.True(throttle.TryAcquire("alice", interval, out _));
    }
}
