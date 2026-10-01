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

    [Theory]
    [InlineData(null, "alice", false)]            // first-time setup names nobody
    [InlineData("", "alice", false)]
    [InlineData("alice", "alice", false)]
    [InlineData("ALICE", "alice", false)]
    [InlineData("j%C3%BCrgen", "jürgen", false)]  // the client URI-escapes the name
    [InlineData("bob", "alice", true)]            // the vault is bob's, alice is signed in
    public void A_refresh_naming_another_account_is_detected(string? header, string signedIn, bool expected)
    {
        Assert.Equal(expected, OfflineEndpoints.IsForAnotherAccount(header, signedIn));
    }
}
