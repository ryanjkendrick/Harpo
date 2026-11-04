using Harpo.Offline;
using Harpo.Security;

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

    [Fact]
    public void A_cooldown_forgets_keys_whose_interval_has_passed()
    {
        var time = new ManualTime();
        var cooldown = new Cooldown<string>(time);
        var interval = TimeSpan.FromSeconds(30);

        for (var i = 0; i < 1000; i++)
        {
            Assert.True(cooldown.TryAcquire($"user{i}", interval, out _));
        }
        Assert.Equal(1000, cooldown.Tracked);

        time.Advance(TimeSpan.FromMinutes(11));
        Assert.True(cooldown.TryAcquire("someone else", interval, out _));
        Assert.Equal(1, cooldown.Tracked);

        // Forgotten means free to go, as it was anyway.
        Assert.True(cooldown.TryAcquire("user1", interval, out _));
    }

    [Fact]
    public void A_cooldown_keeps_a_key_still_inside_its_interval()
    {
        var time = new ManualTime();
        var cooldown = new Cooldown<string>(time);
        var interval = TimeSpan.FromHours(1);

        Assert.True(cooldown.TryAcquire("alice", interval, out _));
        time.Advance(TimeSpan.FromMinutes(11)); // a prune is due, and this one has not expired
        Assert.True(cooldown.TryAcquire("bob", interval, out _));

        Assert.Equal(2, cooldown.Tracked);
        Assert.False(cooldown.TryAcquire("alice", interval, out var retryAfter));
        Assert.Equal(TimeSpan.FromMinutes(49), retryAfter);
    }

    [Fact]
    public void A_cooldown_does_not_prune_on_every_call()
    {
        var time = new ManualTime();
        var cooldown = new Cooldown<string>(time);
        var interval = TimeSpan.FromSeconds(30);

        Assert.True(cooldown.TryAcquire("alice", interval, out _));
        time.Advance(TimeSpan.FromMinutes(5));
        Assert.True(cooldown.TryAcquire("bob", interval, out _));

        Assert.Equal(2, cooldown.Tracked);
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
