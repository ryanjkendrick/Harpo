using Harpo.Security;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Harpo.Tests;

public class LoginThrottleTests
{
    private readonly ManualTime _time = new();

    private LoginThrottle Create(bool enabled = true) => new(
        Options.Create(new LoginThrottleOptions
        {
            Enabled = enabled,
            MaxFailuresPerAccount = 5,
            MaxFailuresPerIp = 20,
            WindowMinutes = 15,
            LockoutMinutes = 5,
        }),
        _time,
        NullLogger<LoginThrottle>.Instance);

    private static void FailTimes(LoginThrottle throttle, string user, string ip, int times)
    {
        for (var i = 0; i < times; i++)
        {
            throttle.RecordFailure(user, ip);
        }
    }

    [Fact]
    public void Account_is_blocked_after_max_failures_and_others_are_not()
    {
        var throttle = Create();
        FailTimes(throttle, "alice", "10.0.0.1", 5);

        var gate = throttle.Check("alice", "10.0.0.1");
        Assert.False(gate.Allowed);
        Assert.InRange(gate.RetryAfter, TimeSpan.FromSeconds(1), TimeSpan.FromMinutes(5));

        // The account is blocked regardless of how the name is written…
        Assert.False(throttle.Check("ALICE", "10.0.0.2").Allowed);
        Assert.False(throttle.Check("alice@corp.example.com", "10.0.0.2").Allowed);
        // …but other accounts from the same address still get through.
        Assert.True(throttle.Check("bob", "10.0.0.1").Allowed);
    }

    [Fact]
    public void Lockout_expires_and_counting_starts_fresh()
    {
        var throttle = Create();
        FailTimes(throttle, "alice", "10.0.0.1", 5);
        Assert.False(throttle.Check("alice", "10.0.0.1").Allowed);

        _time.Advance(TimeSpan.FromMinutes(6));
        Assert.True(throttle.Check("alice", "10.0.0.1").Allowed);

        // A fresh window: four more failures don't immediately re-block.
        FailTimes(throttle, "alice", "10.0.0.1", 4);
        Assert.True(throttle.Check("alice", "10.0.0.1").Allowed);
        throttle.RecordFailure("alice", "10.0.0.1");
        Assert.False(throttle.Check("alice", "10.0.0.1").Allowed);
    }

    [Fact]
    public void Successful_sign_in_resets_the_account_counter()
    {
        var throttle = Create();
        FailTimes(throttle, "alice", "10.0.0.1", 4);
        throttle.RecordSuccess("alice");
        FailTimes(throttle, "alice", "10.0.0.1", 4);
        Assert.True(throttle.Check("alice", "10.0.0.1").Allowed);
    }

    [Fact]
    public void Old_failures_age_out_of_the_window()
    {
        var throttle = Create();
        FailTimes(throttle, "alice", "10.0.0.1", 4);
        _time.Advance(TimeSpan.FromMinutes(16));
        throttle.RecordFailure("alice", "10.0.0.1");
        Assert.True(throttle.Check("alice", "10.0.0.1").Allowed);
    }

    [Fact]
    public void Address_budget_blocks_spraying_across_accounts()
    {
        var throttle = Create();
        for (var i = 0; i < 20; i++)
        {
            throttle.RecordFailure($"user{i}", "10.0.0.9");
        }

        // Any further account from that address is blocked — even a fresh one…
        Assert.False(throttle.Check("victim", "10.0.0.9").Allowed);
        // …while the same account from another address is fine.
        Assert.True(throttle.Check("victim", "10.0.0.10").Allowed);
    }

    [Fact]
    public void Success_does_not_refund_the_address_budget()
    {
        var throttle = Create();
        for (var i = 0; i < 19; i++)
        {
            throttle.RecordFailure($"user{i}", "10.0.0.9");
        }
        throttle.RecordSuccess("user3"); // sprayer found one valid credential
        throttle.RecordFailure("user99", "10.0.0.9");
        Assert.False(throttle.Check("anyone", "10.0.0.9").Allowed);
    }

    [Fact]
    public void Disabled_throttle_never_blocks()
    {
        var throttle = Create(enabled: false);
        FailTimes(throttle, "alice", "10.0.0.1", 50);
        Assert.True(throttle.Check("alice", "10.0.0.1").Allowed);
    }

    [Fact]
    public void Username_and_address_normalization()
    {
        Assert.Equal("jsmith", LoginThrottle.NormalizeUsername("  CORP\\JSmith "));
        Assert.Equal("jsmith", LoginThrottle.NormalizeUsername("jsmith@corp.example.com"));
        Assert.Equal("1.2.3.4", LoginThrottle.NormalizeAddress(System.Net.IPAddress.Parse("::ffff:1.2.3.4")));
        Assert.Null(LoginThrottle.NormalizeAddress(null));
    }
}
