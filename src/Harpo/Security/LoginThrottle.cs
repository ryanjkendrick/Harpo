using System.Collections.Concurrent;
using System.Net;
using Microsoft.Extensions.Options;

namespace Harpo.Security;

public class LoginThrottleOptions
{
    public bool Enabled { get; set; } = true;
    /// <summary>Failed attempts against one account before it is temporarily blocked (mirrors ASP.NET Identity's default of 5).</summary>
    public int MaxFailuresPerAccount { get; set; } = 5;
    /// <summary>Failed attempts from one address (across any accounts) before that address is temporarily blocked.</summary>
    public int MaxFailuresPerIp { get; set; } = 20;
    /// <summary>How long failures keep counting toward the limits.</summary>
    public int WindowMinutes { get; set; } = 15;
    /// <summary>How long a block lasts once a limit is hit.</summary>
    public int LockoutMinutes { get; set; } = 5;
}

public sealed record LoginGate(bool Allowed, TimeSpan RetryAfter);

/// <summary>
/// Brute-force protection for the sign-in form. Counts only *failed* attempts,
/// per normalized account name and per client address; hitting a limit blocks
/// further attempts for a cooldown period — during which nothing reaches the
/// authenticator at all, so a spray also stops generating LDAP binds against
/// your domain controllers (and stops feeding AD's own account-lockout counter).
///
/// State is in-memory and per-site: each Harpo instance defends itself.
/// Note the inherent trade-off of any lockout scheme: someone who knows a
/// username can nuisance-lock that account's *Harpo sign-in* for LockoutMinutes.
/// </summary>
public class LoginThrottle
{
    private sealed class Bucket
    {
        public int Failures;
        public DateTimeOffset WindowStart;
        public DateTimeOffset? LockedUntil;
    }

    private readonly ConcurrentDictionary<string, Bucket> _byAccount = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, Bucket> _byAddress = new(StringComparer.Ordinal);
    private readonly LoginThrottleOptions _options;
    private readonly TimeProvider _time;
    private readonly ILogger<LoginThrottle> _logger;
    private long _lastPruneTicks;

    public LoginThrottle(IOptions<LoginThrottleOptions> options, TimeProvider time, ILogger<LoginThrottle> logger)
    {
        _options = options.Value;
        _time = time;
        _logger = logger;
    }

    private TimeSpan Window => TimeSpan.FromMinutes(Math.Max(1, _options.WindowMinutes));
    private TimeSpan Lockout => TimeSpan.FromMinutes(Math.Max(1, _options.LockoutMinutes));

    /// <summary>Must be consulted before attempting authentication.</summary>
    public LoginGate Check(string username, string? address)
    {
        if (!_options.Enabled)
        {
            return new LoginGate(true, TimeSpan.Zero);
        }
        var now = _time.GetUtcNow();
        PruneIfDue(now);

        var retryAfter = TimeSpan.Zero;
        if (_byAccount.TryGetValue(NormalizeUsername(username), out var account))
        {
            retryAfter = Max(retryAfter, Remaining(account, now));
        }
        if (address is not null && _byAddress.TryGetValue(address, out var addr))
        {
            retryAfter = Max(retryAfter, Remaining(addr, now));
        }
        return retryAfter > TimeSpan.Zero ? new LoginGate(false, retryAfter) : new LoginGate(true, TimeSpan.Zero);
    }

    public void RecordFailure(string username, string? address)
    {
        if (!_options.Enabled)
        {
            return;
        }
        Fail(_byAccount, NormalizeUsername(username), _options.MaxFailuresPerAccount, "account");
        if (address is not null)
        {
            Fail(_byAddress, address, _options.MaxFailuresPerIp, "address");
        }
    }

    /// <summary>A successful sign-in clears the account's failure count — but not the address budget.</summary>
    public void RecordSuccess(string username) =>
        _byAccount.TryRemove(NormalizeUsername(username), out _);

    private void Fail(ConcurrentDictionary<string, Bucket> buckets, string key, int max, string kind)
    {
        var bucket = buckets.GetOrAdd(key, _ => new Bucket());
        lock (bucket)
        {
            var now = _time.GetUtcNow();
            if (bucket.LockedUntil is { } lockedUntil && lockedUntil > now)
            {
                return; // already blocked; gated attempts never even reach here
            }
            if (bucket.WindowStart == default || now - bucket.WindowStart > Window)
            {
                bucket.WindowStart = now;
                bucket.Failures = 0;
            }
            bucket.Failures++;
            if (bucket.Failures >= Math.Max(1, max))
            {
                bucket.LockedUntil = now + Lockout;
                bucket.Failures = 0;
                bucket.WindowStart = now;
                _logger.LogWarning(
                    "Blocking sign-in attempts for {Kind} {Key} for {Minutes} minutes after too many failures",
                    kind, key, Lockout.TotalMinutes);
            }
        }
    }

    private static TimeSpan Remaining(Bucket bucket, DateTimeOffset now)
    {
        lock (bucket)
        {
            return bucket.LockedUntil is { } until && until > now ? until - now : TimeSpan.Zero;
        }
    }

    private static TimeSpan Max(TimeSpan a, TimeSpan b) => a >= b ? a : b;

    private void PruneIfDue(DateTimeOffset now)
    {
        var last = Interlocked.Read(ref _lastPruneTicks);
        if (now.UtcTicks - last < TimeSpan.FromMinutes(10).Ticks
            || Interlocked.CompareExchange(ref _lastPruneTicks, now.UtcTicks, last) != last)
        {
            return;
        }
        foreach (var buckets in new[] { _byAccount, _byAddress })
        {
            foreach (var (key, bucket) in buckets)
            {
                lock (bucket)
                {
                    var expiredLock = bucket.LockedUntil is null || bucket.LockedUntil <= now;
                    if (expiredLock && now - bucket.WindowStart > Window)
                    {
                        buckets.TryRemove(key, out _);
                    }
                }
            }
        }
    }

    /// <summary>Same normalization the authenticator applies: bare, lower-case account name.</summary>
    public static string NormalizeUsername(string username)
    {
        var bare = username.Trim();
        var slash = bare.LastIndexOf('\\');
        if (slash >= 0)
        {
            bare = bare[(slash + 1)..];
        }
        var at = bare.IndexOf('@');
        if (at >= 0)
        {
            bare = bare[..at];
        }
        return bare.ToLowerInvariant();
    }

    /// <summary>Stable string form of the client address (IPv4-mapped IPv6 folded to IPv4).</summary>
    public static string? NormalizeAddress(IPAddress? address)
    {
        if (address is null)
        {
            return null;
        }
        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }
        return address.ToString();
    }
}
