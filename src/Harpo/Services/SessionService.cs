using System.Security.Cryptography;
using Harpo.Data;
using Harpo.Security;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Harpo.Services;

/// <summary>Session lifetime and directory revalidation (bound from the <c>Auth</c> section).</summary>
public class AuthSessionOptions
{
    /// <summary>How long a session lasts (idle time when sliding, total time otherwise). Also the cookie's lifetime.</summary>
    public double SessionHours { get; set; } = 8;

    /// <summary>Whether activity extends the session (and the cookie). False: it ends <see cref="SessionHours"/> after sign-in.</summary>
    public bool SlidingExpiration { get; set; } = true;

    /// <summary>How often each session's account is re-checked against the directory. 0 turns revalidation off.</summary>
    public int RevalidateMinutes { get; set; } = 15;

    /// <summary>
    /// How long past a missed revalidation a session survives while the
    /// directory cannot be reached. After that it ends: the directory has not
    /// vouched for the account for RevalidateMinutes + this long.
    /// </summary>
    public int RevalidateGraceMinutes { get; set; } = 240;
}

/// <summary>
/// Server-side sessions: what makes signing out, a disabled account and a
/// changed admin role take effect on cookies and pages that already exist.
///
/// A sign-in creates a <see cref="UserSession"/> row and puts its id in the
/// cookie. Three places consult the row:
///  - every HTTP request: the cookie handler's ValidatePrincipal event rejects a
///    cookie whose row is gone (one primary-key lookup per request);
///  - every service call that reveals or changes something
///    (<see cref="RequireLiveAsync"/>): an interactive page holds its signed-in
///    user for as long as it stays open, so its connection never passes through
///    the cookie handler again; this is what stops such a page;
///  - every open page, every 30 s (<see cref="Harpo.Security.SessionAuthenticationStateProvider"/>):
///    a page whose session ended navigates to the sign-in page, so secrets
///    already on screen do not stay there.
///
/// The row goes when the user signs out, when it expires, and when the
/// periodic revalidation (<see cref="RevalidateDueAsync"/>, run every
/// <see cref="SweepInterval"/> by <see cref="SessionMaintenanceService"/>) learns
/// that the account was disabled or its site-admin role changed. The bounds,
/// with the defaults:
///  - sign-out: immediate, for every tab and every request;
///  - disabled account / changed admin role: within RevalidateMinutes (15) +
///    one sweep (30 s) + the directory's response time — when the directory can
///    be asked without the user's password (always in Development mode; with
///    Auth:Ldap:ServiceUser in LDAP mode). Without a service account the
///    directory cannot be asked, and the session runs until it expires;
///  - directory unreachable: the session survives RevalidateGraceMinutes (240)
///    past its missed check, then ends.
/// </summary>
public sealed class SessionService
{
    public const string SessionEndedMessage = "Your session has ended — sign in again.";

    /// <summary>How often <see cref="SessionMaintenanceService"/> revalidates and purges.</summary>
    public static readonly TimeSpan SweepInterval = TimeSpan.FromSeconds(30);

    /// <summary>Last-seen is written at most this often per session, so activity costs no write per request.</summary>
    internal static readonly TimeSpan TouchInterval = TimeSpan.FromMinutes(1);

    private readonly IDbContextFactory<HarpoDbContext> _dbFactory;
    private readonly IAuthenticator _authenticator;
    private readonly AuthSessionOptions _options;
    private readonly TimeProvider _time;
    private readonly ILogger<SessionService> _logger;

    public SessionService(
        IDbContextFactory<HarpoDbContext> dbFactory, IAuthenticator authenticator,
        IOptions<AuthSessionOptions> options, TimeProvider time, ILogger<SessionService> logger)
    {
        _dbFactory = dbFactory;
        _authenticator = authenticator;
        _options = options.Value;
        _time = time;
        _logger = logger;
    }

    public TimeSpan Lifetime => TimeSpan.FromHours(Math.Max(_options.SessionHours, 1.0 / 60));
    public bool SlidingExpiration => _options.SlidingExpiration;
    private bool RevalidationEnabled => _options.RevalidateMinutes > 0;
    private TimeSpan RevalidateInterval => TimeSpan.FromMinutes(Math.Max(_options.RevalidateMinutes, 0));
    private TimeSpan Grace => TimeSpan.FromMinutes(Math.Max(_options.RevalidateGraceMinutes, 0));

    /// <summary>Records a sign-in the directory just vouched for; returns the id for the cookie.</summary>
    public async Task<string> CreateAsync(AuthResult result, CancellationToken ct = default)
    {
        var now = _time.GetUtcNow().UtcDateTime;
        var session = new UserSession
        {
            Id = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32)),
            Username = result.Username.ToLowerInvariant(),
            IsSiteAdmin = result.IsSiteAdmin,
            CreatedAtUtc = now,
            LastSeenAtUtc = now,
            LastValidatedAtUtc = now,
        };
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        db.UserSessions.Add(session);
        await db.SaveChangesAsync(ct);
        return session.Id;
    }

    /// <summary>Sign-out: the session ends for every tab and request that shares it.</summary>
    public async Task EndAsync(string? sessionId, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(sessionId))
        {
            return;
        }
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        await db.UserSessions.Where(s => s.Id == sessionId).ExecuteDeleteAsync(ct);
    }

    /// <summary>Ends every session of an account, on this site.</summary>
    public async Task<int> EndAllForUserAsync(string username, CancellationToken ct = default)
    {
        var normalized = username.Trim().ToLowerInvariant();
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        return await db.UserSessions.Where(s => s.Username == normalized).ExecuteDeleteAsync(ct);
    }

    /// <summary>
    /// Whether the session still exists and has not expired. <paramref name="touch"/>
    /// counts this as activity (extends a sliding session); pass false for checks
    /// the user did not cause, such as a page's periodic revalidation, so an idle
    /// open tab does not keep its session alive forever.
    /// </summary>
    public async Task<bool> IsLiveAsync(string? sessionId, bool touch = true, CancellationToken ct = default) =>
        await FindLiveAsync(sessionId, touch, ct) is not null;

    /// <summary>
    /// Called by the services before they reveal or change anything on behalf of
    /// <paramref name="user"/>. Throws <see cref="VaultAccessDeniedException"/>
    /// (which every page already shows as an error) once the session has ended.
    /// </summary>
    public async Task RequireLiveAsync(UserContext user, CancellationToken ct = default)
    {
        if (user.SessionId is null)
        {
            return; // built in-process, never signed in — see UserContext.SessionId
        }
        var session = await FindLiveAsync(user.SessionId, touch: true, ct);
        // The claims were issued together with the row, so these match; checked
        // anyway so a mismatch can only ever deny.
        if (session is null || session.Username != user.Username || session.IsSiteAdmin != user.IsSiteAdmin)
        {
            throw new VaultAccessDeniedException(SessionEndedMessage);
        }
    }

    private async Task<UserSession?> FindLiveAsync(string? sessionId, bool touch, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(sessionId))
        {
            return null;
        }
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var session = await db.UserSessions.AsNoTracking().SingleOrDefaultAsync(s => s.Id == sessionId, ct);
        if (session is null)
        {
            return null;
        }
        var now = _time.GetUtcNow().UtcDateTime;
        if (IsExpired(session, now))
        {
            await db.UserSessions.Where(s => s.Id == sessionId).ExecuteDeleteAsync(ct);
            _logger.LogInformation("Session of {User} expired", session.Username);
            return null;
        }
        if (touch && _options.SlidingExpiration && now - session.LastSeenAtUtc >= TouchInterval)
        {
            // ExecuteUpdate, not SaveChanges: no replication stamping (the table
            // is site-local) and no in-process write gate, which a caller may
            // already be waiting behind.
            await db.UserSessions.Where(s => s.Id == sessionId)
                .ExecuteUpdateAsync(set => set.SetProperty(s => s.LastSeenAtUtc, now), ct);
        }
        return session;
    }

    private bool IsExpired(UserSession session, DateTime now)
    {
        var from = _options.SlidingExpiration ? session.LastSeenAtUtc : session.CreatedAtUtc;
        if (now >= from + Lifetime)
        {
            return true;
        }
        // Not vouched for by the directory for longer than the policy allows:
        // it has been unreachable past the grace period (or the sweep stopped).
        return RevalidationEnabled && now >= session.LastValidatedAtUtc + RevalidateInterval + Grace;
    }

    /// <summary>
    /// Re-checks every session whose last directory check is RevalidateMinutes
    /// old — one directory query per account, not per session. Disabled (or
    /// deleted) accounts lose all their sessions; sessions whose site-admin flag
    /// no longer matches the directory end too, so the user signs in again with
    /// the right role (simpler and safer than rewriting a live principal).
    /// Returns the number of sessions ended.
    /// </summary>
    public async Task<int> RevalidateDueAsync(CancellationToken ct = default)
    {
        if (!RevalidationEnabled)
        {
            return 0;
        }
        var now = _time.GetUtcNow().UtcDateTime;
        var dueBefore = now - RevalidateInterval;
        List<UserSession> due;
        await using (var db = await _dbFactory.CreateDbContextAsync(ct))
        {
            due = await db.UserSessions.AsNoTracking().Where(s => s.LastValidatedAtUtc <= dueBefore).ToListAsync(ct);
        }

        var ended = 0;
        foreach (var account in due.GroupBy(s => s.Username))
        {
            RevalidationResult result;
            try
            {
                result = await _authenticator.RevalidateAsync(account.Key, ct);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogWarning(ex, "Revalidating {User} failed", account.Key);
                result = RevalidationResult.Unavailable;
            }

            await using var db = await _dbFactory.CreateDbContextAsync(ct);
            var ids = account.Select(s => s.Id).ToList();
            switch (result.Status)
            {
                case DirectoryAccountStatus.Disabled:
                    var count = await db.UserSessions.Where(s => s.Username == account.Key).ExecuteDeleteAsync(ct);
                    ended += count;
                    _logger.LogWarning(
                        "{User} is disabled or gone in the directory: ended {Count} session(s)", account.Key, count);
                    break;

                case DirectoryAccountStatus.Active:
                    var roleChanged = account.Where(s => s.IsSiteAdmin != result.IsSiteAdmin).Select(s => s.Id).ToList();
                    if (roleChanged.Count > 0)
                    {
                        ended += await db.UserSessions.Where(s => roleChanged.Contains(s.Id)).ExecuteDeleteAsync(ct);
                        _logger.LogWarning(
                            "{User} is {Change} site admin in the directory: ended {Count} session(s) to apply it",
                            account.Key, result.IsSiteAdmin ? "now a" : "no longer a", roleChanged.Count);
                    }
                    var stillValid = ids.Except(roleChanged).ToList();
                    await db.UserSessions.Where(s => stillValid.Contains(s.Id))
                        .ExecuteUpdateAsync(set => set.SetProperty(s => s.LastValidatedAtUtc, now), ct);
                    break;

                case DirectoryAccountStatus.Unknown:
                    // Nothing to learn without a service account; check again next interval.
                    await db.UserSessions.Where(s => ids.Contains(s.Id))
                        .ExecuteUpdateAsync(set => set.SetProperty(s => s.LastValidatedAtUtc, now), ct);
                    break;

                case DirectoryAccountStatus.Unavailable:
                    // Left due, so every sweep retries. Past the grace period the
                    // session ends (IsExpired says the same to every check meanwhile).
                    var graceEnd = now - RevalidateInterval - Grace;
                    var expired = await db.UserSessions
                        .Where(s => ids.Contains(s.Id) && s.LastValidatedAtUtc <= graceEnd)
                        .ExecuteDeleteAsync(ct);
                    if (expired > 0)
                    {
                        _logger.LogWarning(
                            "Directory unreachable for longer than the grace period: ended {Count} session(s) of {User}",
                            expired, account.Key);
                    }
                    ended += expired;
                    break;
            }
        }
        return ended;
    }

    /// <summary>Deletes expired sessions (their cookies are refused anyway; this keeps the table small).</summary>
    public async Task<int> PurgeExpiredAsync(CancellationToken ct = default)
    {
        var now = _time.GetUtcNow().UtcDateTime;
        var lifetimeCutoff = now - Lifetime;
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var expired = _options.SlidingExpiration
            ? db.UserSessions.Where(s => s.LastSeenAtUtc <= lifetimeCutoff)
            : db.UserSessions.Where(s => s.CreatedAtUtc <= lifetimeCutoff);
        var purged = await expired.ExecuteDeleteAsync(ct);
        if (RevalidationEnabled)
        {
            var validatedCutoff = now - RevalidateInterval - Grace;
            purged += await db.UserSessions.Where(s => s.LastValidatedAtUtc <= validatedCutoff).ExecuteDeleteAsync(ct);
        }
        return purged;
    }
}

/// <summary>Runs session revalidation and the expiry purge every <see cref="SessionService.SweepInterval"/>.</summary>
public sealed class SessionMaintenanceService : BackgroundService
{
    private readonly SessionService _sessions;
    private readonly TimeProvider _time;
    private readonly ILogger<SessionMaintenanceService> _logger;

    public SessionMaintenanceService(SessionService sessions, TimeProvider time, ILogger<SessionMaintenanceService> logger)
    {
        _sessions = sessions;
        _time = time;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            using var timer = new PeriodicTimer(SessionService.SweepInterval, _time);
            while (await timer.WaitForNextTickAsync(stoppingToken))
            {
                try
                {
                    await _sessions.RevalidateDueAsync(stoppingToken);
                    await _sessions.PurgeExpiredAsync(stoppingToken);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _logger.LogError(ex, "Session maintenance sweep failed");
                }
            }
        }
        catch (OperationCanceledException)
        {
        }
    }
}
