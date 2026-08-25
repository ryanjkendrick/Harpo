using Harpo.Data;
using Harpo.Security;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Harpo.Services;

public class AuditOptions
{
    /// <summary>Whether THIS site records audit events. Replicated events from other sites are always stored and shown.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Hard-delete events older than this. 0 keeps them forever.</summary>
    public int RetentionDays { get; set; } = 365;
}

/// <summary>
/// Records and serves the audit trail. Recording is deliberately fail-open: an
/// audit-write failure is logged loudly but never blocks the user's operation.
/// </summary>
public class AuditService
{
    private readonly IDbContextFactory<HarpoDbContext> _dbFactory;
    private readonly AuditOptions _options;
    private readonly TimeProvider _time;
    private readonly ILogger<AuditService> _logger;
    private readonly IHttpContextAccessor? _httpContextAccessor;

    public AuditService(
        IDbContextFactory<HarpoDbContext> dbFactory,
        IOptions<AuditOptions> options,
        TimeProvider time,
        ILogger<AuditService> logger,
        IHttpContextAccessor? httpContextAccessor = null)
    {
        _dbFactory = dbFactory;
        _options = options.Value;
        _time = time;
        _logger = logger;
        _httpContextAccessor = httpContextAccessor;
    }

    public bool Enabled => _options.Enabled;
    public int RetentionDays => _options.RetentionDays;

    public async Task RecordAsync(
        UserContext user, string action, string target,
        string detail = "", Guid? groupId = null, Guid? entryId = null)
    {
        if (!_options.Enabled)
        {
            return;
        }
        try
        {
            await using var db = await _dbFactory.CreateDbContextAsync();
            db.AuditEvents.Add(new AuditEvent
            {
                Id = Guid.NewGuid(),
                OccurredAtUtc = _time.GetUtcNow().UtcDateTime,
                Username = user.Username,
                Action = action,
                GroupId = groupId,
                EntryId = entryId,
                Target = target,
                Detail = detail,
                ClientAddress = LoginThrottle.NormalizeAddress(
                    _httpContextAccessor?.HttpContext?.Connection.RemoteIpAddress) ?? "",
            });
            await db.SaveChangesAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to record audit event {Action} for {User}", action, user.Username);
        }
    }

    /// <summary>Newest-first page of the trail; site admins only.</summary>
    public async Task<List<AuditEvent>> GetEventsAsync(
        UserContext user, DateTime? beforeUtc = null, int take = 100, CancellationToken ct = default)
    {
        RequireSiteAdmin(user);
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var query = db.AuditEvents.AsNoTracking();
        if (beforeUtc is not null)
        {
            query = query.Where(e => e.OccurredAtUtc < beforeUtc);
        }
        return await query
            .OrderByDescending(e => e.OccurredAtUtc)
            .ThenByDescending(e => e.Id)
            .Take(Math.Clamp(take, 1, 500))
            .ToListAsync(ct);
    }

    public async Task<int> CountAsync(UserContext user, CancellationToken ct = default)
    {
        RequireSiteAdmin(user);
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        return await db.AuditEvents.CountAsync(ct);
    }

    /// <summary>Applies the retention policy. Returns the number of purged events.</summary>
    public async Task<int> PurgeExpiredAsync(CancellationToken ct = default)
    {
        if (_options.RetentionDays <= 0)
        {
            return 0;
        }
        var cutoff = _time.GetUtcNow().UtcDateTime.AddDays(-_options.RetentionDays);
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var purged = await db.AuditEvents.Where(e => e.OccurredAtUtc < cutoff).ExecuteDeleteAsync(ct);
        if (purged > 0)
        {
            _logger.LogInformation("Audit retention purged {Count} events older than {Days} days", purged, _options.RetentionDays);
        }
        return purged;
    }

    private static void RequireSiteAdmin(UserContext user)
    {
        if (!user.IsSiteAdmin)
        {
            throw new VaultAccessDeniedException("Only site admins can read the audit log.");
        }
    }
}

/// <summary>Applies audit retention shortly after startup and then once a day.</summary>
public class AuditRetentionService : BackgroundService
{
    private readonly AuditService _audit;
    private readonly ILogger<AuditRetentionService> _logger;

    public AuditRetentionService(AuditService audit, ILogger<AuditRetentionService> logger)
    {
        _audit = audit;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken);
            using var timer = new PeriodicTimer(TimeSpan.FromHours(24));
            do
            {
                try
                {
                    await _audit.PurgeExpiredAsync(stoppingToken);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _logger.LogError(ex, "Audit retention sweep failed");
                }
            } while (await timer.WaitForNextTickAsync(stoppingToken));
        }
        catch (OperationCanceledException)
        {
        }
    }
}
