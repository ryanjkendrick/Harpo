using Harpo.Data;
using Harpo.Security;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Harpo.Services;

public class HealthOptions
{
    /// <summary>
    /// Compute password fingerprints/strength on this site and offer the health
    /// report page. Disabling stops new computation and hides the report;
    /// values already stored (or replicated from other sites) remain until the
    /// passwords change.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>A password unchanged for longer than this counts as stale.</summary>
    public int StalePasswordDays { get; set; } = 365;
}

public sealed record HealthEntry(
    Guid EntryId,
    string Name,
    string Icon,
    Guid GroupId,
    string GroupName,
    int? Strength,
    DateTime PasswordChangedUtc,
    string PasswordChangedBy);

/// <summary>Entries sharing one password. HiddenCount = further sharers outside the caller's scope (names withheld).</summary>
public sealed record ReuseCluster(List<HealthEntry> Entries, int HiddenCount);

public sealed record VaultHealthReport(
    DateTime GeneratedAtUtc,
    int StaleDays,
    int Analyzed,
    int HealthyCount,
    List<HealthEntry> Weak,
    List<ReuseCluster> Reused,
    List<HealthEntry> Stale);

/// <summary>
/// The vault health report: weak, reused, and stale passwords. Reuse detection
/// compares stored keyed fingerprints — nothing is decrypted at report time
/// except pre-upgrade rows that lack a fingerprint, which are healed once
/// (without touching their replication stamps, so healing stays local).
///
/// Scope: site admins see the whole vault; group admins see the groups they
/// administer. Reuse that crosses out of the caller's scope is shown only as a
/// count — never as names.
/// </summary>
public class HealthService
{
    private readonly IDbContextFactory<HarpoDbContext> _dbFactory;
    private readonly CryptoService _crypto;
    private readonly HealthOptions _options;
    private readonly TimeProvider _time;
    private readonly AuditService _audit;
    private readonly ILogger<HealthService> _logger;

    public HealthService(
        IDbContextFactory<HarpoDbContext> dbFactory,
        CryptoService crypto,
        IOptions<HealthOptions> options,
        TimeProvider time,
        AuditService audit,
        ILogger<HealthService> logger)
    {
        _dbFactory = dbFactory;
        _crypto = crypto;
        _options = options.Value;
        _time = time;
        _audit = audit;
        _logger = logger;
    }

    public bool Enabled => _options.Enabled;

    /// <summary>Null when the caller administers nothing (and is no site admin) — the page explains itself.</summary>
    public async Task<VaultHealthReport?> GetReportAsync(UserContext user, CancellationToken ct = default)
    {
        if (!_options.Enabled)
        {
            throw new InvalidOperationException("The vault health report is disabled on this site.");
        }

        await using var db = await _dbFactory.CreateDbContextAsync(ct);

        // The caller's scope: everything for site admins, administered groups otherwise.
        List<Guid>? scopeGroupIds = null;
        if (!user.IsSiteAdmin)
        {
            scopeGroupIds = await db.GroupMembers
                .Where(m => !m.IsDeleted && m.Username == user.Username && m.Role == GroupRole.Admin)
                .Select(m => m.GroupId)
                .ToListAsync(ct);
            if (scopeGroupIds.Count == 0)
            {
                return null;
            }
        }

        var groups = await db.Groups
            .Where(g => !g.IsDeleted)
            .ToDictionaryAsync(g => g.Id, g => g.Name, ct);
        var entries = await db.PasswordEntries
            .Where(e => !e.IsDeleted)
            .ToListAsync(ct);
        entries = entries.Where(e => groups.ContainsKey(e.GroupId)).ToList();

        var entryIds = entries.Select(e => e.Id).ToList();
        var revisions = await db.PasswordRevisions
            .Where(r => entryIds.Contains(r.EntryId))
            .ToListAsync(ct);
        var latestByEntry = revisions
            .GroupBy(r => r.EntryId)
            .ToDictionary(
                g => g.Key,
                g => g.OrderByDescending(r => r.CreatedAtUtc)
                      .ThenByDescending(r => r.OriginSiteId, StringComparer.Ordinal)
                      .ThenByDescending(r => r.Id)
                      .First());

        await HealMissingAnalysisAsync(latestByEntry.Values, ct);

        var inScope = new List<HealthEntry>();
        var fingerprintTotals = new Dictionary<string, int>(StringComparer.Ordinal);
        var fingerprintByEntry = new Dictionary<Guid, string>();

        foreach (var entry in entries)
        {
            if (!latestByEntry.TryGetValue(entry.Id, out var latest))
            {
                continue; // still replicating; no password yet
            }
            if (latest.Fingerprint is { } fingerprint)
            {
                fingerprintTotals[fingerprint] = fingerprintTotals.GetValueOrDefault(fingerprint) + 1;
                fingerprintByEntry[entry.Id] = fingerprint;
            }
            if (scopeGroupIds is null || scopeGroupIds.Contains(entry.GroupId))
            {
                inScope.Add(new HealthEntry(
                    entry.Id, entry.Name, entry.Icon, entry.GroupId, groups[entry.GroupId],
                    latest.Strength, latest.CreatedAtUtc, latest.CreatedBy));
            }
        }

        var now = _time.GetUtcNow().UtcDateTime;
        var staleCutoff = now.AddDays(-Math.Max(1, _options.StalePasswordDays));

        var weak = inScope.Where(e => e.Strength <= 1).OrderBy(e => e.Strength).ThenBy(e => e.Name).ToList();
        var stale = inScope.Where(e => e.PasswordChangedUtc < staleCutoff).OrderBy(e => e.PasswordChangedUtc).ToList();

        var reused = inScope
            .Where(e => fingerprintByEntry.ContainsKey(e.EntryId))
            .GroupBy(e => fingerprintByEntry[e.EntryId], StringComparer.Ordinal)
            .Where(g => fingerprintTotals[g.Key] >= 2)
            .Select(g => new ReuseCluster(
                g.OrderBy(e => e.GroupName).ThenBy(e => e.Name).ToList(),
                fingerprintTotals[g.Key] - g.Count()))
            .OrderByDescending(c => c.Entries.Count + c.HiddenCount)
            .ToList();

        var unhealthy = new HashSet<Guid>();
        unhealthy.UnionWith(weak.Select(e => e.EntryId));
        unhealthy.UnionWith(stale.Select(e => e.EntryId));
        unhealthy.UnionWith(reused.SelectMany(c => c.Entries).Select(e => e.EntryId));

        await _audit.RecordAsync(user, AuditActions.HealthReport, "vault health report",
            detail: $"{inScope.Count} entries analyzed, {unhealthy.Count} with findings");

        return new VaultHealthReport(
            now,
            _options.StalePasswordDays,
            inScope.Count,
            inScope.Count - unhealthy.Count,
            weak,
            reused,
            stale);
    }

    /// <summary>
    /// Computes fingerprint/strength for current revisions that predate this
    /// feature (or arrived from a site without it). Replication stamps are left
    /// untouched: revisions merge by insert-only union, so this stays local and
    /// every site heals its own copy.
    /// </summary>
    private async Task HealMissingAnalysisAsync(IEnumerable<PasswordRevision> latestRevisions, CancellationToken ct)
    {
        var missing = latestRevisions.Where(r => r.Fingerprint is null || r.Strength is null).ToList();
        if (missing.Count == 0)
        {
            return;
        }

        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        db.SuppressReplicationStamping = true;
        var healed = 0;
        foreach (var stale in missing)
        {
            var revision = await db.PasswordRevisions.SingleOrDefaultAsync(r => r.Id == stale.Id, ct);
            if (revision is null)
            {
                continue;
            }
            try
            {
                var plaintext = _crypto.Decrypt(revision.EncryptedPassword);
                revision.Fingerprint = _crypto.Fingerprint(plaintext);
                revision.Strength = PasswordStrength.Score(plaintext);
                stale.Fingerprint = revision.Fingerprint;
                stale.Strength = revision.Strength;
                healed++;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Could not analyze revision {Revision}", revision.Id);
            }
        }
        if (healed > 0)
        {
            await db.SaveChangesAsync(ct);
            _logger.LogInformation("Health analysis backfilled for {Count} password(s)", healed);
        }
    }
}
