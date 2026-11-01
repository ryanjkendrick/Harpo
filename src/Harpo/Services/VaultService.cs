using Harpo.Data;
using Harpo.Import;
using Harpo.Security;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Harpo.Services;

/// <summary>
/// A password entry as a member sees it: the row, its notes decrypted, and the
/// who/when of its newest revision. <paramref name="NotesUnreadable"/> is set
/// when the entry has notes but this site holds no key that opens them (the
/// same situation in which its password could not be revealed); Notes is then
/// empty.
/// </summary>
/// <summary>
/// One page of a vault's live entries, in name order, after the search; plus
/// how many entries match and how many the vault holds, and the page actually
/// returned (the one asked for, pulled back if it lies past the end).
/// </summary>
public sealed record EntryPage(IReadOnlyList<EntryView> Items, int Page, int PageCount, int Matching, int InVault);

public sealed record EntryView(
    PasswordEntry Entry, string Notes, bool NotesUnreadable, string PasswordUpdatedBy, DateTime? PasswordUpdatedAtUtc);

/// <summary>
/// One hit of <see cref="VaultService.SearchEntriesAsync"/>: the plain-text
/// fields a result list shows and the vault it lives in. Deliberately not an
/// <see cref="EntryView"/> — no notes and no secrets travel with a search.
/// </summary>
public sealed record EntryMatch(
    Guid EntryId, string Name, string Icon, string Url, string Username,
    Guid GroupId, string GroupName, bool GroupIsPersonal);

public sealed record RevisionView(Guid RevisionId, string CreatedBy, DateTime CreatedAtUtc, bool IsCurrent);

/// <summary>A row the import did not create because the vault already has an entry with its name and username.</summary>
public sealed record ImportSkip(int Row, string Name);

/// <summary>A row the import could not create, and why (the same message the editor would give).</summary>
public sealed record ImportFailure(int Row, string Name, string Reason);

/// <summary>What <see cref="VaultService.ImportEntriesAsync"/> did with each row of a file.</summary>
public sealed record ImportResult(int Created, IReadOnlyList<ImportSkip> Skipped, IReadOnlyList<ImportFailure> Failed);

public enum RevealPurpose
{
    View,
    Copy,
}

/// <summary>
/// Password entry CRUD, revealing, and history. Every operation checks group
/// membership; passwords are decrypted only on explicit reveal/copy calls.
/// Notes are encrypted at rest too, but are part of what a member sees when
/// listing a group, so they are decrypted with the list.
/// </summary>
public class VaultService
{
    private readonly IDbContextFactory<HarpoDbContext> _dbFactory;
    private readonly CryptoService _crypto;
    private readonly TimeProvider _time;
    private readonly ILogger<VaultService> _logger;
    private readonly AuditService _audit;
    private readonly HealthOptions _health;
    private readonly SessionService _sessions;
    private readonly ExportOptions _export;
    private readonly string _siteId;

    public VaultService(
        IDbContextFactory<HarpoDbContext> dbFactory, CryptoService crypto, TimeProvider time,
        ILogger<VaultService> logger, AuditService audit, IOptions<HealthOptions> health, SessionService sessions,
        IOptions<ExportOptions>? export = null, IOptions<SiteOptions>? site = null)
    {
        _dbFactory = dbFactory;
        _crypto = crypto;
        _time = time;
        _logger = logger;
        _audit = audit;
        _health = health.Value;
        _sessions = sessions;
        _export = export?.Value ?? new ExportOptions();
        _siteId = site?.Value.SiteId ?? "";
    }

    /// <summary>Whether this site offers vault exports at all (<c>Harpo:Export:Enabled</c>).</summary>
    public bool ExportEnabled => _export.Enabled;

    public async Task<List<EntryView>> GetEntriesAsync(UserContext user, Guid groupId, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        await RequireMemberAsync(db, user, groupId, ct);

        var entries = await db.PasswordEntries
            .Where(e => e.GroupId == groupId && !e.IsDeleted)
            .OrderBy(e => e.Name)
            .ToListAsync(ct);
        return await ViewsAsync(db, entries, ct);
    }

    /// <summary>
    /// One page of a vault for the vault page. Search and order need only the
    /// plain-text columns, so those are read for the whole vault (nothing is
    /// decrypted); the full rows, their latest revision and their decrypted
    /// notes are fetched for the one page shown. Reading and decrypting every
    /// entry on every visit made a 5,000-entry vault take seconds under load.
    /// Search matches name, URL or username, ignoring case (any alphabet).
    /// </summary>
    public async Task<EntryPage> GetEntryPageAsync(
        UserContext user, Guid groupId, string? search, int page, int pageSize, CancellationToken ct = default)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(pageSize, 1);
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        await RequireMemberAsync(db, user, groupId, ct);

        var all = await db.PasswordEntries.AsNoTracking()
            .Where(e => e.GroupId == groupId && !e.IsDeleted)
            .OrderBy(e => e.Name).ThenBy(e => e.Id) // a stable order, so pages never overlap
            .Select(e => new { e.Id, e.Name, e.Url, e.Username })
            .ToListAsync(ct);
        var term = search?.Trim() ?? "";
        var matching = term.Length == 0
            ? all
            : all.Where(e => e.Name.Contains(term, StringComparison.OrdinalIgnoreCase)
                             || e.Url.Contains(term, StringComparison.OrdinalIgnoreCase)
                             || e.Username.Contains(term, StringComparison.OrdinalIgnoreCase))
                 .ToList();

        var pageCount = Math.Max(1, (matching.Count + pageSize - 1) / pageSize);
        page = Math.Clamp(page, 1, pageCount);
        var ids = matching.Skip((page - 1) * pageSize).Take(pageSize).Select(e => e.Id).ToList();
        var rows = await db.PasswordEntries.AsNoTracking().Where(e => ids.Contains(e.Id)).ToListAsync(ct);
        var position = ids.Select((id, i) => (id, i)).ToDictionary(x => x.id, x => x.i);
        var ordered = rows.OrderBy(e => position[e.Id]).ToList();
        return new EntryPage(await ViewsAsync(db, ordered, ct), page, pageCount, matching.Count, all.Count);
    }

    /// <summary>Entries with their notes decrypted and who last changed the password, in the order given.</summary>
    private async Task<List<EntryView>> ViewsAsync(HarpoDbContext db, List<PasswordEntry> entries, CancellationToken ct)
    {
        var entryIds = entries.Select(e => e.Id).ToList();
        var revisions = await db.PasswordRevisions
            .Where(r => entryIds.Contains(r.EntryId))
            .Select(r => new { r.EntryId, r.CreatedBy, r.CreatedAtUtc, r.OriginSiteId, r.OriginSeq })
            .ToListAsync(ct);
        var latestByEntry = revisions
            .GroupBy(r => r.EntryId)
            .ToDictionary(
                g => g.Key,
                g => g.OrderByDescending(r => r.CreatedAtUtc)
                      .ThenByDescending(r => r.OriginSiteId, StringComparer.Ordinal)
                      .ThenByDescending(r => r.OriginSeq)
                      .First());

        return entries
            .Select(e =>
            {
                var readable = ProtectedNotes.TryRead(_crypto, e.EncryptedNotes, out var notes);
                return latestByEntry.TryGetValue(e.Id, out var latest)
                    ? new EntryView(e, notes, !readable, latest.CreatedBy, latest.CreatedAtUtc)
                    : new EntryView(e, notes, !readable, e.CreatedBy, null);
            })
            .ToList();
    }

    /// <summary>
    /// Finds entries by name, URL or username across every vault the user can
    /// see (the groups <see cref="GroupService.GetMyGroupsAsync"/> lists — never
    /// someone else's personal vault). Case-insensitive; notes are encrypted at
    /// rest and are not searched. Like listing a group, it is not audited.
    /// <paramref name="excludeGroupId"/> leaves one vault out — the page already
    /// shows the open vault's matches, and its many hits must not crowd the
    /// other vaults' out of <paramref name="limit"/>.
    /// </summary>
    public async Task<List<EntryMatch>> SearchEntriesAsync(
        UserContext user, string term, int limit = 50, CancellationToken ct = default, Guid? excludeGroupId = null)
    {
        await _sessions.RequireLiveAsync(user, ct);
        term = (term ?? "").Trim();
        if (term.Length == 0 || limit <= 0)
        {
            return [];
        }

        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var memberOf = await db.GroupMembers
            .Where(m => !m.IsDeleted && m.Username == user.Username)
            .Select(m => m.GroupId)
            .ToListAsync(ct);
        var visible = GroupService.VisibleGroups(db, user, memberOf);
        if (excludeGroupId is { } excluded)
        {
            visible = visible.Where(g => g.Id != excluded);
        }
        var groups = await visible
            .Select(g => new { g.Id, g.Name, g.OwnerUsername })
            .ToListAsync(ct);
        if (groups.Count == 0)
        {
            return [];
        }

        // Matched in memory rather than with LIKE/instr: SQLite folds case for
        // ASCII only, and this must agree with the vault page's own filter
        // (OrdinalIgnoreCase). Only the plain-text columns are read.
        var groupIds = groups.Select(g => g.Id).ToList();
        var candidates = await db.PasswordEntries
            .Where(e => !e.IsDeleted && groupIds.Contains(e.GroupId))
            .Select(e => new { e.Id, e.Name, e.Icon, e.Url, e.Username, e.GroupId })
            .ToListAsync(ct);
        var groupById = groups.ToDictionary(g => g.Id);

        return candidates
            .Where(e => e.Name.Contains(term, StringComparison.OrdinalIgnoreCase)
                        || e.Url.Contains(term, StringComparison.OrdinalIgnoreCase)
                        || e.Username.Contains(term, StringComparison.OrdinalIgnoreCase))
            .Select(e => (Entry: e, Group: groupById[e.GroupId]))
            .OrderBy(x => x.Entry.Name, StringComparer.OrdinalIgnoreCase)
            .ThenBy(x => x.Group.Name, StringComparer.OrdinalIgnoreCase)
            .ThenBy(x => x.Entry.Id)
            .Take(limit)
            .Select(x => new EntryMatch(
                x.Entry.Id, x.Entry.Name, x.Entry.Icon, x.Entry.Url, x.Entry.Username,
                x.Group.Id, x.Group.Name, x.Group.OwnerUsername.Length > 0))
            .ToList();
    }

    public async Task<PasswordEntry> CreateEntryAsync(
        UserContext user, Guid groupId, string name, string icon, string url, string username, string notes, string password,
        string totpSecret = "", CancellationToken ct = default)
    {
        var (entry, revision) = NewEntry(user, groupId, name, icon, url, username, notes, password, totpSecret,
            _time.GetUtcNow().UtcDateTime);

        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        await RequireMemberAsync(db, user, groupId, ct, requireWrite: true);

        db.PasswordEntries.Add(entry);
        db.PasswordRevisions.Add(revision);
        await db.SaveChangesAsync(ct);
        _logger.LogInformation("{User} created entry {Entry} in group {Group}", user.Username, entry.Id, groupId);
        return entry;
    }

    /// <summary>
    /// A new entry and its first revision, validated: the rules every way of
    /// creating an entry shares (the editor's <see cref="CreateEntryAsync"/> and
    /// <see cref="ImportEntriesAsync"/>). Throws <see cref="VaultValidationException"/>.
    /// </summary>
    private (PasswordEntry Entry, PasswordRevision Revision) NewEntry(
        UserContext user, Guid groupId, string name, string icon, string url, string username, string notes,
        string password, string totpSecret, DateTime now)
    {
        name = name.Trim();
        if (name.Length == 0)
        {
            throw new VaultValidationException("Name is required.", "name");
        }
        if (password.Length == 0)
        {
            throw new VaultValidationException("Password is required.", "password");
        }
        var encryptedTotp = EncryptTotpOrThrow(totpSecret);
        var entry = new PasswordEntry
        {
            Id = Guid.NewGuid(),
            GroupId = groupId,
            Name = name,
            Icon = icon.Trim(),
            Url = NormalizeUrl(url),
            Username = username.Trim(),
            EncryptedNotes = ProtectedNotes.Protect(_crypto, notes.Trim()),
            EncryptedTotpSecret = encryptedTotp,
            CreatedBy = user.Username,
            CreatedAtUtc = now,
            UpdatedBy = user.Username,
        };
        return (entry, NewRevision(entry.Id, password, user, now));
    }

    /// <summary>
    /// Creates an entry for each row read from an import file, in one go. Each
    /// row is checked with the editor's rules (a name and a password are
    /// required, a 2FA secret must parse); a row that fails is reported with
    /// its reason and the rest still go in. With <paramref name="skipDuplicates"/>,
    /// a row whose name and username (ignoring case and surrounding spaces)
    /// match an entry already in the vault, or an earlier row of the same file,
    /// is skipped. Every entry gets an ordinary first revision by the importer,
    /// so it replicates and shows in health and offline copies like any other.
    /// Needs write rights to the vault. Audited once, with the counts.
    /// </summary>
    public async Task<ImportResult> ImportEntriesAsync(
        UserContext user, Guid groupId, IReadOnlyList<ImportRow> rows, bool skipDuplicates = true,
        string format = "CSV", CancellationToken ct = default)
    {
        await _sessions.RequireLiveAsync(user, ct);
        if (rows.Count > ImportReader.MaxRows)
        {
            throw new VaultValidationException(
                $"This file has {rows.Count} rows; one import takes at most {ImportReader.MaxRows}. Split the file and import the parts.");
        }

        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        Group group;
        var created = 0;
        var skipped = new List<ImportSkip>();
        var failed = new List<ImportFailure>();
        using (await db.BeginExclusiveWriteAsync(ct))
        {
            // The duplicate check and the inserts are one step, so two imports of
            // the same file at once cannot both find the vault without the rows.
            group = await RequireMemberAsync(db, user, groupId, ct, requireWrite: true);
            var existing = await db.PasswordEntries
                .Where(e => e.GroupId == groupId && !e.IsDeleted)
                .Select(e => new { e.Name, e.Username })
                .ToListAsync(ct);
            var seen = new HashSet<(string, string)>(
                existing.Select(e => DuplicateKey(e.Name, e.Username)), DuplicateKeyComparer.Instance);

            var now = _time.GetUtcNow().UtcDateTime;
            foreach (var row in rows)
            {
                var key = DuplicateKey(row.Name, row.Username);
                if (skipDuplicates && key.Item1.Length > 0 && seen.Contains(key))
                {
                    skipped.Add(new ImportSkip(row.Row, key.Item1));
                    continue;
                }
                try
                {
                    var (entry, revision) = NewEntry(user, groupId, row.Name, ImportIcon(row.Icon), row.Url, row.Username,
                        row.Notes, row.Password, row.Totp, now);
                    db.PasswordEntries.Add(entry);
                    db.PasswordRevisions.Add(revision);
                    seen.Add(key);
                    created++;
                }
                catch (VaultValidationException ex)
                {
                    failed.Add(new ImportFailure(row.Row, key.Item1, ex.Message));
                }
            }
            await db.SaveChangesAsync(ct);
        }
        _logger.LogInformation("{User} imported {Created} entries into group {Group} ({Skipped} skipped, {Failed} failed)",
            user.Username, created, groupId, skipped.Count, failed.Count);
        await _audit.RecordAsync(user, AuditActions.VaultImport, DescribeVault(group),
            detail: $"{format}: {created} created, {skipped.Count} skipped as duplicates, {failed.Count} failed",
            groupId: groupId);
        return new ImportResult(created, skipped, failed);
    }

    private static (string, string) DuplicateKey(string name, string username) => (name.Trim(), username.Trim());

    private sealed class DuplicateKeyComparer : IEqualityComparer<(string, string)>
    {
        public static readonly DuplicateKeyComparer Instance = new();

        public bool Equals((string, string) x, (string, string) y) =>
            string.Equals(x.Item1, y.Item1, StringComparison.OrdinalIgnoreCase)
            && string.Equals(x.Item2, y.Item2, StringComparison.OrdinalIgnoreCase);

        public int GetHashCode((string, string) key) => HashCode.Combine(
            StringComparer.OrdinalIgnoreCase.GetHashCode(key.Item1), StringComparer.OrdinalIgnoreCase.GetHashCode(key.Item2));
    }

    /// <summary>
    /// The icon an imported row asks for, when it is one the editor could have
    /// set (an emoji or a catalogue reference); anything else — another
    /// manager's idea of an icon — becomes the default.
    /// </summary>
    private static string ImportIcon(string icon)
    {
        icon = icon.Trim();
        return icon.Length == 0 || (CustomIcon.ParseReference(icon) is null && (icon.Length > 16 || icon.Any(char.IsLetterOrDigit)))
            ? DefaultIcon
            : icon;
    }

    /// <summary>The icon a new entry starts with in the editor.</summary>
    public const string DefaultIcon = "🔐";

    /// <summary>
    /// Metadata update. TOTP semantics: empty <paramref name="totpSecret"/> keeps
    /// the current 2FA configuration, a value replaces it, <paramref name="clearTotp"/>
    /// removes it. Notes are replaced by <paramref name="notes"/>, except that
    /// notes this site cannot decrypt survive an empty value (see
    /// <see cref="ProtectedNotes.Replace"/>).
    /// </summary>
    public async Task UpdateEntryAsync(
        UserContext user, Guid entryId, string name, string icon, string url, string username, string notes,
        string totpSecret = "", bool clearTotp = false, CancellationToken ct = default)
    {
        name = name.Trim();
        if (name.Length == 0)
        {
            throw new VaultValidationException("Name is required.", "name");
        }
        var encryptedTotp = EncryptTotpOrThrow(totpSecret);

        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var entry = await RequireEntryAsync(db, user, entryId, ct, requireWrite: true);
        entry.Name = name;
        entry.Icon = icon.Trim();
        entry.Url = NormalizeUrl(url);
        entry.Username = username.Trim();
        entry.EncryptedNotes = ProtectedNotes.Replace(_crypto, entry.EncryptedNotes, notes.Trim());
        var totpChanged = false;
        if (clearTotp && entry.EncryptedTotpSecret is not null)
        {
            entry.EncryptedTotpSecret = null;
            totpChanged = true;
        }
        else if (encryptedTotp is not null)
        {
            entry.EncryptedTotpSecret = encryptedTotp;
            totpChanged = true;
        }
        entry.UpdatedBy = user.Username;
        await db.SaveChangesAsync(ct);
        if (totpChanged)
        {
            await _audit.RecordAsync(user, AuditActions.TotpChange, await DescribeEntryAsync(db, entry, ct),
                detail: entry.EncryptedTotpSecret is null ? "2FA removed" : "2FA secret set",
                groupId: entry.GroupId, entryId: entry.Id);
        }
    }

    private string? EncryptTotpOrThrow(string totpSecret)
    {
        if (string.IsNullOrWhiteSpace(totpSecret))
        {
            return null;
        }
        try
        {
            return _crypto.Encrypt(Totp.Normalize(totpSecret));
        }
        catch (ArgumentException ex)
        {
            throw new VaultValidationException(ex.Message, "totp");
        }
    }

    /// <summary>
    /// Current 2FA code for an entry. Read access suffices (viewers included).
    /// Audited like a reveal, deduplicated so a code panel refreshing every
    /// rollover produces one trail event per viewing, not one per 30 seconds.
    /// </summary>
    public async Task<TotpCode> GetTotpCodeAsync(UserContext user, Guid entryId, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var entry = await RequireEntryAsync(db, user, entryId, ct);
        if (entry.EncryptedTotpSecret is null)
        {
            throw new VaultNotFoundException("This entry has no 2FA secret.");
        }
        var stored = _crypto.Decrypt(entry.EncryptedTotpSecret);
        var code = Totp.GenerateCurrent(stored, _time.GetUtcNow());

        var auditKey = (user.Username, entryId);
        var now = _time.GetUtcNow();
        if (!_recentTotpAudits.TryGetValue(auditKey, out var last) || now - last > TimeSpan.FromMinutes(2))
        {
            _recentTotpAudits[auditKey] = now;
            await _audit.RecordAsync(user, AuditActions.TotpReveal, await DescribeEntryAsync(db, entry, ct),
                groupId: entry.GroupId, entryId: entry.Id);
        }
        return code;
    }

    private readonly System.Collections.Concurrent.ConcurrentDictionary<(string, Guid), DateTimeOffset> _recentTotpAudits = new();

    public async Task ChangePasswordAsync(UserContext user, Guid entryId, string newPassword, CancellationToken ct = default)
    {
        if (newPassword.Length == 0)
        {
            throw new VaultValidationException("Password is required.", "password");
        }

        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var entry = await RequireEntryAsync(db, user, entryId, ct, requireWrite: true);
        var now = _time.GetUtcNow().UtcDateTime;
        db.PasswordRevisions.Add(NewRevision(entry.Id, newPassword, user, now));
        // Touch the entry so list views (and replication consumers) see it moved.
        entry.UpdatedBy = user.Username;
        await db.SaveChangesAsync(ct);
        _logger.LogInformation("{User} changed the password of entry {Entry}", user.Username, entryId);
    }

    public async Task DeleteEntryAsync(UserContext user, Guid entryId, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var entry = await RequireEntryAsync(db, user, entryId, ct, requireWrite: true);
        entry.IsDeleted = true;
        entry.UpdatedBy = user.Username;
        await db.SaveChangesAsync(ct);
        _logger.LogInformation("{User} deleted entry {Entry}", user.Username, entryId);
        await _audit.RecordAsync(
            user, AuditActions.EntryDelete, await DescribeEntryAsync(db, entry, ct),
            groupId: entry.GroupId, entryId: entry.Id);
    }

    public const int DeletedPageSize = 50;

    /// <summary>
    /// A page of tombstoned entries of a live group, newest first, plus the true total. Requires write rights
    /// (viewers have no trash). Ordered by (UpdatedAtUtc, Id) descending and continued from a cursor holding both,
    /// so rows sharing a timestamp are neither skipped nor repeated between pages.
    /// </summary>
    public async Task<DeletedPage<PasswordEntry>> GetDeletedEntriesAsync(
        UserContext user, Guid groupId, DeletedCursor? after = null, int pageSize = DeletedPageSize, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        await RequireMemberAsync(db, user, groupId, ct, requireWrite: true);
        var deleted = db.PasswordEntries.Where(e => e.GroupId == groupId && e.IsDeleted);
        var total = await deleted.CountAsync(ct);
        var page = after is null
            ? deleted
            : deleted.Where(e => e.UpdatedAtUtc < after.UpdatedAtUtc
                || (e.UpdatedAtUtc == after.UpdatedAtUtc && e.Id.CompareTo(after.Id) < 0));
        var items = await page
            .OrderByDescending(e => e.UpdatedAtUtc).ThenByDescending(e => e.Id)
            .Take(pageSize)
            .ToListAsync(ct);
        return new DeletedPage<PasswordEntry>(items, total);
    }

    /// <summary>Undoes a delete — tombstones replicate, so this works on any site and syncs everywhere.</summary>
    public async Task RestoreEntryAsync(UserContext user, Guid entryId, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var entry = await db.PasswordEntries.SingleOrDefaultAsync(e => e.Id == entryId && e.IsDeleted, ct)
            ?? throw new VaultNotFoundException("Deleted entry not found.");
        await RequireMemberAsync(db, user, entry.GroupId, ct, requireWrite: true);
        entry.IsDeleted = false;
        entry.UpdatedBy = user.Username;
        await db.SaveChangesAsync(ct);
        _logger.LogInformation("{User} restored entry {Entry}", user.Username, entryId);
        await _audit.RecordAsync(
            user, AuditActions.EntryRestore, await DescribeEntryAsync(db, entry, ct),
            groupId: entry.GroupId, entryId: entry.Id);
    }

    /// <summary>Decrypts the current password of an entry (and audits the access).</summary>
    public async Task<string> RevealPasswordAsync(
        UserContext user, Guid entryId, RevealPurpose purpose = RevealPurpose.View, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var entry = await RequireEntryAsync(db, user, entryId, ct);
        var latest = await LatestRevisionAsync(db, entry.Id, ct)
            ?? throw new VaultNotFoundException("This entry has no password yet (it may still be replicating).");
        var plaintext = _crypto.Decrypt(latest.EncryptedPassword);
        await _audit.RecordAsync(
            user,
            purpose == RevealPurpose.Copy ? AuditActions.PasswordCopy : AuditActions.PasswordReveal,
            await DescribeEntryAsync(db, entry, ct),
            groupId: entry.GroupId, entryId: entry.Id);
        return plaintext;
    }

    public async Task<List<RevisionView>> GetHistoryAsync(UserContext user, Guid entryId, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        await RequireEntryAsync(db, user, entryId, ct);
        var revisions = await db.PasswordRevisions
            .Where(r => r.EntryId == entryId)
            .ToListAsync(ct);
        var ordered = revisions
            .OrderByDescending(r => r.CreatedAtUtc)
            .ThenByDescending(r => r.OriginSiteId, StringComparer.Ordinal)
            .ThenByDescending(r => r.OriginSeq)
            .ToList();
        return ordered
            .Select((r, i) => new RevisionView(r.Id, r.CreatedBy, r.CreatedAtUtc, i == 0))
            .ToList();
    }

    /// <summary>Decrypts a historical password revision, to show it or to put it on the clipboard.</summary>
    public async Task<string> RevealRevisionAsync(
        UserContext user, Guid entryId, Guid revisionId,
        RevealPurpose purpose = RevealPurpose.View, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        await RequireEntryAsync(db, user, entryId, ct);
        var revision = await db.PasswordRevisions
            .SingleOrDefaultAsync(r => r.Id == revisionId && r.EntryId == entryId, ct)
            ?? throw new VaultNotFoundException("Revision not found.");
        var plaintext = _crypto.Decrypt(revision.EncryptedPassword);
        var entry = await db.PasswordEntries.SingleAsync(e => e.Id == entryId, ct);
        await _audit.RecordAsync(
            user,
            purpose == RevealPurpose.Copy ? AuditActions.RevisionCopy : AuditActions.RevisionReveal,
            await DescribeEntryAsync(db, entry, ct),
            detail: $"historical value set {revision.CreatedAtUtc:u} by {revision.CreatedBy}",
            groupId: entry.GroupId, entryId: entry.Id);
        return plaintext;
    }

    /// <summary>
    /// The audit trail's name for an entry. Entries in a personal vault are
    /// described without their name: the trail is read by site admins, and the
    /// names of what someone keeps privately are theirs. The event itself (who,
    /// what kind of action, when, from where) is still recorded.
    /// </summary>
    private static async Task<string> DescribeEntryAsync(HarpoDbContext db, PasswordEntry entry, CancellationToken ct)
    {
        var group = await db.Groups
            .Where(g => g.Id == entry.GroupId)
            .Select(g => new { g.Name, g.OwnerUsername })
            .FirstOrDefaultAsync(ct);
        return group is null ? entry.Name
            : group.OwnerUsername.Length > 0 ? PersonalEntryDescription
            : $"{entry.Name} ({group.Name})";
    }

    public const string PersonalEntryDescription = "an entry in a personal vault";

    /// <summary>The audit trail's name for a whole vault: a group by its name, a personal vault never by anything of its owner's.</summary>
    private static string DescribeVault(Group group) =>
        group.IsPersonal ? PersonalVaultDescription : group.Name;

    public const string PersonalVaultDescription = "a personal vault";

    // ---- export ----

    /// <summary>
    /// Checks, without decrypting anything, that this site allows exports and
    /// that the caller may export the vault (see <see cref="RequireExportRightsAsync"/>).
    /// The download endpoint asks this first, so a refusal costs no rate-limit slot.
    /// </summary>
    public async Task RequireCanExportAsync(UserContext user, Guid groupId, CancellationToken ct = default)
    {
        RequireExportEnabled();
        await _sessions.RequireLiveAsync(user, ct);
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        await RequireExportRightsAsync(db, user, groupId, ct);
    }

    /// <summary>
    /// The vault's live entries with their current passwords, 2FA secrets and
    /// notes decrypted, as a CSV or JSON file — the one deliberate bulk decrypt
    /// besides the offline snapshot, and treated like it: rights-checked here,
    /// rate-limited and switchable at the endpoint, and always audited (the
    /// format and the count, never a value). No password history.
    /// </summary>
    public async Task<ExportFile> ExportVaultAsync(
        UserContext user, Guid groupId, ExportFormat format, CancellationToken ct = default)
    {
        RequireExportEnabled();
        await _sessions.RequireLiveAsync(user, ct);
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var group = await RequireExportRightsAsync(db, user, groupId, ct);

        var entries = await db.PasswordEntries
            .Where(e => e.GroupId == groupId && !e.IsDeleted)
            .OrderBy(e => e.Name)
            .ToListAsync(ct);
        var latestByEntry = await LatestRevisionsAsync(db, entries.Select(e => e.Id).ToList(), ct);
        var exported = entries
            .Select(e => new ExportEntry(
                e.Name,
                e.Icon,
                e.Url,
                e.Username,
                latestByEntry.TryGetValue(e.Id, out var latest) ? _crypto.Decrypt(latest.EncryptedPassword) : "",
                ProtectedNotes.TryRead(_crypto, e.EncryptedNotes, out var notes) ? notes : "",
                e.EncryptedTotpSecret is null ? "" : _crypto.Decrypt(e.EncryptedTotpSecret)))
            .ToList();

        var now = _time.GetUtcNow().UtcDateTime;
        var fileName = VaultExport.FileName(group.Name, group.IsPersonal, now, format);
        var file = format == ExportFormat.Json
            ? new ExportFile(fileName, "application/json; charset=utf-8",
                System.Text.Encoding.UTF8.GetBytes(
                    VaultExport.ToJson(group.Name, group.IsPersonal, user.Username, _siteId, now, exported)),
                exported.Count)
            : new ExportFile(fileName, "text/csv; charset=utf-8",
                CsvWriter.ToUtf8WithBom(VaultExport.ToCsv(exported)), exported.Count);

        _logger.LogInformation("{User} exported {Count} entries of group {Group} as {Format}",
            user.Username, exported.Count, groupId, format);
        await _audit.RecordAsync(user, AuditActions.VaultExport, DescribeVault(group),
            detail: $"{(format == ExportFormat.Json ? "JSON" : "CSV")}, {exported.Count} {(exported.Count == 1 ? "entry" : "entries")}",
            groupId: groupId);
        return file;
    }

    private void RequireExportEnabled()
    {
        if (!_export.Enabled)
        {
            throw new VaultNotFoundException("Exporting vaults is turned off on this site.");
        }
    }

    // ---- export of all groups (site administrators) ----

    /// <summary>
    /// Whether this site offers site administrators the all-groups archive:
    /// <c>Harpo:Export:AllGroupsEnabled</c> and <c>Harpo:Export:Enabled</c> both on.
    /// </summary>
    public bool AllGroupsExportEnabled => _export.AllGroupsAvailable;

    /// <summary>
    /// The groups the all-groups export covers: every live shared group. Never
    /// a personal vault — not even the caller's own, which its owner exports
    /// from the vault itself. A vault a site admin has taken over is an
    /// ordinary group by then, and is included.
    /// </summary>
    private static IQueryable<Group> ExportableGroups(HarpoDbContext db) =>
        db.Groups.Where(g => !g.IsDeleted && g.OwnerUsername == "");

    /// <summary>The live entries of <see cref="ExportableGroups"/>.</summary>
    private static IQueryable<PasswordEntry> ExportableEntries(HarpoDbContext db) =>
        from e in db.PasswordEntries
        join g in db.Groups on e.GroupId equals g.Id
        where !e.IsDeleted && !g.IsDeleted && g.OwnerUsername == ""
        select e;

    /// <summary>
    /// Checks, without decrypting anything, that the all-groups export is on
    /// and that the caller is a site administrator with a live session (whose
    /// role the session check holds to the directory's). The download endpoint
    /// asks this first, so a refusal costs no rate-limit slot.
    /// </summary>
    public async Task RequireCanExportAllGroupsAsync(UserContext user, CancellationToken ct = default)
    {
        RequireAllGroupsExportEnabled();
        await _sessions.RequireLiveAsync(user, ct);
        if (!user.IsSiteAdmin)
        {
            throw new VaultAccessDeniedException("Only site administrators can export all groups.");
        }
    }

    /// <summary>How many groups and entries the all-groups export would hold — counted, nothing decrypted.</summary>
    public async Task<AllGroupsSummary> GetAllGroupsExportSummaryAsync(UserContext user, CancellationToken ct = default)
    {
        await RequireCanExportAllGroupsAsync(user, ct);
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var groups = await ExportableGroups(db).CountAsync(ct);
        var entries = await ExportableEntries(db).CountAsync(ct);
        return new AllGroupsSummary(groups, entries);
    }

    /// <summary>
    /// Every live shared group with its live entries, current passwords, 2FA
    /// secrets and notes decrypted, as one zip of per-group files written
    /// exactly as <see cref="ExportVaultAsync"/> writes them. The largest bulk
    /// decrypt Harpo has: site admins only, switched off by default, rate-
    /// limited at the endpoint, and audited once (format and counts, never a
    /// group or entry name). Personal vaults never go in.
    /// </summary>
    public async Task<AllGroupsExportFile> ExportAllGroupsAsync(
        UserContext user, ExportFormat format, CancellationToken ct = default)
    {
        await RequireCanExportAllGroupsAsync(user, ct);
        await using var db = await _dbFactory.CreateDbContextAsync(ct);

        var groups = await ExportableGroups(db).ToListAsync(ct);
        var entries = await ExportableEntries(db)
            .OrderBy(e => e.Name)
            .ToListAsync(ct);
        var latestByEntry = await LatestRevisionsAsync(db, entries.Select(e => e.Id).ToList(), ct);
        var byGroup = entries.ToLookup(e => e.GroupId);
        var exported = groups
            // Ties on name and creation time (two sites, the same second) still give one order.
            .OrderBy(g => g.Name, StringComparer.Ordinal).ThenBy(g => g.CreatedAtUtc).ThenBy(g => g.Id)
            .Select(g => new GroupExport(g.Name, byGroup[g.Id]
                .Select(e => new ExportEntry(
                    e.Name,
                    e.Icon,
                    e.Url,
                    e.Username,
                    latestByEntry.TryGetValue(e.Id, out var latest) ? _crypto.Decrypt(latest.EncryptedPassword) : "",
                    ProtectedNotes.TryRead(_crypto, e.EncryptedNotes, out var notes) ? notes : "",
                    e.EncryptedTotpSecret is null ? "" : _crypto.Decrypt(e.EncryptedTotpSecret)))
                .ToList()))
            .ToList();

        var now = _time.GetUtcNow().UtcDateTime;
        var content = AllGroupsArchive.Build(exported, format, user.Username, _siteId, now);
        var file = new AllGroupsExportFile(
            AllGroupsArchive.FileName(_siteId, now), content, exported.Count, exported.Sum(g => g.Entries.Count));

        _logger.LogWarning("{User} exported all {Groups} groups ({Entries} entries) as {Format}",
            user.Username, file.GroupCount, file.EntryCount, format);
        await _audit.RecordAsync(user, AuditActions.SiteExport, AllGroupsAuditTarget,
            detail: $"{(format == ExportFormat.Json ? "JSON" : "CSV")}, "
                    + $"{AllGroupsArchive.Count(file.GroupCount, "group", "groups")}, "
                    + $"{AllGroupsArchive.Count(file.EntryCount, "entry", "entries")}");
        return file;
    }

    /// <summary>The audit target of an all-groups export: no group is named.</summary>
    public const string AllGroupsAuditTarget = "all groups";

    private void RequireAllGroupsExportEnabled()
    {
        if (!_export.AllGroupsAvailable)
        {
            throw new VaultNotFoundException("Exporting all groups is turned off on this site.");
        }
    }

    /// <summary>
    /// Everything the user may take offline: groups they are an explicit member of,
    /// with each entry's current password decrypted. Deliberately scoped to real
    /// memberships — site admins do not get an everything-snapshot; offline copies
    /// should carry the minimum, and admins can always reach the server online.
    /// </summary>
    public async Task<(List<Offline.OfflineGroup> Groups, List<Offline.OfflineEntry> Entries)> GetOfflineDataAsync(
        UserContext user, CancellationToken ct = default)
    {
        await _sessions.RequireLiveAsync(user, ct);
        await using var db = await _dbFactory.CreateDbContextAsync(ct);

        var groupIds = await db.GroupMembers
            .Where(m => !m.IsDeleted && m.Username == user.Username)
            .Select(m => m.GroupId)
            .ToListAsync(ct);

        var groups = await db.Groups
            .Where(g => !g.IsDeleted && groupIds.Contains(g.Id)
                        && (g.OwnerUsername == "" || g.OwnerUsername == user.Username))
            .OrderBy(g => g.OwnerUsername == "" ? 1 : 0)
            .ThenBy(g => g.Name)
            .Select(g => new Offline.OfflineGroup(g.Id, g.Name, g.Description))
            .ToListAsync(ct);

        var liveGroupIds = groups.Select(g => g.Id).ToList();
        var entries = await db.PasswordEntries
            .Where(e => !e.IsDeleted && liveGroupIds.Contains(e.GroupId))
            .OrderBy(e => e.Name)
            .ToListAsync(ct);

        var latestByEntry = await LatestRevisionsAsync(db, entries.Select(e => e.Id).ToList(), ct);

        var offlineEntries = entries
            .Select(e =>
            {
                latestByEntry.TryGetValue(e.Id, out var latest);
                return new Offline.OfflineEntry(
                    e.Id,
                    e.GroupId,
                    e.Name,
                    e.Icon,
                    e.Url,
                    e.Username,
                    ProtectedNotes.TryRead(_crypto, e.EncryptedNotes, out var notes) ? notes : "",
                    latest is null ? null : _crypto.Decrypt(latest.EncryptedPassword),
                    latest?.CreatedBy ?? e.CreatedBy,
                    latest?.CreatedAtUtc,
                    e.EncryptedTotpSecret is null ? null : _crypto.Decrypt(e.EncryptedTotpSecret));
            })
            .ToList();

        return (groups, offlineEntries);
    }

    private PasswordRevision NewRevision(Guid entryId, string password, UserContext user, DateTime now) => new()
    {
        Id = Guid.NewGuid(),
        EntryId = entryId,
        EncryptedPassword = _crypto.Encrypt(password),
        CreatedBy = user.Username,
        CreatedAtUtc = now,
        // Health analysis, when enabled: an equality fingerprint (reuse
        // detection) and a strength score, so the report never needs plaintext.
        Fingerprint = _health.Enabled ? _crypto.Fingerprint(password) : null,
        Strength = _health.Enabled ? PasswordStrength.Score(password) : null,
    };

    // The current password is the newest revision. Two revisions can share a
    // CreatedAtUtc (same site, same clock tick), so ties break by OriginSiteId
    // then OriginSeq — the same total order replication uses in IncomingWins, and
    // OriginSeq is monotonic per origin. (An earlier random-Guid tie-break made
    // "current" non-deterministic for same-tick revisions; see GetHistoryAsync,
    // GetEntriesAsync, GetOfflineDataAsync and HealthService, which order the same way.)
    private static async Task<Dictionary<Guid, PasswordRevision>> LatestRevisionsAsync(
        HarpoDbContext db, List<Guid> entryIds, CancellationToken ct)
    {
        var revisions = await db.PasswordRevisions
            .Where(r => entryIds.Contains(r.EntryId))
            .ToListAsync(ct);
        return revisions
            .GroupBy(r => r.EntryId)
            .ToDictionary(
                g => g.Key,
                g => g.OrderByDescending(r => r.CreatedAtUtc)
                      .ThenByDescending(r => r.OriginSiteId, StringComparer.Ordinal)
                      .ThenByDescending(r => r.OriginSeq)
                      .First());
    }

    private static async Task<PasswordRevision?> LatestRevisionAsync(HarpoDbContext db, Guid entryId, CancellationToken ct)
    {
        var revisions = await db.PasswordRevisions.Where(r => r.EntryId == entryId).ToListAsync(ct);
        return revisions
            .OrderByDescending(r => r.CreatedAtUtc)
            .ThenByDescending(r => r.OriginSiteId, StringComparer.Ordinal)
            .ThenByDescending(r => r.OriginSeq)
            .FirstOrDefault();
    }

    /// <summary>
    /// The access check every entry operation goes through (directly or via
    /// <see cref="RequireEntryAsync"/>) before anything is decrypted or written:
    /// first that the caller's session is still live — a page open since before
    /// a sign-out elsewhere must not get another secret — then group membership.
    /// </summary>
    private async Task<Group> RequireMemberAsync(
        HarpoDbContext db, UserContext user, Guid groupId, CancellationToken ct, bool requireWrite = false)
    {
        await _sessions.RequireLiveAsync(user, ct);
        var group = await db.Groups.SingleOrDefaultAsync(g => g.Id == groupId && !g.IsDeleted, ct)
            ?? throw new VaultNotFoundException("Group not found.");
        GroupService.RequireNotSomeoneElsesPersonalVault(group, user);
        if (group.IsPersonal)
        {
            return group; // the owner, with every right over their own entries
        }
        if (user.IsSiteAdmin)
        {
            return group;
        }
        var role = await GroupService.GetRoleAsync(db, groupId, user.Username, ct);
        if (role is null)
        {
            throw new VaultAccessDeniedException("You are not a member of this group.");
        }
        if (requireWrite && !role.Value.CanWrite())
        {
            throw new VaultAccessDeniedException("Viewers can see passwords but not change them.");
        }
        return group;
    }

    /// <summary>
    /// Who may take a whole vault away as a plain-text file: the owner of a
    /// personal vault (and nobody else — a site admin's rights stop at it, as
    /// everywhere), and for a shared group its admins and the site admins.
    /// Members and viewers reveal passwords one at a time, each audited; a
    /// bulk copy is a group admin's decision.
    /// </summary>
    private static async Task<Group> RequireExportRightsAsync(
        HarpoDbContext db, UserContext user, Guid groupId, CancellationToken ct)
    {
        var group = await db.Groups.SingleOrDefaultAsync(g => g.Id == groupId && !g.IsDeleted, ct)
            ?? throw new VaultNotFoundException("Group not found.");
        GroupService.RequireNotSomeoneElsesPersonalVault(group, user);
        if (group.IsPersonal || user.IsSiteAdmin)
        {
            return group;
        }
        var role = await GroupService.GetRoleAsync(db, groupId, user.Username, ct);
        if (role != GroupRole.Admin)
        {
            throw new VaultAccessDeniedException(role is null
                ? "You are not a member of this group."
                : "Only the group's admins can export it.");
        }
        return group;
    }


    /// <summary>
    /// A URL typed without a scheme ("router.local", "example.com:8443") would
    /// otherwise render as a relative link into Harpo itself. Assume https for
    /// anything schemeless; leave real absolute URIs (and mailto:) alone.
    /// </summary>
    internal static string NormalizeUrl(string url)
    {
        url = url.Trim();
        if (url.Length == 0 || url.Contains("://") || url.StartsWith("mailto:", StringComparison.OrdinalIgnoreCase))
        {
            return url;
        }
        return "https://" + url;
    }

    private async Task<PasswordEntry> RequireEntryAsync(
        HarpoDbContext db, UserContext user, Guid entryId, CancellationToken ct, bool requireWrite = false)
    {
        var entry = await db.PasswordEntries.SingleOrDefaultAsync(e => e.Id == entryId && !e.IsDeleted, ct)
            ?? throw new VaultNotFoundException("Entry not found.");
        await RequireMemberAsync(db, user, entry.GroupId, ct, requireWrite);
        return entry;
    }
}
