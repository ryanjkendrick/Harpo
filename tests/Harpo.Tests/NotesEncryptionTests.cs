using System.Text.Json;
using Harpo.Data;
using Harpo.Replication;
using Harpo.Security;
using Harpo.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Harpo.Tests;

/// <summary>
/// Entry notes are encrypted at rest and on the wire, shown in the clear to
/// members, and upgraded in place from the plain text earlier versions stored —
/// locally at startup and as rows arrive from peers still on such a version.
/// </summary>
public class NotesEncryptionTests
{
    private const string OldKey = TestSite.MasterKey;
    private const string NewKey = "rotated-master-key-passphrase";
    private const string Secret = "recovery codes 4F9K-22QX · maiden name Liddell";

    private static readonly UserContext Alice = TestSite.User("alice", siteAdmin: true);

    private static Task EnsureAsync(TestSite site, CryptoService? crypto = null) =>
        KeyRotation.EnsureMasterKeyStateAsync(site.Db, crypto ?? site.Crypto, site.Audit, NullLogger<CryptoService>.Instance);

    private static async Task<(Guid GroupId, Guid EntryId)> SeedAsync(TestSite site, string notes = Secret, string name = "router")
    {
        var group = await site.Groups.CreateGroupAsync(Alice, "ops", "");
        var entry = await site.Vault.CreateEntryAsync(Alice, group.Id, name, "🔐", "", "admin", notes, "correct horse");
        return (group.Id, entry.Id);
    }

    /// <summary>The column itself, by its database name — not through the model.</summary>
    private static async Task<string> NotesColumnAsync(TestSite site, string entryName = "router")
    {
        await using var db = site.Db.CreateDbContext();
        return await db.Database
            .SqlQueryRaw<string>("SELECT \"Notes\" AS \"Value\" FROM \"PasswordEntries\" WHERE \"Name\" = {0}", entryName)
            .SingleAsync();
    }

    /// <summary>Puts a row in the state an earlier version left it in: notes as plain text, stamps untouched.</summary>
    private static async Task WriteAsEarlierVersionAsync(TestSite site, string plaintext, string entryName = "router")
    {
        await using var db = site.Db.CreateDbContext();
        var rows = await db.Database.ExecuteSqlRawAsync(
            "UPDATE \"PasswordEntries\" SET \"Notes\" = {0} WHERE \"Name\" = {1}", plaintext, entryName);
        Assert.Equal(1, rows);
    }

    private static async Task<PasswordEntry> RowAsync(TestSite site, Guid entryId)
    {
        await using var db = site.Db.CreateDbContext();
        return await db.PasswordEntries.AsNoTracking().SingleAsync(e => e.Id == entryId);
    }

    private static async Task<EntryView> ViewAsync(TestSite site, VaultService vault, Guid groupId, Guid entryId) =>
        (await vault.GetEntriesAsync(Alice, groupId)).Single(v => v.Entry.Id == entryId);

    private static VaultService VaultWith(TestSite site, CryptoService crypto) =>
        new(site.Db, crypto, site.Time, NullLogger<VaultService>.Instance, site.Audit, Options.Create(new HealthOptions()));

    // ---- At rest ----

    [Fact]
    public async Task Notes_are_stored_encrypted_and_shown_to_members_in_the_clear()
    {
        using var site = new TestSite("a");
        var (groupId, entryId) = await SeedAsync(site);

        var column = await NotesColumnAsync(site);
        Assert.StartsWith(ProtectedNotes.Marker, column);
        Assert.DoesNotContain("recovery", column);
        Assert.DoesNotContain("Liddell", column);

        var view = await ViewAsync(site, site.Vault, groupId, entryId);
        Assert.Equal(Secret, view.Notes);
        Assert.False(view.NotesUnreadable);
    }

    [Fact]
    public async Task No_notes_means_an_empty_column_and_clearing_notes_empties_it_again()
    {
        using var site = new TestSite("a");
        var (groupId, entryId) = await SeedAsync(site, notes: "   ");
        Assert.Equal("", await NotesColumnAsync(site));

        await site.Vault.UpdateEntryAsync(Alice, entryId, "router", "🔐", "", "admin", Secret);
        Assert.StartsWith(ProtectedNotes.Marker, await NotesColumnAsync(site));

        await site.Vault.UpdateEntryAsync(Alice, entryId, "router", "🔐", "", "admin", "");
        Assert.Equal("", await NotesColumnAsync(site));
        Assert.Equal("", (await ViewAsync(site, site.Vault, groupId, entryId)).Notes);
    }

    [Fact]
    public async Task Saving_an_entry_without_changing_its_notes_keeps_the_same_ciphertext()
    {
        using var site = new TestSite("a");
        var (groupId, entryId) = await SeedAsync(site);
        var before = await NotesColumnAsync(site);

        await site.Vault.UpdateEntryAsync(Alice, entryId, "core router", "🌐", "https://router.local", "root", Secret);
        Assert.Equal(before, await NotesColumnAsync(site, "core router"));

        await site.Vault.UpdateEntryAsync(Alice, entryId, "core router", "🌐", "https://router.local", "root", Secret + " (updated)");
        Assert.NotEqual(before, await NotesColumnAsync(site, "core router"));
        Assert.Equal(Secret + " (updated)", (await ViewAsync(site, site.Vault, groupId, entryId)).Notes);
    }

    [Fact]
    public async Task Notes_that_happen_to_start_with_the_marker_text_survive_a_round_trip()
    {
        using var site = new TestSite("a");
        var typed = ProtectedNotes.Marker + "this is just what I typed";
        var (groupId, entryId) = await SeedAsync(site, notes: typed);

        Assert.Equal(typed, (await ViewAsync(site, site.Vault, groupId, entryId)).Notes);
    }

    [Fact]
    public async Task The_offline_copy_carries_the_notes_for_the_device_to_re_encrypt()
    {
        using var site = new TestSite("a");
        await SeedAsync(site);

        var (_, entries) = await site.Vault.GetOfflineDataAsync(Alice);
        Assert.Equal(Secret, Assert.Single(entries).Notes);
    }

    // ---- Upgrading a database written by an earlier version ----

    [Fact]
    public async Task Notes_from_an_earlier_version_are_encrypted_at_startup_without_becoming_an_edit()
    {
        var time = new ManualTime();
        using var site = new TestSite("a", time);
        var (groupId, entryId) = await SeedAsync(site);
        var trashed = await site.Vault.CreateEntryAsync(Alice, groupId, "old switch", "🔐", "", "", "x", "pw");
        await site.Vault.DeleteEntryAsync(Alice, trashed.Id);
        await WriteAsEarlierVersionAsync(site, Secret);
        await WriteAsEarlierVersionAsync(site, "kept in the trash", "old switch");

        // A peer that is already in sync, so "did the upgrade replicate?" has an answer.
        using var peer = new TestSite("b", time);
        await peer.PullFromAsync(site);
        var before = await RowAsync(site, entryId);

        // Readable even before the conversion ran…
        Assert.Equal(Secret, (await ViewAsync(site, site.Vault, groupId, entryId)).Notes);

        time.Advance(TimeSpan.FromDays(30));
        await EnsureAsync(site); // what startup does

        // …and encrypted after it, live entries and trashed ones alike.
        var column = await NotesColumnAsync(site);
        Assert.StartsWith(ProtectedNotes.Marker, column);
        Assert.DoesNotContain("recovery", column);
        Assert.StartsWith(ProtectedNotes.Marker, await NotesColumnAsync(site, "old switch"));
        Assert.Equal(Secret, (await ViewAsync(site, site.Vault, groupId, entryId)).Notes);

        // It was not an edit: same stamps, and nothing for the peer to pull.
        var after = await RowAsync(site, entryId);
        Assert.Equal(before.OriginSeq, after.OriginSeq);
        Assert.Equal(before.UpdatedAtUtc, after.UpdatedAtUtc);
        Assert.Equal(before.UpdatedBy, after.UpdatedBy);
        var response = await site.Engine.BuildResponseAsync(
            new PullRequest { SiteId = "b", Vector = await peer.Engine.GetVectorAsync() });
        Assert.Empty(response.Entries);

        // And it happens once: a second start leaves the ciphertext alone.
        await EnsureAsync(site);
        Assert.Equal(column, await NotesColumnAsync(site));
    }

    [Fact]
    public async Task Only_the_exact_marker_counts_as_already_encrypted()
    {
        // The marker is lower case. Plain text that merely resembles it (as an
        // earlier version could have stored) is still plain text and must be
        // converted — the database's own prefix match ignores case, ours must not.
        using var site = new TestSite("a");
        var (groupId, entryId) = await SeedAsync(site);
        var lookalike = "ENC:V1: not ciphertext, just shouting";
        await WriteAsEarlierVersionAsync(site, lookalike);

        await EnsureAsync(site);

        Assert.StartsWith(ProtectedNotes.Marker, await NotesColumnAsync(site));
        Assert.Equal(lookalike, (await ViewAsync(site, site.Vault, groupId, entryId)).Notes);
    }

    [Fact]
    public async Task The_upgrade_removes_the_plain_text_from_the_database_file_itself()
    {
        // A real file in the journal mode production uses. Encrypting a row leaves
        // its old bytes in freed pages and in the write-ahead log; "encrypted at
        // rest" is only true once the file has been rewritten.
        var dir = Directory.CreateTempSubdirectory("harpo-notes-").FullName;
        try
        {
            var path = Path.Combine(dir, "harpo.db");
            using (var site = new TestSite("a", databasePath: path))
            {
                var (groupId, entryId) = await SeedAsync(site);
                // Long notes spill into overflow pages, which SQLite hands back to
                // its free list — content intact — when the row is rewritten.
                var padding = new string('.', 20_000);
                // A note that was replaced long before the upgrade: no row holds it any more.
                await WriteAsEarlierVersionAsync(site, "an older note, since removed: PIN 4471 " + padding);
                await WriteAsEarlierVersionAsync(site, Secret + " " + padding);
                await WriteAsEarlierVersionAsync(site, Secret);
                var beforeUpgrade = FileText(dir);
                Assert.Contains("recovery codes 4F9K-22QX", beforeUpgrade); // the baseline
                Assert.Contains("PIN 4471", beforeUpgrade);

                await EnsureAsync(site);

                Assert.Equal(Secret, (await ViewAsync(site, site.Vault, groupId, entryId)).Notes);
                var afterUpgrade = FileText(dir);
                Assert.DoesNotContain("recovery codes 4F9K-22QX", afterUpgrade);
                Assert.DoesNotContain("PIN 4471", afterUpgrade);
                Assert.Contains(ProtectedNotes.Marker, afterUpgrade);

                // Once per database: the marker is there, and a second start does not rewrite the file again.
                await using var db = site.Db.CreateDbContext();
                Assert.True(await db.SiteSettings.AnyAsync(x => x.Id == KeyRotation.NotesScrubbedId));
            }
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(dir, recursive: true);
        }

        // Everything SQLite keeps for this database: the main file, its write-ahead log, any journal.
        static string FileText(string directory) => string.Concat(
            Directory.GetFiles(directory).OrderBy(f => f).Select(f =>
            {
                using var stream = new FileStream(f, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                using var memory = new MemoryStream();
                stream.CopyTo(memory);
                return System.Text.Encoding.Latin1.GetString(memory.ToArray());
            }));
    }

    // ---- Replication ----

    [Fact]
    public async Task Encrypted_notes_replicate_as_they_are_and_read_the_same_on_the_peer()
    {
        var time = new ManualTime();
        using var a = new TestSite("a", time);
        using var b = new TestSite("b", time);
        var (groupId, entryId) = await SeedAsync(a);

        await b.PullFromAsync(a, viaJson: true);

        Assert.Equal(await NotesColumnAsync(a), await NotesColumnAsync(b));
        Assert.Equal(Secret, (await ViewAsync(b, b.Vault, groupId, entryId)).Notes);
    }

    [Fact]
    public async Task Plain_text_notes_from_a_peer_on_an_earlier_version_are_encrypted_on_arrival()
    {
        var time = new ManualTime();
        using var earlier = new TestSite("earlier", time);
        using var current = new TestSite("current", time);
        var (groupId, entryId) = await SeedAsync(earlier);
        await WriteAsEarlierVersionAsync(earlier, Secret); // what that site holds, and therefore sends

        await current.PullFromAsync(earlier, viaJson: true);

        var column = await NotesColumnAsync(current);
        Assert.StartsWith(ProtectedNotes.Marker, column);
        Assert.DoesNotContain("recovery", column);
        Assert.Equal(Secret, (await ViewAsync(current, current.Vault, groupId, entryId)).Notes);

        // Encrypting its own copy did not make the row "newer" here: same stamps
        // as at the origin, so it is not offered back as a change.
        var origin = await RowAsync(earlier, entryId);
        var copy = await RowAsync(current, entryId);
        Assert.Equal(origin.OriginSiteId, copy.OriginSiteId);
        Assert.Equal(origin.OriginSeq, copy.OriginSeq);
        Assert.Equal(origin.UpdatedAtUtc, copy.UpdatedAtUtc);
        var back = await current.Engine.BuildResponseAsync(
            new PullRequest { SiteId = "earlier", Vector = await earlier.Engine.GetVectorAsync() });
        Assert.Empty(back.Entries);
    }

    [Fact]
    public void Notes_keep_their_name_on_the_wire()
    {
        // Sites on an earlier version send and expect "notes". Renaming it would
        // silently drop every note that crosses between versions.
        var web = new JsonSerializerOptions(JsonSerializerDefaults.Web);

        var json = JsonSerializer.Serialize(new PasswordEntry { Name = "router", EncryptedNotes = "enc:v1:AAAA" }, web);
        Assert.Contains("\"notes\":\"enc:v1:AAAA\"", json);
        Assert.DoesNotContain("encryptedNotes", json, StringComparison.OrdinalIgnoreCase);

        var fromEarlierVersion = JsonSerializer.Deserialize<PasswordEntry>("{\"name\":\"router\",\"notes\":\"plain text\"}", web)!;
        Assert.Equal("plain text", fromEarlierVersion.EncryptedNotes);
    }

    // ---- Master key rotation ----

    [Fact]
    public async Task Rotation_moves_notes_to_the_active_key()
    {
        using var site = new TestSite("a");
        await EnsureAsync(site);
        var (groupId, entryId) = await SeedAsync(site);
        var before = await RowAsync(site, entryId);

        var rotating = new CryptoService(NewKey, [OldKey]);
        await EnsureAsync(site, rotating);

        var newOnly = new CryptoService(NewKey);
        var after = await RowAsync(site, entryId);
        Assert.NotEqual(before.EncryptedNotes, after.EncryptedNotes);
        Assert.True(ProtectedNotes.TryRead(newOnly, after.EncryptedNotes, out var notes));
        Assert.Equal(Secret, notes);
        Assert.Equal(before.OriginSeq, after.OriginSeq);
        Assert.Equal(before.UpdatedAtUtc, after.UpdatedAtUtc);

        // A later start with only the new key still reads them.
        await EnsureAsync(site, newOnly);
        Assert.Equal(Secret, (await ViewAsync(site, VaultWith(site, newOnly), groupId, entryId)).Notes);
    }

    [Fact]
    public async Task Notes_arriving_from_a_not_yet_rotated_peer_are_moved_to_the_active_key()
    {
        var time = new ManualTime();
        using var notRotated = new TestSite("old", time);
        var (_, entryId) = await SeedAsync(notRotated);
        using var rotated = new TestSite("new", time, NewKey, [OldKey]);

        await rotated.PullFromAsync(notRotated, viaJson: true);

        var stored = (await RowAsync(rotated, entryId)).EncryptedNotes;
        Assert.True(ProtectedNotes.TryRead(new CryptoService(NewKey), stored, out var notes));
        Assert.Equal(Secret, notes);
    }

    // ---- Notes this site has no key for ----

    [Fact]
    public async Task Notes_this_site_cannot_decrypt_are_flagged_kept_through_other_edits_and_replaceable()
    {
        var time = new ManualTime();
        using var origin = new TestSite("origin", time);
        var (groupId, entryId) = await SeedAsync(origin);
        var original = (await RowAsync(origin, entryId)).EncryptedNotes;

        // An established site on a different master key (its own data proved its
        // key): it keeps running and stores what it cannot read byte for byte.
        using var home = new TestSite("home", time, "some-entirely-different-key");
        await SeedAsync(home, notes: "home's own notes", name: "home entry");
        await EnsureAsync(home);
        await home.PullFromAsync(origin, viaJson: true);
        Assert.Equal(original, (await RowAsync(home, entryId)).EncryptedNotes);

        var view = await ViewAsync(home, home.Vault, groupId, entryId);
        Assert.True(view.NotesUnreadable);
        Assert.Equal("", view.Notes);

        // Renaming the entry sends the notes field back empty — that is how it was
        // shown. The notes must still be there, untouched, for the day the right
        // key is configured.
        time.Advance(TimeSpan.FromMinutes(1));
        await home.Vault.UpdateEntryAsync(Alice, entryId, "renamed", "🔐", "", "admin", view.Notes);
        Assert.Equal(original, (await RowAsync(home, entryId)).EncryptedNotes);

        // Typing new notes is a deliberate replacement.
        time.Advance(TimeSpan.FromMinutes(1));
        await home.Vault.UpdateEntryAsync(Alice, entryId, "renamed", "🔐", "", "admin", "written at home");
        var replaced = await ViewAsync(home, home.Vault, groupId, entryId);
        Assert.False(replaced.NotesUnreadable);
        Assert.Equal("written at home", replaced.Notes);
    }

    // ---- The format itself ----

    [Fact]
    public void Stored_values_are_empty_marked_ciphertext_or_earlier_plain_text()
    {
        var crypto = new CryptoService(OldKey);

        Assert.Equal("", ProtectedNotes.Protect(crypto, ""));
        var stored = ProtectedNotes.Protect(crypto, Secret);
        Assert.StartsWith(ProtectedNotes.Marker, stored);
        Assert.NotEqual(stored, ProtectedNotes.Protect(crypto, Secret)); // fresh nonce every time

        Assert.True(ProtectedNotes.TryRead(crypto, stored, out var read));
        Assert.Equal(Secret, read);
        Assert.True(ProtectedNotes.TryRead(crypto, "", out var empty));
        Assert.Equal("", empty);
        Assert.True(ProtectedNotes.TryRead(crypto, "written before notes were encrypted", out var earlier));
        Assert.Equal("written before notes were encrypted", earlier);

        Assert.False(ProtectedNotes.TryRead(new CryptoService("another key"), stored, out _));
        Assert.False(ProtectedNotes.TryRead(crypto, ProtectedNotes.Marker + "not a blob at all", out _));
    }

    [Fact]
    public void Bringing_a_value_up_to_date_touches_only_what_needs_it()
    {
        var old = new CryptoService(OldKey);
        var rotating = new CryptoService(NewKey, [OldKey]);
        var underOldKey = ProtectedNotes.Protect(old, Secret);
        var underNewKey = ProtectedNotes.Protect(rotating, Secret);

        // Plain text is encrypted.
        Assert.True(ProtectedNotes.TryBringUpToDate(old, "plain text", out var encrypted, out var unreadable));
        Assert.False(unreadable);
        Assert.True(ProtectedNotes.TryRead(old, encrypted, out var roundTrip));
        Assert.Equal("plain text", roundTrip);

        // Under a previous key: moved to the active one.
        Assert.True(ProtectedNotes.TryBringUpToDate(rotating, underOldKey, out var moved, out unreadable));
        Assert.False(unreadable);
        Assert.True(ProtectedNotes.TryRead(new CryptoService(NewKey), moved, out roundTrip));
        Assert.Equal(Secret, roundTrip);

        // Empty, already current, or unreadable: left exactly as it is.
        Assert.False(ProtectedNotes.TryBringUpToDate(old, "", out var same, out unreadable));
        Assert.Equal("", same);
        Assert.False(unreadable);
        Assert.False(ProtectedNotes.TryBringUpToDate(rotating, underNewKey, out same, out unreadable));
        Assert.Equal(underNewKey, same);
        Assert.False(unreadable);
        Assert.False(ProtectedNotes.TryBringUpToDate(new CryptoService("another key"), underOldKey, out same, out unreadable));
        Assert.Equal(underOldKey, same);
        Assert.True(unreadable);
    }
}
