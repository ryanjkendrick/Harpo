using System.Security.Cryptography;
using Harpo.Data;
using Harpo.Security;
using Harpo.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Harpo.Tests;

public class KeyRotationTests
{
    private const string OldKey = TestSite.MasterKey;
    private const string NewKey = "rotated-master-key-passphrase";

    private static readonly UserContext Alice = TestSite.User("alice", siteAdmin: true);

    /// <summary>Services as they would exist after restarting a site with different key configuration.</summary>
    private static (CryptoService Crypto, VaultService Vault, AuditService Audit) Restart(
        TestSite site, string masterKey, string[]? previousKeys = null)
    {
        var crypto = new CryptoService(masterKey, previousKeys);
        var audit = new AuditService(site.Db, Options.Create(new AuditOptions()), site.Time,
            NullLogger<AuditService>.Instance);
        var vault = new VaultService(site.Db, crypto, site.Time, NullLogger<VaultService>.Instance,
            audit, Options.Create(new HealthOptions()));
        return (crypto, vault, audit);
    }

    private static Task EnsureAsync(TestSite site, CryptoService crypto, AuditService audit) =>
        KeyRotation.EnsureMasterKeyStateAsync(site.Db, crypto, audit, NullLogger<CryptoService>.Instance);

    private static async Task<(Guid GroupId, Guid EntryId)> SeedAsync(TestSite site, string totpSecret = "")
    {
        var group = await site.Groups.CreateGroupAsync(Alice, "ops", "");
        var entry = await site.Vault.CreateEntryAsync(
            Alice, group.Id, "router", "🔐", "https://router.local", username: "admin",
            notes: "notes", password: "correct horse", totpSecret: totpSecret);
        return (group.Id, entry.Id);
    }

    // ---- CryptoService multi-key behaviour ----

    [Fact]
    public void Decrypt_FallsBackToPreviousKeys()
    {
        var oldCrypto = new CryptoService(OldKey);
        var blob = oldCrypto.Encrypt("s3cret");

        var rotated = new CryptoService(NewKey, [OldKey]);
        Assert.Equal("s3cret", rotated.Decrypt(blob));

        Assert.True(rotated.TryDecrypt(blob, out var plain, out var underActive));
        Assert.Equal("s3cret", plain);
        Assert.False(underActive);

        Assert.True(rotated.TryDecrypt(rotated.Encrypt("s3cret"), out _, out var fresh));
        Assert.True(fresh);
    }

    [Fact]
    public void Decrypt_Throws_WhenNoConfiguredKeyMatches()
    {
        var blob = new CryptoService("some-entirely-different-key").Encrypt("s3cret");
        var crypto = new CryptoService(NewKey, [OldKey]);

        Assert.False(crypto.TryDecrypt(blob, out _, out _));
        Assert.Throws<CryptographicException>(() => crypto.Decrypt(blob));
    }

    [Fact]
    public void EncryptAndFingerprint_AlwaysUseTheActiveKey()
    {
        var rotated = new CryptoService(NewKey, [OldKey]);
        var newOnly = new CryptoService(NewKey);
        var oldOnly = new CryptoService(OldKey);

        // Whatever previous keys exist, output is readable by an active-key-only site…
        Assert.Equal("v", newOnly.Decrypt(rotated.Encrypt("v")));
        // …and fingerprints match the active key's, not the previous key's.
        Assert.Equal(newOnly.Fingerprint("v"), rotated.Fingerprint("v"));
        Assert.NotEqual(oldOnly.Fingerprint("v"), rotated.Fingerprint("v"));
    }

    [Fact]
    public void PreviousKeys_AcceptBase64AndPassphraseForms()
    {
        var base64Key = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        var blob = new CryptoService(base64Key).Encrypt("v");
        var rotated = new CryptoService("new-passphrase", [base64Key]);
        Assert.Equal("v", rotated.Decrypt(blob));
    }

    // ---- Canary / fail-fast ----

    [Fact]
    public async Task WrongKey_FailsStartup_EvenWithoutACanary()
    {
        using var site = new TestSite("a");
        await SeedAsync(site);

        // Pre-feature database (no canary row yet) opened with the wrong key.
        var (crypto, _, audit) = Restart(site, "wrong-key-entirely");
        await Assert.ThrowsAsync<InvalidOperationException>(() => EnsureAsync(site, crypto, audit));
    }

    [Fact]
    public async Task WrongKey_FailsStartup_ViaCanary_OnEmptyVault()
    {
        using var site = new TestSite("a");
        await EnsureAsync(site, site.Crypto, site.Audit); // plants canary; vault is empty

        var (crypto, _, audit) = Restart(site, "wrong-key-entirely");
        await Assert.ThrowsAsync<InvalidOperationException>(() => EnsureAsync(site, crypto, audit));
    }

    [Fact]
    public async Task CorrectKey_PlantsCanary_AndStartsQuietly()
    {
        using var site = new TestSite("a");
        await SeedAsync(site);

        await EnsureAsync(site, site.Crypto, site.Audit);

        await using var db = site.Db.CreateDbContext();
        var canary = await db.SiteSettings.SingleAsync(x => x.Id == KeyRotation.CanaryId);
        Assert.Equal(KeyRotation.CanaryPlaintext, site.Crypto.Decrypt(canary.Value));

        // Second start: same key, canary present — still fine.
        await EnsureAsync(site, site.Crypto, site.Audit);
    }

    // ---- The rotation sweep ----

    [Fact]
    public async Task Sweep_Reencrypts_Revisions_Totp_Fingerprints_AndCanary()
    {
        using var site = new TestSite("a");
        await EnsureAsync(site, site.Crypto, site.Audit);
        var (_, entryId) = await SeedAsync(site, totpSecret: "JBSWY3DPEHPK3PXP");
        site.Time.Advance(TimeSpan.FromMinutes(1));
        await site.Vault.ChangePasswordAsync(Alice, entryId, "battery staple");

        // Restart with the new key active and the old key kept for decryption.
        var (crypto, vault, audit) = Restart(site, NewKey, [OldKey]);
        await EnsureAsync(site, crypto, audit);

        // Every blob must now decrypt under the NEW key alone.
        var newOnly = new CryptoService(NewKey);
        await using var db = site.Db.CreateDbContext();
        var revisions = await db.PasswordRevisions.AsNoTracking().ToListAsync();
        Assert.Equal(2, revisions.Count);
        foreach (var revision in revisions)
        {
            Assert.True(newOnly.TryDecrypt(revision.EncryptedPassword, out var plain, out var active));
            Assert.True(active);
            Assert.Equal(newOnly.Fingerprint(plain), revision.Fingerprint);
        }
        var entry = await db.PasswordEntries.AsNoTracking().SingleAsync();
        Assert.Equal("JBSWY3DPEHPK3PXP", ExtractTotpSecret(newOnly, entry.EncryptedTotpSecret!));
        var canary = await db.SiteSettings.AsNoTracking().SingleAsync(x => x.Id == KeyRotation.CanaryId);
        Assert.Equal(KeyRotation.CanaryPlaintext, newOnly.Decrypt(canary.Value));

        // Reveal still returns the original plaintext through the rotated service.
        Assert.Equal("battery staple", await vault.RevealPasswordAsync(Alice, entryId));

        // The sweep is audited.
        var events = await site.Audit.GetEventsAsync(Alice);
        Assert.Contains(events, e => e.Action == AuditActions.KeyRotate);

        // A later start WITHOUT the previous key now succeeds — rotation complete.
        var (finalCrypto, _, finalAudit) = Restart(site, NewKey);
        await EnsureAsync(site, finalCrypto, finalAudit);
    }

    [Fact]
    public async Task Sweep_DoesNotBumpReplicationStamps()
    {
        using var site = new TestSite("a");
        await EnsureAsync(site, site.Crypto, site.Audit);
        var (_, entryId) = await SeedAsync(site, totpSecret: "JBSWY3DPEHPK3PXP");

        await using (var before = site.Db.CreateDbContext())
        {
            var stampsBefore = await before.PasswordRevisions.AsNoTracking()
                .Select(x => new { x.Id, x.OriginSeq, x.UpdatedAtUtc }).ToListAsync();
            var entryBefore = await before.PasswordEntries.AsNoTracking().SingleAsync();

            var (crypto, _, audit) = Restart(site, NewKey, [OldKey]);
            await EnsureAsync(site, crypto, audit);

            await using var after = site.Db.CreateDbContext();
            foreach (var s in stampsBefore)
            {
                var row = await after.PasswordRevisions.AsNoTracking().SingleAsync(x => x.Id == s.Id);
                Assert.Equal(s.OriginSeq, row.OriginSeq);
                Assert.Equal(s.UpdatedAtUtc, row.UpdatedAtUtc);
            }
            var entryAfter = await after.PasswordEntries.AsNoTracking().SingleAsync(x => x.Id == entryId);
            Assert.Equal(entryBefore.OriginSeq, entryAfter.OriginSeq);
            Assert.Equal(entryBefore.UpdatedAtUtc, entryAfter.UpdatedAtUtc);
        }

        // Strongest form of the same claim: a peer that was already in sync
        // pulls nothing new after the sweep (only the key.rotate audit event).
        using var peer = new TestSite("b", site.Time);
        await peer.PullFromAsync(site);
        var request = new Harpo.Replication.PullRequest { SiteId = "b", Vector = await peer.Engine.GetVectorAsync() };
        var response = await site.Engine.BuildResponseAsync(request);
        Assert.Empty(response.Revisions);
        Assert.Empty(response.Entries);
    }

    // ---- Replication during the rotation window ----

    [Fact]
    public async Task Apply_Heals_RowsArrivingFromANotYetRotatedPeer()
    {
        var time = new ManualTime();
        using var oldSite = new TestSite("old", time);
        var (_, entryId) = await SeedAsync(oldSite, totpSecret: "JBSWY3DPEHPK3PXP");

        // "new" site already rotated: NewKey active, OldKey accepted for decryption.
        using var newSite = new TestSite("new", time, NewKey, [OldKey]);
        await newSite.PullFromAsync(oldSite, viaJson: true);

        var newOnly = new CryptoService(NewKey);
        await using var db = newSite.Db.CreateDbContext();
        var revision = await db.PasswordRevisions.AsNoTracking().SingleAsync();
        Assert.True(newOnly.TryDecrypt(revision.EncryptedPassword, out var plain, out var active));
        Assert.True(active);
        Assert.Equal("correct horse", plain);
        Assert.Equal(newOnly.Fingerprint(plain), revision.Fingerprint);
        var entry = await db.PasswordEntries.AsNoTracking().SingleAsync(x => x.Id == entryId);
        Assert.Equal("JBSWY3DPEHPK3PXP", ExtractTotpSecret(newOnly, entry.EncryptedTotpSecret!));
    }

    [Fact]
    public async Task Apply_WithoutPreviousKeys_StoresForeignBlobsVerbatim()
    {
        var time = new ManualTime();
        using var oldSite = new TestSite("old", time);
        await SeedAsync(oldSite);
        await using var source = oldSite.Db.CreateDbContext();
        var original = await source.PasswordRevisions.AsNoTracking().SingleAsync();

        // Misconfigured peer: different key, no previous keys. It must not corrupt
        // what it cannot read — the blob is stored byte-for-byte as received.
        using var strangeSite = new TestSite("strange", time, "some-entirely-different-key");
        await strangeSite.PullFromAsync(oldSite, viaJson: true);

        await using var db = strangeSite.Db.CreateDbContext();
        var stored = await db.PasswordRevisions.AsNoTracking().SingleAsync();
        Assert.Equal(original.EncryptedPassword, stored.EncryptedPassword);
        Assert.Equal(original.Fingerprint, stored.Fingerprint);
    }

    private static string ExtractTotpSecret(CryptoService crypto, string encrypted)
    {
        Assert.True(crypto.TryDecrypt(encrypted, out var plain, out var underActive));
        Assert.True(underActive);
        return plain;
    }
}
