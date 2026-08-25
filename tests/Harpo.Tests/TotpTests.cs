using System.Text;
using Harpo.Data;
using Harpo.Security;
using Harpo.Services;

namespace Harpo.Tests;

public class TotpTests
{
    // RFC 6238 Appendix B reference secrets: ASCII "1234567890…" repeated to the
    // digest's natural key length, given here as base32 (how users enter them).
    private static string Rfc6238Secret(int bytes) =>
        Base32Encode(Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("1234567890", 10))[..bytes]));

    private static string Base32Encode(byte[] data)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var output = new StringBuilder();
        var bits = 0;
        var value = 0;
        foreach (var b in data)
        {
            value = (value << 8) | b;
            bits += 8;
            while (bits >= 5)
            {
                output.Append(alphabet[(value >> (bits - 5)) & 31]);
                bits -= 5;
            }
        }
        if (bits > 0)
        {
            output.Append(alphabet[(value << (5 - bits)) & 31]);
        }
        return output.ToString();
    }

    [Theory]
    // RFC 6238 Appendix B test vectors (8 digits).
    [InlineData(59L, "94287082", "SHA1", 20)]
    [InlineData(1111111109L, "07081804", "SHA1", 20)]
    [InlineData(1234567890L, "89005924", "SHA1", 20)]
    [InlineData(20000000000L, "65353130", "SHA1", 20)]
    [InlineData(59L, "46119246", "SHA256", 32)]
    [InlineData(59L, "90693936", "SHA512", 64)]
    public void Rfc_6238_reference_vectors(long unixTime, string expected, string algorithm, int keyBytes)
    {
        var uri = $"otpauth://totp/RFC?secret={Rfc6238Secret(keyBytes)}&digits=8&period=30&algorithm={algorithm}";
        var parameters = Totp.Parse(uri);
        Assert.Equal(expected, Totp.Generate(parameters, DateTimeOffset.FromUnixTimeSeconds(unixTime)));
    }

    [Fact]
    public void Bare_base32_secret_defaults_to_six_digit_sha1()
    {
        // Same vector as above truncated to the standard 6 digits.
        var code = Totp.Generate(Totp.Parse(Rfc6238Secret(20)), DateTimeOffset.FromUnixTimeSeconds(59));
        Assert.Equal("287082", code);
    }

    [Fact]
    public void Base32_is_tolerant_of_formatting()
    {
        var canonical = Totp.Base32Decode("JBSWY3DPEHPK3PXP");
        Assert.Equal(canonical, Totp.Base32Decode("jbsw y3dp ehpk 3pxp"));
        Assert.Equal(canonical, Totp.Base32Decode("JBSW-Y3DP-EHPK-3PXP=="));
        Assert.Throws<ArgumentException>(() => Totp.Base32Decode("not!base32"));
    }

    [Fact]
    public void Otpauth_parsing_honours_parameters_and_rejects_hotp()
    {
        var parameters = Totp.Parse("otpauth://totp/Corp:root?secret=JBSWY3DPEHPK3PXP&digits=8&period=60&algorithm=SHA256&issuer=Corp");
        Assert.Equal(8, parameters.Digits);
        Assert.Equal(60, parameters.Period);
        Assert.Equal("SHA256", parameters.Algorithm);

        Assert.Throws<ArgumentException>(() => Totp.Parse("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP"));
        Assert.Throws<ArgumentException>(() => Totp.Parse("otpauth://totp/x?digits=6"));
        Assert.Throws<ArgumentException>(() => Totp.Normalize("   "));
    }

    [Fact]
    public void Seconds_remaining_tracks_the_period_window()
    {
        var at = DateTimeOffset.FromUnixTimeSeconds(59); // one second before rollover
        var code = Totp.GenerateCurrent("JBSWY3DPEHPK3PXP", at);
        Assert.Equal(1, code.SecondsRemaining);
        Assert.Equal(30, code.Period);
        Assert.Equal(6, code.Code.Length);
    }
}

public class TotpServiceTests : IDisposable
{
    private const string Seed = "JBSWY3DPEHPK3PXP";

    private readonly TestSite _site = new("test");
    private readonly UserContext _alice = TestSite.User("alice");
    private readonly UserContext _bob = TestSite.User("bob");
    private readonly UserContext _admin = TestSite.User("root", siteAdmin: true);

    public void Dispose() => _site.Dispose();

    [Fact]
    public async Task Totp_can_be_set_read_replaced_and_cleared()
    {
        var group = await _site.Groups.CreateGroupAsync(_alice, "Infra", "");
        var entry = await _site.Vault.CreateEntryAsync(_alice, group.Id, "Router", "🌐", "", "", "", "pw1", Seed);

        var code = await _site.Vault.GetTotpCodeAsync(_alice, entry.Id);
        Assert.Equal(Totp.GenerateCurrent(Seed, _site.Time.GetUtcNow()).Code, code.Code);

        // Empty input keeps the secret; explicit clear removes it.
        await _site.Vault.UpdateEntryAsync(_alice, entry.Id, "Router", "🌐", "", "", "", "");
        Assert.Equal(6, (await _site.Vault.GetTotpCodeAsync(_alice, entry.Id)).Code.Length);

        await _site.Vault.UpdateEntryAsync(_alice, entry.Id, "Router", "🌐", "", "", "", "", clearTotp: true);
        await Assert.ThrowsAsync<VaultNotFoundException>(() => _site.Vault.GetTotpCodeAsync(_alice, entry.Id));
    }

    [Fact]
    public async Task Garbage_secrets_are_rejected_with_a_friendly_error()
    {
        var group = await _site.Groups.CreateGroupAsync(_alice, "Infra", "");
        await Assert.ThrowsAsync<VaultValidationException>(
            () => _site.Vault.CreateEntryAsync(_alice, group.Id, "X", "🔐", "", "", "", "pw", "not!base32"));
    }

    [Fact]
    public async Task Viewers_can_read_codes_but_not_configure_them()
    {
        var group = await _site.Groups.CreateGroupAsync(_alice, "Infra", "");
        var entry = await _site.Vault.CreateEntryAsync(_alice, group.Id, "Router", "🌐", "", "", "", "pw1", Seed);
        await _site.Groups.AddMemberAsync(_alice, group.Id, "bob", "", GroupRole.Viewer);

        Assert.Equal(6, (await _site.Vault.GetTotpCodeAsync(_bob, entry.Id)).Code.Length);
        await Assert.ThrowsAsync<VaultAccessDeniedException>(
            () => _site.Vault.UpdateEntryAsync(_bob, entry.Id, "Router", "🌐", "", "", "", Seed));
    }

    [Fact]
    public async Task Code_reveals_are_audited_once_per_viewing_not_per_tick()
    {
        var group = await _site.Groups.CreateGroupAsync(_alice, "Infra", "");
        var entry = await _site.Vault.CreateEntryAsync(_alice, group.Id, "Router", "🌐", "", "", "", "pw1", Seed);

        await _site.Vault.GetTotpCodeAsync(_alice, entry.Id);
        _site.Time.Advance(TimeSpan.FromSeconds(30)); // rollover refresh
        await _site.Vault.GetTotpCodeAsync(_alice, entry.Id);
        _site.Time.Advance(TimeSpan.FromMinutes(3)); // new viewing
        await _site.Vault.GetTotpCodeAsync(_alice, entry.Id);

        var reveals = (await _site.Audit.GetEventsAsync(_admin))
            .Count(e => e.Action == AuditActions.TotpReveal);
        Assert.Equal(2, reveals);

        // Setting and clearing were audited too (totp.change from the create? create is not audited; only updates).
        await _site.Vault.UpdateEntryAsync(_alice, entry.Id, "Router", "🌐", "", "", "", "", clearTotp: true);
        Assert.Contains(await _site.Audit.GetEventsAsync(_admin),
            e => e.Action == AuditActions.TotpChange && e.Detail == "2FA removed");
    }

    [Fact]
    public async Task Totp_replicates_with_the_entry_and_offline_snapshot_carries_the_seed()
    {
        var clock = new ManualTime();
        using var alpha = new TestSite("alpha", clock);
        using var beta = new TestSite("beta", clock);
        var alice = TestSite.User("alice");

        var group = await alpha.Groups.CreateGroupAsync(alice, "Infra", "");
        var entry = await alpha.Vault.CreateEntryAsync(alice, group.Id, "Router", "🌐", "", "", "", "pw1", Seed);
        await beta.PullFromAsync(alpha, viaJson: true);

        // Same master key, replicated ciphertext → identical codes on the other site.
        Assert.Equal(
            (await alpha.Vault.GetTotpCodeAsync(alice, entry.Id)).Code,
            (await beta.Vault.GetTotpCodeAsync(alice, entry.Id)).Code);

        var (_, entries) = await beta.Vault.GetOfflineDataAsync(alice);
        Assert.Equal(Seed, Assert.Single(entries).Totp);
    }
}
