using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace Harpo.Import;

/// <summary>
/// Site switch for exporting a vault as a plain-text file. Set
/// <c>Harpo__Export__Enabled=false</c> to remove the feature: the button goes
/// and the download endpoint answers 404, like the offline snapshot when
/// offline access is off.
/// </summary>
public class ExportOptions
{
    public bool Enabled { get; set; } = true;

    /// <summary>Minimum seconds between exports per user (each one decrypts a whole vault).</summary>
    public int MinSecondsBetweenExports { get; set; } = 10;
}

public enum ExportFormat
{
    Csv,
    Json,
}

/// <summary>One entry as it leaves Harpo: its current password only, no history.</summary>
public sealed record ExportEntry(
    string Name, string Icon, string Url, string Username, string Password, string Notes, string Totp);

/// <summary>A finished export: what the browser saves, and how many entries it holds (for the audit trail).</summary>
public sealed record ExportFile(string FileName, string ContentType, byte[] Content, int EntryCount);

/// <summary>
/// Writes a vault's entries as CSV (the Bitwarden column names, so other
/// managers and Harpo itself can read it back) or as Harpo's own JSON, which
/// also keeps the icon and says where and when it came from.
/// </summary>
public static class VaultExport
{
    /// <summary>The CSV header row: Bitwarden's names, which most managers' importers know.</summary>
    public static readonly string[] CsvColumns =
        ["name", "login_uri", "login_username", "login_password", "notes", "login_totp"];

    /// <summary>The <c>format</c> value that marks a JSON file as Harpo's export.</summary>
    public const string JsonFormatName = "harpo-vault-export";

    public static string ToCsv(IEnumerable<ExportEntry> entries)
    {
        var output = new StringBuilder();
        CsvWriter.AppendRecord(output, CsvColumns);
        foreach (var e in entries)
        {
            CsvWriter.AppendRecord(output, [e.Name, e.Url, e.Username, e.Password, e.Notes, e.Totp]);
        }
        return output.ToString();
    }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        // A download (attachment, nosniff), never rendered as HTML: emoji icons
        // and accented names may stay readable instead of \u-escaped.
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    public static string ToJson(
        string vaultName, bool personal, string exportedBy, string siteId, DateTime exportedAtUtc,
        IReadOnlyList<ExportEntry> entries)
    {
        var document = new JsonExport(
            JsonFormatName, 1, exportedAtUtc, exportedBy, siteId,
            new JsonVault(vaultName, personal), entries.Count,
            entries.Select(e => new JsonEntry(e.Name, e.Icon, e.Url, e.Username, e.Password, e.Notes, e.Totp)).ToList());
        return JsonSerializer.Serialize(document, JsonOptions);
    }

    /// <summary>
    /// The suggested file name: Harpo, the vault, the date. A personal vault's
    /// file is called "personal"; anything outside plain letters, digits and
    /// dashes is dropped so every browser and file system takes it as is.
    /// </summary>
    public static string FileName(string vaultName, bool personal, DateTime date, ExportFormat format)
    {
        var slug = new StringBuilder();
        foreach (var c in (personal ? "personal" : vaultName).ToLowerInvariant())
        {
            if (c is >= 'a' and <= 'z' or >= '0' and <= '9')
            {
                slug.Append(c);
            }
            else if (slug.Length > 0 && slug[^1] != '-')
            {
                slug.Append('-');
            }
        }
        var name = slug.ToString().Trim('-');
        if (name.Length > 40)
        {
            name = name[..40].Trim('-');
        }
        name = name.Length == 0 ? "vault" : name;
        return $"harpo-{name}-{date:yyyy-MM-dd}.{(format == ExportFormat.Csv ? "csv" : "json")}";
    }

    private sealed record JsonExport(
        string Format, int Version, DateTime ExportedAtUtc, string ExportedBy, string Site,
        JsonVault Vault, int EntryCount, List<JsonEntry> Entries);

    private sealed record JsonVault(string Name, bool Personal);

    private sealed record JsonEntry(
        string Name, string Icon, string Url, string Username, string Password, string Notes, string Totp);
}
