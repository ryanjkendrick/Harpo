using System.Globalization;
using System.IO.Compression;
using System.Text;

namespace Harpo.Import;

/// <summary>One shared group as it goes into the all-groups archive: its name and its live entries.</summary>
public sealed record GroupExport(string Name, IReadOnlyList<ExportEntry> Entries);

/// <summary>What the all-groups export would hold, counted without decrypting anything.</summary>
public sealed record AllGroupsSummary(int Groups, int Entries);

/// <summary>A finished all-groups archive: what the browser saves, and the counts for the audit trail.</summary>
public sealed record AllGroupsExportFile(string FileName, byte[] Content, int GroupCount, int EntryCount)
{
    public const string ContentType = "application/zip";
}

/// <summary>
/// Writes every shared group of a site into one zip archive: a file per group,
/// each exactly what a per-vault export of that group would be (so it imports
/// back into a Harpo vault unchanged), and a README.txt that says what the
/// archive is. Built in memory; nothing touches the disk.
/// </summary>
public static class AllGroupsArchive
{
    public const string ReadmeName = "README.txt";

    /// <summary>Longest file name stem, in UTF-8 bytes (file systems allow 255 for the whole name).</summary>
    public const int MaxStemBytes = 100;

    /// <summary>The download's name: Harpo, the site, the date.</summary>
    public static string FileName(string siteId, DateTime date) =>
        $"harpo-{VaultExport.Slug(siteId, "site")}-all-groups-{date:yyyy-MM-dd}.zip";

    public static byte[] Build(
        IReadOnlyList<GroupExport> groups, ExportFormat format, string exportedBy, string siteId, DateTime exportedAtUtc)
    {
        var used = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ReadmeName };
        var files = new List<(GroupExport Group, string File)>(groups.Count);
        foreach (var group in groups)
        {
            files.Add((group, EntryName(group.Name, format, used)));
        }

        using var buffer = new MemoryStream();
        using (var zip = new ZipArchive(buffer, ZipArchiveMode.Create, leaveOpen: true))
        {
            Add(zip, ReadmeName, Encoding.UTF8.GetBytes(Readme(files, format, exportedBy, siteId, exportedAtUtc)),
                exportedAtUtc);
            foreach (var (group, file) in files)
            {
                var content = format == ExportFormat.Json
                    ? Encoding.UTF8.GetBytes(VaultExport.ToJson(group.Name, false, exportedBy, siteId, exportedAtUtc, group.Entries))
                    : CsvWriter.ToUtf8WithBom(VaultExport.ToCsv(group.Entries));
                Add(zip, file, content, exportedAtUtc);
            }
        }
        return buffer.ToArray();
    }

    private static void Add(ZipArchive zip, string name, byte[] content, DateTime whenUtc)
    {
        var entry = zip.CreateEntry(name, CompressionLevel.Optimal);
        entry.LastWriteTime = new DateTimeOffset(DateTime.SpecifyKind(whenUtc, DateTimeKind.Utc));
        using var stream = entry.Open();
        stream.Write(content);
    }

    /// <summary>
    /// A file name for a group inside the archive, safe to extract anywhere and
    /// not yet in <paramref name="used"/> (which it is then added to). Group
    /// names are free text, so: path separators, the characters Windows
    /// reserves, control and invisible formatting characters (a right-to-left
    /// override could disguise the extension) become "_"; runs of dots become
    /// one, so ".." cannot survive; leading and trailing dots, spaces and "_"
    /// go; Windows device names (CON, NUL, COM1…) get a "_" before any dot; the stem is cut to
    /// <see cref="MaxStemBytes"/> on a character boundary. Names are compared
    /// ignoring case, as Windows and macOS do: a second "Ops" becomes "Ops (2)".
    /// </summary>
    public static string EntryName(string groupName, ExportFormat format, ISet<string> used)
    {
        var stem = Stem(groupName);
        var extension = "." + VaultExport.Extension(format);
        var name = stem + extension;
        for (var n = 2; !used.Add(name); n++)
        {
            name = $"{stem} ({n}){extension}";
        }
        return name;
    }

    private static readonly HashSet<string> DeviceNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "CON", "PRN", "AUX", "NUL",
        "COM0", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT0", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    };

    private static readonly char[] TrimmedAtTheEnds = ['.', ' ', '_'];

    internal static string Stem(string groupName)
    {
        var cleaned = new StringBuilder(groupName.Length);
        foreach (var rune in groupName.EnumerateRunes()) // a lone surrogate arrives as U+FFFD
        {
            var unsafeChar = Rune.GetUnicodeCategory(rune) is UnicodeCategory.Control or UnicodeCategory.Format
                    or UnicodeCategory.LineSeparator or UnicodeCategory.ParagraphSeparator
                    or UnicodeCategory.Surrogate or UnicodeCategory.PrivateUse or UnicodeCategory.OtherNotAssigned
                || (rune.IsAscii && "/\\<>:\"|?*".Contains((char)rune.Value));
            if (unsafeChar)
            {
                cleaned.Append('_');
            }
            else if (Rune.IsWhiteSpace(rune))
            {
                cleaned.Append(' ');
            }
            else if (rune.Value == '.' && cleaned.Length > 0 && cleaned[^1] == '.')
            {
                // ".." never survives, whatever surrounds it.
            }
            else
            {
                cleaned.Append(rune.ToString());
            }
        }

        var stem = Truncate(Collapse(cleaned.ToString()).Trim(TrimmedAtTheEnds), MaxStemBytes).Trim(TrimmedAtTheEnds);
        if (stem.Length == 0)
        {
            return "group";
        }
        // Windows reserves a device name with any extension too ("NUL.txt"), so the "_" goes before the first dot.
        var beforeDot = stem.Split('.', 2)[0].TrimEnd(' ');
        return DeviceNames.Contains(beforeDot) ? beforeDot + "_" + stem[beforeDot.Length..] : stem;
    }

    /// <summary>Runs of "_" or of spaces collapse to one, so a name of separators does not become a wall of them.</summary>
    private static string Collapse(string value)
    {
        var output = new StringBuilder(value.Length);
        foreach (var c in value)
        {
            if ((c is '_' or ' ') && output.Length > 0 && output[^1] == c)
            {
                continue;
            }
            output.Append(c);
        }
        return output.ToString();
    }

    private static string Truncate(string value, int maxBytes)
    {
        if (Encoding.UTF8.GetByteCount(value) <= maxBytes)
        {
            return value;
        }
        var output = new StringBuilder();
        var bytes = 0;
        // Whole text elements, so an emoji or an accented letter is never cut in half.
        var elements = StringInfo.GetTextElementEnumerator(value);
        while (elements.MoveNext())
        {
            var element = elements.GetTextElement();
            bytes += Encoding.UTF8.GetByteCount(element);
            if (bytes > maxBytes)
            {
                break;
            }
            output.Append(element);
        }
        return output.ToString();
    }

    /// <summary>A group name as one line of the README: no control characters, nothing to break the layout.</summary>
    private static string OneLine(string value)
    {
        var output = new StringBuilder(value.Length);
        foreach (var rune in value.EnumerateRunes())
        {
            output.Append(Rune.IsControl(rune) || Rune.GetUnicodeCategory(rune) is UnicodeCategory.Format
                    or UnicodeCategory.LineSeparator or UnicodeCategory.ParagraphSeparator
                ? " "
                : rune.ToString());
        }
        return output.ToString().Trim();
    }

    private static string Readme(
        IReadOnlyList<(GroupExport Group, string File)> files, ExportFormat format, string exportedBy, string siteId,
        DateTime exportedAtUtc)
    {
        var entries = files.Sum(f => f.Group.Entries.Count);
        var text = new StringBuilder();
        text.Append("Harpo export of all groups\r\n");
        text.Append("==========================\r\n\r\n");
        text.Append($"Site:         {siteId}\r\n");
        text.Append($"Exported at:  {exportedAtUtc.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture)} UTC\r\n");
        text.Append($"Exported by:  {exportedBy}\r\n");
        text.Append($"Format:       {(format == ExportFormat.Json ? "JSON (Harpo's own format)" : "CSV (Bitwarden's column names)")}, one file per group\r\n");
        text.Append($"Contents:     {Count(files.Count, "group", "groups")}, {Count(entries, "entry", "entries")}\r\n\r\n");
        text.Append("THIS ARCHIVE IS NOT ENCRYPTED. Its files hold the current passwords, 2FA\r\n");
        text.Append("secrets and notes of every shared group on the site in plain text. Anyone\r\n");
        text.Append("who gets hold of it can read all of them. The export is recorded in Harpo's\r\n");
        text.Append("audit log. Delete this archive and every file taken out of it, and empty\r\n");
        text.Append("the recycle bin, as soon as you have used it.\r\n\r\n");
        text.Append("Not included: personal vaults (each owner can export their own), deleted\r\n");
        text.Append("groups, deleted entries, and password history.\r\n\r\n");
        text.Append("Each file imports back into a Harpo vault unchanged: open the vault and use\r\n");
        text.Append("Import... in its toolbar.\r\n\r\n");
        text.Append("Groups and their files\r\n");
        text.Append("----------------------\r\n");
        if (files.Count == 0)
        {
            text.Append("(none)\r\n");
        }
        foreach (var (group, file) in files)
        {
            text.Append($"{OneLine(group.Name)}  ->  {file}  ({Count(group.Entries.Count, "entry", "entries")})\r\n");
        }
        return text.ToString();
    }

    internal static string Count(int n, string one, string many) => $"{n} {(n == 1 ? one : many)}";
}
