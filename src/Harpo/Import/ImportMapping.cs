using System.Text;
using System.Text.Json;

namespace Harpo.Import;

/// <summary>What a column of an imported file becomes in Harpo.</summary>
public enum ImportField
{
    Ignore,
    Name,
    Username,
    Password,
    Url,
    Notes,
    Totp,
    Icon,
}

/// <summary>One entry to create, as read from a file. <see cref="Row"/> is where it came from, for the summary.</summary>
public sealed record ImportRow(
    int Row, string Name, string Username, string Password, string Url, string Notes, string Totp, string Icon = "");

/// <summary>
/// A file read for import, before the user has confirmed how its columns map:
/// the column names, every data row (with the line or position it came from),
/// and Harpo's guess at the mapping.
/// </summary>
public sealed class ImportTable
{
    public required IReadOnlyList<string> Columns { get; init; }
    public required IReadOnlyList<CsvRecord> Rows { get; init; }
    /// <summary>"CSV", "Harpo CSV" (the header is exactly Harpo's export's) or "Harpo JSON" — shown in the dialog and the audit detail.</summary>
    public required string Format { get; init; }

    public const string CsvFormat = "CSV";
    public const string HarpoCsvFormat = "Harpo CSV";
    public const string HarpoJsonFormat = "Harpo JSON";

    /// <summary>The cell of a row under a column; empty where a short row has none.</summary>
    public static string Cell(CsvRecord row, int column) => column < row.Cells.Count ? row.Cells[column] : "";
}

/// <summary>
/// Reads a file chosen for import (CSV from another password manager, or
/// Harpo's own JSON export), guesses which column is which from the header
/// row, and turns the rows into <see cref="ImportRow"/>s under a mapping.
/// Everything happens in memory; nothing here touches the disk.
/// </summary>
public static class ImportReader
{
    /// <summary>Largest file the import dialog accepts.</summary>
    public const long MaxBytes = 5 * 1024 * 1024;

    /// <summary>Most rows one import creates; a larger export should be split.</summary>
    public const int MaxRows = 5000;

    /// <summary>
    /// Text from file bytes: UTF-8 (with or without a byte order mark) or
    /// UTF-16 with one; anything that is not valid UTF-8 is read as Latin-1,
    /// which is what older Windows exports usually are close enough to.
    /// </summary>
    public static string Decode(byte[] bytes)
    {
        if (bytes.Length >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE)
        {
            return Encoding.Unicode.GetString(bytes, 2, bytes.Length - 2);
        }
        if (bytes.Length >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF)
        {
            return Encoding.BigEndianUnicode.GetString(bytes, 2, bytes.Length - 2);
        }
        var offset = bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF ? 3 : 0;
        try
        {
            return new UTF8Encoding(false, throwOnInvalidBytes: true).GetString(bytes, offset, bytes.Length - offset);
        }
        catch (DecoderFallbackException)
        {
            return Encoding.Latin1.GetString(bytes);
        }
    }

    /// <summary>Reads a file as Harpo JSON when it is one (by name or by content), otherwise as CSV.</summary>
    public static ImportTable Read(string fileName, string text)
    {
        var trimmed = text.TrimStart('﻿', ' ', '\t', '\r', '\n');
        if (fileName.EndsWith(".json", StringComparison.OrdinalIgnoreCase) || trimmed.StartsWith('{'))
        {
            return ReadHarpoJson(trimmed);
        }
        return ReadCsv(text);
    }

    public static ImportTable ReadCsv(string text)
    {
        var records = CsvReader.Read(text);
        if (records.Count == 0)
        {
            throw new CsvFormatException("The file is empty.");
        }
        var header = records[0].Cells;
        var width = records.Max(r => r.Cells.Count);
        var columns = Enumerable.Range(0, width)
            .Select(i => i < header.Count && header[i].Trim().Length > 0 ? header[i].Trim() : $"Column {i + 1}")
            .ToList();
        // Only a file with Harpo's own header had the formula guard applied on
        // the way out; another manager's file is taken exactly as it is.
        var isHarpo = header.Count == VaultExport.CsvColumns.Length
            && header.Select(h => h.Trim()).SequenceEqual(VaultExport.CsvColumns, StringComparer.OrdinalIgnoreCase);
        return new ImportTable
        {
            Columns = columns,
            Rows = records.Skip(1).ToList(),
            Format = isHarpo ? ImportTable.HarpoCsvFormat : ImportTable.CsvFormat,
        };
    }

    /// <summary>The fields of Harpo's JSON export, in the order they become columns.</summary>
    private static readonly string[] JsonFields = ["name", "icon", "url", "username", "password", "notes", "totp"];

    public static ImportTable ReadHarpoJson(string text)
    {
        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(text);
        }
        catch (JsonException)
        {
            throw new CsvFormatException("This file is not valid JSON.");
        }
        using (document)
        {
            if (document.RootElement.ValueKind != JsonValueKind.Object
                || !document.RootElement.TryGetProperty("format", out var format)
                || format.ValueKind != JsonValueKind.String
                || format.GetString() != VaultExport.JsonFormatName
                || !document.RootElement.TryGetProperty("entries", out var entries)
                || entries.ValueKind != JsonValueKind.Array)
            {
                throw new CsvFormatException("This JSON file is not a Harpo export. Other managers' exports can be imported as CSV.");
            }
            var rows = new List<CsvRecord>();
            var number = 0;
            foreach (var entry in entries.EnumerateArray())
            {
                number++;
                var cells = JsonFields
                    .Select(field => entry.ValueKind == JsonValueKind.Object
                                     && entry.TryGetProperty(field, out var value)
                                     && value.ValueKind == JsonValueKind.String
                        ? value.GetString() ?? ""
                        : "")
                    .ToArray();
                rows.Add(new CsvRecord(number, cells));
            }
            return new ImportTable { Columns = JsonFields, Rows = rows, Format = ImportTable.HarpoJsonFormat };
        }
    }

    // Header names as the common password managers write them, compared with
    // case, spaces, underscores and dashes ignored ("login_username" = "Login Username").
    //   Bitwarden:  folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp
    //   1Password:  Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes  (older: Website)
    //   KeePass:    Title,Username,Password,URL,Notes  (KeePassXC adds Group,TOTP; KeePass 2: Account,Login Name,Web Site,Comments)
    //   LastPass:   url,username,password,totp,extra,name,grouping,fav
    //   Chrome/Edge: name,url,username,password,note
    private static readonly Dictionary<string, ImportField> KnownHeaders = new(StringComparer.Ordinal)
    {
        ["name"] = ImportField.Name,
        ["title"] = ImportField.Name,
        ["account"] = ImportField.Name,
        ["entry"] = ImportField.Name,
        ["itemname"] = ImportField.Name,

        ["username"] = ImportField.Username,
        ["loginusername"] = ImportField.Username,
        ["loginname"] = ImportField.Username,
        ["login"] = ImportField.Username,
        ["user"] = ImportField.Username,
        ["userid"] = ImportField.Username,
        ["email"] = ImportField.Username,

        ["password"] = ImportField.Password,
        ["loginpassword"] = ImportField.Password,
        ["pass"] = ImportField.Password,
        ["pwd"] = ImportField.Password,

        ["url"] = ImportField.Url,
        ["loginuri"] = ImportField.Url,
        ["loginurl"] = ImportField.Url,
        ["uri"] = ImportField.Url,
        ["website"] = ImportField.Url,
        ["web"] = ImportField.Url,
        ["address"] = ImportField.Url,

        ["notes"] = ImportField.Notes,
        ["note"] = ImportField.Notes,
        ["extra"] = ImportField.Notes,
        ["comments"] = ImportField.Notes,
        ["comment"] = ImportField.Notes,

        ["totp"] = ImportField.Totp,
        ["logintotp"] = ImportField.Totp,
        ["otpauth"] = ImportField.Totp,
        ["otp"] = ImportField.Totp,
        ["2fa"] = ImportField.Totp,
        ["onetimepassword"] = ImportField.Totp,

        ["icon"] = ImportField.Icon,
    };

    // Folders and groups, which the import does not use: everything goes into the open vault.
    private static readonly HashSet<string> FolderHeaders =
        new(["folder", "grouping", "group", "collections", "collection", "path", "category"], StringComparer.Ordinal);

    private static string Normalize(string header)
    {
        var builder = new StringBuilder(header.Length);
        foreach (var c in header.Trim().TrimStart('﻿'))
        {
            if (char.IsLetterOrDigit(c))
            {
                builder.Append(char.ToLowerInvariant(c));
            }
        }
        return builder.ToString();
    }

    /// <summary>True for a column that holds folders or groups (shown, but not imported).</summary>
    public static bool IsFolderColumn(string header) => FolderHeaders.Contains(Normalize(header));

    /// <summary>
    /// A mapping guessed from the column names. Each Harpo field is taken by the
    /// first column that names it; any later column naming it again is ignored.
    /// </summary>
    public static ImportField[] GuessMapping(IReadOnlyList<string> columns)
    {
        var mapping = new ImportField[columns.Count];
        var taken = new HashSet<ImportField>();
        for (var i = 0; i < columns.Count; i++)
        {
            if (KnownHeaders.TryGetValue(Normalize(columns[i]), out var field) && taken.Add(field))
            {
                mapping[i] = field;
            }
        }
        return mapping;
    }

    /// <summary>
    /// The rows under a mapping. In a CSV Harpo itself exported, a value guarded
    /// against formula injection gets its quote back off (<see cref="CsvInjection.Undo"/>);
    /// a file from anywhere else is imported exactly as written.
    /// </summary>
    public static List<ImportRow> BuildRows(ImportTable table, IReadOnlyList<ImportField> mapping)
    {
        var undo = table.Format == ImportTable.HarpoCsvFormat;
        string Value(CsvRecord row, ImportField field)
        {
            var index = -1;
            for (var i = 0; i < mapping.Count; i++)
            {
                if (mapping[i] == field)
                {
                    index = i;
                    break;
                }
            }
            if (index < 0)
            {
                return "";
            }
            var cell = ImportTable.Cell(row, index);
            return undo ? CsvInjection.Undo(cell) : cell;
        }

        return table.Rows
            .Select(r => new ImportRow(
                r.Line,
                Value(r, ImportField.Name),
                Value(r, ImportField.Username),
                Value(r, ImportField.Password),
                Value(r, ImportField.Url),
                Value(r, ImportField.Notes),
                Value(r, ImportField.Totp),
                Value(r, ImportField.Icon)))
            .ToList();
    }
}
