using System.Text;

namespace Harpo.Import;

/// <summary>One record of a CSV file and the line it starts on (1-based; the header is line 1).</summary>
public sealed record CsvRecord(int Line, IReadOnlyList<string> Cells);

/// <summary>The file could not be read as CSV; the message says where.</summary>
public sealed class CsvFormatException(string message) : Exception(message);

/// <summary>
/// A small RFC 4180 reader: quoted fields, <c>""</c> inside quotes, line breaks
/// inside quoted fields, CRLF, LF or a lone CR between records, a UTF-8 byte
/// order mark at the start, and the delimiter (comma, semicolon or tab) taken
/// from the first line. Cells are returned exactly as written — never trimmed,
/// since a password may begin or end with a space. Blank lines are skipped.
/// </summary>
public static class CsvReader
{
    private static readonly char[] Candidates = [',', ';', '\t'];

    public static List<CsvRecord> Read(string text, char? delimiter = null)
    {
        if (text.Length > 0 && text[0] == '﻿')
        {
            text = text[1..];
        }
        var sep = delimiter ?? DetectDelimiter(text);
        var records = new List<CsvRecord>();
        var cells = new List<string>();
        var cell = new StringBuilder();
        var line = 1;
        var recordLine = 1;
        var i = 0;
        var atCellStart = true;

        void EndCell()
        {
            cells.Add(cell.ToString());
            cell.Clear();
            atCellStart = true;
        }

        void EndRecord()
        {
            EndCell();
            if (!(cells.Count == 1 && cells[0].Length == 0))
            {
                records.Add(new CsvRecord(recordLine, cells.ToArray()));
            }
            cells.Clear();
        }

        while (i < text.Length)
        {
            var c = text[i];
            if (atCellStart && c == '"')
            {
                // A quoted field: runs to the quote that is not doubled.
                var openedOn = line;
                i++;
                var closed = false;
                while (i < text.Length)
                {
                    var q = text[i];
                    if (q == '"')
                    {
                        if (i + 1 < text.Length && text[i + 1] == '"')
                        {
                            cell.Append('"');
                            i += 2;
                            continue;
                        }
                        i++;
                        closed = true;
                        break;
                    }
                    if (q == '\n' || (q == '\r' && (i + 1 >= text.Length || text[i + 1] != '\n')))
                    {
                        line++;
                    }
                    cell.Append(q);
                    i++;
                }
                if (!closed)
                {
                    throw new CsvFormatException(
                        $"The quoted value that starts on line {openedOn} is never closed — the file may be cut short or not be CSV.");
                }
                atCellStart = false;
                continue;
            }

            if (c == sep)
            {
                EndCell();
                i++;
                continue;
            }
            if (c == '\r' || c == '\n')
            {
                EndRecord();
                i += c == '\r' && i + 1 < text.Length && text[i + 1] == '\n' ? 2 : 1;
                line++;
                recordLine = line;
                continue;
            }
            // Anything else, a stray quote in an unquoted field or text after a
            // closing quote included, is taken literally (as spreadsheets do).
            cell.Append(c);
            atCellStart = false;
            i++;
        }
        if (cell.Length > 0 || cells.Count > 0 || !atCellStart)
        {
            EndRecord();
        }
        return records;
    }

    /// <summary>
    /// The delimiter used on the first line, outside quotes: whichever of comma,
    /// semicolon and tab occurs most (comma when none does, or on a tie).
    /// </summary>
    public static char DetectDelimiter(string text)
    {
        var counts = new int[Candidates.Length];
        var inQuotes = false;
        foreach (var c in text)
        {
            if (c == '"')
            {
                inQuotes = !inQuotes;
                continue;
            }
            if (!inQuotes && (c == '\r' || c == '\n'))
            {
                break;
            }
            if (!inQuotes)
            {
                var index = Array.IndexOf(Candidates, c);
                if (index >= 0)
                {
                    counts[index]++;
                }
            }
        }
        var best = 0;
        for (var k = 1; k < counts.Length; k++)
        {
            if (counts[k] > counts[best])
            {
                best = k;
            }
        }
        return Candidates[best];
    }
}

/// <summary>
/// Writes RFC 4180 CSV (comma-separated, CRLF between records) that is safe to
/// open in a spreadsheet: a cell beginning with <c>=</c>, <c>+</c>, <c>-</c>,
/// <c>@</c>, a tab or a carriage return would be taken for a formula, so it is
/// prefixed with a single quote (and quoted). <see cref="CsvInjection.Undo"/>
/// reverses exactly that on the way back in.
/// </summary>
public static class CsvWriter
{
    public static void AppendRecord(StringBuilder output, IEnumerable<string> cells)
    {
        var first = true;
        foreach (var cell in cells)
        {
            if (!first)
            {
                output.Append(',');
            }
            first = false;
            output.Append(Escape(cell));
        }
        output.Append("\r\n");
    }

    public static string Escape(string cell)
    {
        var guarded = CsvInjection.IsDangerous(cell);
        if (guarded)
        {
            cell = "'" + cell;
        }
        var quote = guarded
            || cell.IndexOfAny([',', '"', '\r', '\n', ';', '\t']) >= 0
            || (cell.Length > 0 && (char.IsWhiteSpace(cell[0]) || char.IsWhiteSpace(cell[^1])));
        return quote ? "\"" + cell.Replace("\"", "\"\"") + "\"" : cell;
    }

    /// <summary>The bytes of a CSV document: UTF-8 with a byte order mark, so Excel reads it as UTF-8.</summary>
    public static byte[] ToUtf8WithBom(string csv) =>
        [.. Encoding.UTF8.GetPreamble(), .. Encoding.UTF8.GetBytes(csv)];
}

/// <summary>Spreadsheet formula injection ("CSV injection") and its guard.</summary>
public static class CsvInjection
{
    private static bool IsTrigger(char c) => c is '=' or '+' or '-' or '@' or '\t' or '\r';

    /// <summary>True when a spreadsheet would treat the cell as a formula.</summary>
    public static bool IsDangerous(string cell) => cell.Length > 0 && IsTrigger(cell[0]);

    /// <summary>
    /// Removes the quote <see cref="CsvWriter"/> put in front of a dangerous
    /// cell, so an export read back in is exactly what was exported. Only a
    /// quote followed by one of the trigger characters is removed.
    /// </summary>
    public static string Undo(string cell) =>
        cell.Length > 1 && cell[0] == '\'' && IsTrigger(cell[1]) ? cell[1..] : cell;
}
