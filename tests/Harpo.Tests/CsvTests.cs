using System.Text;
using Harpo.Import;

namespace Harpo.Tests;

/// <summary>The RFC 4180 reader and writer behind import and export.</summary>
public class CsvTests
{
    private static string[][] Cells(string text, char? delimiter = null) =>
        CsvReader.Read(text, delimiter).Select(r => r.Cells.ToArray()).ToArray();

    [Fact]
    public void Plain_records_split_on_commas_and_line_breaks()
    {
        Assert.Equal([["a", "b", "c"], ["1", "2", "3"]], Cells("a,b,c\r\n1,2,3\r\n"));
        Assert.Equal([["a", "b"], ["1", "2"]], Cells("a,b\n1,2"));
        Assert.Equal([["a", "b"], ["1", "2"], ["3", "4"]], Cells("a,b\r1,2\r3,4")); // old Mac line ends
    }

    [Fact]
    public void Quoted_fields_keep_delimiters_quotes_and_line_breaks()
    {
        var rows = Cells("name,notes\r\n\"Mail, work\",\"line one\r\nline \"\"two\"\"\nline three\"\r\n");
        Assert.Equal(2, rows.Length);
        Assert.Equal("Mail, work", rows[1][0]);
        Assert.Equal("line one\r\nline \"two\"\nline three", rows[1][1]);
    }

    [Fact]
    public void Cells_are_not_trimmed_and_empty_cells_survive()
    {
        Assert.Equal([[" pass word ", "", "x", ""]], Cells(" pass word ,,x,"));
        Assert.Equal([["", ""]], Cells("\"\",\"\""));
    }

    [Fact]
    public void A_byte_order_mark_and_blank_lines_are_ignored()
    {
        Assert.Equal([["name", "password"], ["a", "b"]], Cells("﻿name,password\r\n\r\n\na,b\r\n\r\n"));
    }

    [Fact]
    public void Records_report_the_line_they_start_on()
    {
        var records = CsvReader.Read("h1,h2\r\n\"multi\r\nline\",x\r\n\r\nlast,y\r\n");
        Assert.Equal([1, 2, 5], records.Select(r => r.Line));
    }

    [Fact]
    public void Text_after_a_closing_quote_and_stray_quotes_are_kept_literally()
    {
        Assert.Equal([["abcdef", "x\"y"]], Cells("\"abc\"def,x\"y"));
    }

    [Fact]
    public void An_unterminated_quote_is_an_error_naming_its_line()
    {
        var ex = Assert.Throws<CsvFormatException>(() => CsvReader.Read("a,b\r\n1,\"never closed\r\n2,3\r\n"));
        Assert.Contains("line 2", ex.Message);
    }

    [Theory]
    [InlineData("name,url,password", ',')]
    [InlineData("name;url;password", ';')]
    [InlineData("name\turl\tpassword", '\t')]
    [InlineData("\"a;b\",c,d", ',')]           // the semicolon is inside quotes
    [InlineData("\"a,b,c\";d;e", ';')]
    [InlineData("single", ',')]                 // nothing to go on: comma
    public void The_delimiter_is_detected_from_the_first_line(string firstLine, char expected)
    {
        Assert.Equal(expected, CsvReader.DetectDelimiter(firstLine + "\r\nx,y;z\r\n"));
    }

    [Fact]
    public void Semicolon_files_from_european_spreadsheets_read_like_comma_files()
    {
        Assert.Equal([["Title", "Password"], ["Bank, private", "p;w"]],
            Cells("Title;Password\r\n\"Bank, private\";\"p;w\"\r\n"));
    }

    [Theory]
    [InlineData("plain", "plain")]
    [InlineData("a,b", "\"a,b\"")]
    [InlineData("say \"hi\"", "\"say \"\"hi\"\"\"")]
    [InlineData("two\nlines", "\"two\nlines\"")]
    [InlineData("semi;colon", "\"semi;colon\"")]
    [InlineData(" padded ", "\" padded \"")]
    [InlineData("", "")]
    public void The_writer_quotes_what_needs_quoting(string cell, string expected)
    {
        Assert.Equal(expected, CsvWriter.Escape(cell));
    }

    [Theory]
    [InlineData("=SUM(A1:A9)", "\"'=SUM(A1:A9)\"")]
    [InlineData("+1 555 0100", "\"'+1 555 0100\"")]
    [InlineData("-x9kQ!", "\"'-x9kQ!\"")]
    [InlineData("@cmd", "\"'@cmd\"")]
    [InlineData("\tlead", "\"'\tlead\"")]
    [InlineData("\rlead", "\"'\rlead\"")]
    [InlineData("=HYPERLINK(\"http://evil\",\"x\")", "\"'=HYPERLINK(\"\"http://evil\"\",\"\"x\"\")\"")]
    [InlineData("a=b", "a=b")]                  // only the first character counts
    public void Cells_a_spreadsheet_would_run_as_formulas_are_neutralised(string cell, string expected)
    {
        Assert.Equal(expected, CsvWriter.Escape(cell));
    }

    [Theory]
    [InlineData("'=SUM(A1)", "=SUM(A1)")]
    [InlineData("'-dash", "-dash")]
    [InlineData("'plain", "'plain")]            // a quote before anything else is the value's own
    [InlineData("'", "'")]
    [InlineData("=raw", "=raw")]
    public void Reading_back_removes_only_the_quote_the_writer_added(string cell, string expected)
    {
        Assert.Equal(expected, CsvInjection.Undo(cell));
    }

    [Fact]
    public void Whatever_the_writer_writes_the_reader_reads_back()
    {
        string[][] rows =
        [
            ["name", "notes"],
            ["Mail, \"work\"", "line 1\nline 2\r\nline 3"],
            ["=1+1", " spaces "],
            ["", "ünïcödé 🔐"],
        ];
        var output = new StringBuilder();
        foreach (var row in rows)
        {
            CsvWriter.AppendRecord(output, row);
        }
        var back = CsvReader.Read(output.ToString()).Select(r => r.Cells.Select(CsvInjection.Undo).ToArray()).ToArray();
        Assert.Equal(rows, back);
    }

    [Fact]
    public void Csv_files_are_utf8_with_a_byte_order_mark()
    {
        var bytes = CsvWriter.ToUtf8WithBom("é\r\n");
        Assert.Equal(new byte[] { 0xEF, 0xBB, 0xBF, 0xC3, 0xA9, 0x0D, 0x0A }, bytes);
    }

    [Fact]
    public void Files_are_decoded_from_utf8_utf16_or_latin1()
    {
        Assert.Equal("é,🔐", ImportReader.Decode([0xEF, 0xBB, 0xBF, .. Encoding.UTF8.GetBytes("é,🔐")]));
        Assert.Equal("é,🔐", ImportReader.Decode(Encoding.UTF8.GetBytes("é,🔐")));
        Assert.Equal("é,x", ImportReader.Decode([0xFF, 0xFE, .. Encoding.Unicode.GetBytes("é,x")]));
        Assert.Equal("é,x", ImportReader.Decode([0xFE, 0xFF, .. Encoding.BigEndianUnicode.GetBytes("é,x")]));
        Assert.Equal("café", ImportReader.Decode([0x63, 0x61, 0x66, 0xE9])); // Windows-1252 / Latin-1, not UTF-8
    }
}
