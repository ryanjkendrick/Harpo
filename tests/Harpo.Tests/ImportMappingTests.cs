using Harpo.Import;
using static Harpo.Import.ImportField;

namespace Harpo.Tests;

/// <summary>Reading other managers' exports: the column mapping guessed from their header rows.</summary>
public class ImportMappingTests
{
    private static ImportField[] Guess(string headerLine) =>
        ImportReader.GuessMapping(ImportReader.ReadCsv(headerLine + "\r\nx\r\n").Columns);

    [Fact]
    public void Bitwarden_needs_no_clicks()
    {
        Assert.Equal(
            [Ignore, Ignore, Ignore, Name, Notes, Ignore, Ignore, Url, Username, Password, Totp],
            Guess("folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp"));
    }

    [Fact]
    public void OnePassword_needs_no_clicks()
    {
        Assert.Equal([Name, Url, Username, Password, Totp, Ignore, Ignore, Ignore, Notes],
            Guess("Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes"));
        Assert.Equal([Name, Url, Username, Password, Notes], Guess("Title,Website,Username,Password,Notes"));
    }

    [Fact]
    public void KeePass_needs_no_clicks()
    {
        Assert.Equal([Name, Username, Password, Url, Notes], Guess("Title,Username,Password,URL,Notes"));
        // KeePassXC, quoted, with its group and 2FA columns
        Assert.Equal([Ignore, Name, Username, Password, Url, Notes, Totp, Icon, Ignore, Ignore],
            Guess("\"Group\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\",\"TOTP\",\"Icon\",\"Last Modified\",\"Created\""));
        // KeePass 2's own CSV
        Assert.Equal([Name, Username, Password, Url, Notes], Guess("\"Account\",\"Login Name\",\"Password\",\"Web Site\",\"Comments\""));
    }

    [Fact]
    public void LastPass_needs_no_clicks()
    {
        Assert.Equal([Url, Username, Password, Notes, Name, Ignore, Totp], Guess("url,username,password,extra,name,grouping,totp"));
        Assert.Equal([Url, Username, Password, Totp, Notes, Name, Ignore, Ignore],
            Guess("url,username,password,totp,extra,name,grouping,fav"));
    }

    [Fact]
    public void Chrome_and_Edge_need_no_clicks()
    {
        Assert.Equal([Name, Url, Username, Password, Notes], Guess("name,url,username,password,note"));
        Assert.Equal([Name, Url, Username, Password], Guess("name,url,username,password"));
    }

    [Fact]
    public void Harpos_own_csv_needs_no_clicks()
    {
        Assert.Equal([Name, Url, Username, Password, Notes, Totp], Guess(string.Join(',', VaultExport.CsvColumns)));
    }

    [Fact]
    public void Case_spacing_and_a_byte_order_mark_do_not_matter()
    {
        Assert.Equal([Name, Username, Password], Guess("﻿ NAME , User Name ,login-password"));
    }

    [Fact]
    public void A_field_named_twice_is_taken_from_the_first_column()
    {
        Assert.Equal([Name, Ignore, Password, Ignore], Guess("name,title,password,pass"));
    }

    [Fact]
    public void Unknown_columns_are_ignored_and_unnamed_ones_get_a_label()
    {
        var table = ImportReader.ReadCsv("name,,colour\r\na,b,c,d\r\n");
        Assert.Equal(["name", "Column 2", "colour", "Column 4"], table.Columns);
        Assert.Equal([Name, Ignore, Ignore, Ignore], ImportReader.GuessMapping(table.Columns));
    }

    [Theory]
    [InlineData("folder", true)]
    [InlineData("grouping", true)]
    [InlineData("Group", true)]
    [InlineData("collections", true)]
    [InlineData("name", false)]
    public void Folder_columns_are_recognised(string header, bool expected)
    {
        Assert.Equal(expected, ImportReader.IsFolderColumn(header));
    }

    [Fact]
    public void Rows_are_built_under_the_mapping_with_the_line_they_came_from()
    {
        var table = ImportReader.ReadCsv(
            "folder,name,login_username,login_password,notes,login_uri,login_totp\r\n" +
            "Work,Mail,me@example.com,\"p,w\",\"two\nlines\",mail.example.com,JBSWY3DPEHPK3PXP\r\n" +
            ",Short\r\n" +
            ",\"'=SUM(1)\",,\"'-pw\"\r\n");
        var rows = ImportReader.BuildRows(table, ImportReader.GuessMapping(table.Columns));

        Assert.Equal(3, rows.Count);
        Assert.Equal(new ImportRow(2, "Mail", "me@example.com", "p,w", "mail.example.com", "two\nlines", "JBSWY3DPEHPK3PXP"), rows[0]);
        Assert.Equal(new ImportRow(4, "Short", "", "", "", "", ""), rows[1]);        // a short row: missing cells are empty
        Assert.Equal(("'=SUM(1)", "'-pw"), (rows[2].Name, rows[2].Password));    // not Harpo's file: a leading quote is the value's own
    }

    [Fact]
    public void A_csv_with_harpos_own_header_has_the_formula_guard_taken_off()
    {
        var table = ImportReader.ReadCsv(
            "name,login_uri,login_username,login_password,notes,login_totp\r\n" +
            "\"'=SUM(1)\",,\"'@ops\",\"'-pw\",\"''=my own quote\",\r\n" +
            "Plain,,,\"'plain\",,\r\n");

        Assert.Equal(ImportTable.HarpoCsvFormat, table.Format);
        var rows = ImportReader.BuildRows(table, ImportReader.GuessMapping(table.Columns));
        Assert.Equal(("=SUM(1)", "@ops", "-pw", "'=my own quote"), (rows[0].Name, rows[0].Username, rows[0].Password, rows[0].Notes));
        Assert.Equal("'plain", rows[1].Password);   // a lone quote before plain text is never a guard
    }

    [Theory]
    [InlineData("Name,Login_URI,login_username,login_password,notes,login_totp", true)]     // case does not matter
    [InlineData("name,login_uri,login_username,login_password,notes", false)]             // a column short
    [InlineData("folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp", false)] // real Bitwarden
    public void Only_harpos_exact_header_marks_a_file_as_harpos(string header, bool harpo)
    {
        var table = ImportReader.ReadCsv(header + "\r\n");
        Assert.Equal(harpo ? ImportTable.HarpoCsvFormat : ImportTable.CsvFormat, table.Format);
    }

    [Fact]
    public void A_harpo_json_export_reads_as_a_table_of_its_fields()
    {
        var json = VaultExport.ToJson("Ops", false, "alice", "alpha", new DateTime(2026, 1, 1),
            [new ExportEntry("Router", "🖥️", "https://r", "admin", "'=pw", "n1\nn2", "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP")]);
        var table = ImportReader.Read("export.json", json);

        Assert.Equal("Harpo JSON", table.Format);
        var rows = ImportReader.BuildRows(table, ImportReader.GuessMapping(table.Columns));
        // JSON carries no formula guard, so nothing is taken off.
        Assert.Equal(new ImportRow(1, "Router", "admin", "'=pw", "https://r", "n1\nn2",
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP", "🖥️"), Assert.Single(rows));
    }

    [Theory]
    [InlineData("{\"items\": []}")]
    [InlineData("{\"format\": \"bitwarden\", \"entries\": []}")]
    [InlineData("{ not json")]
    public void Other_json_is_refused_with_a_message(string json)
    {
        Assert.Throws<CsvFormatException>(() => ImportReader.Read("other.json", json));
    }

    [Fact]
    public void An_empty_file_is_refused()
    {
        Assert.Throws<CsvFormatException>(() => ImportReader.Read("empty.csv", "\r\n"));
    }
}
