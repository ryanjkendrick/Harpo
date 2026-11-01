using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Harpo.Migrations
{
    /// <inheritdoc />
    public partial class AddPurge : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "IsPurged",
                table: "PasswordEntries",
                type: "INTEGER",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<bool>(
                name: "IsPurged",
                table: "Groups",
                type: "INTEGER",
                nullable: false,
                defaultValue: false);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "IsPurged",
                table: "PasswordEntries");

            migrationBuilder.DropColumn(
                name: "IsPurged",
                table: "Groups");
        }
    }
}
