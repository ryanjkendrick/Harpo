using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Harpo.Migrations
{
    /// <inheritdoc />
    public partial class AddPasswordHealth : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "Fingerprint",
                table: "PasswordRevisions",
                type: "TEXT",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "Strength",
                table: "PasswordRevisions",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_PasswordRevisions_Fingerprint",
                table: "PasswordRevisions",
                column: "Fingerprint");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_PasswordRevisions_Fingerprint",
                table: "PasswordRevisions");

            migrationBuilder.DropColumn(
                name: "Fingerprint",
                table: "PasswordRevisions");

            migrationBuilder.DropColumn(
                name: "Strength",
                table: "PasswordRevisions");
        }
    }
}
