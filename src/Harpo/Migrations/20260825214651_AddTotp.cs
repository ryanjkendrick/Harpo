using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Harpo.Migrations
{
    /// <inheritdoc />
    public partial class AddTotp : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "EncryptedTotpSecret",
                table: "PasswordEntries",
                type: "TEXT",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "EncryptedTotpSecret",
                table: "PasswordEntries");
        }
    }
}
