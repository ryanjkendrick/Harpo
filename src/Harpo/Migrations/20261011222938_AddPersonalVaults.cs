using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Harpo.Migrations
{
    /// <inheritdoc />
    public partial class AddPersonalVaults : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "OwnerUsername",
                table: "Groups",
                type: "TEXT",
                nullable: false,
                defaultValue: "");

            migrationBuilder.CreateIndex(
                name: "IX_Groups_OwnerUsername",
                table: "Groups",
                column: "OwnerUsername");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_Groups_OwnerUsername",
                table: "Groups");

            migrationBuilder.DropColumn(
                name: "OwnerUsername",
                table: "Groups");
        }
    }
}
