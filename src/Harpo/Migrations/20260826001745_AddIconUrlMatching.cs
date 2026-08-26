using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Harpo.Migrations
{
    /// <inheritdoc />
    public partial class AddIconUrlMatching : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "MatchUrls",
                table: "CustomIcons",
                type: "TEXT",
                nullable: false,
                defaultValue: "");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "MatchUrls",
                table: "CustomIcons");
        }
    }
}
