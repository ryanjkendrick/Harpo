using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Harpo.Migrations
{
    /// <inheritdoc />
    public partial class AddVerifiedMembers : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "Verified",
                table: "GroupMembers",
                type: "INTEGER",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "Verified",
                table: "GroupMembers");
        }
    }
}
