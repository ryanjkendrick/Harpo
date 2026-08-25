using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Harpo.Migrations
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "GroupMembers",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    GroupId = table.Column<Guid>(type: "TEXT", nullable: false),
                    Username = table.Column<string>(type: "TEXT", nullable: false),
                    DisplayName = table.Column<string>(type: "TEXT", nullable: false),
                    Role = table.Column<int>(type: "INTEGER", nullable: false),
                    AddedBy = table.Column<string>(type: "TEXT", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    OriginSiteId = table.Column<string>(type: "TEXT", nullable: false),
                    OriginSeq = table.Column<long>(type: "INTEGER", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    IsDeleted = table.Column<bool>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_GroupMembers", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Groups",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Name = table.Column<string>(type: "TEXT", nullable: false),
                    Description = table.Column<string>(type: "TEXT", nullable: false),
                    CreatedBy = table.Column<string>(type: "TEXT", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    OriginSiteId = table.Column<string>(type: "TEXT", nullable: false),
                    OriginSeq = table.Column<long>(type: "INTEGER", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    IsDeleted = table.Column<bool>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Groups", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "PasswordEntries",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    GroupId = table.Column<Guid>(type: "TEXT", nullable: false),
                    Name = table.Column<string>(type: "TEXT", nullable: false),
                    Icon = table.Column<string>(type: "TEXT", nullable: false),
                    Url = table.Column<string>(type: "TEXT", nullable: false),
                    Username = table.Column<string>(type: "TEXT", nullable: false),
                    Notes = table.Column<string>(type: "TEXT", nullable: false),
                    CreatedBy = table.Column<string>(type: "TEXT", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    UpdatedBy = table.Column<string>(type: "TEXT", nullable: false),
                    OriginSiteId = table.Column<string>(type: "TEXT", nullable: false),
                    OriginSeq = table.Column<long>(type: "INTEGER", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    IsDeleted = table.Column<bool>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PasswordEntries", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "PasswordRevisions",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    EntryId = table.Column<Guid>(type: "TEXT", nullable: false),
                    EncryptedPassword = table.Column<string>(type: "TEXT", nullable: false),
                    CreatedBy = table.Column<string>(type: "TEXT", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    OriginSiteId = table.Column<string>(type: "TEXT", nullable: false),
                    OriginSeq = table.Column<long>(type: "INTEGER", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    IsDeleted = table.Column<bool>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PasswordRevisions", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "PeerCursors",
                columns: table => new
                {
                    OriginSiteId = table.Column<string>(type: "TEXT", nullable: false),
                    LastSeq = table.Column<long>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PeerCursors", x => x.OriginSiteId);
                });

            migrationBuilder.CreateTable(
                name: "SiteCounters",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    NextSeq = table.Column<long>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SiteCounters", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_GroupMembers_GroupId_Username",
                table: "GroupMembers",
                columns: new[] { "GroupId", "Username" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_GroupMembers_OriginSiteId_OriginSeq",
                table: "GroupMembers",
                columns: new[] { "OriginSiteId", "OriginSeq" });

            migrationBuilder.CreateIndex(
                name: "IX_GroupMembers_Username",
                table: "GroupMembers",
                column: "Username");

            migrationBuilder.CreateIndex(
                name: "IX_Groups_OriginSiteId_OriginSeq",
                table: "Groups",
                columns: new[] { "OriginSiteId", "OriginSeq" });

            migrationBuilder.CreateIndex(
                name: "IX_PasswordEntries_GroupId",
                table: "PasswordEntries",
                column: "GroupId");

            migrationBuilder.CreateIndex(
                name: "IX_PasswordEntries_OriginSiteId_OriginSeq",
                table: "PasswordEntries",
                columns: new[] { "OriginSiteId", "OriginSeq" });

            migrationBuilder.CreateIndex(
                name: "IX_PasswordRevisions_EntryId",
                table: "PasswordRevisions",
                column: "EntryId");

            migrationBuilder.CreateIndex(
                name: "IX_PasswordRevisions_OriginSiteId_OriginSeq",
                table: "PasswordRevisions",
                columns: new[] { "OriginSiteId", "OriginSeq" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "GroupMembers");

            migrationBuilder.DropTable(
                name: "Groups");

            migrationBuilder.DropTable(
                name: "PasswordEntries");

            migrationBuilder.DropTable(
                name: "PasswordRevisions");

            migrationBuilder.DropTable(
                name: "PeerCursors");

            migrationBuilder.DropTable(
                name: "SiteCounters");
        }
    }
}
