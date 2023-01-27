using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Identity.Web.Migrations
{
    /// <inheritdoc />
    public partial class twoFactorAppUser : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "TwoFactorAuth",
                table: "AspNetUsers",
                type: "int",
                nullable: false,
                defaultValue: 0);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "TwoFactorAuth",
                table: "AspNetUsers");
        }
    }
}
