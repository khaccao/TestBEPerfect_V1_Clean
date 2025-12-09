using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PerfectKeyV1.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class AddNewColumnToUserTable : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Thêm cột IsTwoFactorVerified vào bảng LoginSessions
            migrationBuilder.AddColumn<bool>(
                name: "IsTwoFactorVerified",
                table: "LoginSessions",
                type: "bit",
                nullable: false,
                defaultValue: false);

            // Thêm các cột mới vào bảng DATA_Users
            migrationBuilder.AddColumn<DateTime>(
                name: "LastLogin",
                table: "DATA_Users",
                type: "datetime2",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ResetToken",
                table: "DATA_Users",
                type: "nvarchar(max)",
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "ResetTokenExpiry",
                table: "DATA_Users",
                type: "datetime2",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // Xóa các cột đã thêm
            migrationBuilder.DropColumn(
                name: "IsTwoFactorVerified",
                table: "LoginSessions");

            migrationBuilder.DropColumn(
                name: "LastLogin",
                table: "DATA_Users");

            migrationBuilder.DropColumn(
                name: "ResetToken",
                table: "DATA_Users");

            migrationBuilder.DropColumn(
                name: "ResetTokenExpiry",
                table: "DATA_Users");
        }
    }
}