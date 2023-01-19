using JwtApi.Helper;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace JwtApi.Migrations
{
    public partial class SeedDefaulteUserAdmin : Migration
    {

        const string userID = "f6340718-6003-4b99-8e83-fb8ebeaa7ddf";
        const string userRoleID = "dabb3c64-0ae5-4df8-8d44-c3f97fcaa2df";
        const string AdminUserID = "c19f60f3-8ae3-4976-a514-13a7fa98ac9a";
        const string AdminUserRoleID = "865c4814-e4a2-4c6b-901c-e957010d1fbb";
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            var hasher = new PasswordHasher<IdentityUser>();

            //normal user

            migrationBuilder.InsertData(
                table: "AspNetUsers",
                 columns: new[] { "Id", "UserName", "NormalizedUserName", "Email", "NormalizedEmail", "EmailConfirmed", "PasswordHash", "SecurityStamp", "AccessFailedCount", "TwoFactorEnabled", "LockoutEnabled",  "PhoneNumberConfirmed" },
                values: new object[] { userID, "user", "user".ToUpper(), "user@email.com", "user@email.com".ToUpper(),true,
                hasher.HashPassword(null, "userpassword"),string.Empty,0,false,false, false
                });

            migrationBuilder.InsertData(
              table: "AspNetRoles",
               columns: new[] { "Id", "Name", "NormalizedName", "ConcurrencyStamp" },
              values: new object[] { userRoleID, ApplicationRoleName.UserRoleName, ApplicationRoleName.UserRoleName.ToUpper(), userRoleID });

            migrationBuilder.InsertData(
              table: "AspNetUserRoles",
               columns: new[] { "UserId", "RoleId" },
              values: new object[] { userID, userRoleID });


            //admin user

            migrationBuilder.InsertData(
                table: "AspNetUsers",
                columns: new[] { "Id", "UserName", "NormalizedUserName", "Email", "NormalizedEmail", "EmailConfirmed", "PasswordHash", "SecurityStamp", "AccessFailedCount", "TwoFactorEnabled", "LockoutEnabled" , "PhoneNumberConfirmed" },
                values: new object[] { AdminUserID, "admin", "admin".ToUpper(), "admin@email.com", "admin@email.com".ToUpper(),true,
                hasher.HashPassword(null, "adminpassword"),string.Empty,0,false,false ,false
                });

            migrationBuilder.InsertData(
              table: "AspNetRoles",
              columns: new[] { "Id", "Name", "NormalizedName", "ConcurrencyStamp" },
              values: new object[] { AdminUserRoleID, ApplicationRoleName.AdminRoleName, ApplicationRoleName.AdminRoleName.ToUpper(), AdminUserRoleID });

            migrationBuilder.InsertData(
              table: "AspNetUserRoles",
              columns: new[] { "UserId", "RoleId" },
              values: new object[] { AdminUserID, AdminUserRoleID });

            migrationBuilder.InsertData(
            table: "AspNetUserRoles",
            columns: new[] { "UserId", "RoleId" },
            values: new object[] { AdminUserID, userRoleID });
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
            table: "AspNetUsers",
            keyColumns: new[] { "Id" },
            keyValues: new object[] { userID });


            migrationBuilder.DeleteData(
                 table: "AspNetUsers",
                  keyColumns: new[] { "Id" },
                 keyValues: new object[] { AdminUserID });
        }
    }
}
