using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace JwtApi.Models
{
    public class ApplicationDbContext:IdentityDbContext<IdentityUser>
    {

        public ApplicationDbContext (DbContextOptions<ApplicationDbContext> options) : base(options)
        {

        }
    }
}
