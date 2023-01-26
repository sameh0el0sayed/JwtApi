using Microsoft.AspNetCore.Identity;

namespace JwtApi.Models
{
    public class ApplicationUser:IdentityUser
    {
        public List<RefreshToken> ? RefreshTokens { get; set; }
    }
}
