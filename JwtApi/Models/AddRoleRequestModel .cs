using System.ComponentModel.DataAnnotations;

namespace JwtApi.Models
{
    public class AddRoleRequestModel
    {
        [Required]
        public string UserId { get; set; }

        [Required]
        public string Role { get; set; }
    }
}
