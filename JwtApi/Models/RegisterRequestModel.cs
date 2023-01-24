using System.ComponentModel.DataAnnotations;

namespace JwtApi.Models
{
    public class RegisterRequestModel
    {
        [Required]
        public string  Username { get; set; }

        [Required]
        [EmailAddress]
        public string Email { get; set; }

         [Required(ErrorMessage = "Password is required")]
        [StringLength(100, ErrorMessage = "Must be between 4 and 100 characters", MinimumLength = 4)]
        [RegularExpression("^[a-zA-Z0-9]+$", ErrorMessage = "Passwords must have at least one digit ('0'-'9')")]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        public string Password { get; set; }
    }
}
