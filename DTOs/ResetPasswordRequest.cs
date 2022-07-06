using System.ComponentModel.DataAnnotations;

namespace Auth.DTOs
{
    public class ResetPasswordRequest
    {
        [Required]
        public string Token { get; set; }
        [Required]
        [MinLength(6)]
        public string Password { get; set; }
        [Required]
        [Compare("Password")]
        public string ConforimrPassword { get; set; }
    }
}