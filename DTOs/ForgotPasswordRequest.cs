using System.ComponentModel.DataAnnotations;

namespace Auth.DTOs
{
    public class ForgotPasswordRequest
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}