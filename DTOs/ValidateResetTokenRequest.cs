using System.ComponentModel.DataAnnotations;

namespace Auth.DTOs
{
    public class ValidateResetTokenRequest
    {
        [Required]
        public string Token { get; set; }
    }
}