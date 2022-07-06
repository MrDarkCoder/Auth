using System.ComponentModel.DataAnnotations;

namespace Auth.DTOs
{
    public class VerifyEmailRequest
    {
        [Required]
        public string Token { get; set; }
    }
}