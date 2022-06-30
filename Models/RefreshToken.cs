using System.ComponentModel.DataAnnotations;
using Microsoft.EntityFrameworkCore;

namespace Auth.Models
{
    [Owned]
    public class RefreshToken
    {
        [Key]
        public int Id { get; set; }
        public Account Account { get; set; }

        public string Token { get; set; }
        public DateTime Expires { get; set; }
        public DateTime Created { get; set; }
        public string CreatedByIP { get; set; }

        public DateTime? Revoked { get; set; }
        public string RevokedByIP { get; set; }
        public string ReplaceRevoked { get; set; }
        public string ReplacedByToken { get; set; }

        public bool IsExpired => DateTime.UtcNow >= Expires;
        public bool IsRevoked => Revoked != null;
        public bool IsActive => Revoked == null && !IsExpired;
    }
}

/*
The [Owned] attribute marks the refresh token class as an owned entity type, 
meaning it can only exist as a child / dependant of another entity class
*/