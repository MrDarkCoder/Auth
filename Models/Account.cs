namespace Auth.Models
{
    public class Account
    {
        public int Id { get; set; }
        public string Title { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public Role Role { get; set; }

        public string Email { get; set; }
        public string PasswordHash { get; set; }
        public bool AcceptTerms { get; set; }
        public string Verification { get; set; }
        public string RefreshToken { get; set; }
        public DateTime? ResetTokenExpires { get; set; }
        public DateTime? Verified { get; set; }
        public DateTime? PasswordReset { get; set; }
        public bool IsVerified => Verified.HasValue || PasswordReset.HasValue;
        public DateTime Created { get; set; }
        public DateTime? Updated { get; set; }

        public List<RefreshToken> RefreshTokens { get; set; }

        public bool OwnsToken(string token)
        {
            return this.RefreshTokens?.Find(x => x.Token == token) != null;
        }

    }
}

/*
The OwnsToken method is a convenience method that returns true 
if the specified refresh token belongs to the account, 
it's used in the RevokeToken method of the accounts controller 
to improve code readability by making it more intention revealing
*/