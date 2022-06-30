using Auth.Models;

namespace Auth.Repository.Interfaces
{
    public interface IJwtUtillRepository
    {
        public string GenerateJwtToken(Account account);
        public int? ValidateJwtToken(string accessToken);
        public RefreshToken GetRefreshToken(string ipAddress);
    }
}