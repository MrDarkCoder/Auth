using Auth.Models;
using Auth.Repository.Interfaces;

namespace Auth.Repository.Services
{
    public class JwtUtillAsymetricService : IJwtUtillRepository
    {
        public string GenerateJwtToken(Account account)
        {
            throw new NotImplementedException();
        }

        public RefreshToken GetRefreshToken(string ipAddress)
        {
            throw new NotImplementedException();
        }

        public int? ValidateJwtToken(string accessToken)
        {
            throw new NotImplementedException();
        }
    }
}