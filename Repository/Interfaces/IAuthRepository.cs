using Auth.DTOs;

namespace Auth.Repository.Interfaces
{
    public interface IAuthRepository
    {
        void Register(RegisterRequest registerRequest, string origin);
        AuthenticateResponse Authenticate(AuthenticateRequest authenticateRequest, string ipAddress);
        AuthenticateResponse RefreshToken(string token, string ipAddress);
        void RevokeToken(string token, string ipAddress);

    }
}