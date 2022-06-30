using Auth.DTOs;

namespace Auth.Repository.Interfaces
{
    public interface IAccountRepository
    {
        void Register(RegisterRequest registerRequest, string origin);
        AuthenticateResponse Authenticate(AuthenticateRequest authenticateRequest, string ipAddress);
        AuthenticateResponse RefreshToken(string token, string ipAddress);
        void RevokeToken(string token, string ipAddress);


        IEnumerable<AccountResponse> GetAllAccounts();
        AccountResponse GetById(int id);
        AccountResponse Create(CreateRequest createRequest);
        AccountResponse Update(int id, UpdateRequest updateRequest);

        void Delete(int id);
    }
}