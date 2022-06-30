using Auth.DTOs;

namespace Auth.Repository.Interfaces
{
    public interface IAccountRepository
    {
        IEnumerable<AccountResponse> GetAllAccounts();
        AccountResponse GetById(int id);
        AccountResponse Create(CreateRequest createRequest);
        AccountResponse Update(int id, UpdateRequest updateRequest);

        void Delete(int id);
    }
}