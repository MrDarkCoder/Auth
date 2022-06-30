using Auth.Data;
using Auth.DTOs;
using Auth.Helper;
using Auth.Models;
using Auth.Repository.Interfaces;
using AutoMapper;
using Microsoft.Extensions.Options;

namespace Auth.Repository.Services
{
    public class AccountService : IAccountRepository
    {
        private readonly AuthContext _authContext;
        private readonly IJwtUtillRepository _jwtUtillRepository;
        private readonly AppSettings _appSettings;
        private readonly IMapper _mapper;

        public AccountService(AuthContext authContext, IMapper mapper, IJwtUtillRepository jwtUtillRepository, IOptions<AppSettings> appSettings)
        {
            _authContext = authContext;
            _jwtUtillRepository = jwtUtillRepository;
            _appSettings = appSettings.Value;
            _mapper = mapper;
        }

        // Account CRUD
        public AccountResponse Create(CreateRequest createRequest)
        {

            if (_authContext.Accounts.Any(a => a.Email == createRequest.Email))
            {
                throw new AppException($"Email '{createRequest.Email}' is already registered");
            }

            var account = _mapper.Map<Account>(createRequest);

            // Roles
            var isFirstAccount = _authContext.Accounts.Count() == 0;
            account.Role = isFirstAccount ? Role.Admin : Role.User;

            account.Created = DateTime.UtcNow;
            account.Verification = null;
            account.Verified = DateTime.UtcNow;

            // hash pwd
            var salt = BCrypt.Net.BCrypt.GenerateSalt(10);
            account.PasswordHash = BCrypt.Net.BCrypt.HashPassword(createRequest.Password, salt);

            _authContext.Accounts.Add(account);
            _authContext.SaveChanges();

            return _mapper.Map<AccountResponse>(account);
        }

        public IEnumerable<AccountResponse> GetAllAccounts()
        {
            var accounts = _authContext.Accounts;
            return _mapper.Map<IList<AccountResponse>>(accounts);
        }

        public AccountResponse GetById(int id)
        {
            var account = _authContext.Accounts.Find(id);
            if (account == null) throw new KeyNotFoundException("Account Not Found");
            return _mapper.Map<AccountResponse>(account);
        }

        public AccountResponse Update(int id, UpdateRequest updateRequest)
        {
            var account = _authContext.Accounts.Find(id);
            if (account == null) throw new KeyNotFoundException("Account Not Found");

            // 01) Validating Email
            if (account.Email != updateRequest.Email && _authContext.Accounts.Any(ac => ac.Email == updateRequest.Email))
            {
                throw new AppException($"Email '{updateRequest.Email}' is already registered");
            }

            // 02) Hash Password
            if (!string.IsNullOrEmpty(updateRequest.Password))
            {
                account.PasswordHash = BCrypt.Net.BCrypt.HashPassword(updateRequest.Password, BCrypt.Net.BCrypt.GenerateSalt(10));
            }

            // 03) Mapping : updaterequest to account
            _mapper.Map(updateRequest, account);

            account.Updated = DateTime.UtcNow;

            _authContext.Update(account);
            _authContext.SaveChanges();

            return _mapper.Map<AccountResponse>(account);
        }

        public void Delete(int id)
        {
            var account = _authContext.Accounts.Find(id);
            if (account == null) throw new KeyNotFoundException("Account Not Found");

            _authContext.Accounts.Remove(account);
            _authContext.SaveChanges();
        }

    }
}