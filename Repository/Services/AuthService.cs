using Auth.Data;
using Auth.DTOs;
using Auth.Helper;
using Auth.Models;
using Auth.Repository.Interfaces;
using AutoMapper;
using Microsoft.Extensions.Options;

namespace Auth.Repository.Services
{
    public class AuthService : IAuthRepository
    {
        private readonly AuthContext _authContext;
        private readonly IJwtUtillRepository _jwtUtillRepository;
        private readonly AppSettings _appSettings;
        private readonly IMapper _mapper;
        public AuthService(AuthContext authContext, IMapper mapper, IJwtUtillRepository jwtUtillRepository, IOptions<AppSettings> appSettings)
        {
            _authContext = authContext;
            _jwtUtillRepository = jwtUtillRepository;
            _appSettings = appSettings.Value;
            _mapper = mapper;
        }

        // Login
        public AuthenticateResponse Authenticate(AuthenticateRequest authenticateRequest, string ipAddress)
        {
            // 01) fetching user account
            var account = _authContext.Accounts.SingleOrDefault(a => a.Email == authenticateRequest.Email);

            // 02) Verification
            if (account == null || !account.IsVerified || !BCrypt.Net.BCrypt.Verify(authenticateRequest.Password, account.PasswordHash))
            {
                throw new AppException("Email or password is incorrect");
            }

            // account/pwd/ - verified
            // 03) Generating tokens
            var accessToken = _jwtUtillRepository.GenerateJwtToken(account);
            var refreshToken = _jwtUtillRepository.GetRefreshToken(ipAddress);

            // 04) adding refreshtoken to account refreshtokenlist
            account.RefreshToken = refreshToken.Token;
            account.RefreshTokens.Add(refreshToken);

            // 05) removing old refresh token
            removeOldRefreshToken(account);

            // 07) update to db
            _authContext.Update(account);
            _authContext.SaveChanges();

            var response = _mapper.Map<AuthenticateResponse>(account);
            response.AccessToken = accessToken;
            response.RefreshToken = refreshToken.Token;

            return response;
        }

        // Register
        public void Register(RegisterRequest registerRequest, string origin)
        {
            if (_authContext.Accounts.Any(a => a.Email == registerRequest.Email))
            {
                throw new AppException($"Email '{registerRequest.Email}' is already registered");
            }

            // 01) Mapping to account model
            var account = _mapper.Map<Account>(registerRequest);

            // 02) Temp : making First reg user as ADMIn
            var isFirstAccount = _authContext.Accounts.Count() == 0;
            account.Role = isFirstAccount ? Role.Admin : Role.User;

            account.Created = DateTime.UtcNow;

            // skiping verification mail
            // account.Verification = generateVerficationToken();
            // Making the mail verified!
            account.Verification = null;
            account.Verified = DateTime.UtcNow;

            // 03 Hash Password
            var salt = BCrypt.Net.BCrypt.GenerateSalt(10);
            account.PasswordHash = BCrypt.Net.BCrypt.HashPassword(registerRequest.Password, salt);

            _authContext.Accounts.Add(account);
            _authContext.SaveChanges();

            // skiping sendverifymail

        }

        // refresh token
        public AuthenticateResponse RefreshToken(string token, string ipAddress)
        {
            var account = getAccountByRefreshToken(token);

            var refreshToken = account.RefreshTokens.Single(rt => rt.Token == token);

            if (refreshToken.IsRevoked)
            {
                // revoke all descendant tokens in case this token has been compromised
                revokeDescendantRefreshTokens(refreshToken, account, ipAddress, $"Attempted reuse of revoked ancestor token: {token}");
                _authContext.Update(account);
                _authContext.SaveChanges();
            }

            if (!refreshToken.IsActive)
            {
                throw new AppException("Invalid Token");
            }

            var newRefreshToken = rotateRefreshToken(refreshToken, ipAddress);
            account.RefreshTokens.Add(newRefreshToken);

            // remove old refresh tokens
            removeOldRefreshToken(account);

            _authContext.Update(account);
            _authContext.SaveChanges();

            // New JWT token
            var accessToken = _jwtUtillRepository.GenerateJwtToken(account);

            var response = _mapper.Map<AuthenticateResponse>(account);
            response.AccessToken = accessToken;
            response.RefreshToken = newRefreshToken.Token;

            return response;
        }

        public void RevokeToken(string token, string ipAddress)
        {
            var account = getAccountByRefreshToken(token);
            var refreshToken = account.RefreshTokens.Single(rt => rt.Token == token);

            if (!refreshToken.IsActive) throw new AppException("Invalide");

            revokeRefreshToken(refreshToken, ipAddress, "Revoked without Replacement");

            _authContext.Update(account);
            _authContext.SaveChanges();
        }



        // Removing old refreshtoken
        private void removeOldRefreshToken(Account account)
        {
            account.RefreshTokens.RemoveAll(
                rt => !rt.IsActive &&
                rt.Created.AddMinutes(_appSettings.RefreshTokenTTL) >= DateTime.UtcNow
            );
        }

        private Account getAccountByRefreshToken(string token)
        {
            var account = _authContext.Accounts.SingleOrDefault(ac => ac.RefreshTokens.Any(rt => rt.Token == token));
            if (account == null) throw new AppException("Invalid Token");
            return account;
        }

        private RefreshToken rotateRefreshToken(RefreshToken refreshToken, string ipAddress)
        {
            var newRefreshToken = _jwtUtillRepository.GetRefreshToken(ipAddress);
            revokeRefreshToken(refreshToken, ipAddress, "Replaced by new token", newRefreshToken.Token);
            return newRefreshToken;
        }

        private void revokeRefreshToken(RefreshToken token, string ipAddress, string reason = null, string replacedByToken = null)
        {
            token.Revoked = DateTime.UtcNow;
            token.RevokedByIP = ipAddress;
            token.ReplaceRevoked = reason;
            token.ReplacedByToken = replacedByToken;
        }

        private void revokeDescendantRefreshTokens(RefreshToken refreshToken, Account account, string ipAddress, string reason)
        {
            // recursively traverse the refresh token chain and ensure all descendants are revoked
            if (!string.IsNullOrEmpty(refreshToken.ReplacedByToken))
            {
                var childToken = account.RefreshTokens.SingleOrDefault(x => x.Token == refreshToken.ReplacedByToken);
                if (childToken.IsActive)
                    revokeRefreshToken(childToken, ipAddress, reason);
                else
                    revokeDescendantRefreshTokens(childToken, account, ipAddress, reason);
            }
        }


    }
}