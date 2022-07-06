using System.Security.Cryptography;
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
        private readonly IEmailRepository _emailRepository;
        private readonly AppSettings _appSettings;
        private readonly IMapper _mapper;
        public AuthService(AuthContext authContext, IMapper mapper, IJwtUtillRepository jwtUtillRepository, IEmailRepository emailRepository, IOptions<AppSettings> appSettings)
        {
            _authContext = authContext;
            _jwtUtillRepository = jwtUtillRepository;
            _emailRepository = emailRepository;
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

        // Register : Pending Verfication
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
            account.Verification = generateVerificationToken();
            // Making the mail verified!
            // account.Verification = null;
            // account.Verified = DateTime.UtcNow;

            // 03 Hash Password
            var salt = BCrypt.Net.BCrypt.GenerateSalt(10);
            account.PasswordHash = BCrypt.Net.BCrypt.HashPassword(registerRequest.Password, salt);

            _authContext.Accounts.Add(account);
            _authContext.SaveChanges();

            // skiping sendverifymail
            sendVerificationEmail(account, origin);
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
            account.RefreshToken = newRefreshToken.Token;

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


        // Part of Mailing 
        public void VerifyEmail(string token)
        {
            var account = _authContext.Accounts.SingleOrDefault(x => x.Verification == token);
            if (account == null) throw new AppException("Verification Failed");

            account.Verified = DateTime.UtcNow;
            account.Verification = null;

            _authContext.Accounts.Update(account);
            _authContext.SaveChanges();
        }

        public void ForgotPassword(ForgotPasswordRequest forgotPasswordRequest, string origin)
        {
            var account = _authContext.Accounts.SingleOrDefault(a => a.Email == forgotPasswordRequest.Email);

            // always return ok response to prevent email enumeration
            if (account == null) return;

            // create reset token that expires after 1 day
            account.ResetToken = generateResetToken();
            account.ResetTokenExpires = DateTime.UtcNow.AddDays(1);

            _authContext.Accounts.Update(account);
            _authContext.SaveChanges();

            // Send Email
            sendPasswordResetEmail(account, origin);

        }

        public void ResetPassword(ResetPasswordRequest resetPasswordRequest)
        {
            var account = getAccountByResetToken(resetPasswordRequest.Token);

            // update password and remove reset token
            account.PasswordHash = BCrypt.Net.BCrypt.HashPassword(resetPasswordRequest.Password);
            account.PasswordReset = DateTime.UtcNow;
            account.ResetToken = null;
            account.ResetTokenExpires = null;

            _authContext.Accounts.Update(account);
            _authContext.SaveChanges();
        }

        public void ValidateResetToken(ValidateResetTokenRequest validateResetTokenRequest)
        {
            getAccountByResetToken(validateResetTokenRequest.Token);
        }

        private Account getAccountByResetToken(string token)
        {
            var account = _authContext.Accounts.SingleOrDefault(x =>
                x.ResetToken == token && x.ResetTokenExpires > DateTime.UtcNow);
            if (account == null) throw new AppException("Invalid token");
            return account;
        }

        private string generateResetToken()
        {
            // token is a cryptographically strong random sequence of values
            var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(64));

            // ensure token is unique by checking against db
            var tokenIsUnique = !_authContext.Accounts.Any(x => x.ResetToken == token);
            if (!tokenIsUnique)
                return generateResetToken();

            return token;
        }

        private string generateVerificationToken()
        {
            // token is a cryptographically strong random sequence of values
            var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(64));

            // ensure token is unique by checking against db
            var tokenIsUnique = !_authContext.Accounts.Any(x => x.Verification == token);
            if (!tokenIsUnique)
                return generateVerificationToken();

            return token;
        }

        private void sendPasswordResetEmail(Account account, string origin)
        {
            string message;
            if (!string.IsNullOrEmpty(origin))
            {
                var resetUrl = $"{origin}/account/reset-password?token={account.ResetToken}";
                message = $@"<p>Please click the below link to reset your password, the link will be valid for 1 day:</p>
                            <p><a href=""{resetUrl}"">{resetUrl}</a></p>";
            }
            else
            {
                message = $@"<p>Please use the below token to reset your password with the <code>/accounts/reset-password</code> api route:</p>
                            <p><code>{account.ResetToken}</code></p>";
            }

            _emailRepository.Send(
                to: account.Email,
                subject: "Sign-up Verification API - Reset Password",
                html: $@"<h4>Reset Password Email</h4>
                        {message}"
            );
        }

        private void sendVerificationEmail(Account account, string origin)
        {
            string message;
            if (!string.IsNullOrEmpty(origin))
            {
                // origin exists if request sent from browser single page app (e.g. Angular or React)
                // so send link to verify via single page app
                var verifyUrl = $"{origin}/account/verify-email?token={account.Verification}";
                message = $@"<p>Please click the below link to verify your email address:</p>
                            <p><a href=""{verifyUrl}"">{verifyUrl}</a></p>";
            }
            else
            {
                // origin missing if request sent directly to api (e.g. from Postman)
                // so send instructions to verify directly with api
                message = $@"<p>Please use the below token to verify your email address with the <code>/accounts/verify-email</code> api route:</p>
                            <p><code>{account.Verification}</code></p>";
            }

            _emailRepository.Send(
                to: account.Email,
                subject: "Sign-up Verification API - Verify Email",
                html: $@"<h4>Verify Email</h4>
                        <p>Thanks for registering!</p>
                        {message}"
            );
        }

    }
}