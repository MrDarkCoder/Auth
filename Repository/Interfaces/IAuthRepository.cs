using Auth.DTOs;

namespace Auth.Repository.Interfaces
{
    public interface IAuthRepository
    {
        void Register(RegisterRequest registerRequest, string origin);
        AuthenticateResponse Authenticate(AuthenticateRequest authenticateRequest, string ipAddress);
        AuthenticateResponse RefreshToken(string token, string ipAddress);
        void RevokeToken(string token, string ipAddress);

        void VerifyEmail(string token);
        void ForgotPassword(ForgotPasswordRequest forgotPasswordRequest, string origin);
        void ResetPassword(ResetPasswordRequest resetPasswordRequest);
        void ValidateResetToken(ValidateResetTokenRequest validateResetTokenRequest);

    }
}