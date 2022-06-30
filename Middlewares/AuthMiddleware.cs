using System.Diagnostics;
using Auth.Data;
using Auth.Helper;
using Auth.Repository.Interfaces;
using Microsoft.Extensions.Options;

namespace Auth.Middlewares
{
    public class AuthMiddleware
    {

        private readonly RequestDelegate _next;
        private readonly AppSettings _appSettings;
        public AuthMiddleware(RequestDelegate next, IOptions<AppSettings> appSetting)
        {
            _next = next;
            _appSettings = appSetting.Value;
        }

        public async Task Invoke(HttpContext _httpContext, AuthContext _authContext, IJwtUtillRepository _jwtUtillRepository)
        {
            // extracting token from header
            var accessToken = _httpContext.Request.Headers["Authorization"].FirstOrDefault()?.Split(" ").Last();
            // Validating access token (method gives NULL | AccountId)
            var accountId = _jwtUtillRepository.ValidateJwtToken(accessToken);
            // Debug.WriteLine(_httpContext.Request.Headers["Authorization"]);
            if (accountId != null)
            {
                // attach account details to httpcontext on successful jwt validation
                _httpContext.Items["Account"] = await _authContext.Accounts.FindAsync(accountId.Value);
            }

            await _next(_httpContext);
        }

    }
}