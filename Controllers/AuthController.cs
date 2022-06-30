using Auth.Customs;
using Auth.DTOs;
using Auth.Models;
using Auth.Repository.Interfaces;
using Microsoft.AspNetCore.Mvc;

namespace Auth.Controllers
{

    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : BaseController
    {
        private readonly IAuthRepository _authRepository;
        public AuthController(IAuthRepository authRepository)
        {
            _authRepository = authRepository;
        }

        [AllowAnonymous]
        [HttpPost("authenticate")]
        public ActionResult<AuthenticateResponse> Authenticate(AuthenticateRequest authenticateRequest)
        {
            var response = _authRepository.Authenticate(authenticateRequest, IPAddress());
            setTokenCookie(response.RefreshToken);
            return Ok(response);
        }

        [AllowAnonymous]
        [HttpPost("refresh-token")]
        public ActionResult<AuthenticateResponse> RefreshToken()
        {
            var refreshToken = Request.Cookies["refreshToken"];
            var response = _authRepository.RefreshToken(refreshToken, IPAddress());
            setTokenCookie(response.RefreshToken);
            return Ok(response);
        }

        [HttpPost("revoke-token")]
        public IActionResult RevokeToken(RevokeTokenRequest revokeTokenRequest)
        {
            var token = revokeTokenRequest.Token ?? Request.Cookies["refreshToken"];

            if (string.IsNullOrEmpty(token))
            {
                return BadRequest(new { message = "Token is Required" });
            }

            if (!Account.OwnsToken(token) && Account.Role != Role.Admin)
            {
                return Unauthorized(new { message = "Unauthorized" });
            }

            _authRepository.RefreshToken(token, IPAddress());
            return Ok(new { message = "Token revoked" });
        }

        [AllowAnonymous]
        [HttpPost("register")]
        public IActionResult Register(RegisterRequest registerRequest)
        {
            _authRepository.Register(registerRequest, Request.Headers["origin"]);
            return Ok(new { message = "Registration successful, Please Login" });
        }
        
        // [AllowAnonymous]
        // [HttpPost("register")]
        // public ActionResult<AccountResponse> Create(CreateRequest createRequest)
        // {
        //     var response = _accountRepository.Create(createRequest);
        //     return Ok(response);
        // }


        private void setTokenCookie(string token)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = DateTime.UtcNow.AddDays(1),
            };

            Response.Cookies.Append("refreshtoken", token, cookieOptions);
        }

        private string IPAddress()
        {
            if (Request.Headers.ContainsKey("X-Forwarded-For")) return Request.Headers["X-Forwarded-For"];
            else return HttpContext.Connection.RemoteIpAddress.MapToIPv4().ToString();
        }



    }
}