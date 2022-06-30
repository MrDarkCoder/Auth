using Microsoft.AspNetCore.Mvc;

using Auth.Customs;
using Auth.Repository.Interfaces;
using Auth.DTOs;
using Auth.Models;

namespace Auth.Controllers
{
    // custom authorize attribute
    [Authorize]
    [ApiController]
    [Route("api/[controller]")]
    public class AccountsController : BaseController
    {

        private readonly IAccountRepository _accountRepository;

        public AccountsController(IAccountRepository accountRepository)
        {
            _accountRepository = accountRepository;
        }


        // Login
        [AllowAnonymous]
        [HttpPost("authenticate")]
        public ActionResult<AuthenticateResponse> Authenticate(AuthenticateRequest authenticateRequest)
        {
            var response = _accountRepository.Authenticate(authenticateRequest, IPAddress());
            setTokenCookie(response.RefreshToken);
            return Ok(response);
        }

        [AllowAnonymous]
        [HttpPost("refresh-token")]
        public ActionResult<AuthenticateResponse> RefreshToken()
        {
            var refreshToken = Request.Cookies["refreshToken"];
            var response = _accountRepository.RefreshToken(refreshToken, IPAddress());
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

            _accountRepository.RefreshToken(token, IPAddress());
            return Ok(new { message = "Token revoked" });
        }

        [AllowAnonymous]
        [HttpPost("register")]
        public IActionResult Register(RegisterRequest registerRequest)
        {
            _accountRepository.Register(registerRequest, Request.Headers["origin"]);
            return Ok(new { message = "Registration successful, Please Login" });
        }

        // [AllowAnonymous]
        // [HttpPost("register")]
        // public ActionResult<AccountResponse> Create(CreateRequest createRequest)
        // {
        //     var response = _accountRepository.Create(createRequest);
        //     return Ok(response);
        // }

        [Authorize(Role.Admin)]
        [HttpGet]
        public ActionResult<IEnumerable<AccountResponse>> GetAll()
        {
            var accounts = _accountRepository.GetAllAccounts();
            return Ok(accounts);
        }

        [HttpGet("{id:int}")]
        public ActionResult<AccountResponse> GetById(int id)
        {
            // users can get their own account and admins can get any account
            if (id != Account.Id && Account.Role != Role.Admin)
                return Unauthorized(new { message = "Unauthorized" });

            var account = _accountRepository.GetById(id);
            return Ok(account);
        }

        [Authorize(Role.Admin)]
        [HttpPost]
        public ActionResult<AccountResponse> Create(CreateRequest model)
        {
            var account = _accountRepository.Create(model);
            return Ok(account);
        }

        [HttpPut("{id:int}")]
        public ActionResult<AccountResponse> Update(int id, UpdateRequest updateRequest)
        {
            // users can update their own account and admins can update any account
            if (id != Account.Id && Account.Role != Role.Admin)
                return Unauthorized(new { message = "Unauthorized" });

            // only admins can update role
            if (Account.Role != Role.Admin)
                updateRequest.Role = null;

            var account = _accountRepository.Update(id, updateRequest);
            return Ok(account);
        }

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