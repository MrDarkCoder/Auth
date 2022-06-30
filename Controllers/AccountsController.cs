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


    }
}