using JwtApi.Helper;
using JwtApi.Models;
using JwtApi.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JwtApi.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthController : ControllerBase
    {

        private readonly IAuthService _service;

        public AuthController(IAuthService service)
        {
            _service = service;
        }

        [HttpPost("Register")]
        public async Task<IActionResult> RegisterAsync([FromBody] RegisterRequestModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var result = await _service.RegisterAsync(model);

            if(!result.IsAuthenticated)
                return BadRequest(result);


            return Ok(result);
        }
        [HttpPost("GetToken")]
        public async Task<IActionResult> GetTokenAsync([FromBody] TokenRequestModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var result = await _service.GetTokenAsync(model);

            if(!result.IsAuthenticated)
                return BadRequest(result);


            return Ok(result);
        }
        [HttpPost("AddUserRole")]
        [Authorize(Roles =ApplicationRoleName.AdminRoleName)]
       
        public async Task<IActionResult> AddUserRoleAsync([FromBody] AddRoleRequestModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var result = await _service.AddUserRoleAsync(model);

            if(!result.IsAuthenticated)
                return BadRequest(result);

            return Ok(result);
        }
    }
}
