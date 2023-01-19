using JwtApi.Helper;
using JwtApi.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using System.IdentityModel.Tokens.Jwt;

namespace JwtApi.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly JWTMaper _jwt;

        public AuthService(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager, IOptions<JWTMaper> jwt)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _jwt = jwt.Value;
        }

        public async Task<AuthModel> RegisterAsync(RegisterRequestModel model)
        {
            if (await _userManager.FindByEmailAsync(model.Email) is not null)
            {
                return new AuthModel
                {
                    Message = "Email is already registered!"
                };
            }
            if (await _userManager.FindByNameAsync(model.Username) is not null)
            {
                return new AuthModel
                {
                    Message = "Username is already registered!"
                };
            }
            var _user = new IdentityUser
            {
                UserName = model.Username,
                Email = model.Email,

            };
            var CreateResult = await _userManager.CreateAsync(_user, model.Password);
            if (!CreateResult.Succeeded)
            {

                var errors = string.Empty;

                foreach (var error in CreateResult.Errors)
                {
                    errors += $"{error.Description},";
                    return new AuthModel
                    {
                        Message = errors
                    };
                }

            }

            var AddRoleResult = await AddRoleAsync(new AddRoleRequestModel
            {
                UserId = _user.Id,
                Role = ApplicationRoleName.UserRoleName
            });

            if (!AddRoleResult.IsAuthenticated)
            {
                var errors = string.Empty;

                foreach (var error in CreateResult.Errors)
                {
                    errors += $"{error.Description},";
                    return new AuthModel
                    {
                        Message = errors
                    };
                }
            }

            var jwtSecurtyToken = await CreateJwtToken(_user);

            return await GetTokenAsync(new TokenRequestModel
            {


            });
        }

        public async Task<AuthModel> AddRoleAsync(AddRoleRequestModel model)
        {

            return new AuthModel
            {

            };
        }

        public async Task<AuthModel> GetTokenAsync(TokenRequestModel model)
        {

            //var jwtSecurtyToken = await CreateJwtToken(_user);

            //return new AuthModel
            //{
            //    Username = _user.UserName,
            //    Email = _user.Email,
            //    Roles = new List<string> { ApplicationRoleName.UserRoleName },
            //    IsAuthenticated = true,
            //    Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurtyToken),
            //    ExpireOn = jwtSecurtyToken.ValidTo

            //};
        }


        public async Task<JwtSecurityToken> CreateJwtToken(IdentityUser model)
        {

            return new JwtSecurityToken
            {

            };
        }


    }
}
