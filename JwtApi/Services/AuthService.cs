using JwtApi.Helper;
using JwtApi.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

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
                EmailConfirmed = true,
                LockoutEnabled= false,
                
            };
            var CreateResult = await _userManager.CreateAsync(_user, model.Password);
            if (!CreateResult.Succeeded)
            {

                var errors = string.Empty;

                foreach (var error in CreateResult.Errors)
                {
                    errors += $"{error.Description},";
                    
                }
                return new AuthModel
                {
                    Message = errors.Substring(0, errors.Length - 1)
                };
            }

            var AddRoleResult = await AddUserRoleAsync(new AddRoleRequestModel
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
                }
                return new AuthModel
                {
                   Message = errors.Substring(0, errors.Length - 1)
                };
            } 
 
            return await GetTokenAsync(new TokenRequestModel
            {
                Email = model.Email,
                Password= model.Password

            });
        }

        public async Task<AuthModel> AddUserRoleAsync(AddRoleRequestModel model)
        {

            var user = await _userManager.FindByIdAsync(model.UserId);

            if (user is null || !await _roleManager.RoleExistsAsync(model.Role))
                return new AuthModel { Message = "Invalid user ID or Role" };

            if (await _userManager.IsInRoleAsync(user, model.Role))
                return new AuthModel { Message = "User already assigned to this role" };

            var result = await _userManager.AddToRoleAsync(user, model.Role);

            if (!result.Succeeded)
                return new AuthModel { Message = "Sonething went wrong" };


            var jwtSecurtyToken = await CreateJwtToken(user);
            var roleList = await _userManager.GetRolesAsync(user);

            return new AuthModel
            {
                Username = user.UserName,
                Email = user.Email,
                Roles = roleList.ToList(),
                IsAuthenticated = true,
                Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurtyToken),
                ExpireOn = jwtSecurtyToken.ValidTo

            };
           
           
        }

        public async Task<AuthModel> GetTokenAsync(TokenRequestModel model)
        {
            var _user=await _userManager.FindByEmailAsync(model.Email);

            if (_user == null || !await _userManager.CheckPasswordAsync(_user, model.Password))
            {
                return new AuthModel
                {
                    Message = "invalid email or password"
                };
            }
              
            var jwtSecurtyToken = await CreateJwtToken(_user);
            var roleList= await _userManager.GetRolesAsync(_user);
            return new AuthModel
            {
                Username = _user.UserName,
                Email = _user.Email,
                Roles = roleList.ToList(),
                IsAuthenticated = true,
                Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurtyToken),
                ExpireOn = jwtSecurtyToken.ValidTo

            };
        }


        public async Task<JwtSecurityToken> CreateJwtToken(IdentityUser model)
        {
            var userClaims = await _userManager.GetClaimsAsync(model);
            var roles = await _userManager.GetRolesAsync(model);
            var roleClaims = new List<Claim>();

            foreach (var role in roles)
                roleClaims.Add(new Claim("roles", role));

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, model.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Email, model.Email),
                new Claim("uid", model.Id)
            }
            .Union(userClaims)
            .Union(roleClaims);

            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.Key));
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);



            return  new JwtSecurityToken(
                issuer: _jwt.Issuer,
                audience: _jwt.Audience,
                claims: claims,
                expires: DateTime.Now.AddDays(_jwt.DurationInDays),
                signingCredentials: signingCredentials);
 
        }


    }
}
