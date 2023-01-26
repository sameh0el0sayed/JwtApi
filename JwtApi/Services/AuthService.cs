using JwtApi.Helper;
using JwtApi.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace JwtApi.Services
{

    public class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly JWTMaper _jwt;

        public AuthService(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, IOptions<JWTMaper> jwt)
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
            var _user = new ApplicationUser
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

            var jwtSecurityToken = await CreateJwtToken(_user);

            var refreshToken = GenerateRefreshToken();
            _user.RefreshTokens?.Add(refreshToken);
            await _userManager.UpdateAsync(_user);

            return new AuthModel
            {
                Email = _user.Email,
                ExpireOn = jwtSecurityToken.ValidTo.ToLocalTime(),
                IsAuthenticated = true,
                Roles = new List<string> { "User" },
                Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken),
                Username = _user.UserName,
                RefreshToken = refreshToken.Token,
                RefreshTokenExpiration = refreshToken.ExpiresOn.ToLocalTime()
            };
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
                ExpireOn = jwtSecurtyToken.ValidTo.ToLocalTime()

            };
           
           
        }

        public async Task<AuthModel> GetTokenAsync(TokenRequestModel model)
        {
            var _user=await _userManager.FindByEmailAsync(model.Email);
            AuthModel authModel = new AuthModel();

            if (_user == null || !await _userManager.CheckPasswordAsync(_user, model.Password))
            {
                authModel.Message = "invalid email or password";
                return authModel;
               
            }
              
            var jwtSecurtyToken = await CreateJwtToken(_user);
            var roleList= await _userManager.GetRolesAsync(_user);

            authModel.Username = _user.UserName;
            authModel.Email = _user.Email;
            authModel.Roles = roleList.ToList();
            authModel.IsAuthenticated = true;
            authModel.Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurtyToken);
            authModel.ExpireOn = jwtSecurtyToken.ValidTo.ToLocalTime();

            if (_user.RefreshTokens.Any(t=>t.IsActive))
            {
                var activeRefrishToken = _user.RefreshTokens.FirstOrDefault(t => t.IsActive);
                authModel.RefreshToken = activeRefrishToken.Token;
                authModel.RefreshTokenExpiration = activeRefrishToken.ExpiresOn.ToLocalTime();

            }
            else
            {
                var newRefrishToken = GenerateRefreshToken();
                authModel.RefreshToken = newRefrishToken.Token;
                authModel.RefreshTokenExpiration = newRefrishToken.ExpiresOn.ToLocalTime();

                _user.RefreshTokens.Add(newRefrishToken);
                await _userManager.UpdateAsync(_user);

            }
            return authModel;

        }


        public async Task<JwtSecurityToken> CreateJwtToken(ApplicationUser model)
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
                expires: DateTime.Now.AddMinutes(_jwt.DurationInMinutes),
                signingCredentials: signingCredentials);
 
        }

        public async Task<AuthModel> RefreshTokenAsync(string token)
        {
            var _user = await _userManager.Users.SingleOrDefaultAsync(u => u.RefreshTokens.Any(t => t.Token == token));
 
            if (_user is null )
                return new AuthModel { Message = "Invalid user ID " };

            var refreshToken = _user.RefreshTokens.Single(t => t.Token == token);

            if (!refreshToken.IsActive || refreshToken is null)
                return new AuthModel { Message = "Inactive token" };

            refreshToken.RevokedOn= DateTime.UtcNow;

            var newRefreshToken = GenerateRefreshToken();
            _user.RefreshTokens.Add(newRefreshToken);
            await _userManager.UpdateAsync(_user);


            var jwtSecurtyToken = await CreateJwtToken(_user);
            var roleList = await _userManager.GetRolesAsync(_user);
            return new AuthModel
            {
                Username = _user.UserName,
                Email = _user.Email,
                Roles = roleList.ToList(),
                IsAuthenticated = true,
                Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurtyToken),
                ExpireOn = jwtSecurtyToken.ValidTo.ToLocalTime(),
                RefreshToken=newRefreshToken.Token,
                RefreshTokenExpiration=newRefreshToken.ExpiresOn.ToLocalTime()

            };

        }

        public async Task<bool> RevokeTokenAsync(string token)
        {

            var _user = await _userManager.Users.SingleOrDefaultAsync(u => u.RefreshTokens.Any(t => t.Token == token));

            if (_user is null)
                return false;

            var refreshToken = _user.RefreshTokens.Single(t => t.Token == token);

            if (!refreshToken.IsActive || refreshToken is null)
                return false;
            var refreshTokenExpiration = _user;

            refreshToken.RevokedOn = DateTime.UtcNow;

            await _userManager.UpdateAsync(_user);

            return true;

        }

        private RefreshToken GenerateRefreshToken()
        {
            var randomNumber = new byte[32];

            using var generator = new RNGCryptoServiceProvider();

            generator.GetBytes(randomNumber);

            return new RefreshToken
            {
                Token = Convert.ToBase64String(randomNumber),
                ExpiresOn = DateTime.UtcNow.AddDays(_jwt.DurationInDays),
                CreatedOn = DateTime.UtcNow
            };
        }
    }
}
