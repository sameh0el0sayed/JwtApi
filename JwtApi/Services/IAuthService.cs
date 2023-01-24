using JwtApi.Models;

namespace JwtApi.Services
{
    public interface IAuthService
    {
        Task<AuthModel> RegisterAsync(RegisterRequestModel model);
        Task<AuthModel> GetTokenAsync(TokenRequestModel model);
        Task<AuthModel> AddUserRoleAsync(AddRoleRequestModel model);
    }
}
