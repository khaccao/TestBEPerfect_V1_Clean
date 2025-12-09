using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using PerfectKeyV1.Application.DTOs.Auth;

namespace PerfectKeyV1.Application.Interfaces
{
    public interface IAuthService
    {
        // Authentication
        Task<AuthResponse> LoginAsync(LoginRequest request);
        Task<AuthResponse> VerifyTwoFactorAsync(TwoFactorRequest request);
        Task<AuthResponse> RefreshTokenAsync(string token, string refreshToken);
        Task<bool> LogoutAsync(string refreshToken);

        // Hotel management
        Task<IEnumerable<UserHotelDto>> GetUserHotelsAsync(string username);

        // Two-Factor Authentication
        Task<TwoFactorSetupResponse> EnableTwoFactorAsync(int userId);
        Task<TwoFactorSetupResponse> ConfirmEnableTwoFactorAsync(int userId, string code);
        Task<TwoFactorSetupResponse> RegenerateQRAsync(int userId);
        Task<bool> DisableTwoFactorAsync(int userId, string code);
        Task<List<string>> GetRecoveryCodesAsync(int userId);
        Task<List<string>> GenerateNewRecoveryCodesAsync(int userId);

        // User management
        Task<AuthResponse> RegisterAsync(RegisterRequest request);
        Task<bool> ForgotPasswordAsync(ForgotPasswordRequest request);
        Task<bool> ResetPasswordAsync(ResetPasswordRequest request);

        // Token management
        Task<bool> RevokeTokenAsync(int userId);

        // Admin functions
        Task<TwoFactorSetupResponse> AdminEnableTwoFactorForUserAsync(int targetUserId);
        Task<AuthResponse> AdminConfirmEnableTwoFactorForUserAsync(int targetUserId);
        Task<TwoFactorSetupResponse> AdminRegenerateQRForUserAsync(int targetUserId);

        // Session validation
        Task<bool> ValidateSessionAsync(string token);

        // Password generation (nếu cần)
        Task<string> GeneratePasswordAsync();
    }
}