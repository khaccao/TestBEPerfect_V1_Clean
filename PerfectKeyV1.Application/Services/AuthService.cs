using PerfectKeyV1.Application.Common;
using PerfectKeyV1.Application.DTOs.Auth;
using PerfectKeyV1.Application.Interfaces;
using PerfectKeyV1.Domain.Entities;
using PerfectKeyV1.Domain.Enums;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;

namespace PerfectKeyV1.Application.Services
{
    public class AuthService : IAuthService
    {
        private readonly IUserRepository _userRepo;
        private readonly IJwtService _jwtService;
        private readonly ILoginSessionRepository _loginSessionRepo;
        private readonly ILoginSessionService _loginSessionService;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly ITwoFactorService _twoFactorService;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IConfiguration _configuration;
        private readonly IUserHotelRepository _userHotelRepo;

        public AuthService(
            IUserRepository userRepo,
            IJwtService jwtService,
            ILoginSessionRepository loginSessionRepo,
            ILoginSessionService loginSessionService,
            IHttpContextAccessor httpContextAccessor,
            ITwoFactorService twoFactorService,
            IHttpClientFactory httpClientFactory,
            IConfiguration configuration,
            IUserHotelRepository userHotelRepo)
        {
            _userRepo = userRepo;
            _jwtService = jwtService;
            _loginSessionRepo = loginSessionRepo;
            _loginSessionService = loginSessionService;
            _httpContextAccessor = httpContextAccessor;
            _twoFactorService = twoFactorService;
            _httpClientFactory = httpClientFactory;
            _configuration = configuration;
            _userHotelRepo = userHotelRepo;
        }

        // ==================== AUTHENTICATION METHODS ====================

        public async Task<AuthResponse> LoginAsync(LoginRequest request)
        {
            try
            {
                // Validate input
                if (string.IsNullOrEmpty(request.Username) || string.IsNullOrEmpty(request.Password) || string.IsNullOrEmpty(request.HotelCode))
                {
                    return new AuthResponse { Success = false, Message = "Username, password, and hotel code are required" };
                }

                // Gọi API Gateway để đăng nhập
                var gatewayResponse = await CallGatewayLoginAsync(request);
                
                if (!gatewayResponse.Success)
                {
                    return new AuthResponse 
                    { 
                        Success = false, 
                        Message = gatewayResponse.Message 
                    };
                }

                // Lấy user từ database để lấy thông tin bổ sung
                var user = await _userRepo.GetByUserNameAsync(request.Username);
                if (user == null)
                {
                    // Nếu user không tồn tại trong local database, tạo mới từ thông tin Gateway
                    user = await CreateOrUpdateUserFromGateway(request.Username, gatewayResponse.UserInfo);
                }
                else
                {
                    // Cập nhật thông tin user từ Gateway
                    await UpdateUserFromGateway(user, gatewayResponse.UserInfo);
                }

                // Kiểm tra trạng thái user
                if (user.Status == (int)UserStatus.Deleted)
                    return new AuthResponse { Success = false, Message = "Account has been deleted" };

                if (user.Status == (int)UserStatus.Pending)
                    return new AuthResponse { Success = false, Message = "Account is pending approval" };

                // Check if 2FA is required (chỉ cho admin users)
                if (IsAdminUser(user) && user.TwoFactorEnabled == 1 && !string.IsNullOrEmpty(user.TwoFactorSecret))
                {
                    // Tạo session tạm thời chưa xác thực 2FA
                    var tempSession = await CreateLoginSessionAsync(user, gatewayResponse.Token, gatewayResponse.RefreshToken, false);
                    
                    return new AuthResponse
                    {
                        Success = true,
                        Message = "2FA required",
                        RequiresTwoFactor = true,
                        User = MapToUserDto(user),
                        Token = gatewayResponse.Token,
                        RefreshToken = gatewayResponse.RefreshToken,
                        SessionId = tempSession.Id
                    };
                }

                // Tạo session đầy đủ (đã xác thực)
                var session = await CreateLoginSessionAsync(user, gatewayResponse.Token, gatewayResponse.RefreshToken, false);
                session.IsTwoFactorVerified = true;
                await _loginSessionRepo.UpdateAsync(session);

                return new AuthResponse
                {
                    Success = true,
                    Message = "Authentication successful",
                    Token = gatewayResponse.Token,
                    RefreshToken = gatewayResponse.RefreshToken,
                    Expiration = gatewayResponse.ExpiresAt,
                    User = MapToUserDto(user),
                    SessionId = session.Id
                };
            }
            catch (Exception ex)
            {
                return new AuthResponse 
                { 
                    Success = false, 
                    Message = $"Login failed: {ex.Message}" 
                };
            }
        }

        public async Task<AuthResponse> VerifyTwoFactorAsync(TwoFactorRequest request)
        {
            try
            {
                var user = await _userRepo.GetByIdAsync(request.UserId);
                if (user == null || user.TwoFactorEnabled != 1 || string.IsNullOrEmpty(user.TwoFactorSecret))
                {
                    return new AuthResponse { Success = false, Message = "2FA not enabled or user not found" };
                }

                // Validate OTP code
                if (!_twoFactorService.ValidateTwoFactorCode(user.TwoFactorSecret, request.Code))
                {
                    // Kiểm tra xem có phải là recovery code không
                    if (!await ValidateRecoveryCode(user, request.Code))
                    {
                        return new AuthResponse { Success = false, Message = "Invalid OTP or recovery code" };
                    }
                }

                // Lấy session hiện tại và đánh dấu đã xác thực 2FA
                var currentToken = GetCurrentToken();
                var session = await _loginSessionRepo.GetByTokenAsync(currentToken);
                
                if (session == null)
                {
                    return new AuthResponse { Success = false, Message = "Session not found" };
                }

                session.IsTwoFactorVerified = true;
                session.LastActivity = DateTime.UtcNow;
                await _loginSessionRepo.UpdateAsync(session);

                return new AuthResponse
                {
                    Success = true,
                    Message = "2FA verified successfully",
                    Token = session.Token,
                    RefreshToken = session.RefreshToken,
                    Expiration = session.TokenExpiry ?? DateTime.UtcNow.AddMinutes(60),
                    User = MapToUserDto(user),
                    SessionId = session.Id
                };
            }
            catch (Exception ex)
            {
                return new AuthResponse { Success = false, Message = $"2FA verification failed: {ex.Message}" };
            }
        }

        public async Task<AuthResponse> RefreshTokenAsync(string token, string refreshToken)
        {
            try
            {
                // Gọi API Gateway để refresh token
                var gatewayResponse = await CallGatewayRefreshTokenAsync(refreshToken);
                
                if (!gatewayResponse.Success)
                {
                    return new AuthResponse 
                    { 
                        Success = false, 
                        Message = gatewayResponse.Message 
                    };
                }

                // Cập nhật session trong database
                var oldSession = await _loginSessionRepo.GetByRefreshTokenAsync(refreshToken);
                if (oldSession != null)
                {
                    oldSession.RefreshTokens(gatewayResponse.Token, gatewayResponse.RefreshToken, gatewayResponse.ExpiresAt);
                    await _loginSessionRepo.UpdateAsync(oldSession);
                    
                    // Lấy thông tin user
                    var user = await _userRepo.GetByIdAsync(oldSession.UserId);

                    return new AuthResponse
                    {
                        Success = true,
                        Message = "Token refreshed successfully",
                        Token = gatewayResponse.Token,
                        RefreshToken = gatewayResponse.RefreshToken,
                        Expiration = gatewayResponse.ExpiresAt,
                        User = user != null ? MapToUserDto(user) : null,
                        SessionId = oldSession.Id
                    };
                }

                return new AuthResponse 
                { 
                    Success = false, 
                    Message = "Session not found for refresh token" 
                };
            }
            catch (Exception ex)
            {
                return new AuthResponse 
                { 
                    Success = false, 
                    Message = $"Refresh token failed: {ex.Message}" 
                };
            }
        }

        public async Task<bool> LogoutAsync(string refreshToken)
        {
            try
            {
                // Gọi API Gateway để logout
                var logoutSuccess = await CallGatewayLogoutAsync(refreshToken);

                // Vô hiệu hóa session trong database
                var session = await _loginSessionRepo.GetByRefreshTokenAsync(refreshToken);
                if (session != null)
                {
                    session.Logout();
                    await _loginSessionRepo.UpdateAsync(session);
                }

                return logoutSuccess;
            }
            catch
            {
                return false;
            }
        }

        // ==================== HOTEL MANAGEMENT ====================

        public async Task<IEnumerable<UserHotelDto>> GetUserHotelsAsync(string username)
        {
            try
            {
                // Gọi API Gateway để lấy danh sách hotel
                var gatewayHotels = await CallGatewayGetUserHotelsAsync(username);
                
                // Cũng có thể lấy từ local database nếu cần
                var user = await _userRepo.GetByUserNameAsync(username);
                if (user != null)
                {
                    var localHotels = await _userHotelRepo.GetByUserIdAsync(user.Id);
                    // Kết hợp thông tin nếu cần
                }

                return gatewayHotels;
            }
            catch (Exception ex)
            {
                // Log error
                Console.WriteLine($"Error getting user hotels: {ex.Message}");
                return new List<UserHotelDto>();
            }
        }

        // ==================== TWO-FACTOR AUTHENTICATION ====================

        public async Task<TwoFactorSetupResponse> EnableTwoFactorAsync(int userId)
        {
            var user = await _userRepo.GetByIdAsync(userId);
            if (user == null)
                return new TwoFactorSetupResponse { Success = false, Message = "User not found" };

            if (user.TwoFactorEnabled == 1)
                return new TwoFactorSetupResponse { Success = false, Message = "2FA already enabled" };

            var secretKey = _twoFactorService.GenerateSecretKey();
            var recoveryCodes = _twoFactorService.GenerateRecoveryCodes();

            user.TwoFactorSecret = secretKey;
            user.TwoFactorRecoveryCodes = string.Join(";", recoveryCodes);

            var setupResponse = _twoFactorService.GenerateSetupCode(user.Email ?? string.Empty, secretKey);
            setupResponse.RecoveryCodes = recoveryCodes;

            await _userRepo.UpdateAsync(user);
            return setupResponse;
        }

        public async Task<TwoFactorSetupResponse> ConfirmEnableTwoFactorAsync(int userId, string code)
        {
            var user = await _userRepo.GetByIdAsync(userId);
            if (user == null || string.IsNullOrEmpty(user.TwoFactorSecret))
                return new TwoFactorSetupResponse { Success = false, Message = "User not found or 2FA not setup" };

            // Tạo TwoFactorRequest từ tham số
            var twoFactorRequest = new TwoFactorRequest
            {
                UserId = userId,
                Code = code
            };

            // Sử dụng VerifyTwoFactorAsync để xác thực code
            var verifyResult = await VerifyTwoFactorAsync(twoFactorRequest);
            
            if (!verifyResult.Success)
                return new TwoFactorSetupResponse { Success = false, Message = "Invalid OTP code" };

            user.TwoFactorEnabled = 1;
            await _userRepo.UpdateAsync(user);

            return new TwoFactorSetupResponse { Success = true, Message = "2FA enabled successfully" };
        }

        public async Task<TwoFactorSetupResponse> RegenerateQRAsync(int userId)
        {
            var user = await _userRepo.GetByIdAsync(userId);
            if (user == null || user.TwoFactorEnabled != 1 || string.IsNullOrEmpty(user.TwoFactorSecret))
                return new TwoFactorSetupResponse { Success = false, Message = "User not found or 2FA not enabled" };

            var setupResponse = _twoFactorService.GenerateSetupCode(user.Email ?? string.Empty, user.TwoFactorSecret);
            setupResponse.RecoveryCodes = user.TwoFactorRecoveryCodes?.Split(';').ToList() ?? new List<string>();

            return setupResponse;
        }

        public async Task<bool> DisableTwoFactorAsync(int userId, string code)
        {
            var user = await _userRepo.GetByIdAsync(userId);
            if (user == null || user.TwoFactorEnabled != 1)
                return false;

            // Tạo TwoFactorRequest để xác thực
            var twoFactorRequest = new TwoFactorRequest
            {
                UserId = userId,
                Code = code
            };

            // Sử dụng VerifyTwoFactorAsync để xác thực code
            var verifyResult = await VerifyTwoFactorAsync(twoFactorRequest);
            
            if (!verifyResult.Success)
                return false;

            user.TwoFactorEnabled = 0;
            user.TwoFactorSecret = null;
            user.TwoFactorRecoveryCodes = null;
            await _userRepo.UpdateAsync(user);

            return true;
        }

        public async Task<List<string>> GetRecoveryCodesAsync(int userId)
        {
            var user = await _userRepo.GetByIdAsync(userId);
            if (user == null || string.IsNullOrEmpty(user.TwoFactorRecoveryCodes))
                return new List<string>();

            return user.TwoFactorRecoveryCodes.Split(';').ToList();
        }

        public async Task<List<string>> GenerateNewRecoveryCodesAsync(int userId)
        {
            var user = await _userRepo.GetByIdAsync(userId);
            if (user == null || user.TwoFactorEnabled != 1)
                return new List<string>();

            var newRecoveryCodes = _twoFactorService.GenerateRecoveryCodes();
            user.TwoFactorRecoveryCodes = string.Join(";", newRecoveryCodes);
            await _userRepo.UpdateAsync(user);

            return newRecoveryCodes;
        }

        // ==================== USER MANAGEMENT ====================

        public async Task<AuthResponse> RegisterAsync(RegisterRequest request)
        {
            // Kiểm tra trong local database
            if (await _userRepo.UserNameExistsAsync(request.UserName))
                return new AuthResponse { Success = false, Message = "Username already exists" };

            if (await _userRepo.EmailExistsAsync(request.Email))
                return new AuthResponse { Success = false, Message = "Email already exists" };

            try
            {
                // 1. Đăng ký trên Gateway trước
                var gatewayRegistrationSuccess = await RegisterOnGatewayAsync(request);

                if (!gatewayRegistrationSuccess)
                {
                    return new AuthResponse
                    {
                        Success = false,
                        Message = "Failed to register on authentication service"
                    };
                }

                // 2. Tạo user trong local database
                var user = new User
                {
                    Guid = Guid.NewGuid(),
                    UserName = request.UserName,
                    PasswordHash = SecurePasswordHasher.Hash(request.Password),
                    FullName = request.FullName,
                    Email = request.Email,
                    Status = (int)UserStatus.Pending,
                    CreateDate = DateTime.UtcNow
                };

                await _userRepo.AddAsync(user);

                return new AuthResponse
                {
                    Success = true,
                    Message = "Registration successful. Please wait for admin approval.",
                    User = MapToUserDto(user)
                };
            }
            catch (Exception ex)
            {
                return new AuthResponse
                {
                    Success = false,
                    Message = $"Registration failed: {ex.Message}"
                };
            }
        }

        private async Task<bool> RegisterOnGatewayAsync(RegisterRequest request)
        {
            try
            {
                var httpClient = _httpClientFactory.CreateClient("Gateway");

                // Kiểm tra xem Gateway có API đăng ký không
                // Nếu không có, có thể cần liên hệ với team quản lý Gateway
                var gatewayBaseUrl = _configuration["Gateway:BaseUrl"] ?? "https://sit.api-pms.perfectkey.vn";

                // Giả sử Gateway có endpoint đăng ký (cần xác nhận với team Gateway)
                // var endpoint = $"{gatewayBaseUrl}/identity/api/v1/Auth/register";
                // var response = await httpClient.PostAsJsonAsync(endpoint, request);

                // Tạm thời return true nếu Gateway không có API đăng ký
                Console.WriteLine("NOTE: Gateway registration not implemented. Please contact Gateway team.");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Gateway registration error: {ex.Message}");
                return false;
            }
        }

        public async Task<bool> ForgotPasswordAsync(ForgotPasswordRequest request)
        {
            // Tạm thời implement đơn giản - có thể mở rộng sau
            var user = await _userRepo.GetByEmailAsync(request.Email);
            if (user == null)
                return true; // Security: always return true

            // Tạo reset token
            var resetToken = Guid.NewGuid().ToString();
            user.ResetToken = resetToken;
            user.ResetTokenExpiry = DateTime.UtcNow.AddHours(24);
            await _userRepo.UpdateAsync(user);

            // Gửi email (giả lập)
            Console.WriteLine($"Reset token for {user.Email}: {resetToken}");
            
            return true;
        }

        public async Task<bool> ResetPasswordAsync(ResetPasswordRequest request)
        {
            // Tìm user bằng reset token
            var user = await _userRepo.GetByResetTokenAsync(request.Token);
            if (user == null || user.ResetTokenExpiry < DateTime.UtcNow)
                return false;

            user.PasswordHash = SecurePasswordHasher.Hash(request.NewPassword);
            user.ResetToken = null;
            user.ResetTokenExpiry = null;
            user.LastModify = DateTime.UtcNow;

            await _userRepo.UpdateAsync(user);
            return true;
        }

        // ==================== TOKEN MANAGEMENT ====================

        public async Task<bool> RevokeTokenAsync(int userId)
        {
            var currentToken = GetCurrentToken();
            if (!string.IsNullOrEmpty(currentToken))
            {
                var session = await _loginSessionRepo.GetByTokenAsync(currentToken);
                if (session != null && session.UserId == userId)
                {
                    await _loginSessionRepo.DeactivateSessionAsync(session.Id);
                    
                    // Cũng có thể gọi Gateway để revoke token
                    try
                    {
                        await CallGatewayLogoutAsync(session.RefreshToken);
                    }
                    catch
                    {
                        // Continue even if Gateway call fails
                    }
                }
            }
            return true;
        }

        // ==================== ADMIN FUNCTIONS ====================

        public async Task<TwoFactorSetupResponse> AdminEnableTwoFactorForUserAsync(int targetUserId)
        {
            var user = await _userRepo.GetByIdAsync(targetUserId);
            if (user == null)
                return new TwoFactorSetupResponse { Success = false, Message = "User not found" };

            // Admin có thể enable 2FA mà không cần xác nhận OTP
            var secretKey = _twoFactorService.GenerateSecretKey();
            var recoveryCodes = _twoFactorService.GenerateRecoveryCodes();

            user.TwoFactorSecret = secretKey;
            user.TwoFactorRecoveryCodes = string.Join(";", recoveryCodes);
            user.TwoFactorEnabled = 1;

            await _userRepo.UpdateAsync(user);

            var setupResponse = _twoFactorService.GenerateSetupCode(user.Email ?? string.Empty, secretKey);
            setupResponse.RecoveryCodes = recoveryCodes;
            setupResponse.Message = "2FA enabled by admin";

            return setupResponse;
        }

        public async Task<AuthResponse> AdminConfirmEnableTwoFactorForUserAsync(int targetUserId)
        {
            // Admin xác nhận 2FA cho user
            var response = await ConfirmEnableTwoFactorAsync(targetUserId, "admin-confirm");
            if (response.Success)
            {
                response.Message = "2FA enabled by admin";
            }
            return new AuthResponse
            {
                Success = response.Success,
                Message = response.Message
            };
        }

        public async Task<TwoFactorSetupResponse> AdminRegenerateQRForUserAsync(int targetUserId)
        {
            // Admin có thể regenerate QR code cho user
            return await RegenerateQRAsync(targetUserId);
        }

        // ==================== SESSION VALIDATION ====================

        public async Task<bool> ValidateSessionAsync(string token)
        {
            if (string.IsNullOrEmpty(token))
                return false;

            var session = await _loginSessionRepo.GetByTokenAsync(token);
            if (session == null || !session.IsActive)
                return false;

            // Check if session is expired
            if (session.IsExpired())
            {
                session.IsActive = false;
                await _loginSessionRepo.UpdateAsync(session);
                return false;
            }

            // Check if 2FA is required and verified
            var user = await _userRepo.GetByIdAsync(session.UserId);
            if (user != null && IsAdminUser(user) && user.TwoFactorEnabled == 1)
            {
                return session.IsTwoFactorVerified;
            }

            return true;
        }

        // ==================== PASSWORD GENERATION ====================

        public async Task<string> GeneratePasswordAsync()
        {
            // Generate a random password
            const string validChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*";
            var random = new Random();
            var password = new string(Enumerable.Repeat(validChars, 12)
                .Select(s => s[random.Next(s.Length)]).ToArray());

            return await Task.FromResult(password);
        }

        // ==================== PRIVATE METHODS ====================

        #region Gateway Integration

        private async Task<GatewayLoginResponse> CallGatewayLoginAsync(LoginRequest request)
        {
            var httpClient = _httpClientFactory.CreateClient("Gateway");
            
            var gatewayBaseUrl = _configuration["Gateway:BaseUrl"] ?? "https://sit.api-pms.perfectkey.vn";
            var endpoint = $"{gatewayBaseUrl}/identity/api/v1/Auth/login";

            var response = await httpClient.PostAsJsonAsync(endpoint, new
            {
                username = request.Username,
                password = request.Password,
                hotelCode = request.HotelCode
            });

            if (response.IsSuccessStatusCode)
            {
                var content = await response.Content.ReadAsStringAsync();
                var loginResponse = JsonSerializer.Deserialize<LoginResponse>(content, new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });
                
                return new GatewayLoginResponse
                {
                    Success = true,
                    Token = loginResponse?.Token ?? string.Empty,
                    RefreshToken = loginResponse?.RefreshToken ?? string.Empty,
                    ExpiresAt = loginResponse?.ExpiresAt ?? DateTime.UtcNow.AddMinutes(60),
                    UserInfo = loginResponse?.User
                };
            }
            else
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                try
                {
                    var error = JsonSerializer.Deserialize<GatewayErrorResponse>(errorContent, new JsonSerializerOptions
                    {
                        PropertyNameCaseInsensitive = true
                    });
                    return new GatewayLoginResponse
                    {
                        Success = false,
                        Message = error?.Message ?? $"Login failed: {response.StatusCode}"
                    };
                }
                catch
                {
                    return new GatewayLoginResponse
                    {
                        Success = false,
                        Message = $"Login failed: {response.StatusCode} - {errorContent}"
                    };
                }
            }
        }

        private async Task<GatewayLoginResponse> CallGatewayRefreshTokenAsync(string refreshToken)
        {
            var httpClient = _httpClientFactory.CreateClient("Gateway");
            
            var gatewayBaseUrl = _configuration["Gateway:BaseUrl"] ?? "https://sit.api-pms.perfectkey.vn";
            var endpoint = $"{gatewayBaseUrl}/identity/api/v1/Auth/refresh-token";

            var response = await httpClient.PostAsJsonAsync(endpoint, new
            {
                refreshToken = refreshToken
            });

            if (response.IsSuccessStatusCode)
            {
                var content = await response.Content.ReadAsStringAsync();
                var refreshResponse = JsonSerializer.Deserialize<LoginResponse>(content, new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });
                
                return new GatewayLoginResponse
                {
                    Success = true,
                    Token = refreshResponse?.Token ?? string.Empty,
                    RefreshToken = refreshResponse?.RefreshToken ?? string.Empty,
                    ExpiresAt = refreshResponse?.ExpiresAt ?? DateTime.UtcNow.AddMinutes(60)
                };
            }
            else
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                return new GatewayLoginResponse
                {
                    Success = false,
                    Message = $"Refresh token failed: {response.StatusCode} - {errorContent}"
                };
            }
        }

        private async Task<bool> CallGatewayLogoutAsync(string refreshToken)
        {
            var httpClient = _httpClientFactory.CreateClient("Gateway");
            
            var gatewayBaseUrl = _configuration["Gateway:BaseUrl"] ?? "https://sit.api-pms.perfectkey.vn";
            var endpoint = $"{gatewayBaseUrl}/identity/api/v1/Auth/logout";

            var response = await httpClient.PostAsJsonAsync(endpoint, new
            {
                refreshToken = refreshToken
            });

            return response.IsSuccessStatusCode;
        }

        private async Task<List<UserHotelDto>> CallGatewayGetUserHotelsAsync(string username)
        {
            var httpClient = _httpClientFactory.CreateClient("Gateway");
            
            var gatewayBaseUrl = _configuration["Gateway:BaseUrl"] ?? "https://sit.api-pms.perfectkey.vn";
            var endpoint = $"{gatewayBaseUrl}/identity/api/v1/Auth/hotels/{Uri.EscapeDataString(username)}";

            var response = await httpClient.GetAsync(endpoint);

            if (response.IsSuccessStatusCode)
            {
                var content = await response.Content.ReadAsStringAsync();
                var hotels = JsonSerializer.Deserialize<List<UserHotelDto>>(content, new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });
                return hotels ?? new List<UserHotelDto>();
            }

            return new List<UserHotelDto>();
        }

        #endregion

        #region Helper Methods

        private bool IsAdminUser(User user)
        {
            return user.UserType == 0 || (user.UserName?.ToLower() == "admin");
        }

        private async Task<bool> ValidateRecoveryCode(User user, string code)
        {
            if (string.IsNullOrEmpty(user.TwoFactorRecoveryCodes))
                return false;

            var recoveryCodes = user.TwoFactorRecoveryCodes.Split(';');
            var isValid = recoveryCodes.Contains(code);

            if (isValid)
            {
                var updatedCodes = recoveryCodes.Where(c => c != code).ToList();
                user.TwoFactorRecoveryCodes = string.Join(";", updatedCodes);
                await _userRepo.UpdateAsync(user);
            }

            return isValid;
        }

        private async Task<LoginSession> CreateLoginSessionAsync(User user, string token, string refreshToken, bool rememberMe = false)
        {
            var httpContext = _httpContextAccessor.HttpContext;
            if (httpContext == null)
                throw new InvalidOperationException("HttpContext is not available");

            var ipAddress = httpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
            var userAgent = httpContext.Request.Headers["User-Agent"].ToString();

            var deviceInfo = await _loginSessionService.GetDeviceInfoAsync(httpContext.Request);
            var parsedDeviceInfo = await _loginSessionService.ParseDeviceInfoAsync(userAgent);
            var location = await _loginSessionService.GetLocationFromIpAsync(ipAddress);

            var session = new LoginSession
            {
                UserId = user.Id,
                Token = token,
                RefreshToken = refreshToken,
                DeviceInfo = deviceInfo,
                IpAddress = ipAddress,
                Location = location,
                Browser = parsedDeviceInfo.Browser,
                OperatingSystem = parsedDeviceInfo.OperatingSystem,
                SessionType = parsedDeviceInfo.IsMobile ? "Mobile" :
                             parsedDeviceInfo.IsTablet ? "Tablet" : "Web",
                UserAgent = userAgent,
                LoginTime = DateTime.UtcNow,
                LastActivity = DateTime.UtcNow,
                TokenExpiry = DateTime.UtcNow.AddMinutes(60),
                IsActive = true,
                IsTwoFactorVerified = false, // Mặc định chưa xác thực 2FA
                IsRememberMe = rememberMe,
                CreateDate = DateTime.UtcNow
            };

            return await _loginSessionRepo.AddAsync(session);
        }

        private async Task<User> CreateOrUpdateUserFromGateway(string username, UserInfoDto? userInfo)
        {
            var user = new User
            {
                Guid = userInfo?.Guid ?? Guid.NewGuid(),
                UserName = username,
                FullName = userInfo?.FullName ?? username,
                Email = userInfo?.Email ?? $"{username}@perfectkey.com",
                Status = (int)UserStatus.Active,
                UserType = 2, // Default to staff
                CreateDate = DateTime.UtcNow
            };

            await _userRepo.AddAsync(user);
            return user;
        }

        private async Task UpdateUserFromGateway(User user, UserInfoDto? userInfo)
        {
            if (userInfo != null)
            {
                user.FullName = userInfo.FullName ?? user.FullName;
                user.Email = userInfo.Email ?? user.Email;
                user.LastModify = DateTime.UtcNow;
                
                await _userRepo.UpdateAsync(user);
            }
        }

        private string GetCurrentToken()
        {
            var httpContext = _httpContextAccessor.HttpContext;
            if (httpContext == null) return string.Empty;

            var authHeader = httpContext.Request.Headers["Authorization"].FirstOrDefault();
            return authHeader?.Replace("Bearer ", "") ?? string.Empty;
        }

        private UserDto MapToUserDto(User user)
        {
            return new UserDto
            {
                Id = user.Id,
                Guid = user.Guid,
                UserName = user.UserName ?? string.Empty,
                FullName = user.FullName ?? string.Empty,
                Email = user.Email ?? string.Empty,
                Status = user.Status,
                UserType = user.UserType,
                TwoFactorEnabled = user.TwoFactorEnabled,
                CreateDate = user.CreateDate,
                LastModify = user.LastModify
            };
        }

        #endregion

        #region Helper Classes

        private class GatewayLoginResponse
        {
            public bool Success { get; set; }
            public string Message { get; set; } = string.Empty;
            public string Token { get; set; } = string.Empty;
            public string RefreshToken { get; set; } = string.Empty;
            public DateTime ExpiresAt { get; set; }
            public UserInfoDto? UserInfo { get; set; }
        }

        private class GatewayErrorResponse
        {
            public string? Message { get; set; }
            public string? Type { get; set; }
            public int? Status { get; set; }
        }

        #endregion
    }
}