using PerfectKeyV1.Application.DTOs.LoginSession;
using PerfectKeyV1.Application.Interfaces;
using PerfectKeyV1.Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using UAParser;

namespace PerfectKeyV1.Application.Services
{
    public class LoginSessionService : ILoginSessionService
    {
        private readonly ILoginSessionRepository _loginSessionRepo;
        private readonly IUserRepository _userRepo;
        private readonly IUserHotelRepository _userHotelRepo; // Thêm dependency này
        private readonly IHttpContextAccessor _httpContextAccessor;

        public LoginSessionService(
            ILoginSessionRepository loginSessionRepo,
            IUserRepository userRepo,
            IUserHotelRepository userHotelRepo, // Thêm parameter này
            IHttpContextAccessor httpContextAccessor)
        {
            _loginSessionRepo = loginSessionRepo;
            _userRepo = userRepo;
            _userHotelRepo = userHotelRepo; // Khởi tạo
            _httpContextAccessor = httpContextAccessor;
        }

        public async Task<LoginSessionResponse> GetUserSessionsAsync(int currentUserId, LoginSessionRequest request)
        {
            var targetUserId = request.UserId ?? currentUserId;

            var sessions = await _loginSessionRepo.GetUserSessionsPagedAsync(
                targetUserId, request.PageNumber, request.PageSize, request.SortBy, request.ShowActiveOnly);

            var totalCount = await _loginSessionRepo.GetUserSessionsCountAsync(targetUserId, request.ShowActiveOnly);
            var totalPages = (int)Math.Ceiling(totalCount / (double)request.PageSize);

            var currentToken = GetCurrentToken();
            LoginSession? currentSession = !string.IsNullOrEmpty(currentToken)
                ? await _loginSessionRepo.GetByTokenAsync(currentToken)
                : null;

            var sessionDtos = new List<LoginSessionDto>();
            foreach (var session in sessions)
            {
                var dto = await MapToDtoAsync(session, currentSession?.Id);
                sessionDtos.Add(dto);
            }

            return new LoginSessionResponse
            {
                Success = true,
                Message = "Sessions retrieved successfully",
                Sessions = sessionDtos,
                TotalCount = totalCount,
                PageNumber = request.PageNumber,
                PageSize = request.PageSize,
                TotalPages = totalPages
            };
        }

        public async Task<bool> LogoutSessionAsync(int sessionId, int currentUserId)
        {
            var session = await _loginSessionRepo.GetByIdAsync(sessionId);
            if (session == null || session.UserId != currentUserId) // Sửa == null thay vì is null
                return false;

            return await _loginSessionRepo.DeactivateSessionAsync(sessionId);
        }

        public async Task<bool> LogoutOtherSessionsAsync(int currentUserId, int currentSessionId)
        {
            return await _loginSessionRepo.DeactivateAllSessionsAsync(currentUserId, currentSessionId);
        }

        public async Task<bool> UpdateSessionActivityAsync(string token)
        {
            var session = await _loginSessionRepo.GetByTokenAsync(token);
            if (session == null) // Sửa == null thay vì is null
                return false;

            return await _loginSessionRepo.UpdateActivityAsync(session.Id);
        }

        public async Task<string> GetLocationFromIpAsync(string ipAddress)
        {
            try
            {
                if (string.IsNullOrEmpty(ipAddress) || ipAddress == "::1" || ipAddress == "127.0.0.1")
                    return "Localhost";

                using var httpClient = new HttpClient();
                httpClient.Timeout = TimeSpan.FromSeconds(5);

                var response = await httpClient.GetStringAsync($"http://ip-api.com/json/{ipAddress}");
                var ipInfo = JsonSerializer.Deserialize<IpApiResponse>(response);

                if (ipInfo?.Status == "success")
                {
                    var parts = new List<string>();
                    if (!string.IsNullOrEmpty(ipInfo.City)) parts.Add(ipInfo.City);
                    if (!string.IsNullOrEmpty(ipInfo.Country)) parts.Add(ipInfo.Country);
                    return string.Join(", ", parts);
                }
            }
            catch
            {
                // Fallback if IP service fails
            }

            return "Unknown Location";
        }

        public async Task<string> GetDeviceInfoAsync(HttpRequest request)
        {
            var userAgent = request.Headers["User-Agent"].ToString();
            var deviceInfo = "Unknown Device";

            if (userAgent.Contains("Windows"))
                deviceInfo = "Windows";
            else if (userAgent.Contains("Mac"))
                deviceInfo = "Mac";
            else if (userAgent.Contains("Linux"))
                deviceInfo = "Linux";
            else if (userAgent.Contains("Android"))
                deviceInfo = "Android";
            else if (userAgent.Contains("iOS") || userAgent.Contains("iPhone"))
                deviceInfo = "iOS";

            if (userAgent.Contains("Chrome"))
                deviceInfo += " · Chrome";
            else if (userAgent.Contains("Firefox"))
                deviceInfo += " · Firefox";
            else if (userAgent.Contains("Safari") && !userAgent.Contains("Chrome"))
                deviceInfo += " · Safari";
            else if (userAgent.Contains("Edge"))
                deviceInfo += " · Edge";

            return await Task.FromResult(deviceInfo); // Sửa để tránh warning CS1998
        }

        #region Private Methods

        private string GetCurrentToken()
        {
            var httpContext = _httpContextAccessor.HttpContext;
            if (httpContext == null) return string.Empty;

            var authHeader = httpContext.Request.Headers["Authorization"].FirstOrDefault();
            return authHeader?.Replace("Bearer ", "") ?? string.Empty;
        }

        private async Task<LoginSessionDto> MapToDtoAsync(LoginSession session, int? currentSessionId)
        {
            var isCurrentSession = currentSessionId.HasValue && session.Id == currentSessionId.Value;

            var user = await _userRepo.GetByIdAsync(session.UserId);
            var userInfo = user != null ? MapToUserSessionInfoDto(user) : null; // Sửa != null thay vì is not null

            return new LoginSessionDto
            {
                Id = session.Id,
                UserId = session.UserId,
                DeviceInfo = session.DeviceInfo,
                IpAddress = session.IpAddress,
                Location = session.Location,
                LoginTime = session.LoginTime,
                LastActivity = session.LastActivity,
                LogoutTime = session.LogoutTime,
                IsActive = session.IsActive,
                IsCurrentSession = isCurrentSession,
                StatusDisplay = isCurrentSession ? "Phiên hiện tại" :
                              session.IsActive ? "Đang hoạt động" : "Đã đăng xuất",
                TimeAgo = GetTimeAgo(session.LastActivity ?? session.LoginTime),
                User = userInfo
            };
        }

        private UserSessionInfoDto MapToUserSessionInfoDto(User user)
        {
            return new UserSessionInfoDto
            {
                Id = user.Id,
                UserName = user.UserName,
                FullName = user.FullName,
                Email = user.Email ?? string.Empty,
                AvatarUrl = user.AvatarUrl,
                UserType = user.UserType,
                Status = user.Status,
                UserTypeDisplay = GetUserTypeDisplay(user.UserType),
                StatusDisplay = GetStatusDisplay(user.Status)
            };
        }

        private string GetUserTypeDisplay(int? userType)
        {
            return userType switch
            {
                0 => "Super Admin",
                1 => "Hotel Admin",
                2 => "Staff",
                3 => "Customer",
                _ => "Unknown"
            };
        }

        private string GetStatusDisplay(int status)
        {
            return status switch
            {
                -1 => "Đã xóa",
                0 => "Đang hoạt động",
                1 => "Đang chờ",
                _ => "Unknown"
            };
        }

        private string GetTimeAgo(DateTime dateTime)
        {
            var timeSpan = DateTime.UtcNow - dateTime;

            if (timeSpan.TotalMinutes < 1)
                return "Vừa xong";
            if (timeSpan.TotalHours < 1)
                return $"{(int)timeSpan.TotalMinutes} phút trước";
            if (timeSpan.TotalDays < 1)
                return $"{(int)timeSpan.TotalHours} giờ trước";
            if (timeSpan.TotalDays < 30)
                return $"{(int)timeSpan.TotalDays} ngày trước";

            return $"{(int)(timeSpan.TotalDays / 30)} tháng trước";
        }

        private class IpApiResponse
        {
            public string Status { get; set; } = string.Empty;
            public string Country { get; set; } = string.Empty;
            public string City { get; set; } = string.Empty;
        }

        #endregion

        public async Task<LoginSessionDetailDto?> GetSessionDetailAsync(int sessionId, int currentUserId)
        {
            var session = await _loginSessionRepo.GetByIdAsync(sessionId);
            if (session == null || session.UserId != currentUserId)
                return null;

            var user = await _userRepo.GetByIdAsync(session.UserId);
            var currentToken = GetCurrentToken();
            var isCurrentSession = session.Token == currentToken;

            return MapToDetailDto(session, user, isCurrentSession);
        }

        public async Task<ActiveSessionStatsDto> GetSessionStatsAsync(int userId)
        {
            var sessions = await _loginSessionRepo.GetUserSessionsAsync(userId);
            var activeSessions = sessions.Where(s => s.IsActive).ToList();

            var stats = new ActiveSessionStatsDto
            {
                TotalSessions = sessions.Count,
                ActiveSessions = activeSessions.Count,
                ExpiredSessions = sessions.Count(s => s.IsExpired()),
                UniqueDevices = activeSessions.Select(s => s.DeviceInfo).Distinct().Count(),
                UniqueLocations = activeSessions.Select(s => s.Location).Distinct().Count(),
                DeviceStats = activeSessions
                    .GroupBy(s => s.DeviceInfo)
                    .Select(g => new DeviceStatsDto
                    {
                        DeviceType = g.Key,
                        Browser = g.First().Browser ?? "Unknown",
                        SessionCount = g.Count()
                    })
                    .ToList(),
                LocationStats = activeSessions
                    .GroupBy(s => s.Location)
                    .Select(g => new LocationStatsDto
                    {
                        Location = g.Key,
                        IpAddress = g.First().IpAddress,
                        SessionCount = g.Count(),
                        LastAccess = g.Max(s => s.LastActivity ?? s.LoginTime)
                    })
                    .ToList()
            };

            return await Task.FromResult(stats); // Sửa để tránh warning CS1998
        }

        public async Task<bool> LogoutAllSessionsAsync(int currentUserId)
        {
            return await _loginSessionRepo.DeactivateAllSessionsAsync(currentUserId);
        }

        public async Task<bool> ValidateSessionAsync(string token)
        {
            var session = await _loginSessionRepo.GetByTokenAsync(token);
            return session != null && session.IsActive && !session.IsExpired(); // Sửa != null thay vì !=
        }

        public async Task<DeviceInfoDto> ParseDeviceInfoAsync(string userAgent)
        {
            var parser = Parser.GetDefault();
            var clientInfo = parser.Parse(userAgent);

            var deviceInfo = new DeviceInfoDto
            {
                DeviceType = clientInfo.Device.Family,
                Browser = clientInfo.UA.Family,
                OperatingSystem = clientInfo.OS.Family,
                Platform = GetPlatform(clientInfo),
                IsMobile = clientInfo.Device.IsSpider == false &&
                          (clientInfo.Device.Family.ToLower().Contains("mobile") ||
                           clientInfo.Device.Family.ToLower().Contains("phone")),
                IsTablet = clientInfo.Device.Family.ToLower().Contains("tablet"),
                IsDesktop = !clientInfo.Device.Family.ToLower().Contains("mobile") &&
                           !clientInfo.Device.Family.ToLower().Contains("tablet") &&
                           !clientInfo.Device.Family.ToLower().Contains("phone")
            };

            return await Task.FromResult(deviceInfo); // Sửa để tránh warning CS1998
        }

        public async Task<bool> AdminLogoutUserSessionsAsync(int targetUserId)
        {
            return await _loginSessionRepo.DeactivateAllSessionsAsync(targetUserId);
        }

        public async Task<List<LoginSessionDetailDto>> GetSessionsByHotelAsync(Guid hotelGuid, bool activeOnly = true)
        {
            // Get all users who have access to this hotel
            var userHotels = await _userHotelRepo.GetByHotelGuidAsync(hotelGuid);
            var userIds = userHotels.Select(uh => uh.UserId).Distinct().ToList();

            var allSessions = new List<LoginSession>();
            foreach (var userId in userIds)
            {
                var userSessions = await _loginSessionRepo.GetUserSessionsAsync(userId, activeOnly);
                allSessions.AddRange(userSessions);
            }

            var sessionDtos = new List<LoginSessionDetailDto>();
            foreach (var session in allSessions)
            {
                var user = await _userRepo.GetByIdAsync(session.UserId);
                sessionDtos.Add(MapToDetailDto(session, user, false));
            }

            return sessionDtos;
        }

        #region Private Helper Methods

        private LoginSessionDetailDto MapToDetailDto(LoginSession session, User? user, bool isCurrentSession)
        {
            var dto = new LoginSessionDetailDto
            {
                Id = session.Id,
                UserId = session.UserId,
                DeviceInfo = session.DeviceInfo,
                IpAddress = session.IpAddress,
                Location = session.Location,
                Browser = session.Browser ?? "Unknown",
                OperatingSystem = session.OperatingSystem ?? "Unknown",
                SessionType = session.SessionType ?? "Web",
                LoginTime = session.LoginTime,
                LastActivity = session.LastActivity,
                LogoutTime = session.LogoutTime,
                IsActive = session.IsActive,
                IsCurrentSession = isCurrentSession,
                IsRememberMe = session.IsRememberMe,
                StatusDisplay = GetStatusDisplay(session),
                TimeAgo = GetTimeAgo(session.LastActivity ?? session.LoginTime),
                Duration = GetDurationDisplay(session),
                IsExpired = session.IsExpired(),
                IsLongLived = session.IsLongLived(),
                RiskLevel = CalculateRiskLevel(session),
                User = user != null ? MapToUserSessionInfoDto(user) : null
            };

            return dto;
        }

        private string GetStatusDisplay(LoginSession session)
        {
            if (!session.IsActive)
                return "Đã đăng xuất";

            if (session.IsExpired())
                return "Đã hết hạn";

            return "Đang hoạt động";
        }

        private string GetDurationDisplay(LoginSession session)
        {
            var duration = session.GetSessionDuration();

            if (duration.TotalDays >= 1)
                return $"{(int)duration.TotalDays} ngày {(int)duration.Hours} giờ";

            if (duration.TotalHours >= 1)
                return $"{(int)duration.TotalHours} giờ {(int)duration.Minutes} phút";

            return $"{(int)duration.TotalMinutes} phút";
        }

        private string CalculateRiskLevel(LoginSession session)
        {
            // Simple risk assessment logic
            if (session.Location == "Unknown Location" || session.IpAddress == "Unknown")
                return "High";

            if (session.IsLongLived())
                return "Medium";

            return "Low";
        }

        private string GetPlatform(ClientInfo clientInfo)
        {
            var os = clientInfo.OS.Family.ToLower();
            if (os.Contains("windows")) return "Windows";
            if (os.Contains("mac")) return "macOS";
            if (os.Contains("linux")) return "Linux";
            if (os.Contains("android")) return "Android";
            if (os.Contains("ios")) return "iOS";
            return "Unknown";
        }

        #endregion
    }
}