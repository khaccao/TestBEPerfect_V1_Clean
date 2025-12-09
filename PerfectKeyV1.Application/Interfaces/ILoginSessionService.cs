using Microsoft.AspNetCore.Http;
using PerfectKeyV1.Application.DTOs.LoginSession;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PerfectKeyV1.Application.Interfaces
{
    public interface ILoginSessionService
    {
        Task<LoginSessionResponse> GetUserSessionsAsync(int currentUserId, LoginSessionRequest request);
        Task<LoginSessionDetailDto?> GetSessionDetailAsync(int sessionId, int currentUserId);
        Task<ActiveSessionStatsDto> GetSessionStatsAsync(int userId);
        Task<bool> LogoutSessionAsync(int sessionId, int currentUserId);
        Task<bool> LogoutOtherSessionsAsync(int currentUserId, int currentSessionId);
        Task<bool> LogoutAllSessionsAsync(int currentUserId);
        Task<bool> UpdateSessionActivityAsync(string token);
        Task<bool> ValidateSessionAsync(string token);
        Task<string> GetLocationFromIpAsync(string ipAddress);
        Task<string> GetDeviceInfoAsync(HttpRequest request);
        Task<DeviceInfoDto> ParseDeviceInfoAsync(string userAgent);

        // Admin methods
        Task<bool> AdminLogoutUserSessionsAsync(int targetUserId);
        Task<List<LoginSessionDetailDto>> GetSessionsByHotelAsync(Guid hotelGuid, bool activeOnly = true);
    }

    public class DeviceInfoDto
    {
        public string DeviceType { get; set; } = "Unknown";
        public string Browser { get; set; } = "Unknown";
        public string OperatingSystem { get; set; } = "Unknown";
        public string Platform { get; set; } = "Unknown";
        public bool IsMobile { get; set; }
        public bool IsTablet { get; set; }
        public bool IsDesktop { get; set; }
    }
}
