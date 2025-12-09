using PerfectKeyV1.Domain.Entities;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace PerfectKeyV1.Application.Interfaces
{
    public interface ILoginSessionRepository
    {
        // Basic CRUD
        Task<LoginSession> AddAsync(LoginSession session);
        Task<LoginSession?> GetByIdAsync(int id);
        Task<bool> UpdateAsync(LoginSession session);

        // Token-based queries
        Task<LoginSession?> GetByTokenAsync(string token);
        Task<LoginSession?> GetByRefreshTokenAsync(string refreshToken);

        // User sessions
        Task<List<LoginSession>> GetUserSessionsAsync(int userId, bool? activeOnly = null);
        Task<List<LoginSession>> GetUserSessionsPagedAsync(int userId, int pageNumber, int pageSize, string sortBy = "Newest", bool? activeOnly = null);
        Task<int> GetUserSessionsCountAsync(int userId, bool? activeOnly = null);

        // Session management
        Task<bool> DeactivateSessionAsync(int sessionId);
        Task<bool> DeactivateAllSessionsAsync(int userId, int? excludeSessionId = null);
        Task<bool> DeactivateExpiredSessionsAsync();

        // Activity tracking
        Task<bool> UpdateActivityAsync(int sessionId);

        // Hotel-based sessions (mới thêm)
        Task<List<LoginSession>> GetSessionsByHotelAsync(Guid hotelGuid, bool activeOnly = true);

        // Session validation
        Task<bool> IsTokenActiveAsync(string token);

        // Session stats
        Task<int> GetActiveSessionCountAsync(int userId);
        Task<int> GetTotalSessionCountAsync(int userId);
    }
}