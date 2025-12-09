using PerfectKeyV1.Domain.Entities;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace PerfectKeyV1.Application.Interfaces
{
    public interface IUserRepository
    {
        // ========== GET METHODS ==========
        Task<User?> GetByIdAsync(int id);
        Task<User?> GetByGuidAsync(Guid guid);
        Task<User?> GetByUserNameAsync(string userName);
        Task<User?> GetByEmailAsync(string email);
        Task<User?> GetByResetTokenAsync(string resetToken);
        Task<User?> GetByCodeAsync(string code);

        // ========== LIST METHODS ==========
        Task<IEnumerable<User>> GetAllAsync();
        Task<IEnumerable<User>> GetAllActiveAsync();
        Task<IEnumerable<User>> GetUsersByStatusAsync(int status);
        Task<IEnumerable<User>> GetUsersByUserTypeAsync(int userType);
        Task<IEnumerable<User>> GetUsersByHotelAsync(Guid hotelGuid);
        Task<IEnumerable<User>> GetUsersByGroupParentAsync(int groupParentId);
        Task<IEnumerable<User>> GetUsersByGroupParentGuidAsync(Guid groupParentGuid);

        // ========== CHECK METHODS ==========
        Task<bool> UserNameExistsAsync(string userName, int? excludeUserId = null);
        Task<bool> EmailExistsAsync(string email, int? excludeUserId = null);
        Task<bool> CodeExistsAsync(string code, int? excludeUserId = null);
        Task<bool> IsUserActiveAsync(int userId);
        Task<bool> HasHotelAccessAsync(int userId, Guid hotelGuid);

        // ========== CRUD METHODS ==========
        Task AddAsync(User user);
        Task UpdateAsync(User user);
        Task DeleteAsync(User user);
        Task<bool> SoftDeleteAsync(int userId);

        // ========== UPDATE METHODS ==========
        Task<bool> UpdateProfileAsync(int userId, string fullName, string email, string? mobile, string? avatarUrl);
        Task<bool> UpdatePasswordAsync(int userId, string newPasswordHash);
        Task<bool> UpdateStatusAsync(int userId, int status);
        Task<bool> UpdateUserTypeAsync(int userId, int userType);
        Task<bool> UpdateTwoFactorAsync(int userId, string? secretKey, string? recoveryCodes, int enabled);
        Task<bool> SetResetTokenAsync(string email, string resetToken, DateTime expiry);
        Task<bool> ClearResetTokenAsync(int userId);
        Task<bool> UpdateLastLoginAsync(int userId);

        // ========== SEARCH & FILTER METHODS ==========
        Task<IEnumerable<User>> SearchUsersAsync(string keyword);
        Task<IEnumerable<User>> GetUsersPagedAsync(int pageNumber, int pageSize, string sortBy = "Newest");
        Task<IEnumerable<User>> FilterUsersAsync(int? status = null, int? userType = null, DateTime? fromDate = null, DateTime? toDate = null);

        // ========== STATISTICS METHODS ==========
        Task<int> GetTotalUserCountAsync();
        Task<int> GetActiveUserCountAsync();
        Task<int> GetUserCountByStatusAsync(int status);
        Task<int> GetUserCountByUserTypeAsync(int userType);
        Task<Dictionary<string, int>> GetUserStatisticsAsync();

        // ========== VALIDATION METHODS ==========
        Task<bool> IsValidUserAsync(int userId);
        Task<bool> IsUserExpiredAsync(int userId);
        Task<bool> ValidateCredentialsAsync(string userName, string passwordHash);
    }
}