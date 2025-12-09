using PerfectKeyV1.Application.Interfaces;
using PerfectKeyV1.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace PerfectKeyV1.Infrastructure.Persistence.Repositories
{
    public class UserRepository : IUserRepository
    {
        private readonly ApplicationDbContext _context;

        public UserRepository(ApplicationDbContext context)
        {
            _context = context;
        }

        // ========== GET METHODS ==========

        public async Task<User?> GetByIdAsync(int id)
        {
            return await _context.Users
                .Include(u => u.UserHotels)
                .FirstOrDefaultAsync(u => u.Id == id);
        }

        public async Task<User?> GetByGuidAsync(Guid guid)
        {
            return await _context.Users
                .Include(u => u.UserHotels)
                .FirstOrDefaultAsync(u => u.Guid == guid);
        }

        public async Task<User?> GetByUserNameAsync(string userName)
        {
            return await _context.Users
                .Include(u => u.UserHotels)
                .FirstOrDefaultAsync(u => u.UserName == userName);
        }

        public async Task<User?> GetByEmailAsync(string email)
        {
            return await _context.Users
                .FirstOrDefaultAsync(u => u.Email == email);
        }

        public async Task<User?> GetByResetTokenAsync(string resetToken)
        {
            return await _context.Users
                .FirstOrDefaultAsync(u => u.ResetToken == resetToken && u.ResetTokenExpiry > DateTime.UtcNow);
        }

        public async Task<User?> GetByCodeAsync(string code)
        {
            return await _context.Users
                .FirstOrDefaultAsync(u => u.Code == code);
        }

        // ========== LIST METHODS ==========

        public async Task<IEnumerable<User>> GetAllAsync()
        {
            return await _context.Users
                .Include(u => u.UserHotels)
                .Where(u => u.Status != -1) // Exclude deleted users
                .OrderByDescending(u => u.CreateDate)
                .ToListAsync();
        }

        public async Task<IEnumerable<User>> GetAllActiveAsync()
        {
            return await _context.Users
                .Where(u => u.Status == 0) // Only active users
                .OrderByDescending(u => u.CreateDate)
                .ToListAsync();
        }

        public async Task<IEnumerable<User>> GetUsersByStatusAsync(int status)
        {
            return await _context.Users
                .Where(u => u.Status == status)
                .OrderByDescending(u => u.CreateDate)
                .ToListAsync();
        }

        public async Task<IEnumerable<User>> GetUsersByUserTypeAsync(int userType)
        {
            return await _context.Users
                .Where(u => u.UserType == userType && u.Status != -1)
                .OrderByDescending(u => u.CreateDate)
                .ToListAsync();
        }

        public async Task<IEnumerable<User>> GetUsersByHotelAsync(Guid hotelGuid)
        {
            return await _context.Users
                .Include(u => u.UserHotels)
                .Where(u => u.UserHotels.Any(uh => uh.HotelGuid == hotelGuid) && u.Status != -1)
                .OrderByDescending(u => u.CreateDate)
                .ToListAsync();
        }

        public async Task<IEnumerable<User>> GetUsersByGroupParentAsync(int groupParentId)
        {
            return await _context.Users
                .Where(u => u.GroupParent == groupParentId && u.Status != -1)
                .OrderByDescending(u => u.CreateDate)
                .ToListAsync();
        }

        public async Task<IEnumerable<User>> GetUsersByGroupParentGuidAsync(Guid groupParentGuid)
        {
            return await _context.Users
                .Where(u => u.GroupParentGuid == groupParentGuid && u.Status != -1)
                .OrderByDescending(u => u.CreateDate)
                .ToListAsync();
        }

        // ========== CHECK METHODS ==========

        public async Task<bool> UserNameExistsAsync(string userName, int? excludeUserId = null)
        {
            var query = _context.Users
                .Where(u => u.UserName.ToLower() == userName.ToLower());

            if (excludeUserId.HasValue)
            {
                query = query.Where(u => u.Id != excludeUserId.Value);
            }

            return await query.AnyAsync();
        }

        public async Task<bool> EmailExistsAsync(string email, int? excludeUserId = null)
        {
            if (string.IsNullOrEmpty(email))
                return false;

            var query = _context.Users
                .Where(u => u.Email != null && u.Email.ToLower() == email.ToLower());

            if (excludeUserId.HasValue)
            {
                query = query.Where(u => u.Id != excludeUserId.Value);
            }

            return await query.AnyAsync();
        }

        public async Task<bool> CodeExistsAsync(string code, int? excludeUserId = null)
        {
            if (string.IsNullOrEmpty(code))
                return false;

            var query = _context.Users
                .Where(u => u.Code != null && u.Code.ToLower() == code.ToLower());

            if (excludeUserId.HasValue)
            {
                query = query.Where(u => u.Id != excludeUserId.Value);
            }

            return await query.AnyAsync();
        }

        public async Task<bool> IsUserActiveAsync(int userId)
        {
            var user = await GetByIdAsync(userId);
            return user != null && user.Status == 0; // Status 0 = Active
        }

        public async Task<bool> HasHotelAccessAsync(int userId, Guid hotelGuid)
        {
            return await _context.UserHotels
                .AnyAsync(uh => uh.UserId == userId && uh.HotelGuid == hotelGuid && uh.Status == 1);
        }

        // ========== CRUD METHODS ==========

        public async Task AddAsync(User user)
        {
            user.CreateDate = DateTime.UtcNow;
            user.Guid = Guid.NewGuid();
            _context.Users.Add(user);
            await _context.SaveChangesAsync();
        }

        public async Task UpdateAsync(User user)
        {
            user.LastModify = DateTime.UtcNow;
            _context.Users.Update(user);
            await _context.SaveChangesAsync();
        }

        public async Task DeleteAsync(User user)
        {
            _context.Users.Remove(user);
            await _context.SaveChangesAsync();
        }

        public async Task<bool> SoftDeleteAsync(int userId)
        {
            var user = await GetByIdAsync(userId);
            if (user == null)
                return false;

            user.Status = -1; // Mark as deleted
            user.LastModify = DateTime.UtcNow;

            try
            {
                _context.Users.Update(user);
                return await _context.SaveChangesAsync() > 0;
            }
            catch
            {
                return false;
            }
        }

        // ========== UPDATE METHODS ==========

        public async Task<bool> UpdateProfileAsync(int userId, string fullName, string email, string? mobile, string? avatarUrl)
        {
            var user = await GetByIdAsync(userId);
            if (user == null)
                return false;

            user.FullName = fullName;
            user.Email = email;
            user.Mobile = mobile;
            user.AvatarUrl = avatarUrl;
            user.LastModify = DateTime.UtcNow;

            try
            {
                _context.Users.Update(user);
                return await _context.SaveChangesAsync() > 0;
            }
            catch
            {
                return false;
            }
        }

        public async Task<bool> UpdatePasswordAsync(int userId, string newPasswordHash)
        {
            var user = await GetByIdAsync(userId);
            if (user == null)
                return false;

            user.PasswordHash = newPasswordHash;
            user.LastModify = DateTime.UtcNow;

            try
            {
                _context.Users.Update(user);
                return await _context.SaveChangesAsync() > 0;
            }
            catch
            {
                return false;
            }
        }

        public async Task<bool> UpdateStatusAsync(int userId, int status)
        {
            var user = await GetByIdAsync(userId);
            if (user == null)
                return false;

            user.Status = status;
            user.LastModify = DateTime.UtcNow;

            try
            {
                _context.Users.Update(user);
                return await _context.SaveChangesAsync() > 0;
            }
            catch
            {
                return false;
            }
        }

        public async Task<bool> UpdateUserTypeAsync(int userId, int userType)
        {
            var user = await GetByIdAsync(userId);
            if (user == null)
                return false;

            user.UserType = userType;
            user.LastModify = DateTime.UtcNow;

            try
            {
                _context.Users.Update(user);
                return await _context.SaveChangesAsync() > 0;
            }
            catch
            {
                return false;
            }
        }

        public async Task<bool> UpdateTwoFactorAsync(int userId, string? secretKey, string? recoveryCodes, int enabled)
        {
            var user = await GetByIdAsync(userId);
            if (user == null)
                return false;

            user.TwoFactorSecret = secretKey;
            user.TwoFactorRecoveryCodes = recoveryCodes;
            user.TwoFactorEnabled = enabled;
            user.LastModify = DateTime.UtcNow;

            try
            {
                _context.Users.Update(user);
                return await _context.SaveChangesAsync() > 0;
            }
            catch
            {
                return false;
            }
        }

        public async Task<bool> SetResetTokenAsync(string email, string resetToken, DateTime expiry)
        {
            var user = await GetByEmailAsync(email);
            if (user == null)
                return false;

            user.ResetToken = resetToken;
            user.ResetTokenExpiry = expiry;
            user.LastModify = DateTime.UtcNow;

            try
            {
                _context.Users.Update(user);
                return await _context.SaveChangesAsync() > 0;
            }
            catch
            {
                return false;
            }
        }

        public async Task<bool> ClearResetTokenAsync(int userId)
        {
            var user = await GetByIdAsync(userId);
            if (user == null)
                return false;

            user.ResetToken = null;
            user.ResetTokenExpiry = null;
            user.LastModify = DateTime.UtcNow;

            try
            {
                _context.Users.Update(user);
                return await _context.SaveChangesAsync() > 0;
            }
            catch
            {
                return false;
            }
        }

        public async Task<bool> UpdateLastLoginAsync(int userId)
        {
            var user = await GetByIdAsync(userId);
            if (user == null)
                return false;

            // Cập nhật ValidTime cho lần đăng nhập tiếp theo
            user.ValidTime = DateTime.UtcNow.AddHours(1); // Ví dụ: valid trong 1 giờ
            user.LastModify = DateTime.UtcNow;

            try
            {
                _context.Users.Update(user);
                return await _context.SaveChangesAsync() > 0;
            }
            catch
            {
                return false;
            }
        }

        // ========== SEARCH & FILTER METHODS ==========

        public async Task<IEnumerable<User>> SearchUsersAsync(string keyword)
        {
            if (string.IsNullOrEmpty(keyword))
                return await GetAllAsync();

            keyword = keyword.ToLower();

            return await _context.Users
                .Where(u => u.Status != -1 && (
                    (u.UserName != null && u.UserName.ToLower().Contains(keyword)) ||
                    (u.FullName != null && u.FullName.ToLower().Contains(keyword)) ||
                    (u.Email != null && u.Email.ToLower().Contains(keyword)) ||
                    (u.Code != null && u.Code.ToLower().Contains(keyword)) ||
                    (u.Mobile != null && u.Mobile.Contains(keyword)) ||
                    (u.JobTitle != null && u.JobTitle.ToLower().Contains(keyword)) ||
                    (u.Alias != null && u.Alias.ToLower().Contains(keyword))
                ))
                .OrderByDescending(u => u.CreateDate)
                .ToListAsync();
        }

        public async Task<IEnumerable<User>> GetUsersPagedAsync(int pageNumber, int pageSize, string sortBy = "Newest")
        {
            var query = _context.Users
                .Where(u => u.Status != -1);

            query = sortBy?.ToLower() switch
            {
                "name" => query.OrderBy(u => u.FullName),
                "username" => query.OrderBy(u => u.UserName),
                "email" => query.OrderBy(u => u.Email),
                "oldest" => query.OrderBy(u => u.CreateDate),
                "status" => query.OrderBy(u => u.Status),
                _ => query.OrderByDescending(u => u.CreateDate)
            };

            return await query
                .Include(u => u.UserHotels)
                .Skip((pageNumber - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync();
        }

        public async Task<IEnumerable<User>> FilterUsersAsync(int? status = null, int? userType = null, DateTime? fromDate = null, DateTime? toDate = null)
        {
            var query = _context.Users.AsQueryable();

            if (status.HasValue)
            {
                query = query.Where(u => u.Status == status.Value);
            }

            if (userType.HasValue)
            {
                query = query.Where(u => u.UserType == userType.Value);
            }

            if (fromDate.HasValue)
            {
                query = query.Where(u => u.CreateDate >= fromDate.Value);
            }

            if (toDate.HasValue)
            {
                query = query.Where(u => u.CreateDate <= toDate.Value);
            }

            return await query
                .Where(u => u.Status != -1)
                .OrderByDescending(u => u.CreateDate)
                .ToListAsync();
        }

        // ========== STATISTICS METHODS ==========

        public async Task<int> GetTotalUserCountAsync()
        {
            return await _context.Users
                .Where(u => u.Status != -1)
                .CountAsync();
        }

        public async Task<int> GetActiveUserCountAsync()
        {
            return await _context.Users
                .Where(u => u.Status == 0)
                .CountAsync();
        }

        public async Task<int> GetUserCountByStatusAsync(int status)
        {
            return await _context.Users
                .Where(u => u.Status == status)
                .CountAsync();
        }

        public async Task<int> GetUserCountByUserTypeAsync(int userType)
        {
            return await _context.Users
                .Where(u => u.UserType == userType && u.Status != -1)
                .CountAsync();
        }

        public async Task<Dictionary<string, int>> GetUserStatisticsAsync()
        {
            var stats = new Dictionary<string, int>();

            // Total users
            stats.Add("TotalUsers", await GetTotalUserCountAsync());

            // Active users
            stats.Add("ActiveUsers", await GetActiveUserCountAsync());

            // Pending users
            stats.Add("PendingUsers", await GetUserCountByStatusAsync(1));

            // Deleted users
            stats.Add("DeletedUsers", await GetUserCountByStatusAsync(-1));

            // Users by type
            var userTypes = new[] { 0, 1, 2, 3 }; // Super Admin, Hotel Admin, Staff, Customer
            foreach (var type in userTypes)
            {
                var count = await GetUserCountByUserTypeAsync(type);
                stats.Add($"UserType{type}", count);
            }

            // Users created today
            var today = DateTime.UtcNow.Date;
            stats.Add("TodayUsers", await _context.Users
                .Where(u => u.CreateDate >= today && u.Status != -1)
                .CountAsync());

            // Users created this month
            var firstDayOfMonth = new DateTime(DateTime.UtcNow.Year, DateTime.UtcNow.Month, 1);
            stats.Add("ThisMonthUsers", await _context.Users
                .Where(u => u.CreateDate >= firstDayOfMonth && u.Status != -1)
                .CountAsync());

            return stats;
        }

        // ========== VALIDATION METHODS ==========

        public async Task<bool> IsValidUserAsync(int userId)
        {
            var user = await GetByIdAsync(userId);
            if (user == null)
                return false;

            // Check if user is active
            if (user.Status != 0)
                return false;

            // Check if user has valid time
            if (user.ValidTime.HasValue && user.ValidTime < DateTime.UtcNow)
                return false;

            return true;
        }

        public async Task<bool> IsUserExpiredAsync(int userId)
        {
            var user = await GetByIdAsync(userId);
            if (user == null || !user.ValidTime.HasValue)
                return false;

            return user.ValidTime < DateTime.UtcNow;
        }

        public async Task<bool> ValidateCredentialsAsync(string userName, string passwordHash)
        {
            var user = await GetByUserNameAsync(userName);
            if (user == null)
                return false;

            return user.PasswordHash == passwordHash && user.Status == 0;
        }

        // ========== ADDITIONAL HELPER METHODS ==========

        public async Task<IEnumerable<User>> GetUsersWithTwoFactorEnabledAsync()
        {
            return await _context.Users
                .Where(u => u.TwoFactorEnabled == 1 && u.Status == 0)
                .OrderByDescending(u => u.CreateDate)
                .ToListAsync();
        }

        public async Task<bool> UpdateUserGroupAsync(int userId, int? groupParent, Guid? groupParentGuid)
        {
            var user = await GetByIdAsync(userId);
            if (user == null)
                return false;

            user.GroupParent = groupParent;
            user.GroupParentGuid = groupParentGuid;
            user.LastModify = DateTime.UtcNow;

            try
            {
                _context.Users.Update(user);
                return await _context.SaveChangesAsync() > 0;
            }
            catch
            {
                return false;
            }
        }

        public async Task<IEnumerable<User>> GetUsersWithoutHotelAccessAsync(Guid hotelGuid)
        {
            var usersWithAccess = await _context.UserHotels
                .Where(uh => uh.HotelGuid == hotelGuid && uh.Status == 1)
                .Select(uh => uh.UserId)
                .ToListAsync();

            return await _context.Users
                .Where(u => u.Status == 0 && !usersWithAccess.Contains(u.Id))
                .OrderBy(u => u.FullName)
                .ToListAsync();
        }

        public async Task<bool> BulkUpdateStatusAsync(List<int> userIds, int status)
        {
            var users = await _context.Users
                .Where(u => userIds.Contains(u.Id))
                .ToListAsync();

            if (!users.Any())
                return false;

            foreach (var user in users)
            {
                user.Status = status;
                user.LastModify = DateTime.UtcNow;
            }

            try
            {
                _context.Users.UpdateRange(users);
                return await _context.SaveChangesAsync() > 0;
            }
            catch
            {
                return false;
            }
        }
    }
}