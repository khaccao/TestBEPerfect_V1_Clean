using PerfectKeyV1.Application.Interfaces;
using PerfectKeyV1.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace PerfectKeyV1.Infrastructure.Persistence.Repositories
{
    public class LoginSessionRepository : ILoginSessionRepository
    {
        private readonly ApplicationDbContext _context;

        public LoginSessionRepository(ApplicationDbContext context)
        {
            _context = context;
        }

        public async Task<LoginSession> AddAsync(LoginSession session)
        {
            _context.LoginSessions.Add(session);
            await _context.SaveChangesAsync();
            return session;
        }

        public async Task<LoginSession?> GetByIdAsync(int id)
        {
            return await _context.LoginSessions
                .Include(ls => ls.User)
                .FirstOrDefaultAsync(ls => ls.Id == id);
        }

        public async Task<LoginSession?> GetByTokenAsync(string token)
        {
            return await _context.LoginSessions
                .Include(ls => ls.User)
                .FirstOrDefaultAsync(ls => ls.Token == token && ls.IsActive);
        }

        public async Task<LoginSession?> GetByRefreshTokenAsync(string refreshToken)
        {
            return await _context.LoginSessions
                .Include(ls => ls.User)
                .FirstOrDefaultAsync(ls => ls.RefreshToken == refreshToken && ls.IsActive);
        }

        public async Task<List<LoginSession>> GetUserSessionsAsync(int userId, bool? activeOnly = null)
        {
            var query = _context.LoginSessions
                .Where(ls => ls.UserId == userId);

            if (activeOnly.HasValue)
            {
                query = query.Where(ls => ls.IsActive == activeOnly.Value);
            }

            return await query
                .OrderByDescending(ls => ls.LoginTime)
                .ToListAsync();
        }

        public async Task<List<LoginSession>> GetUserSessionsPagedAsync(int userId, int pageNumber, int pageSize, string sortBy = "Newest", bool? activeOnly = null)
        {
            var query = _context.LoginSessions
                .Where(ls => ls.UserId == userId);

            if (activeOnly.HasValue)
            {
                query = query.Where(ls => ls.IsActive == activeOnly.Value);
            }

            query = sortBy?.ToLower() switch
            {
                "oldest" => query.OrderBy(ls => ls.LoginTime),
                "device" => query.OrderBy(ls => ls.DeviceInfo),
                "location" => query.OrderBy(ls => ls.Location),
                _ => query.OrderByDescending(ls => ls.LoginTime)
            };

            return await query
                .Include(ls => ls.User)
                .Skip((pageNumber - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync();
        }

        public async Task<int> GetUserSessionsCountAsync(int userId, bool? activeOnly = null)
        {
            var query = _context.LoginSessions
                .Where(ls => ls.UserId == userId);

            if (activeOnly.HasValue)
            {
                query = query.Where(ls => ls.IsActive == activeOnly.Value);
            }

            return await query.CountAsync();
        }

        public async Task<bool> UpdateAsync(LoginSession session)
        {
            session.LastModify = DateTime.UtcNow;
            _context.LoginSessions.Update(session);
            return await _context.SaveChangesAsync() > 0;
        }

        public async Task<bool> DeactivateSessionAsync(int sessionId)
        {
            var session = await GetByIdAsync(sessionId);
            if (session is null) return false;

            session.IsActive = false;
            session.LogoutTime = DateTime.UtcNow;
            session.LastModify = DateTime.UtcNow;

            return await UpdateAsync(session);
        }

        public async Task<bool> DeactivateAllSessionsAsync(int userId, int? excludeSessionId = null)
        {
            var sessions = await _context.LoginSessions
                .Where(ls => ls.UserId == userId && ls.IsActive)
                .ToListAsync();

            if (excludeSessionId.HasValue)
            {
                sessions = sessions.Where(ls => ls.Id != excludeSessionId.Value).ToList();
            }

            foreach (var session in sessions)
            {
                session.IsActive = false;
                session.LogoutTime = DateTime.UtcNow;
                session.LastModify = DateTime.UtcNow;
            }

            return await _context.SaveChangesAsync() > 0;
        }

        public async Task<bool> DeactivateExpiredSessionsAsync()
        {
            var expiredSessions = await _context.LoginSessions
                .Where(ls => ls.IsActive && ls.LastActivity < DateTime.UtcNow.AddDays(-30))
                .ToListAsync();

            foreach (var session in expiredSessions)
            {
                session.IsActive = false;
                session.LastModify = DateTime.UtcNow;
            }

            return await _context.SaveChangesAsync() > 0;
        }

        public async Task<bool> UpdateActivityAsync(int sessionId)
        {
            var session = await GetByIdAsync(sessionId);
            if (session is null) return false;

            session.LastActivity = DateTime.UtcNow;
            session.LastModify = DateTime.UtcNow;

            return await UpdateAsync(session);
        }

        public async Task<List<LoginSession>> GetSessionsByHotelAsync(Guid hotelGuid, bool activeOnly = true)
        {
            // This requires joining with UserHotel table
            var query = from ls in _context.LoginSessions
                        join uh in _context.UserHotels on ls.UserId equals uh.UserId
                        where uh.HotelGuid == hotelGuid && (!activeOnly || ls.IsActive)
                        select ls;

            return await query
                .Include(ls => ls.User)
                .OrderByDescending(ls => ls.LoginTime)
                .ToListAsync();
        }

        public async Task<bool> IsTokenActiveAsync(string token)
        {
            var session = await _context.LoginSessions
                .FirstOrDefaultAsync(ls => ls.Token == token && ls.IsActive);

            return session != null && !session.IsExpired();
        }

        public async Task<int> GetActiveSessionCountAsync(int userId)
        {
            return await _context.LoginSessions
                .CountAsync(ls => ls.UserId == userId && ls.IsActive);
        }

        public async Task<int> GetTotalSessionCountAsync(int userId)
        {
            return await _context.LoginSessions
                .CountAsync(ls => ls.UserId == userId);
        }
    }
}