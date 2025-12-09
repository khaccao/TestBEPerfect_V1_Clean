using PerfectKeyV1.Application.Interfaces;
using PerfectKeyV1.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace PerfectKeyV1.Infrastructure.Persistence.Repositories
{
    public class UserHotelRepository : IUserHotelRepository
    {
        private readonly ApplicationDbContext _context;

        public UserHotelRepository(ApplicationDbContext context)
        {
            _context = context;
        }

        public async Task<UserHotel?> GetByIdAsync(int id)
            => await _context.UserHotels
                .Include(uh => uh.User)
                .Include(uh => uh.Hotel)
                .FirstOrDefaultAsync(uh => uh.Id == id);

        public async Task<UserHotel?> FindByUserAndHotelAsync(int userId, Guid hotelGuid)
            => await _context.UserHotels
                .FirstOrDefaultAsync(uh => uh.UserId == userId && uh.HotelGuid == hotelGuid);

        public async Task<IEnumerable<UserHotel>> GetByUserIdAsync(int userId)
            => await _context.UserHotels
                .Where(uh => uh.UserId == userId)
                .Include(uh => uh.Hotel)
                .ToListAsync();

        public async Task<IEnumerable<UserHotel>> GetByHotelGuidAsync(Guid hotelGuid)
            => await _context.UserHotels
                .Where(uh => uh.HotelGuid == hotelGuid)
                .Include(uh => uh.User)
                .ToListAsync();

        public async Task AddAsync(UserHotel userHotel)
        {
            _context.UserHotels.Add(userHotel);
            await _context.SaveChangesAsync();
        }

        public async Task UpdateAsync(UserHotel userHotel)
        {
            _context.UserHotels.Update(userHotel);
            await _context.SaveChangesAsync();
        }

        public async Task DeleteAsync(UserHotel userHotel)
        {
            _context.UserHotels.Remove(userHotel);
            await _context.SaveChangesAsync();
        }

        public async Task DeleteByUserIdAsync(int userId)
        {
            var userHotels = await _context.UserHotels
                .Where(uh => uh.UserId == userId)
                .ToListAsync();

            _context.UserHotels.RemoveRange(userHotels);
            await _context.SaveChangesAsync();
        }

        public async Task<bool> HasHotelAccessAsync(int userId, Guid hotelGuid)
        {
            return await _context.UserHotels
                .AnyAsync(uh => uh.UserId == userId &&
                               uh.HotelGuid == hotelGuid &&
                               uh.Status == 1);
        }
    }
}
