using PerfectKeyV1.Application.Interfaces;
using PerfectKeyV1.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace PerfectKeyV1.Infrastructure.Persistence.Repositories
{
    public class HotelRepository : IHotelRepository
    {
        private readonly ApplicationDbContext _context;

        public HotelRepository(ApplicationDbContext context)
        {
            _context = context;
        }

        public async Task<Hotel?> GetByIdAsync(int id)
            => await _context.Hotels.FirstOrDefaultAsync(h => h.Id == id);

        public async Task<Hotel?> GetByCodeAsync(string code)
            => await _context.Hotels.FirstOrDefaultAsync(h => h.Code == code);

        public async Task<Hotel?> GetByGuidAsync(Guid guid)
            => await _context.Hotels.FirstOrDefaultAsync(h => h.Guid == guid);

        public async Task<IEnumerable<Hotel>> GetAllAsync()
            => await _context.Hotels.Where(h => !h.IsDeleted).ToListAsync();

        public async Task<Hotel> CreateAsync(Hotel hotel)
        {
            _context.Hotels.Add(hotel);
            await _context.SaveChangesAsync();
            return hotel;
        }

        public async Task UpdateAsync(Hotel hotel)
        {
            _context.Hotels.Update(hotel);
            await _context.SaveChangesAsync();
        }

        public async Task DeleteAsync(Hotel hotel)
        {
            _context.Hotels.Remove(hotel);
            await _context.SaveChangesAsync();
        }
    }
}
