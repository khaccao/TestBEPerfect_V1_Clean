using PerfectKeyV1.Application.Interfaces;
using PerfectKeyV1.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace PerfectKeyV1.Infrastructure.Persistence.Repositories
{
    public class AreaTypeRepository : IAreaTypeRepository
    {
        private readonly ApplicationDbContext _context;

        public AreaTypeRepository(ApplicationDbContext context)
        {
            _context = context;
        }

        public async Task<AreaType?> GetByIdAsync(int id)
            => await _context.AreaTypes.FindAsync(id);

        public async Task<AreaType?> GetByGuidAsync(Guid guid)
            => await _context.AreaTypes.FirstOrDefaultAsync(at => at.Guid == guid);

        public async Task<AreaType?> GetByCodeAsync(string code, Guid hotelGuid)
            => await _context.AreaTypes.FirstOrDefaultAsync(at => at.Code == code && at.HotelGuid == hotelGuid);

        public async Task<IEnumerable<AreaType>> GetAllByHotelAsync(Guid hotelGuid)
            => await _context.AreaTypes.Where(at => at.HotelGuid == hotelGuid).ToListAsync();

        public async Task<IEnumerable<AreaType>> GetByGroupAsync(string groupCode, Guid hotelGuid)
            => await _context.AreaTypes.Where(at => at.GroupCode == groupCode && at.HotelGuid == hotelGuid).ToListAsync();

        public async Task<AreaType> CreateAsync(AreaType areaType)
        {
            _context.AreaTypes.Add(areaType);
            await _context.SaveChangesAsync();
            return areaType;
        }

        public async Task UpdateAsync(AreaType areaType)
        {
            _context.AreaTypes.Update(areaType);
            await _context.SaveChangesAsync();
        }

        public async Task DeleteAsync(AreaType areaType)
        {
            _context.AreaTypes.Remove(areaType);
            await _context.SaveChangesAsync();
        }
    }
}
