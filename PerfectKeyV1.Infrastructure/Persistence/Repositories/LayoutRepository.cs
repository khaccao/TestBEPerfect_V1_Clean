using PerfectKeyV1.Application.Interfaces;
using PerfectKeyV1.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace PerfectKeyV1.Infrastructure.Persistence.Repositories
{
    public class LayoutRepository : ILayoutRepository
    {
        private readonly ApplicationDbContext _context;

        public LayoutRepository(ApplicationDbContext context)
        {
            _context = context;
        }

        public async Task<Area?> GetAreaByIdAsync(int id)
            => await _context.Areas
                .Include(a => a.Children)
                .Include(a => a.Elements)
                .FirstOrDefaultAsync(a => a.Id == id);

        public async Task<Area?> GetAreaByGuidAsync(Guid guid)
            => await _context.Areas
                .Include(a => a.Children)
                .Include(a => a.Elements)
                .FirstOrDefaultAsync(a => a.Guid == guid);

        public async Task<IEnumerable<Area>> GetAreasByHotelAsync(Guid hotelGuid)
            => await _context.Areas
                .Where(a => a.HotelGuid == hotelGuid && a.IsActive)
                .ToListAsync();

        public async Task<IEnumerable<Area>> GetAreaTreeAsync(Guid hotelGuid)
        {
            var areas = await _context.Areas
                .Where(a => a.HotelGuid == hotelGuid && a.IsActive)
                .Include(a => a.Children)
                .ThenInclude(c => c.Elements)
                .ToListAsync();

            return areas.Where(a => a.ParentId == null); // Return root areas only
        }

        public async Task<Area> CreateAreaAsync(Area area)
        {
            _context.Areas.Add(area);
            await _context.SaveChangesAsync();
            return area;
        }

        public async Task UpdateAreaAsync(Area area)
        {
            _context.Areas.Update(area);
            await _context.SaveChangesAsync();
        }

        public async Task DeleteAreaAsync(Area area)
        {
            _context.Areas.Remove(area);
            await _context.SaveChangesAsync();
        }

        public async Task<Element?> GetElementByIdAsync(int id)
            => await _context.Elements
                .Include(e => e.Area)
                .FirstOrDefaultAsync(e => e.Id == id);

        public async Task<Element?> GetElementByGuidAsync(Guid guid)
            => await _context.Elements
                .Include(e => e.Area)
                .FirstOrDefaultAsync(e => e.Guid == guid);

        public async Task<IEnumerable<Element>> GetElementsByAreaAsync(Guid areaGuid)
            => await _context.Elements
                .Where(e => e.AreaGuid == areaGuid && e.IsActive)
                .ToListAsync();

        public async Task<IEnumerable<Element>> GetElementsByHotelAsync(Guid hotelGuid)
            => await _context.Elements
                .Where(e => e.HotelGuid == hotelGuid && e.IsActive)
                .Include(e => e.Area)
                .ToListAsync();

        public async Task<Element> CreateElementAsync(Element element)
        {
            _context.Elements.Add(element);
            await _context.SaveChangesAsync();
            return element;
        }

        public async Task UpdateElementAsync(Element element)
        {
            _context.Elements.Update(element);
            await _context.SaveChangesAsync();
        }

        public async Task DeleteElementAsync(Element element)
        {
            _context.Elements.Remove(element);
            await _context.SaveChangesAsync();
        }
    }
}
