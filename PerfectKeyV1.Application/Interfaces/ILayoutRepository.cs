using PerfectKeyV1.Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PerfectKeyV1.Application.Interfaces
{
    public interface ILayoutRepository
    {
        // Area methods
        Task<Area?> GetAreaByIdAsync(int id);
        Task<Area?> GetAreaByGuidAsync(Guid guid);
        Task<IEnumerable<Area>> GetAreasByHotelAsync(Guid hotelGuid);
        Task<IEnumerable<Area>> GetAreaTreeAsync(Guid hotelGuid);
        Task<Area> CreateAreaAsync(Area area);
        Task UpdateAreaAsync(Area area);
        Task DeleteAreaAsync(Area area);

        // Element methods
        Task<Element?> GetElementByIdAsync(int id);
        Task<Element?> GetElementByGuidAsync(Guid guid);
        Task<IEnumerable<Element>> GetElementsByAreaAsync(Guid areaGuid);
        Task<IEnumerable<Element>> GetElementsByHotelAsync(Guid hotelGuid);
        Task<Element> CreateElementAsync(Element element);
        Task UpdateElementAsync(Element element);
        Task DeleteElementAsync(Element element);
    }
}
