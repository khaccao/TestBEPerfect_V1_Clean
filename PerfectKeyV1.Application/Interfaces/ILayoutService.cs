using PerfectKeyV1.Application.DTOs.Layout;
using PerfectKeyV1.Application.DTOs.Users;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PerfectKeyV1.Application.Interfaces
{
    public interface ILayoutService
    {
        // Area CRUD
        Task<AreaDto> CreateAreaAsync(CreateAreaRequest request, Guid hotelGuid, string hotelCode);
        Task<AreaDto?> GetAreaAsync(Guid areaGuid);
        Task<IEnumerable<AreaDto>> GetAreaTreeAsync(Guid hotelGuid);
        Task<AreaDto> UpdateAreaAsync(Guid areaGuid, UpdateAreaRequest request);
        Task<bool> DeleteAreaAsync(Guid areaGuid);

        // Element CRUD - SỬA: Trả về DTO thay vì Entity
        Task<ElementDto> CreateElementAsync(CreateElementRequest request, Guid hotelGuid, string hotelCode);
        Task<ElementDto?> GetElementAsync(Guid elementGuid);
        Task<IEnumerable<ElementDto>> GetElementsByAreaAsync(Guid areaGuid);
        Task<IEnumerable<ElementDto>> GetElementsByHotelAsync(Guid hotelGuid);
        Task<ElementDto> UpdateElementAsync(Guid elementGuid, UpdateElementRequest request);
        Task<bool> DeleteElementAsync(Guid elementGuid);
    }
}
