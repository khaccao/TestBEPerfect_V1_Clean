using PerfectKeyV1.Application.DTOs.Layout;
using PerfectKeyV1.Application.DTOs.Users;
using PerfectKeyV1.Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PerfectKeyV1.Application.Interfaces
{
    public interface IAreaTypeService
    {
        // SỬA: Trả về AreaTypeDto thay vì AreaType entity
        Task<AreaTypeDto> CreateAreaTypeAsync(CreateAreaTypeRequest request, Guid hotelGuid, string hotelCode);
        Task<AreaTypeDto?> GetAreaTypeAsync(Guid areaTypeGuid);
        Task<AreaTypeDto?> GetAreaTypeByCodeAsync(string code, Guid hotelGuid);
        Task<IEnumerable<AreaTypeDto>> GetAreaTypesByHotelAsync(Guid hotelGuid);
        Task<IEnumerable<AreaTypeDto>> GetAreaTypesByGroupAsync(string groupCode, Guid hotelGuid);
        Task<AreaTypeDto> UpdateAreaTypeAsync(Guid areaTypeGuid, UpdateAreaTypeRequest request);
        Task<bool> DeleteAreaTypeAsync(Guid areaTypeGuid);
    }
}