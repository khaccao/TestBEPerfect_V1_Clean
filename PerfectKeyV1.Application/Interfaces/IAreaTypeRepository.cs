using PerfectKeyV1.Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PerfectKeyV1.Application.Interfaces
{
    public interface IAreaTypeRepository
    {
        Task<AreaType?> GetByIdAsync(int id);
        Task<AreaType?> GetByGuidAsync(Guid guid);
        Task<AreaType?> GetByCodeAsync(string code, Guid hotelGuid);
        Task<IEnumerable<AreaType>> GetAllByHotelAsync(Guid hotelGuid);
        Task<IEnumerable<AreaType>> GetByGroupAsync(string groupCode, Guid hotelGuid);
        Task<AreaType> CreateAsync(AreaType areaType);
        Task UpdateAsync(AreaType areaType);
        Task DeleteAsync(AreaType areaType);
    }
}
