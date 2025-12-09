using PerfectKeyV1.Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PerfectKeyV1.Application.Interfaces
{
    public interface IHotelRepository
    {
        Task<Hotel?> GetByIdAsync(int id);
        Task<Hotel?> GetByCodeAsync(string code);
        Task<Hotel?> GetByGuidAsync(Guid guid);
        Task<IEnumerable<Hotel>> GetAllAsync();
        Task<Hotel> CreateAsync(Hotel hotel);
        Task UpdateAsync(Hotel hotel);
        Task DeleteAsync(Hotel hotel);
    }
}
