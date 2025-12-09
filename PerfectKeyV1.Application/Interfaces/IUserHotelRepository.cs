// Application/Interfaces/IUserHotelRepository.cs
using PerfectKeyV1.Domain.Entities;

namespace PerfectKeyV1.Application.Interfaces
{
    public interface IUserHotelRepository
    {
        Task<UserHotel?> GetByIdAsync(int id);
        Task<UserHotel?> FindByUserAndHotelAsync(int userId, Guid hotelGuid);
        Task<IEnumerable<UserHotel>> GetByUserIdAsync(int userId);
        Task<IEnumerable<UserHotel>> GetByHotelGuidAsync(Guid hotelGuid);
        Task AddAsync(UserHotel userHotel);
        Task UpdateAsync(UserHotel userHotel);
        Task DeleteAsync(UserHotel userHotel);
        Task DeleteByUserIdAsync(int userId);
        Task<bool> HasHotelAccessAsync(int userId, Guid hotelGuid);
    }
}