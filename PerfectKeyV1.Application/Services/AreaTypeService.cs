using Microsoft.Extensions.Caching.Distributed;
using PerfectKeyV1.Application.DTOs.Layout;
using PerfectKeyV1.Application.DTOs.Users;
using PerfectKeyV1.Application.Interfaces;
using PerfectKeyV1.Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PerfectKeyV1.Application.Services
{
    public class AreaTypeService : IAreaTypeService
    {
        private readonly IAreaTypeRepository _areaTypeRepo;
        private readonly IDistributedCache _cache;

        public AreaTypeService(IAreaTypeRepository areaTypeRepo, IDistributedCache cache)
        {
            _areaTypeRepo = areaTypeRepo;
            _cache = cache;
        }

        public async Task<AreaTypeDto> CreateAreaTypeAsync(CreateAreaTypeRequest request, Guid hotelGuid, string hotelCode)
        {
            var areaType = new AreaType
            {
                Guid = Guid.NewGuid(),
                HotelGuid = hotelGuid,
                HotelCode = hotelCode,
                Code = request.Code,
                Name = request.Name,
                GroupCode = request.GroupCode,
                Descriptions = request.Descriptions
            };

            var createdAreaType = await _areaTypeRepo.CreateAsync(areaType);

            // Clear cache
            await ClearAreaTypeCache(hotelGuid);

            return MapToAreaTypeDto(createdAreaType);
        }

        public async Task<AreaTypeDto?> GetAreaTypeAsync(Guid areaTypeGuid)
        {
            var cacheKey = $"areaType_{areaTypeGuid}";

            try
            {
                var cachedAreaType = await _cache.GetStringAsync(cacheKey);
                if (!string.IsNullOrEmpty(cachedAreaType))
                    return System.Text.Json.JsonSerializer.Deserialize<AreaTypeDto>(cachedAreaType);
            }
            catch (Exception ex)
            {
                // Log cache error và tiếp tục lấy từ database
                Console.WriteLine($"Cache error for {cacheKey}: {ex.Message}");
            }

            var areaType = await _areaTypeRepo.GetByGuidAsync(areaTypeGuid);
            if (areaType != null)
            {
                var areaTypeDto = MapToAreaTypeDto(areaType);

                try
                {
                    await _cache.SetStringAsync(cacheKey,
                        System.Text.Json.JsonSerializer.Serialize(areaTypeDto),
                        new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(10) });
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Cache set error for {cacheKey}: {ex.Message}");
                }

                return areaTypeDto;
            }

            return null;
        }

        public async Task<AreaTypeDto?> GetAreaTypeByCodeAsync(string code, Guid hotelGuid)
        {
            var areaType = await _areaTypeRepo.GetByCodeAsync(code, hotelGuid);
            return areaType != null ? MapToAreaTypeDto(areaType) : null;
        }

        public async Task<IEnumerable<AreaTypeDto>> GetAreaTypesByHotelAsync(Guid hotelGuid)
        {
            var cacheKey = $"areaTypes_hotel_{hotelGuid}";

            try
            {
                var cachedAreaTypes = await _cache.GetStringAsync(cacheKey);
                if (!string.IsNullOrEmpty(cachedAreaTypes))
                    return System.Text.Json.JsonSerializer.Deserialize<IEnumerable<AreaTypeDto>>(cachedAreaTypes) ?? new List<AreaTypeDto>();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Cache error for {cacheKey}: {ex.Message}");
            }

            var areaTypes = await _areaTypeRepo.GetAllByHotelAsync(hotelGuid);
            var areaTypeDtos = areaTypes.Select(MapToAreaTypeDto).ToList();

            try
            {
                await _cache.SetStringAsync(cacheKey,
                    System.Text.Json.JsonSerializer.Serialize(areaTypeDtos),
                    new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(5) });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Cache set error for {cacheKey}: {ex.Message}");
            }

            return areaTypeDtos;
        }

        public async Task<IEnumerable<AreaTypeDto>> GetAreaTypesByGroupAsync(string groupCode, Guid hotelGuid)
        {
            var areaTypes = await _areaTypeRepo.GetByGroupAsync(groupCode, hotelGuid);
            return areaTypes.Select(MapToAreaTypeDto).ToList();
        }

        public async Task<AreaTypeDto> UpdateAreaTypeAsync(Guid areaTypeGuid, UpdateAreaTypeRequest request)
        {
            var existingAreaType = await _areaTypeRepo.GetByGuidAsync(areaTypeGuid);
            if (existingAreaType == null)
                throw new Exception("AreaType not found");

            existingAreaType.Code = request.Code;
            existingAreaType.Name = request.Name;
            existingAreaType.GroupCode = request.GroupCode;
            existingAreaType.Descriptions = request.Descriptions;

            await _areaTypeRepo.UpdateAsync(existingAreaType);

            // Clear cache
            await ClearAreaTypeCache(existingAreaType.HotelGuid);

            return MapToAreaTypeDto(existingAreaType);
        }

        public async Task<bool> DeleteAreaTypeAsync(Guid areaTypeGuid)
        {
            var areaType = await _areaTypeRepo.GetByGuidAsync(areaTypeGuid);
            if (areaType == null)
                return false;

            await _areaTypeRepo.DeleteAsync(areaType);

            // Clear cache
            await ClearAreaTypeCache(areaType.HotelGuid);

            return true;
        }

        private async Task ClearAreaTypeCache(Guid hotelGuid)
        {
            try
            {
                await _cache.RemoveAsync($"areaTypes_hotel_{hotelGuid}");
                // Có thể clear thêm các cache key khác nếu cần
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Cache clear error for hotel {hotelGuid}: {ex.Message}");
            }
        }

        private AreaTypeDto MapToAreaTypeDto(AreaType areaType)
        {
            return new AreaTypeDto
            {
                Id = areaType.Id,
                Guid = areaType.Guid,
                HotelGuid = areaType.HotelGuid,
                HotelCode = areaType.HotelCode ?? string.Empty,
                Code = areaType.Code ?? string.Empty,
                Name = areaType.Name ?? string.Empty,
                GroupCode = areaType.GroupCode ?? string.Empty,
                Descriptions = areaType.Descriptions
            };
        }
    }
}