using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using PerfectKeyV1.Application.DTOs.Layout;
using PerfectKeyV1.Application.DTOs.Users;
using PerfectKeyV1.Application.Interfaces;
using PerfectKeyV1.Domain.Entities;

namespace PerfectKeyV1.Application.Services
{
    public class LayoutService : ILayoutService
    {
        private readonly ILayoutRepository _layoutRepo;
        private readonly IAreaTypeRepository _areaTypeRepo;
        private readonly IDistributedCache _cache;
        private readonly IHotelRepository _hotelRepo;
        private readonly ILogger<LayoutService> _logger;

        public LayoutService(
            ILayoutRepository layoutRepo,
            IAreaTypeRepository areaTypeRepo,
            IDistributedCache cache,
            IHotelRepository hotelRepo,
            ILogger<LayoutService> logger)
        {
            _layoutRepo = layoutRepo;
            _areaTypeRepo = areaTypeRepo;
            _cache = cache;
            _hotelRepo = hotelRepo;
            _logger = logger;
        }

        // AREA METHODS (giữ nguyên)
        public async Task<AreaDto> CreateAreaAsync(CreateAreaRequest request, Guid hotelGuid, string hotelCode)
        {
            var hotel = await _hotelRepo.GetByGuidAsync(hotelGuid);
            if (hotel == null)
                throw new Exception($"Hotel with GUID '{hotelGuid}' not found");

            if (request.AreaTypeGuid.HasValue && request.AreaTypeGuid != Guid.Empty)
            {
                var areaType = await _areaTypeRepo.GetByGuidAsync(request.AreaTypeGuid.Value);
                if (areaType == null)
                    throw new Exception("AreaType not found");
            }

            var area = new Area
            {
                Guid = Guid.NewGuid(),
                HotelId = hotel.Id,
                HotelGuid = hotelGuid,
                HotelCode = hotelCode,
                AreaName = request.AreaName,
                AreaCode = request.AreaCode,
                AreaType = request.AreaType,
                AreaTypeGuid = request.AreaTypeGuid,
                ParentGuid = request.ParentGuid,
                AreaAlias = request.AreaAlias,
                AreaDescription = request.AreaDescription,
                AreaAvatar = request.AreaAvatar,
                Color = request.Color,
                PositionX = request.PositionX,
                PositionY = request.PositionY,
                Width = request.Width,
                Height = request.Height,
                IsActive = true,
                CreateDate = DateTime.UtcNow
            };

            var createdArea = await _layoutRepo.CreateAreaAsync(area);
            await SafeClearAreaCache(hotelGuid);

            return MapToAreaDto(createdArea);
        }

        public async Task<AreaDto?> GetAreaAsync(Guid areaGuid)
        {
            var cacheKey = $"area_{areaGuid}";

            try
            {
                var cachedArea = await _cache.GetStringAsync(cacheKey);
                if (!string.IsNullOrEmpty(cachedArea))
                    return System.Text.Json.JsonSerializer.Deserialize<AreaDto>(cachedArea);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to get area from cache for {AreaGuid}", areaGuid);
            }

            var area = await _layoutRepo.GetAreaByGuidAsync(areaGuid);
            if (area != null)
            {
                var areaDto = MapToAreaDto(area);
                try
                {
                    await _cache.SetStringAsync(cacheKey,
                        System.Text.Json.JsonSerializer.Serialize(areaDto),
                        new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(10) });
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to set area to cache for {AreaGuid}", areaGuid);
                }
                return areaDto;
            }

            return null;
        }

        public async Task<IEnumerable<AreaDto>> GetAreaTreeAsync(Guid hotelGuid)
        {
            var cacheKey = $"area_tree_{hotelGuid}";

            try
            {
                var cachedTree = await _cache.GetStringAsync(cacheKey);
                if (!string.IsNullOrEmpty(cachedTree))
                    return System.Text.Json.JsonSerializer.Deserialize<IEnumerable<AreaDto>>(cachedTree) ?? new List<AreaDto>();
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to get area tree from cache for hotel {HotelGuid}", hotelGuid);
            }

            var areas = await _layoutRepo.GetAreaTreeAsync(hotelGuid);
            var areaDtos = areas.Select(MapToAreaDto).ToList();

            try
            {
                await _cache.SetStringAsync(cacheKey,
                    System.Text.Json.JsonSerializer.Serialize(areaDtos),
                    new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(5) });
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to set area tree to cache for hotel {HotelGuid}", hotelGuid);
            }

            return areaDtos;
        }

        public async Task<AreaDto> UpdateAreaAsync(Guid areaGuid, UpdateAreaRequest request)
        {
            var existingArea = await _layoutRepo.GetAreaByGuidAsync(areaGuid);
            if (existingArea == null)
                throw new Exception("Area not found");

            if (request.AreaTypeGuid.HasValue && request.AreaTypeGuid != Guid.Empty)
            {
                var areaType = await _areaTypeRepo.GetByGuidAsync(request.AreaTypeGuid.Value);
                if (areaType == null)
                    throw new Exception("AreaType not found");
            }

            existingArea.AreaName = request.AreaName;
            existingArea.AreaCode = request.AreaCode;
            existingArea.AreaType = request.AreaType;
            existingArea.ParentGuid = request.ParentGuid;
            existingArea.AreaAlias = request.AreaAlias;
            existingArea.AreaDescription = request.AreaDescription;
            existingArea.AreaAvatar = request.AreaAvatar;
            existingArea.Color = request.Color;
            existingArea.PositionX = request.PositionX ?? existingArea.PositionX;
            existingArea.PositionY = request.PositionY ?? existingArea.PositionY;
            existingArea.Width = request.Width ?? existingArea.Width;
            existingArea.Height = request.Height ?? existingArea.Height;
            existingArea.AreaTypeGuid = request.AreaTypeGuid;
            existingArea.IsActive = request.IsActive;
            existingArea.LastModify = DateTime.UtcNow;

            await _layoutRepo.UpdateAreaAsync(existingArea);
            await SafeClearAreaCache(existingArea.HotelGuid);

            return MapToAreaDto(existingArea);
        }

        public async Task<bool> DeleteAreaAsync(Guid areaGuid)
        {
            var area = await _layoutRepo.GetAreaByGuidAsync(areaGuid);
            if (area == null)
                return false;

            await _layoutRepo.DeleteAreaAsync(area);
            await SafeClearAreaCache(area.HotelGuid);

            return true;
        }

        // ELEMENT METHODS - SỬA: Trả về DTO thay vì Entity
        public async Task<ElementDto> CreateElementAsync(CreateElementRequest request, Guid hotelGuid, string hotelCode)
        {
            var hotel = await _hotelRepo.GetByGuidAsync(hotelGuid);
            if (hotel == null)
                throw new Exception($"Hotel with GUID '{hotelGuid}' not found");

            var area = await _layoutRepo.GetAreaByGuidAsync(request.AreaGuid);
            if (area == null)
                throw new Exception("Area not found");

            var element = new Element
            {
                Guid = Guid.NewGuid(),
                AreaId = area.Id,
                AreaGuid = area.Guid,
                HotelGuid = hotelGuid,
                HotelCode = hotelCode,
                Name = request.Name,
                Type = request.Type,
                Alias = request.Alias,
                Capacity = request.Capacity,
                Description = request.Description,
                PositionX = request.PositionX ?? 0,
                PositionY = request.PositionY ?? 0,
                Width = request.Width,
                Height = request.Height,
                Rotation = request.Rotation ?? 0,
                Color = request.Color,
                Icon = request.Icon,
                GroupElements = request.GroupElements,
                GroupElementsGuid = request.GroupElementsGuid,
                DockGuid = request.DockGuid,
                Settings = request.Settings,
                IsActive = true,
                IsOccupied = false,
                CreateDate = DateTime.UtcNow
            };

            var createdElement = await _layoutRepo.CreateElementAsync(element);
            await SafeClearElementCache(request.AreaGuid, hotelGuid);

            return await MapToElementDtoAsync(createdElement);
        }

        public async Task<ElementDto?> GetElementAsync(Guid elementGuid)
        {
            var element = await _layoutRepo.GetElementByGuidAsync(elementGuid);
            if (element == null)
                return null;

            return await MapToElementDtoAsync(element);
        }

        public async Task<IEnumerable<ElementDto>> GetElementsByAreaAsync(Guid areaGuid)
        {
            var cacheKey = $"elements_area_{areaGuid}";

            try
            {
                var cachedElements = await _cache.GetStringAsync(cacheKey);
                if (!string.IsNullOrEmpty(cachedElements))
                    return System.Text.Json.JsonSerializer.Deserialize<IEnumerable<ElementDto>>(cachedElements) ?? new List<ElementDto>();
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to get elements from cache for area {AreaGuid}", areaGuid);
            }

            var elements = await _layoutRepo.GetElementsByAreaAsync(areaGuid);
            var elementDtos = new List<ElementDto>();

            foreach (var element in elements)
            {
                var dto = await MapToElementDtoAsync(element);
                elementDtos.Add(dto);
            }

            try
            {
                await _cache.SetStringAsync(cacheKey,
                    System.Text.Json.JsonSerializer.Serialize(elementDtos),
                    new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(5) });
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to set elements to cache for area {AreaGuid}", areaGuid);
            }

            return elementDtos;
        }

        public async Task<IEnumerable<ElementDto>> GetElementsByHotelAsync(Guid hotelGuid)
        {
            var cacheKey = $"elements_hotel_{hotelGuid}";

            try
            {
                var cachedElements = await _cache.GetStringAsync(cacheKey);
                if (!string.IsNullOrEmpty(cachedElements))
                    return System.Text.Json.JsonSerializer.Deserialize<IEnumerable<ElementDto>>(cachedElements) ?? new List<ElementDto>();
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to get elements from cache for hotel {HotelGuid}", hotelGuid);
            }

            var elements = await _layoutRepo.GetElementsByHotelAsync(hotelGuid);
            var elementDtos = new List<ElementDto>();

            foreach (var element in elements)
            {
                var dto = await MapToElementDtoAsync(element);
                elementDtos.Add(dto);
            }

            try
            {
                await _cache.SetStringAsync(cacheKey,
                    System.Text.Json.JsonSerializer.Serialize(elementDtos),
                    new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(5) });
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to set elements to cache for hotel {HotelGuid}", hotelGuid);
            }

            return elementDtos;
        }

        public async Task<ElementDto> UpdateElementAsync(Guid elementGuid, UpdateElementRequest request)
        {
            var existingElement = await _layoutRepo.GetElementByGuidAsync(elementGuid);
            if (existingElement == null)
                throw new Exception("Element not found");

            existingElement.Name = request.Name;
            existingElement.Type = request.Type;
            existingElement.AreaGuid = request.AreaGuid;
            existingElement.Alias = request.Alias;
            existingElement.Capacity = request.Capacity;
            existingElement.Description = request.Description;
            existingElement.PositionX = request.PositionX ?? existingElement.PositionX;
            existingElement.PositionY = request.PositionY ?? existingElement.PositionY;
            existingElement.Width = request.Width ?? existingElement.Width;
            existingElement.Height = request.Height ?? existingElement.Height;
            existingElement.Rotation = request.Rotation ?? existingElement.Rotation;
            existingElement.Color = request.Color;
            existingElement.Icon = request.Icon;
            existingElement.GroupElements = request.GroupElements;
            existingElement.GroupElementsGuid = request.GroupElementsGuid;
            existingElement.DockGuid = request.DockGuid;
            existingElement.Settings = request.Settings;
            existingElement.IsActive = request.IsActive;
            existingElement.IsOccupied = request.IsOccupied;
            existingElement.LastModify = DateTime.UtcNow;

            await _layoutRepo.UpdateElementAsync(existingElement);
            await SafeClearElementCache(request.AreaGuid, existingElement.HotelGuid);

            return await MapToElementDtoAsync(existingElement);
        }

        public async Task<bool> DeleteElementAsync(Guid elementGuid)
        {
            var element = await _layoutRepo.GetElementByGuidAsync(elementGuid);
            if (element == null)
                return false;

            await _layoutRepo.DeleteElementAsync(element);
            await SafeClearElementCache(element.AreaGuid, element.HotelGuid);

            return true;
        }

        // HELPER METHODS
        private async Task SafeClearAreaCache(Guid hotelGuid)
        {
            try
            {
                await _cache.RemoveAsync($"area_tree_{hotelGuid}");
                await _cache.RemoveAsync($"areas_{hotelGuid}");
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to clear area cache for hotel {HotelGuid}", hotelGuid);
            }
        }

        private async Task SafeClearElementCache(Guid areaGuid, Guid hotelGuid)
        {
            try
            {
                await _cache.RemoveAsync($"elements_area_{areaGuid}");
                await _cache.RemoveAsync($"elements_hotel_{hotelGuid}");
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to clear element cache for area {AreaGuid}, hotel {HotelGuid}", areaGuid, hotelGuid);
            }
        }

        private AreaDto MapToAreaDto(Area area)
        {
            return new AreaDto
            {
                Id = area.Id,
                Guid = area.Guid,
                ParentGuid = area.ParentGuid,
                HotelGuid = area.HotelGuid,
                HotelCode = area.HotelCode ?? string.Empty,
                AreaCode = area.AreaCode ?? string.Empty,
                AreaName = area.AreaName ?? string.Empty,
                AreaType = area.AreaType ?? string.Empty,
                AreaTypeGuid = area.AreaTypeGuid,
                AreaAlias = area.AreaAlias,
                AreaDescription = area.AreaDescription,
                AreaAvatar = area.AreaAvatar,
                Color = area.Color,
                PositionX = area.PositionX,
                PositionY = area.PositionY,
                Width = area.Width,
                Height = area.Height,
                IsActive = area.IsActive,
                CreateDate = area.CreateDate,
                LastModify = area.LastModify
            };
        }

        private async Task<ElementDto> MapToElementDtoAsync(Element element)
        {
            var area = await _layoutRepo.GetAreaByGuidAsync(element.AreaGuid);

            return new ElementDto
            {
                Id = element.Id,
                Guid = element.Guid,
                AreaGuid = element.AreaGuid,
                HotelGuid = element.HotelGuid,
                HotelCode = element.HotelCode ?? string.Empty,
                Name = element.Name ?? string.Empty,
                Type = element.Type ?? string.Empty,
                Alias = element.Alias,
                Capacity = element.Capacity,
                Description = element.Description,
                PositionX = element.PositionX,
                PositionY = element.PositionY,
                Width = element.Width,
                Height = element.Height,
                Rotation = element.Rotation,
                Color = element.Color,
                Icon = element.Icon,
                GroupElements = element.GroupElements,
                GroupElementsGuid = element.GroupElementsGuid,
                DockGuid = element.DockGuid,
                Settings = element.Settings,
                IsActive = element.IsActive,
                IsOccupied = element.IsOccupied,
                CreateDate = element.CreateDate,
                LastModify = element.LastModify,
                Area = area != null ? new AreaSimpleDto
                {
                    Guid = area.Guid,
                    AreaName = area.AreaName ?? string.Empty,
                    AreaCode = area.AreaCode ?? string.Empty,
                    AreaType = area.AreaType,
                    ParentGuid = area.ParentGuid
                } : null
            };
        }
    }
}