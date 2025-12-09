using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using PerfectKeyV1.Application.DTOs.Layout;
using PerfectKeyV1.Application.DTOs.Users;
using PerfectKeyV1.Application.Interfaces;
using PerfectKeyV1.Domain.Entities;

namespace PerfectKeyV1.Api.Controllers.V1
{
    /// <summary>
    /// Controller quản lý loại khu vực (Area Type)
    /// </summary>
    [ApiController]
    [Route("api/v1/area-types")]
    public class AreaTypeController : ControllerBase
    {
        private readonly IAreaTypeService _areaTypeService;
        private readonly IHotelRepository _hotelRepo;

        public AreaTypeController(IAreaTypeService areaTypeService, IHotelRepository hotelRepo)
        {
            _areaTypeService = areaTypeService;
            _hotelRepo = hotelRepo;
        }

        /// <summary>
        /// Tạo mới loại khu vực
        /// </summary>
        /// <param name="request">Thông tin tạo loại khu vực</param>
        /// <param name="hotelCode">Mã khách sạn (từ header)</param>
        /// <returns>Thông tin loại khu vực đã tạo</returns>
        /// <response code="200">Tạo thành công</response>
        /// <response code="400">Dữ liệu không hợp lệ hoặc mã khách sạn không tồn tại</response>
        [HttpPost]
        [ProducesResponseType(typeof(AreaTypeDto), 200)]
        [ProducesResponseType(400)]
        public async Task<ActionResult<AreaTypeDto>> CreateAreaType(
            [FromBody] CreateAreaTypeRequest request,
            [FromHeader(Name = "X-HotelCode")] string hotelCode)
        {
            try
            {
                if (string.IsNullOrEmpty(hotelCode))
                    return BadRequest(new { message = "Hotel code is required" });

                var hotelGuid = await GetHotelGuidFromCodeAsync(hotelCode);
                if (hotelGuid == Guid.Empty)
                    return BadRequest(new { message = $"Hotel with code '{hotelCode}' not found" });

                var areaType = await _areaTypeService.CreateAreaTypeAsync(request, hotelGuid, hotelCode);
                return Ok(areaType);
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        /// <summary>
        /// Lấy danh sách tất cả loại khu vực theo khách sạn
        /// </summary>
        /// <param name="hotelCode">Mã khách sạn (từ header)</param>
        /// <returns>Danh sách loại khu vực</returns>
        /// <response code="200">Lấy danh sách thành công</response>
        /// <response code="400">Mã khách sạn không hợp lệ</response>
        [HttpGet]
        [ProducesResponseType(typeof(IEnumerable<AreaTypeDto>), 200)]
        [ProducesResponseType(400)]
        public async Task<ActionResult<IEnumerable<AreaTypeDto>>> GetAreaTypesByHotel(
            [FromHeader(Name = "X-HotelCode")] string hotelCode)
        {
            try
            {
                if (string.IsNullOrEmpty(hotelCode))
                    return BadRequest(new { message = "Hotel code is required" });

                var hotelGuid = await GetHotelGuidFromCodeAsync(hotelCode);
                if (hotelGuid == Guid.Empty)
                    return BadRequest(new { message = $"Hotel with code '{hotelCode}' not found" });

                var areaTypes = await _areaTypeService.GetAreaTypesByHotelAsync(hotelGuid);
                return Ok(areaTypes);
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        /// <summary>
        /// Lấy thông tin chi tiết loại khu vực theo GUID
        /// </summary>
        /// <param name="areaTypeGuid">GUID của loại khu vực</param>
        /// <returns>Thông tin chi tiết loại khu vực</returns>
        /// <response code="200">Lấy thông tin thành công</response>
        /// <response code="404">Không tìm thấy loại khu vực</response>
        [HttpGet("{areaTypeGuid}")]
        [ProducesResponseType(typeof(AreaTypeDto), 200)]
        [ProducesResponseType(404)]
        public async Task<ActionResult<AreaTypeDto>> GetAreaType(Guid areaTypeGuid)
        {
            try
            {
                var areaType = await _areaTypeService.GetAreaTypeAsync(areaTypeGuid);
                if (areaType == null)
                    return NotFound();

                return Ok(areaType);
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        /// <summary>
        /// Lấy thông tin loại khu vực theo mã code
        /// </summary>
        /// <param name="code">Mã code của loại khu vực</param>
        /// <param name="hotelCode">Mã khách sạn (từ header)</param>
        /// <returns>Thông tin loại khu vực</returns>
        /// <response code="200">Lấy thông tin thành công</response>
        /// <response code="404">Không tìm thấy loại khu vực</response>
        [HttpGet("code/{code}")]
        [ProducesResponseType(typeof(AreaTypeDto), 200)]
        [ProducesResponseType(404)]
        public async Task<ActionResult<AreaTypeDto>> GetAreaTypeByCode(
            string code,
            [FromHeader(Name = "X-HotelCode")] string hotelCode)
        {
            try
            {
                if (string.IsNullOrEmpty(hotelCode))
                    return BadRequest(new { message = "Hotel code is required" });

                var hotelGuid = await GetHotelGuidFromCodeAsync(hotelCode);
                if (hotelGuid == Guid.Empty)
                    return BadRequest(new { message = $"Hotel with code '{hotelCode}' not found" });

                var areaType = await _areaTypeService.GetAreaTypeByCodeAsync(code, hotelGuid);
                if (areaType == null)
                    return NotFound();

                return Ok(areaType);
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        /// <summary>
        /// Lấy danh sách loại khu vực theo nhóm
        /// </summary>
        /// <param name="groupCode">Mã nhóm</param>
        /// <param name="hotelCode">Mã khách sạn (từ header)</param>
        /// <returns>Danh sách loại khu vực thuộc nhóm</returns>
        /// <response code="200">Lấy danh sách thành công</response>
        /// <response code="400">Mã khách sạn không hợp lệ</response>
        [HttpGet("group/{groupCode}")]
        [ProducesResponseType(typeof(IEnumerable<AreaTypeDto>), 200)]
        [ProducesResponseType(400)]
        public async Task<ActionResult<IEnumerable<AreaTypeDto>>> GetAreaTypesByGroup(
            string groupCode,
            [FromHeader(Name = "X-HotelCode")] string hotelCode)
        {
            try
            {
                if (string.IsNullOrEmpty(hotelCode))
                    return BadRequest(new { message = "Hotel code is required" });

                var hotelGuid = await GetHotelGuidFromCodeAsync(hotelCode);
                if (hotelGuid == Guid.Empty)
                    return BadRequest(new { message = $"Hotel with code '{hotelCode}' not found" });

                var areaTypes = await _areaTypeService.GetAreaTypesByGroupAsync(groupCode, hotelGuid);
                return Ok(areaTypes);
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        /// <summary>
        /// Cập nhật thông tin loại khu vực
        /// </summary>
        /// <param name="areaTypeGuid">GUID của loại khu vực cần cập nhật</param>
        /// <param name="request">Thông tin cập nhật</param>
        /// <returns>Thông tin loại khu vực đã cập nhật</returns>
        /// <response code="200">Cập nhật thành công</response>
        /// <response code="400">Dữ liệu không hợp lệ</response>
        /// <response code="404">Không tìm thấy loại khu vực</response>
        [HttpPut("{areaTypeGuid}")]
        [ProducesResponseType(typeof(AreaTypeDto), 200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(404)]
        public async Task<ActionResult<AreaTypeDto>> UpdateAreaType(
            Guid areaTypeGuid,
            [FromBody] UpdateAreaTypeRequest request)
        {
            try
            {
                var areaType = await _areaTypeService.UpdateAreaTypeAsync(areaTypeGuid, request);
                return Ok(areaType);
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        /// <summary>
        /// Xóa loại khu vực
        /// </summary>
        /// <param name="areaTypeGuid">GUID của loại khu vực cần xóa</param>
        /// <returns>Kết quả xóa</returns>
        /// <response code="200">Xóa thành công</response>
        /// <response code="404">Không tìm thấy loại khu vực</response>
        [HttpDelete("{areaTypeGuid}")]
        [ProducesResponseType(200)]
        [ProducesResponseType(404)]
        public async Task<ActionResult> DeleteAreaType(Guid areaTypeGuid)
        {
            try
            {
                var result = await _areaTypeService.DeleteAreaTypeAsync(areaTypeGuid);
                if (!result)
                    return NotFound();

                return Ok(new { message = "AreaType deleted successfully" });
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        /// <summary>
        /// Lấy HotelGuid từ mã khách sạn
        /// </summary>
        /// <param name="hotelCode">Mã khách sạn</param>
        /// <returns>GUID của khách sạn</returns>
        private async Task<Guid> GetHotelGuidFromCodeAsync(string hotelCode)
        {
            if (string.IsNullOrEmpty(hotelCode))
                return Guid.Empty;

            var hotel = await _hotelRepo.GetByCodeAsync(hotelCode);
            return hotel?.Guid ?? Guid.Empty;
        }
    }
}