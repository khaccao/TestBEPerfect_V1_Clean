using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using PerfectKeyV1.Application.DTOs.Layout;
using PerfectKeyV1.Application.DTOs.Users;
using PerfectKeyV1.Application.Interfaces;
using PerfectKeyV1.Application.Services;
using PerfectKeyV1.Domain.Entities;

namespace PerfectKeyV1.Api.Controllers.V1
{
    /// <summary>
    /// Controller quản lý layout, khu vực và phần tử
    /// </summary>
    [ApiController]
    [Route("api/v1/layout")]
    public class LayoutController : ControllerBase
    {
        private readonly ILayoutService _layoutService;
        private readonly IHotelRepository _hotelRepo;

        public LayoutController(ILayoutService layoutService, IHotelRepository hotelRepo)
        {
            _layoutService = layoutService;
            _hotelRepo = hotelRepo;
        }

        // AREA ENDPOINTS

        /// <summary>
        /// Tạo mới khu vực
        /// </summary>
        /// <param name="request">Thông tin tạo khu vực</param>
        /// <param name="hotelCode">Mã khách sạn (từ header)</param>
        /// <returns>Thông tin khu vực đã tạo</returns>
        /// <response code="200">Tạo khu vực thành công</response>
        /// <response code="400">Dữ liệu không hợp lệ hoặc mã khách sạn không tồn tại</response>
        [HttpPost("areas")]
        [ProducesResponseType(typeof(AreaDto), 200)]
        [ProducesResponseType(400)]
        public async Task<ActionResult<AreaDto>> CreateArea(
            [FromBody] CreateAreaRequest request,
            [FromHeader(Name = "X-HotelCode")] string hotelCode)
        {
            try
            {
                if (string.IsNullOrEmpty(hotelCode))
                    return BadRequest(new { message = "Hotel code is required" });

                var hotel = await _hotelRepo.GetByCodeAsync(hotelCode);
                if (hotel == null)
                    return BadRequest(new { message = $"Hotel with code '{hotelCode}' not found" });

                var hotelGuid = hotel.Guid;
                var area = await _layoutService.CreateAreaAsync(request, hotelGuid, hotelCode);
                return Ok(area);
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        /// <summary>
        /// Lấy cây khu vực theo khách sạn
        /// </summary>
        /// <param name="hotelCode">Mã khách sạn (từ header)</param>
        /// <returns>Danh sách khu vực dạng cây</returns>
        /// <response code="200">Lấy danh sách thành công</response>
        /// <response code="400">Mã khách sạn không hợp lệ</response>
        [HttpGet("areas")]
        [ProducesResponseType(typeof(IEnumerable<AreaDto>), 200)]
        [ProducesResponseType(400)]
        public async Task<ActionResult<IEnumerable<AreaDto>>> GetAreaTree(
            [FromHeader(Name = "X-HotelCode")] string hotelCode)
        {
            try
            {
                if (string.IsNullOrEmpty(hotelCode))
                    return BadRequest(new { message = "Hotel code is required" });

                var hotel = await _hotelRepo.GetByCodeAsync(hotelCode);
                if (hotel == null)
                    return BadRequest(new { message = $"Hotel with code '{hotelCode}' not found" });

                var hotelGuid = hotel.Guid;
                var areas = await _layoutService.GetAreaTreeAsync(hotelGuid);
                return Ok(areas);
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        /// <summary>
        /// Lấy thông tin chi tiết khu vực theo GUID
        /// </summary>
        /// <param name="areaGuid">GUID của khu vực</param>
        /// <returns>Thông tin chi tiết khu vực</returns>
        /// <response code="200">Lấy thông tin thành công</response>
        /// <response code="404">Không tìm thấy khu vực</response>
        [HttpGet("areas/{areaGuid}")]
        [ProducesResponseType(typeof(AreaDto), 200)]
        [ProducesResponseType(404)]
        public async Task<ActionResult<AreaDto>> GetArea(Guid areaGuid)
        {
            try
            {
                var area = await _layoutService.GetAreaAsync(areaGuid);
                if (area == null)
                    return NotFound();

                return Ok(area);
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        /// <summary>
        /// Cập nhật thông tin khu vực
        /// </summary>
        /// <param name="areaGuid">GUID của khu vực cần cập nhật</param>
        /// <param name="request">Thông tin cập nhật</param>
        /// <returns>Thông tin khu vực đã cập nhật</returns>
        /// <response code="200">Cập nhật thành công</response>
        /// <response code="400">Dữ liệu không hợp lệ</response>
        /// <response code="404">Không tìm thấy khu vực</response>
        [HttpPut("areas/{areaGuid}")]
        [ProducesResponseType(typeof(AreaDto), 200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(404)]
        public async Task<ActionResult<AreaDto>> UpdateArea(
            Guid areaGuid,
            [FromBody] UpdateAreaRequest request)
        {
            try
            {
                var area = await _layoutService.UpdateAreaAsync(areaGuid, request);
                return Ok(area);
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        /// <summary>
        /// Xóa khu vực
        /// </summary>
        /// <param name="areaGuid">GUID của khu vực cần xóa</param>
        /// <returns>Kết quả xóa</returns>
        /// <response code="200">Xóa thành công</response>
        /// <response code="404">Không tìm thấy khu vực</response>
        [HttpDelete("areas/{areaGuid}")]
        [ProducesResponseType(200)]
        [ProducesResponseType(404)]
        public async Task<ActionResult> DeleteArea(Guid areaGuid)
        {
            try
            {
                var result = await _layoutService.DeleteAreaAsync(areaGuid);
                if (!result)
                    return NotFound();

                return Ok(new { message = "Area deleted successfully" });
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        // ELEMENT ENDPOINTS

        /// <summary>
        /// Tạo mới phần tử (element)
        /// </summary>
        /// <param name="request">Thông tin tạo phần tử</param>
        /// <param name="hotelCode">Mã khách sạn (từ header)</param>
        /// <returns>Thông tin phần tử đã tạo</returns>
        /// <response code="200">Tạo phần tử thành công</response>
        /// <response code="400">Dữ liệu không hợp lệ hoặc mã khách sạn không tồn tại</response>
        [HttpPost("elements")]
        [ProducesResponseType(typeof(ElementDto), 200)]
        [ProducesResponseType(400)]
        public async Task<ActionResult<ElementDto>> CreateElement(
            [FromBody] CreateElementRequest request,
            [FromHeader(Name = "X-HotelCode")] string hotelCode)
        {
            try
            {
                if (string.IsNullOrEmpty(hotelCode))
                    return BadRequest(new { message = "Hotel code is required" });

                var hotel = await _hotelRepo.GetByCodeAsync(hotelCode);
                if (hotel == null)
                    return BadRequest(new { message = $"Hotel with code '{hotelCode}' not found" });

                var hotelGuid = hotel.Guid;
                var element = await _layoutService.CreateElementAsync(request, hotelGuid, hotelCode);
                return Ok(element);
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        /// <summary>
        /// Lấy thông tin chi tiết phần tử theo GUID
        /// </summary>
        /// <param name="elementGuid">GUID của phần tử</param>
        /// <returns>Thông tin chi tiết phần tử</returns>
        /// <response code="200">Lấy thông tin thành công</response>
        /// <response code="404">Không tìm thấy phần tử</response>
        [HttpGet("elements/{elementGuid}")]
        [ProducesResponseType(typeof(ElementDto), 200)]
        [ProducesResponseType(404)]
        public async Task<ActionResult<ElementDto>> GetElement(Guid elementGuid)
        {
            try
            {
                var element = await _layoutService.GetElementAsync(elementGuid);
                if (element == null)
                    return NotFound();

                return Ok(element);
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        /// <summary>
        /// Lấy danh sách phần tử theo khu vực
        /// </summary>
        /// <param name="areaGuid">GUID của khu vực</param>
        /// <returns>Danh sách phần tử thuộc khu vực</returns>
        /// <response code="200">Lấy danh sách thành công</response>
        /// <response code="400">GUID khu vực không hợp lệ</response>
        [HttpGet("elements/area/{areaGuid}")]
        [ProducesResponseType(typeof(IEnumerable<ElementDto>), 200)]
        [ProducesResponseType(400)]
        public async Task<ActionResult<IEnumerable<ElementDto>>> GetElementsByArea(Guid areaGuid)
        {
            try
            {
                var elements = await _layoutService.GetElementsByAreaAsync(areaGuid);
                return Ok(elements);
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        /// <summary>
        /// Lấy danh sách phần tử theo khách sạn
        /// </summary>
        /// <param name="hotelCode">Mã khách sạn (từ header)</param>
        /// <returns>Danh sách phần tử thuộc khách sạn</returns>
        /// <response code="200">Lấy danh sách thành công</response>
        /// <response code="400">Mã khách sạn không hợp lệ</response>
        [HttpGet("elements")]
        [ProducesResponseType(typeof(IEnumerable<ElementDto>), 200)]
        [ProducesResponseType(400)]
        public async Task<ActionResult<IEnumerable<ElementDto>>> GetElementsByHotel(
            [FromHeader(Name = "X-HotelCode")] string hotelCode)
        {
            try
            {
                if (string.IsNullOrEmpty(hotelCode))
                    return BadRequest(new { message = "Hotel code is required" });

                var hotel = await _hotelRepo.GetByCodeAsync(hotelCode);
                if (hotel == null)
                    return BadRequest(new { message = $"Hotel with code '{hotelCode}' not found" });

                var hotelGuid = hotel.Guid;
                var elements = await _layoutService.GetElementsByHotelAsync(hotelGuid);
                return Ok(elements);
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        /// <summary>
        /// Cập nhật thông tin phần tử
        /// </summary>
        /// <param name="elementGuid">GUID của phần tử cần cập nhật</param>
        /// <param name="request">Thông tin cập nhật</param>
        /// <returns>Thông tin phần tử đã cập nhật</returns>
        /// <response code="200">Cập nhật thành công</response>
        /// <response code="400">Dữ liệu không hợp lệ</response>
        /// <response code="404">Không tìm thấy phần tử</response>
        [HttpPut("elements/{elementGuid}")]
        [ProducesResponseType(typeof(ElementDto), 200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(404)]
        public async Task<ActionResult<ElementDto>> UpdateElement(
            Guid elementGuid,
            [FromBody] UpdateElementRequest request)
        {
            try
            {
                var element = await _layoutService.UpdateElementAsync(elementGuid, request);
                return Ok(element);
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        /// <summary>
        /// Xóa phần tử
        /// </summary>
        /// <param name="elementGuid">GUID của phần tử cần xóa</param>
        /// <returns>Kết quả xóa</returns>
        /// <response code="200">Xóa thành công</response>
        /// <response code="404">Không tìm thấy phần tử</response>
        [HttpDelete("elements/{elementGuid}")]
        [ProducesResponseType(200)]
        [ProducesResponseType(404)]
        public async Task<ActionResult> DeleteElement(Guid elementGuid)
        {
            try
            {
                var result = await _layoutService.DeleteElementAsync(elementGuid);
                if (!result)
                    return NotFound();

                return Ok(new { message = "Element deleted successfully" });
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }
    }
}