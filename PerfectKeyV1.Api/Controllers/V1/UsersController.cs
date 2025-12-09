using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using PerfectKeyV1.Application.DTOs.Users;
using PerfectKeyV1.Application.Services;
using PerfectKeyV1.Domain.Entities;

namespace PerfectKeyV1.Api.Controllers.V1
{
    /// <summary>
    /// Controller quản lý người dùng
    /// </summary>
    [ApiController]
    [Route("api/v1/users")]
    public class UsersController : ControllerBase
    {
        private readonly IUserService _userService;

        public UsersController(IUserService userService)
        {
            _userService = userService;
        }

        /// <summary>
        /// Tạo mới người dùng
        /// </summary>
        /// <param name="request">Thông tin tạo người dùng</param>
        /// <returns>Thông tin người dùng đã tạo</returns>
        /// <response code="200">Tạo người dùng thành công</response>
        /// <response code="400">Dữ liệu không hợp lệ</response>
        [HttpPost]
        [ProducesResponseType(typeof(User), 200)]
        [ProducesResponseType(400)]
        public async Task<ActionResult<User>> CreateUser(CreateUserRequest request)
        {
            try
            {
                var user = await _userService.CreateUserAsync(request);
                return Ok(user);
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        /// <summary>
        /// Lấy danh sách tất cả người dùng
        /// </summary>
        /// <returns>Danh sách người dùng</returns>
        /// <response code="200">Lấy danh sách thành công</response>
        [HttpGet]
        [ProducesResponseType(typeof(IEnumerable<User>), 200)]
        public async Task<ActionResult<IEnumerable<User>>> GetUsers()
        {
            var users = await _userService.GetAllUsersAsync();
            return Ok(users);
        }

        /// <summary>
        /// Lấy thông tin người dùng theo ID
        /// </summary>
        /// <param name="id">ID người dùng</param>
        /// <returns>Thông tin chi tiết người dùng</returns>
        /// <response code="200">Lấy thông tin thành công</response>
        /// <response code="404">Không tìm thấy người dùng</response>
        [HttpGet("{id:int}")]
        [ProducesResponseType(typeof(User), 200)]
        [ProducesResponseType(404)]
        public async Task<ActionResult<User>> GetUser(int id)
        {
            var user = await _userService.GetUserByIdAsync(id);
            if (user == null)
                return NotFound();

            return Ok(user);
        }

        /// <summary>
        /// Lấy thông tin người dùng theo GUID
        /// </summary>
        /// <param name="guid">GUID người dùng</param>
        /// <returns>Thông tin chi tiết người dùng</returns>
        /// <response code="200">Lấy thông tin thành công</response>
        /// <response code="404">Không tìm thấy người dùng</response>
        [HttpGet("guid/{guid}")]
        [ProducesResponseType(typeof(User), 200)]
        [ProducesResponseType(404)]
        public async Task<ActionResult<User>> GetUserByGuid(Guid guid)
        {
            var user = await _userService.GetUserByGuidAsync(guid);
            if (user == null)
                return NotFound();

            return Ok(user);
        }

        /// <summary>
        /// Cập nhật thông tin người dùng
        /// </summary>
        /// <param name="id">ID người dùng cần cập nhật</param>
        /// <param name="request">Thông tin cập nhật</param>
        /// <returns>Thông tin người dùng đã cập nhật</returns>
        /// <response code="200">Cập nhật thành công</response>
        /// <response code="400">Dữ liệu không hợp lệ</response>
        /// <response code="404">Không tìm thấy người dùng</response>
        [HttpPut("{id:int}")]
        [ProducesResponseType(typeof(User), 200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(404)]
        public async Task<ActionResult<User>> UpdateUser(int id, UpdateUserRequest request)
        {
            try
            {
                var user = await _userService.UpdateUserAsync(id, request);
                return Ok(user);
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        /// <summary>
        /// Xóa người dùng
        /// </summary>
        /// <param name="id">ID người dùng cần xóa</param>
        /// <returns>Kết quả xóa</returns>
        /// <response code="204">Xóa thành công</response>
        /// <response code="400">Không thể xóa người dùng</response>
        /// <response code="404">Không tìm thấy người dùng</response>
        [HttpDelete("{id:int}")]
        [ProducesResponseType(204)]
        [ProducesResponseType(400)]
        [ProducesResponseType(404)]
        public async Task<IActionResult> DeleteUser(int id)
        {
            try
            {
                await _userService.DeleteUserAsync(id);
                return NoContent();
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        /// <summary>
        /// Gán danh sách khách sạn cho người dùng
        /// </summary>
        /// <param name="id">ID người dùng</param>
        /// <param name="hotelCodes">Danh sách mã khách sạn</param>
        /// <returns>Kết quả gán khách sạn</returns>
        /// <response code="200">Gán khách sạn thành công</response>
        /// <response code="400">Dữ liệu không hợp lệ</response>
        /// <response code="404">Không tìm thấy người dùng</response>
        [HttpPost("{id:int}/hotels")]
        [ProducesResponseType(200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(404)]
        public async Task<IActionResult> AssignHotels(int id, [FromBody] List<string> hotelCodes)
        {
            try
            {
                await _userService.AssignHotelsAsync(id, hotelCodes);
                return Ok(new { message = "Hotels assigned successfully" });
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        /// <summary>
        /// Lấy danh sách khách sạn của người dùng
        /// </summary>
        /// <param name="id">ID người dùng</param>
        /// <returns>Danh sách khách sạn</returns>
        /// <response code="200">Lấy danh sách thành công</response>
        /// <response code="404">Không tìm thấy người dùng</response>
        [HttpGet("{id:int}/hotels")]
        [ProducesResponseType(typeof(IEnumerable<Hotel>), 200)]
        [ProducesResponseType(404)]
        public async Task<ActionResult<IEnumerable<Hotel>>> GetUserHotels(int id)
        {
            var hotels = await _userService.GetUserHotelsAsync(id);
            return Ok(hotels);
        }
    }
}