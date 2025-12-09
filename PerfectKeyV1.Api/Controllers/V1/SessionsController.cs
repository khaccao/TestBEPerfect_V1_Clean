using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using PerfectKeyV1.Application.DTOs.LoginSession;
using PerfectKeyV1.Application.Interfaces;

namespace PerfectKeyV1.Api.Controllers.V1
{
    /// <summary>
    /// Controller quản lý phiên đăng nhập của người dùng
    /// </summary>
    [ApiController]
    [Route("api/v1/sessions")]
    public class SessionsController : ControllerBase
    {
        private readonly ILoginSessionService _loginSessionService;

        public SessionsController(ILoginSessionService loginSessionService)
        {
            _loginSessionService = loginSessionService;
        }

        /// <summary>
        /// Lấy danh sách phiên đăng nhập của người dùng
        /// </summary>
        /// <param name="request">Thông tin phân trang và lọc</param>
        /// <returns>Danh sách phiên đăng nhập với thông tin chi tiết</returns>
        /// <response code="200">Lấy danh sách thành công</response>
        /// <response code="401">Không có quyền truy cập</response>
        [HttpGet]
        [ProducesResponseType(typeof(LoginSessionResponse), 200)]
        [ProducesResponseType(401)]
        public async Task<ActionResult<LoginSessionResponse>> GetUserSessions([FromQuery] LoginSessionRequest request)
        {
            var userId = GetCurrentUserId();
            if (userId == 0)
                return Unauthorized();

            var result = await _loginSessionService.GetUserSessionsAsync(userId, request);
            return Ok(result);
        }

        /// <summary>
        /// Đăng xuất một phiên đăng nhập cụ thể
        /// </summary>
        /// <param name="sessionId">ID của phiên đăng nhập cần đăng xuất</param>
        /// <returns>Kết quả đăng xuất</returns>
        /// <response code="200">Đăng xuất thành công</response>
        /// <response code="400">Không thể đăng xuất phiên</response>
        /// <response code="401">Không có quyền thực hiện</response>
        [HttpPost("{sessionId}/logout")]
        [ProducesResponseType(200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(401)]
        public async Task<IActionResult> LogoutSession(int sessionId)
        {
            var userId = GetCurrentUserId();
            if (userId == 0)
                return Unauthorized();

            var result = await _loginSessionService.LogoutSessionAsync(sessionId, userId);

            if (!result)
                return BadRequest(new { message = "Failed to logout session" });

            return Ok(new { message = "Session logged out successfully" });
        }

        /// <summary>
        /// Đăng xuất tất cả các phiên đăng nhập khác (trừ phiên hiện tại)
        /// </summary>
        /// <returns>Kết quả đăng xuất</returns>
        /// <response code="200">Đăng xuất các phiên khác thành công</response>
        /// <response code="400">Không thể đăng xuất các phiên khác</response>
        /// <response code="401">Không có quyền thực hiện</response>
        [HttpPost("logout-others")]
        [ProducesResponseType(200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(401)]
        public async Task<IActionResult> LogoutOtherSessions()
        {
            var userId = GetCurrentUserId();
            if (userId == 0)
                return Unauthorized();

            var currentSessionId = GetCurrentSessionId();
            var result = await _loginSessionService.LogoutOtherSessionsAsync(userId, currentSessionId);

            if (!result)
                return BadRequest(new { message = "Failed to logout other sessions" });

            return Ok(new { message = "Other sessions logged out successfully" });
        }

        /// <summary>
        /// Lấy ID người dùng hiện tại từ token
        /// </summary>
        /// <returns>ID người dùng</returns>
        private int GetCurrentUserId()
        {
            var userIdClaim = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier);
            return userIdClaim != null ? int.Parse(userIdClaim.Value) : 0;
        }

        /// <summary>
        /// Lấy ID phiên đăng nhập hiện tại
        /// </summary>
        /// <returns>ID phiên đăng nhập</returns>
        private int GetCurrentSessionId()
        {
            // This would need to be implemented based on how you track current session
            // For now, return 0 as placeholder
            return 0;
        }
    }
}