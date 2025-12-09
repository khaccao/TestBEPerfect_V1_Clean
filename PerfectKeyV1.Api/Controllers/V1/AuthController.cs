using Microsoft.AspNetCore.Mvc;
using PerfectKeyV1.Application.DTOs.Auth;
using PerfectKeyV1.Application.Interfaces;

namespace PerfectKeyV1.Api.Controllers.V1
{
    /// <summary>
    /// Controller xác thực và quản lý người dùng
    /// </summary>
    [ApiController]
    [Route("api/v1/auth")]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;

        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }

        /// <summary>
        /// Đăng nhập vào hệ thống
        /// </summary>
        /// <param name="request">Thông tin đăng nhập</param>
        /// <returns>Kết quả đăng nhập với token và thông tin người dùng</returns>
        /// <response code="200">Đăng nhập thành công</response>
        /// <response code="400">Thông tin đăng nhập không hợp lệ</response>
        [HttpPost("login")]
        [ProducesResponseType(typeof(AuthResponse), 200)]
        [ProducesResponseType(400)]
        public async Task<ActionResult<AuthResponse>> Login(LoginRequest request)
        {
            var result = await _authService.LoginAsync(request);

            if (!result.Success)
                return BadRequest(result);

            if (result.RequiresTwoFactor)
                return Ok(result);

            return Ok(result);
        }

        /// <summary>
        /// Xác thực hai yếu tố (2FA)
        /// </summary>
        /// <param name="request">Thông tin xác thực 2FA</param>
        /// <returns>Kết quả xác thực với token</returns>
        /// <response code="200">Xác thực thành công</response>
        /// <response code="400">Mã xác thực không hợp lệ</response>
        [HttpPost("verify-2fa")]
        [ProducesResponseType(typeof(AuthResponse), 200)]
        [ProducesResponseType(400)]
        public async Task<ActionResult<AuthResponse>> VerifyTwoFactor(TwoFactorRequest request)
        {
            // Sửa lỗi: Chỉ truyền request object, không truyền thêm userId
            var result = await _authService.VerifyTwoFactorAsync(request);

            if (!result.Success)
                return BadRequest(result);

            return Ok(result);
        }

        /// <summary>
        /// Đăng ký tài khoản mới
        /// </summary>
        /// <param name="request">Thông tin đăng ký</param>
        /// <returns>Kết quả đăng ký</returns>
        /// <response code="200">Đăng ký thành công</response>
        /// <response code="400">Thông tin đăng ký không hợp lệ</response>
        [HttpPost("register")]
        [ProducesResponseType(typeof(AuthResponse), 200)]
        [ProducesResponseType(400)]
        public async Task<ActionResult<AuthResponse>> Register(RegisterRequest request)
        {
            var result = await _authService.RegisterAsync(request);

            if (!result.Success)
                return BadRequest(result);

            return Ok(result);
        }

        /// <summary>
        /// Làm mới token (Refresh Token)
        /// </summary>
        /// <param name="request">Token và Refresh Token hiện tại</param>
        /// <returns>Token mới và Refresh Token mới</returns>
        /// <response code="200">Làm mới token thành công</response>
        /// <response code="400">Token không hợp lệ hoặc đã hết hạn</response>
        [HttpPost("refresh-token")]
        [ProducesResponseType(typeof(AuthResponse), 200)]
        [ProducesResponseType(400)]
        public async Task<ActionResult<AuthResponse>> RefreshToken([FromBody] RefreshTokenRequest request)
        {
            var result = await _authService.RefreshTokenAsync(request.Token, request.RefreshToken);

            if (!result.Success)
                return BadRequest(result);

            return Ok(result);
        }

        /// <summary>
        /// Đăng xuất (Logout)
        /// </summary>
        /// <param name="request">Refresh token cần hủy</param>
        /// <returns>Kết quả đăng xuất</returns>
        /// <response code="200">Đăng xuất thành công</response>
        /// <response code="400">Refresh token không hợp lệ</response>
        [HttpPost("logout")]
        [ProducesResponseType(200)]
        [ProducesResponseType(400)]
        public async Task<IActionResult> Logout([FromBody] LogoutRequest request)
        {
            var result = await _authService.LogoutAsync(request.RefreshToken);

            if (!result)
                return BadRequest(new { message = "Logout failed" });

            return Ok(new { message = "Logout successful" });
        }

        /// <summary>
        /// Lấy danh sách khách sạn của người dùng
        /// </summary>
        /// <param name="username">Tên đăng nhập</param>
        /// <returns>Danh sách khách sạn</returns>
        /// <response code="200">Lấy danh sách thành công</response>
        /// <response code="404">Người dùng không tồn tại</response>
        [HttpGet("hotels/{username}")]
        [ProducesResponseType(typeof(IEnumerable<UserHotelDto>), 200)]
        [ProducesResponseType(404)]
        public async Task<ActionResult<IEnumerable<UserHotelDto>>> GetUserHotels(string username)
        {
            var hotels = await _authService.GetUserHotelsAsync(username);

            if (!hotels.Any())
                return NotFound(new { message = "No hotels found for this user" });

            return Ok(hotels);
        }

        /// <summary>
        /// Thu hồi token (Đăng xuất)
        /// </summary>
        /// <returns>Kết quả thu hồi token</returns>
        /// <response code="200">Thu hồi token thành công</response>
        /// <response code="401">Không có quyền thực hiện</response>
        [HttpPost("revoke-token")]
        [ProducesResponseType(200)]
        [ProducesResponseType(401)]
        public async Task<IActionResult> RevokeToken()
        {
            var userId = GetCurrentUserId();
            if (userId == 0)
                return Unauthorized();

            await _authService.RevokeTokenAsync(userId);
            return Ok(new { message = "Token revoked successfully" });
        }

        /// <summary>
        /// Kích hoạt xác thực hai yếu tố (2FA)
        /// </summary>
        /// <returns>Thông tin thiết lập 2FA (QR code và secret key)</returns>
        /// <response code="200">Thiết lập 2FA thành công</response>
        /// <response code="401">Không có quyền thực hiện</response>
        [HttpPost("enable-2fa")]
        [ProducesResponseType(typeof(TwoFactorSetupResponse), 200)]
        [ProducesResponseType(401)]
        public async Task<ActionResult<TwoFactorSetupResponse>> EnableTwoFactor()
        {
            var userId = GetCurrentUserId();
            if (userId == 0)
                return Unauthorized();

            var result = await _authService.EnableTwoFactorAsync(userId);

            if (!result.Success)
                return BadRequest(result);

            return Ok(result);
        }

        /// <summary>
        /// Xác nhận kích hoạt 2FA
        /// </summary>
        /// <param name="code">Mã OTP từ ứng dụng xác thực</param>
        /// <returns>Kết quả xác nhận</returns>
        /// <response code="200">Xác nhận thành công</response>
        /// <response code="400">Mã OTP không hợp lệ</response>
        /// <response code="401">Không có quyền thực hiện</response>
        [HttpPost("confirm-2fa")]
        [ProducesResponseType(typeof(TwoFactorSetupResponse), 200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(401)]
        public async Task<ActionResult<TwoFactorSetupResponse>> ConfirmTwoFactor([FromBody] string code)
        {
            var userId = GetCurrentUserId();
            if (userId == 0)
                return Unauthorized();

            var result = await _authService.ConfirmEnableTwoFactorAsync(userId, code);

            if (!result.Success)
                return BadRequest(result);

            return Ok(result);
        }

        /// <summary>
        /// Tắt xác thực hai yếu tố (2FA)
        /// </summary>
        /// <param name="code">Mã OTP hoặc recovery code</param>
        /// <returns>Kết quả tắt 2FA</returns>
        /// <response code="200">Tắt 2FA thành công</response>
        /// <response code="400">Mã xác thực không hợp lệ</response>
        /// <response code="401">Không có quyền thực hiện</response>
        [HttpPost("disable-2fa")]
        [ProducesResponseType(200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(401)]
        public async Task<IActionResult> DisableTwoFactor([FromBody] string code)
        {
            var userId = GetCurrentUserId();
            if (userId == 0)
                return Unauthorized();

            var result = await _authService.DisableTwoFactorAsync(userId, code);

            if (!result)
                return BadRequest(new { message = "Invalid OTP or recovery code" });

            return Ok(new { message = "2FA disabled successfully" });
        }

        /// <summary>
        /// Lấy danh sách recovery codes
        /// </summary>
        /// <returns>Danh sách recovery codes</returns>
        /// <response code="200">Lấy danh sách thành công</response>
        /// <response code="401">Không có quyền thực hiện</response>
        [HttpGet("recovery-codes")]
        [ProducesResponseType(typeof(List<string>), 200)]
        [ProducesResponseType(401)]
        public async Task<ActionResult<List<string>>> GetRecoveryCodes()
        {
            var userId = GetCurrentUserId();
            if (userId == 0)
                return Unauthorized();

            var codes = await _authService.GetRecoveryCodesAsync(userId);
            return Ok(codes);
        }

        /// <summary>
        /// Tạo mới recovery codes
        /// </summary>
        /// <returns>Danh sách recovery codes mới</returns>
        /// <response code="200">Tạo mới thành công</response>
        /// <response code="401">Không có quyền thực hiện</response>
        [HttpPost("generate-recovery-codes")]
        [ProducesResponseType(typeof(List<string>), 200)]
        [ProducesResponseType(401)]
        public async Task<ActionResult<List<string>>> GenerateNewRecoveryCodes()
        {
            var userId = GetCurrentUserId();
            if (userId == 0)
                return Unauthorized();

            var codes = await _authService.GenerateNewRecoveryCodesAsync(userId);
            return Ok(codes);
        }

        /// <summary>
        /// Quên mật khẩu - Yêu cầu reset mật khẩu
        /// </summary>
        /// <param name="request">Email người dùng</param>
        /// <returns>Kết quả yêu cầu reset mật khẩu</returns>
        /// <response code="200">Yêu cầu được chấp nhận</response>
        [HttpPost("forgot-password")]
        [ProducesResponseType(200)]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest request)
        {
            await _authService.ForgotPasswordAsync(request);
            // Luôn trả về 200 để không tiết lộ thông tin user
            return Ok(new { message = "If your email exists in our system, you will receive a reset link" });
        }

        /// <summary>
        /// Đặt lại mật khẩu
        /// </summary>
        /// <param name="request">Token reset và mật khẩu mới</param>
        /// <returns>Kết quả đặt lại mật khẩu</returns>
        /// <response code="200">Đặt lại mật khẩu thành công</response>
        /// <response code="400">Token không hợp lệ hoặc đã hết hạn</response>
        [HttpPost("reset-password")]
        [ProducesResponseType(200)]
        [ProducesResponseType(400)]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
        {
            var result = await _authService.ResetPasswordAsync(request);

            if (!result)
                return BadRequest(new { message = "Invalid or expired reset token" });

            return Ok(new { message = "Password reset successfully" });
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
    }

    /// <summary>
    /// Request làm mới token
    /// </summary>
    public class RefreshTokenRequest
    {
        /// <summary>
        /// Token hiện tại
        /// </summary>
        /// <example>eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...</example>
        public string Token { get; set; } = string.Empty;

        /// <summary>
        /// Refresh token
        /// </summary>
        /// <example>abc123def456...</example>
        public string RefreshToken { get; set; } = string.Empty;
    }

    /// <summary>
    /// Request đăng xuất
    /// </summary>
    public class LogoutRequest
    {
        /// <summary>
        /// Refresh token cần hủy
        /// </summary>
        /// <example>xyz789abc123...</example>
        public string RefreshToken { get; set; } = string.Empty;
    }
}