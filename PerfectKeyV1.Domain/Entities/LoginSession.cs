using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace PerfectKeyV1.Domain.Entities
{
    [Table("LoginSessions")]
    public class LoginSession
    {
        [Key]
        [Column("Id")]
        public int Id { get; set; }

        [Required]
        [Column("UserId")]
        public int UserId { get; set; }

        [ForeignKey("UserId")]
        public virtual User User { get; set; } = null!;

        [Required]
        [MaxLength(500)]
        [Column("Token")]
        public string Token { get; set; } = string.Empty;

        [MaxLength(500)]
        [Column("RefreshToken")]
        public string RefreshToken { get; set; } = string.Empty;

        [MaxLength(100)]
        [Column("DeviceInfo")]
        public string DeviceInfo { get; set; } = string.Empty;

        [MaxLength(50)]
        [Column("IpAddress")]
        public string IpAddress { get; set; } = string.Empty;

        [MaxLength(200)]
        [Column("Location")]
        public string Location { get; set; } = string.Empty;

        [MaxLength(100)]
        [Column("Browser")]
        public string? Browser { get; set; } = string.Empty;

        [MaxLength(100)]
        [Column("OperatingSystem")]
        public string? OperatingSystem { get; set; } = string.Empty;

        [MaxLength(50)]
        [Column("SessionType")]
        public string? SessionType { get; set; } = "Web"; // Web, Mobile,...

        [Column("LoginTime")]
        public DateTime LoginTime { get; set; } = DateTime.UtcNow;

        [Column("LastActivity")]
        public DateTime? LastActivity { get; set; }

        [Column("LogoutTime")]
        public DateTime? LogoutTime { get; set; }

        [Required]
        [Column("IsActive")]
        public bool IsActive { get; set; } = true;

        [Column("TokenExpiry")]
        public DateTime? TokenExpiry { get; set; }

        [Column("IsRememberMe")]
        public bool IsRememberMe { get; set; }

        [Column("IsTwoFactorVerified")]
        public bool IsTwoFactorVerified { get; set; } = false;

        [MaxLength(1000)]
        [Column("UserAgent")]
        public string? UserAgent { get; set; }

        [Column("CreateDate")]
        public DateTime CreateDate { get; set; } = DateTime.UtcNow;

        [Column("LastModify")]
        public DateTime? LastModify { get; set; }

        // ---- METHODS ----

        public bool IsExpired() => TokenExpiry.HasValue && TokenExpiry < DateTime.UtcNow;

        public void UpdateActivity()
        {
            LastActivity = DateTime.UtcNow;
            LastModify = DateTime.UtcNow;
        }

        public void Logout()
        {
            IsActive = false;
            LogoutTime = DateTime.UtcNow;
            LastModify = DateTime.UtcNow;
        }

        public void RefreshTokens(string newToken, string newRefreshToken, DateTime newExpiry)
        {
            Token = newToken;
            RefreshToken = newRefreshToken;
            TokenExpiry = newExpiry;
            LastActivity = DateTime.UtcNow;
            LastModify = DateTime.UtcNow;
        }

        public TimeSpan GetSessionDuration()
        {
            var endTime = LogoutTime ?? DateTime.UtcNow;
            return endTime - LoginTime;
        }

        public bool IsLongLived() => GetSessionDuration().TotalHours > 24;
    }
}