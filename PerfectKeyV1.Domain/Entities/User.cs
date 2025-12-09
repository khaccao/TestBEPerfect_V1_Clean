using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace PerfectKeyV1.Domain.Entities
{
    [Table("DATA_Users")]
    public class User
    {
        [Key]
        [Column("ID")]
        public int Id { get; set; }

        [Column("Guid")]
        public Guid Guid { get; set; } = Guid.NewGuid();

        [Column("GroupParent")]
        public int? GroupParent { get; set; }

        [Column("GroupParentGuid")]
        public Guid? GroupParentGuid { get; set; }

        [Column("UserName")]
        public string UserName { get; set; } = string.Empty;

        // DB column name is "Password"
        [Column("Password")]
        public string PasswordHash { get; set; } = string.Empty;

        [Column("JobTitle")]
        public string? JobTitle { get; set; }

        [Column("Alias")]
        public string? Alias { get; set; }

        [Column("FullName")]
        public string FullName { get; set; } = string.Empty;

        [Column("AvatarDes")]
        public string? AvatarDes { get; set; }

        [Column("AvatarUrl")]
        public string? AvatarUrl { get; set; }

        [Column("Code")]
        public string? Code { get; set; }

        [Column("Email")]
        public string? Email { get; set; }

        [Column("Comments")]
        public string? Comments { get; set; }

        [Column("UserType")]
        public int? UserType { get; set; }

        [Column("ValidTime")]
        public DateTime? ValidTime { get; set; }

        [Column("Status")]
        public int Status { get; set; } = 1;

        [Column("CreateDate")]
        public DateTime CreateDate { get; set; } = DateTime.UtcNow;

        [Column("LastModify")]
        public DateTime? LastModify { get; set; }

        [Column("TwoFactorEnabled")]
        public int TwoFactorEnabled { get; set; } = 0;

        [Column("TwoFactorSecret")]
        public string? TwoFactorSecret { get; set; }

        [Column("TwoFactorRecoveryCodes")]
        public string? TwoFactorRecoveryCodes { get; set; }

        [Column("Mobile")]
        public string? Mobile { get; set; }

        // Thêm các properties mới cho password reset
        [Column("ResetToken")]
        public string? ResetToken { get; set; }

        [Column("ResetTokenExpiry")]
        public DateTime? ResetTokenExpiry { get; set; }

        [Column("LastLogin")]
        public DateTime? LastLogin { get; set; }

        // Navigation properties
        public virtual ICollection<UserHotel> UserHotels { get; set; } = new List<UserHotel>();
        public virtual ICollection<LoginSession> LoginSessions { get; set; } = new List<LoginSession>();

        // Helper methods
        public bool IsActive() => Status == 0;
        public bool IsPending() => Status == 1;
        public bool IsDeleted() => Status == -1;
        public bool HasTwoFactorEnabled() => TwoFactorEnabled == 1;
        public bool CanResetPassword() => ResetTokenExpiry.HasValue && ResetTokenExpiry > DateTime.UtcNow;
        public bool IsValid() => ValidTime.HasValue ? ValidTime > DateTime.UtcNow : true;
    }
}