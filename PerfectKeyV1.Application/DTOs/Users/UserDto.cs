using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PerfectKeyV1.Application.DTOs.Users
{
    public class UserDto
    {
        public int Id { get; set; } // Đảm bảo đây là int
        public Guid Guid { get; set; }
        public string UserName { get; set; } = string.Empty;
        public string FullName { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public int? UserType { get; set; }
        public int Status { get; set; }
        public int TwoFactorEnabled { get; set; }
        public string? TwoFactorSecret { get; set; }
        public string? TwoFactorRecoveryCodes { get; set; }
        public DateTime CreateDate { get; set; }
        public DateTime? LastModify { get; set; }
    }
}