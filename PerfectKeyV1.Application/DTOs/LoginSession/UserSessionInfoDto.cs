using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PerfectKeyV1.Application.DTOs.LoginSession
{
    public class UserSessionInfoDto
    {
        public int Id { get; set; }
        public string UserName { get; set; } = string.Empty;
        public string FullName { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string? AvatarUrl { get; set; }
        public int? UserType { get; set; }
        public int Status { get; set; }
        public string UserTypeDisplay { get; set; } = string.Empty;
        public string StatusDisplay { get; set; } = string.Empty;
    }
}
