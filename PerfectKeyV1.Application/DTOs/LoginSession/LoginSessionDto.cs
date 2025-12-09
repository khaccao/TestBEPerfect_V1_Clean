using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PerfectKeyV1.Application.DTOs.LoginSession
{
    public class LoginSessionDto
    {
        public int Id { get; set; }
        public int UserId { get; set; }
        public string DeviceInfo { get; set; } = string.Empty;
        public string IpAddress { get; set; } = string.Empty;
        public string Location { get; set; } = string.Empty;
        public DateTime LoginTime { get; set; }
        public DateTime? LastActivity { get; set; }
        public DateTime? LogoutTime { get; set; }
        public bool IsActive { get; set; }
        public bool IsCurrentSession { get; set; }
        public string StatusDisplay { get; set; } = string.Empty;
        public string TimeAgo { get; set; } = string.Empty;
        public UserSessionInfoDto? User { get; set; }
    }
}
