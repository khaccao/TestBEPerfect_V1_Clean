using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PerfectKeyV1.Application.DTOs.LoginSession
{
    public class DeviceStatsDto
    {
        public string DeviceType { get; set; } = string.Empty;
        public string Browser { get; set; } = string.Empty;
        public int SessionCount { get; set; }
    }
}
