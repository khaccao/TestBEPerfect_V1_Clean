using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PerfectKeyV1.Application.DTOs.LoginSession
{
    public class LocationStatsDto
    {
        public string Location { get; set; } = string.Empty;
        public string IpAddress { get; set; } = string.Empty;
        public int SessionCount { get; set; }
        public DateTime LastAccess { get; set; }
    }
}
