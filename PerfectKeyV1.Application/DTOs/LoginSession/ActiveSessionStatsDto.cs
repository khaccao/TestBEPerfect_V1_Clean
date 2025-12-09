using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PerfectKeyV1.Application.DTOs.LoginSession
{
    public class ActiveSessionStatsDto
    {
        public int TotalSessions { get; set; }
        public int ActiveSessions { get; set; }
        public int ExpiredSessions { get; set; }
        public int UniqueDevices { get; set; }
        public int UniqueLocations { get; set; }
        public List<DeviceStatsDto> DeviceStats { get; set; } = new();
        public List<LocationStatsDto> LocationStats { get; set; } = new();
    }
}
