using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PerfectKeyV1.Application.DTOs.Hotel
{
    public class HotelDto
    {
        public int Id { get; set; }
        public Guid Guid { get; set; }
        public string Code { get; set; } = string.Empty;
        public string HotelName { get; set; } = string.Empty;
        public string? Note { get; set; }
        public string? DBName { get; set; }
        public string? IPAddress { get; set; }
        public string? ISS_DBName { get; set; }
        public string? ISS_IPAddress { get; set; }
        public string? PKMTablet { get; set; }
        public string? IP_VPN_FO { get; set; }
        public string? IP_VPN_ISS { get; set; }
        public string? IPLAN_Server { get; set; }
        public string? Email { get; set; }
        public bool IsDeleted { get; set; }
        public int? IsAutoUpdateOTA { get; set; }
        public string? OTATimesAuto { get; set; }
        public string? HotelAvatarUrl { get; set; }
        public DateTime? StartDate { get; set; }
        public DateTime? EndDate { get; set; }
        public DateTime CreateDate { get; set; }
    }
}
