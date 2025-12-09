using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PerfectKeyV1.Application.DTOs.Layout
{
    public class AreaTypeDto
    {
        public int Id { get; set; }
        public Guid Guid { get; set; }
        public Guid HotelGuid { get; set; }
        public string HotelCode { get; set; } = string.Empty;
        public string Code { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string GroupCode { get; set; } = string.Empty;
        public string? Descriptions { get; set; }
    }
}
