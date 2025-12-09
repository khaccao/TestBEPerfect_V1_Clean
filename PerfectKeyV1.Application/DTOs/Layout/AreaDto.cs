using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PerfectKeyV1.Application.DTOs.Layout
{
    public class AreaDto
    {
        public int Id { get; set; }
        public Guid Guid { get; set; }
        public Guid? ParentGuid { get; set; }
        public Guid HotelGuid { get; set; }
        public string HotelCode { get; set; } = string.Empty;
        public string AreaCode { get; set; } = string.Empty;
        public string AreaName { get; set; } = string.Empty;
        public string AreaType { get; set; } = string.Empty;
        public Guid? AreaTypeGuid { get; set; }
        public string? AreaAlias { get; set; }
        public string? AreaDescription { get; set; }
        public string? AreaAvatar { get; set; }
        public string? Color { get; set; }
        public int? PositionX { get; set; }
        public int? PositionY { get; set; }
        public int? Width { get; set; }
        public int? Height { get; set; }
        public bool IsActive { get; set; }
        public DateTime CreateDate { get; set; }
        public DateTime? LastModify { get; set; }

        // Không include navigation properties để tránh circular reference
    }
}
