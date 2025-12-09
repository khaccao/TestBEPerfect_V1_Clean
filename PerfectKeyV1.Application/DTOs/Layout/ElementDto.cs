using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PerfectKeyV1.Application.DTOs.Layout
{
    public class ElementDto
    {
        public int Id { get; set; }
        public Guid Guid { get; set; }
        public Guid AreaGuid { get; set; }
        public Guid HotelGuid { get; set; }
        public string HotelCode { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string Type { get; set; } = string.Empty;
        public string? Alias { get; set; }
        public int? Capacity { get; set; }
        public string? Description { get; set; }
        public double PositionX { get; set; }
        public double PositionY { get; set; }
        public double? Width { get; set; }
        public double? Height { get; set; }
        public double? Rotation { get; set; }
        public string? Color { get; set; }
        public string? Icon { get; set; }
        public string? GroupElements { get; set; }
        public Guid? GroupElementsGuid { get; set; }
        public Guid? DockGuid { get; set; }
        public string? Settings { get; set; }
        public bool IsActive { get; set; }
        public bool IsOccupied { get; set; }
        public DateTime CreateDate { get; set; }
        public DateTime? LastModify { get; set; }

        // Simple area info để tránh circular reference
        public AreaSimpleDto? Area { get; set; }
    }

    public class AreaSimpleDto
    {
        public Guid Guid { get; set; }
        public string AreaName { get; set; } = string.Empty;
        public string AreaCode { get; set; } = string.Empty;
        public string? AreaType { get; set; }
        public Guid? ParentGuid { get; set; }
    }
}
