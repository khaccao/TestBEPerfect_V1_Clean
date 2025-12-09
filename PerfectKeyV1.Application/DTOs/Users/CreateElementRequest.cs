using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PerfectKeyV1.Application.DTOs.Users
{
    public class CreateElementRequest
    {
        public Guid AreaGuid { get; set; }
        public string Name { get; set; } = string.Empty;
        public string Type { get; set; } = string.Empty;
        public string? Alias { get; set; }
        public int? Capacity { get; set; }
        public string? Description { get; set; }
        public int? PositionX { get; set; } // DTO có thể nullable
        public int? PositionY { get; set; } // DTO có thể nullable
        public int? Width { get; set; }
        public int? Height { get; set; }
        public int? Rotation { get; set; } // DTO có thể nullable
        public string? Color { get; set; }
        public string? Icon { get; set; }
        public string? GroupElements { get; set; }
        public Guid? GroupElementsGuid { get; set; }
        public Guid? DockGuid { get; set; }
        public string? Settings { get; set; }
    }
}
