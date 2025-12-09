// Domain/Entities/AreaType.cs
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace PerfectKeyV1.Domain.Entities
{
    [Table("AreaType")]
    public class AreaType
    {
        [Key]
        [Column("Id")]
        public int Id { get; set; }

        [Column("Guid")]
        public Guid Guid { get; set; } = Guid.NewGuid();

        [Column("HotelCode")]
        [MaxLength(50)]
        public string HotelCode { get; set; } = string.Empty;

        [Column("HotelGuid")]
        public Guid HotelGuid { get; set; }

        [Column("GroupCode")]
        [MaxLength(50)]
        public string? GroupCode { get; set; }

        [Column("Code")]
        [MaxLength(50)]
        public string Code { get; set; } = string.Empty;

        [Column("Name")]
        [MaxLength(200)]
        public string Name { get; set; } = string.Empty;

        [Column("Descriptions")]
        [MaxLength(500)]
        public string? Descriptions { get; set; }

        // Navigation properties
        public virtual ICollection<Area> Areas { get; set; } = new List<Area>();
    }
}