using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace PerfectKeyV1.Domain.Entities
{
    [Table("Elements")]
    public class Element
    {
        [Key]
        [Column("Id")]
        public int Id { get; set; }

        [Column("Guid")]
        public Guid Guid { get; set; } = Guid.NewGuid();

        [Column("GroupElements")]
        [MaxLength(50)]
        public string? GroupElements { get; set; }

        [Column("GroupElementsGuid")]
        public Guid? GroupElementsGuid { get; set; }

        [Column("DockGuid")]
        public Guid? DockGuid { get; set; }

        [Column("HotelCode")]
        [MaxLength(50)]
        public string HotelCode { get; set; } = string.Empty;

        [Column("HotelGuid")]
        public Guid HotelGuid { get; set; }

        [Column("AreaId")]
        public int AreaId { get; set; }

        [Column("AreaGuid")]
        public Guid AreaGuid { get; set; }

        [Column("Name")]
        [MaxLength(200)]
        [Required]
        public string Name { get; set; } = string.Empty;

        [Column("Alias")]
        [MaxLength(200)]
        public string? Alias { get; set; }

        [Column("Type")]
        [MaxLength(50)]
        [Required]
        public string Type { get; set; } = string.Empty; // POS, ROOM, etc.

        [Column("Capacity")]
        public int? Capacity { get; set; }

        [Column("Description")]
        [MaxLength(500)]
        public string? Description { get; set; }

        [Column("PositionX")]
        public int PositionX { get; set; }

        [Column("PositionY")]
        public int PositionY { get; set; }

        [Column("Width")]
        public int? Width { get; set; }

        [Column("Height")]
        public int? Height { get; set; }

        [Column("Rotation")]
        public int Rotation { get; set; }

        [Column("Color")]
        [MaxLength(20)]
        public string? Color { get; set; }

        [Column("Icon")]
        [MaxLength(10)]
        public string? Icon { get; set; }

        [Column("IsActive")]
        public bool IsActive { get; set; } = true;

        [Column("IsOccupied")]
        public bool IsOccupied { get; set; }

        [Column("Settings")]
        public string? Settings { get; set; }

        [Column("CreateDate")]
        public DateTime CreateDate { get; set; } = DateTime.UtcNow;

        [Column("LastModify")]
        public DateTime? LastModify { get; set; }

        // Navigation properties
        [ForeignKey("AreaId")]
        public virtual Area Area { get; set; } = null!;
    }
}
