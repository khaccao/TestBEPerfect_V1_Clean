// Domain/Entities/Area.cs
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace PerfectKeyV1.Domain.Entities
{
    [Table("Areas")]
    public class Area
    {
        [Key]
        [Column("Id")]
        public int Id { get; set; }

        [Column("Guid")]
        public Guid Guid { get; set; } = Guid.NewGuid();

        // Parent Mapping
        [Column("Parent")]
        public int? ParentId { get; set; }

        [Column("ParentGuid")]
        public Guid? ParentGuid { get; set; }

        [Column("HotelId")]
        public int HotelId { get; set; }

        [Column("HotelGuid")]
        public Guid HotelGuid { get; set; }

        [Column("HotelCode")]
        [MaxLength(50)]
        public string HotelCode { get; set; } = string.Empty;

        [Column("AreaCode")]
        [MaxLength(50)]
        public string? AreaCode { get; set; }

        [Column("AreaName")]
        [MaxLength(200)]
        public string AreaName { get; set; } = string.Empty;

        [Column("AreaType")]
        [MaxLength(50)]
        public string? AreaType { get; set; }

        [Column("AreaTypeGuid")]
        public Guid? AreaTypeGuid { get; set; }

        [Column("AreaAlias")]
        [MaxLength(500)]
        public string? AreaAlias { get; set; }

        [Column("AreaDescription")]
        [MaxLength(500)]
        public string? AreaDescription { get; set; }

        [Column("AreaAvatar")]
        [MaxLength(500)]
        public string? AreaAvatar { get; set; }

        [Column("Color")]
        [MaxLength(20)]
        public string? Color { get; set; }

        // Vị trí & kích thước
        [Column("PositionX")]
        public int? PositionX { get; set; }

        [Column("PositionY")]
        public int? PositionY { get; set; }

        [Column("Width")]
        public int? Width { get; set; }

        [Column("Height")]
        public int? Height { get; set; }

        [Column("IsActive")]
        public bool IsActive { get; set; } = true;

        // SỬA: Đổi tên column cho khớp với database
        [Column("CreateDate")]
        public DateTime CreateDate { get; set; } = DateTime.UtcNow;

        [Column("LastModify")]
        public DateTime? LastModify { get; set; }

        // Navigation properties
        [ForeignKey("ParentId")]
        public virtual Area? Parent { get; set; }

        public virtual ICollection<Area> Children { get; set; } = new List<Area>();

        [ForeignKey("HotelId")]
        public virtual Hotel Hotel { get; set; } = null!;

        [ForeignKey("AreaTypeGuid")]
        public virtual AreaType? AreaTypeNavigation { get; set; }

        public virtual ICollection<Element> Elements { get; set; } = new List<Element>();
    }
}