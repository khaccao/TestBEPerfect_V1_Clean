using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace PerfectKeyV1.Domain.Entities
{
    [Table("DATA_KhachSan")]
    public class Hotel
    {
        [Key]
        [Column("ID")]
        public int Id { get; set; }

        [Column("GUID")]
        public Guid Guid { get; set; } = Guid.NewGuid();

        [Column("Parent")]
        public int? ParentId { get; set; }

        [Column("ParentGUID")]
        public Guid? ParentGuid { get; set; }

        [Column("Sequency")]
        public int? Sequency { get; set; }

        [Column("Ma")]
        [MaxLength(50)]
        public string Code { get; set; } = string.Empty;

        [Column("HotelName")]
        [MaxLength(200)]
        public string HotelName { get; set; } = string.Empty;

        [Column("GhiChu")]
        [MaxLength(500)]
        public string? Note { get; set; }

        [Column("DBName")]
        [MaxLength(100)]
        public string? DBName { get; set; }

        [Column("IPAddress")]
        [MaxLength(200)]
        public string? IPAddress { get; set; }

        [Column("ISS_DBName")]
        [MaxLength(50)]
        public string? ISS_DBName { get; set; }

        [Column("ISS_IPAddress")]
        [MaxLength(500)]
        public string? ISS_IPAddress { get; set; }

        [Column("PKMTablet")]
        [MaxLength(50)]
        public string? PKMTablet { get; set; }

        [Column("IP_VPN_FO")]
        [MaxLength(100)]
        public string? IP_VPN_FO { get; set; }

        [Column("IP_VPN_ISS")]
        [MaxLength(100)]
        public string? IP_VPN_ISS { get; set; }

        [Column("IPLAN_Server")]
        [MaxLength(100)]
        public string? IPLAN_Server { get; set; }

        [Column("Email")]
        [MaxLength(500)]
        public string? Email { get; set; }

        [Column("IsDeleted")]
        public bool IsDeleted { get; set; }

        [Column("IsAutoUpdateOTA")]
        public int? IsAutoUpdateOTA { get; set; }

        [Column("OTATimesAuto")]
        [MaxLength(20)]
        public string? OTATimesAuto { get; set; }

        [Column("HotelAvatarUrl")]
        [MaxLength(500)]
        public string? HotelAvatarUrl { get; set; }

        [Column("NgayBatDau")]
        public DateTime? StartDate { get; set; }

        [Column("NgayKetThuc")]
        public DateTime? EndDate { get; set; }

        [Column("UserID")]
        public Guid? UserGuid { get; set; }

        [Column("AutoID")]
        public int AutoId { get; set; }

        [Column("CreateDate")]
        public DateTime CreateDate { get; set; } = DateTime.UtcNow;

        // Navigation properties
        [ForeignKey("ParentId")]
        public virtual Hotel? Parent { get; set; }

        public virtual ICollection<Hotel> Children { get; set; } = new List<Hotel>();

        public virtual ICollection<UserHotel> UserHotels { get; set; } = new List<UserHotel>();
        public virtual ICollection<Area> Areas { get; set; } = new List<Area>();
    }
}
