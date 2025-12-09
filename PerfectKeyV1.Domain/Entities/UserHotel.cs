using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace PerfectKeyV1.Domain.Entities
{
    [Table("DATA_User_Hotels")]
    public class UserHotel
    {
        [Key]
        [Column("ID")]
        public int Id { get; set; }

        [Column("Guid")]
        public Guid Guid { get; set; } = Guid.NewGuid();

        [Column("UserID")]
        public int UserId { get; set; }

        [Column("UserGuid")]
        public Guid UserGuid { get; set; }

        [Column("HotelCode")]
        public string HotelCode { get; set; } = string.Empty;

        [Column("HotelGUID")]
        public Guid HotelGuid { get; set; }

        [Column("Comments")]
        public string? Comments { get; set; }

        [Column("UserFO")]
        public string? UserFO { get; set; }

        [Column("UserBO")]
        public string? UserBO { get; set; }

        [Column("UserPOS")]
        public string? UserPOS { get; set; }

        [Column("UserERP")]
        public string? UserERP { get; set; }

        [Column("UserHR")]
        public string? UserHR { get; set; }

        [Column("ValidDate")]
        public DateTime? ValidDate { get; set; }

        [Column("Status")]
        public int Status { get; set; } = 1;

        [Column("CreateDate")]
        public DateTime CreateDate { get; set; } = DateTime.UtcNow;

        [Column("LastModify")]
        public DateTime? LastModify { get; set; }

        [Column("UserCreatedGuid")]
        public Guid? UserCreatedGuid { get; set; }

        // Navigation properties
        [ForeignKey("UserId")]
        public virtual User User { get; set; } = null!;

        [ForeignKey("HotelGuid")]
        public virtual Hotel Hotel { get; set; } = null!;
    }
}
