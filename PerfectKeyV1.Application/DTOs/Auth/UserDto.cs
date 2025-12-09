using System;

namespace PerfectKeyV1.Application.DTOs.Auth
{
    public class UserDto
    {
        public int Id { get; set; }
        public Guid Guid { get; set; }
        public string UserName { get; set; } = string.Empty;
        public string FullName { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public int Status { get; set; }
        public int? UserType { get; set; }
        public int TwoFactorEnabled { get; set; }
        public DateTime CreateDate { get; set; }
        public DateTime? LastModify { get; set; }
    }
}