using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PerfectKeyV1.Application.DTOs.Auth
{
    public class TwoFactorSetupResponse
    {
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
        public string? SecretKey { get; set; }
        public string? QrCodeImageUrl { get; set; }
        public List<string>? RecoveryCodes { get; set; }
    }
}
