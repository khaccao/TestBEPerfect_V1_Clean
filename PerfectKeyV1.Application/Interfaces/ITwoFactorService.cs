using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PerfectKeyV1.Application.DTOs.Auth;
namespace PerfectKeyV1.Application.Interfaces
{
    public interface ITwoFactorService
    {
        TwoFactorSetupResponse GenerateSetupCode(string email, string? secretKey = null);
        bool ValidateTwoFactorCode(string secretKey, string code);
        string GenerateSecretKey();
        List<string> GenerateRecoveryCodes(int count = 8);
        bool ValidateRecoveryCode(List<string> recoveryCodes, string code);
        string GenerateQrCodeUrl(string appName, string email, string secretKey);
        string GenerateManualEntryKey(string secretKey);
        bool IsValidSecretKey(string secretKey);
    }
}
