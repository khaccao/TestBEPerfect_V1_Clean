using PerfectKeyV1.Application.DTOs.Auth;
using PerfectKeyV1.Application.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
namespace PerfectKeyV1.Application.Services
{
    public class TwoFactorService : ITwoFactorService
    {
        private readonly string _appName;

        public TwoFactorService(IConfiguration configuration)
        {
            _appName = configuration["App:Name"] ?? "PerfectKey-BE";
        }

        public TwoFactorSetupResponse GenerateSetupCode(string email, string? secretKey = null)
        {
            secretKey ??= GenerateSecretKey();
            var qrCodeUrl = GenerateQrCodeUrl(_appName, email, secretKey);

            return new TwoFactorSetupResponse
            {
                Success = true,
                Message = "2FA setup code generated successfully",
                SecretKey = secretKey,
                QrCodeImageUrl = qrCodeUrl
            };
        }

        public bool ValidateTwoFactorCode(string secretKey, string code)
        {
            if (string.IsNullOrEmpty(secretKey) || string.IsNullOrEmpty(code) || code.Length != 6)
                return false;

            try
            {
                var keyBytes = Base32Decode(secretKey);
                var currentTimeStep = GetCurrentTimeStepNumber();

                for (int i = -1; i <= 1; i++)
                {
                    var expectedCode = GenerateCode(keyBytes, currentTimeStep + i);
                    if (expectedCode == code)
                        return true;
                }
            }
            catch
            {
                return false;
            }

            return false;
        }

        public string GenerateSecretKey()
        {
            var key = new byte[20];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(key);
            }
            return Base32Encode(key);
        }

        public List<string> GenerateRecoveryCodes(int count = 8)
        {
            var codes = new List<string>();
            var random = new Random();

            for (int i = 0; i < count; i++)
            {
                var part1 = random.Next(1000000).ToString("000000");
                var part2 = random.Next(1000000).ToString("000000");
                var code = $"{part1}-{part2}";
                codes.Add(code);
            }

            return codes;
        }

        public bool ValidateRecoveryCode(List<string> recoveryCodes, string code)
        {
            return recoveryCodes?.Contains(code) == true;
        }

        public string GenerateQrCodeUrl(string appName, string email, string secretKey)
        {
            var encodedAppName = Uri.EscapeDataString(appName);
            var encodedEmail = Uri.EscapeDataString(email);
            return $"otpauth://totp/{encodedAppName}:{encodedEmail}?secret={secretKey}&issuer={encodedAppName}&algorithm=SHA1&digits=6&period=30";
        }

        public string GenerateManualEntryKey(string secretKey)
        {
            return secretKey;
        }

        public bool IsValidSecretKey(string secretKey)
        {
            if (string.IsNullOrEmpty(secretKey))
                return false;

            try
            {
                var decoded = Base32Decode(secretKey);
                return decoded.Length > 0;
            }
            catch
            {
                return false;
            }
        }

        #region Private Methods

        private string GenerateCode(byte[] keyBytes, long timeStepNumber)
        {
            var timeStepBytes = BitConverter.GetBytes(timeStepNumber);

            if (BitConverter.IsLittleEndian)
                Array.Reverse(timeStepBytes);

            using (var hmac = new HMACSHA1(keyBytes))
            {
                var hash = hmac.ComputeHash(timeStepBytes);
                var offset = hash[hash.Length - 1] & 0x0F;
                var binaryCode = ((hash[offset] & 0x7F) << 24) |
                                ((hash[offset + 1] & 0xFF) << 16) |
                                ((hash[offset + 2] & 0xFF) << 8) |
                                (hash[offset + 3] & 0xFF);

                var code = binaryCode % 1000000;
                return code.ToString("000000");
            }
        }

        private long GetCurrentTimeStepNumber()
        {
            var unixTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            return unixTime / 30;
        }

        private string Base32Encode(byte[] data)
        {
            const string base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            var result = new StringBuilder();
            var bits = 0;
            var bitsCount = 0;

            foreach (var b in data)
            {
                bits = (bits << 8) | b;
                bitsCount += 8;

                while (bitsCount >= 5)
                {
                    bitsCount -= 5;
                    var index = (bits >> bitsCount) & 31;
                    result.Append(base32Chars[index]);
                }
            }

            if (bitsCount > 0)
            {
                var index = (bits << (5 - bitsCount)) & 31;
                result.Append(base32Chars[index]);
            }

            return result.ToString();
        }

        private byte[] Base32Decode(string base32)
        {
            if (string.IsNullOrEmpty(base32))
                throw new ArgumentException("Base32 string cannot be null or empty");

            const string base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            base32 = base32.ToUpper().Replace(" ", "").Replace("-", "");

            foreach (var c in base32)
            {
                if (base32Chars.IndexOf(c) < 0)
                    throw new ArgumentException($"Invalid base32 character: '{c}'");
            }

            var bytes = new List<byte>();
            var bits = 0;
            var bitsCount = 0;

            foreach (var c in base32)
            {
                var value = base32Chars.IndexOf(c);
                bits = (bits << 5) | value;
                bitsCount += 5;

                if (bitsCount >= 8)
                {
                    bitsCount -= 8;
                    bytes.Add((byte)((bits >> bitsCount) & 0xFF));
                }
            }

            return bytes.ToArray();
        }

        #endregion
    }
}
