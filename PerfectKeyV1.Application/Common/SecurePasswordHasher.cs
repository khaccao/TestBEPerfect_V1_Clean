using BCrypt.Net;

namespace PerfectKeyV1.Application.Common
{
    public static class SecurePasswordHasher
    {
        // HashPassword sẽ tự động tạo ra một salt duy nhất
        public static string Hash(string password)
        {
            return BCrypt.Net.BCrypt.HashPassword(password, 12); // work factor = 12
        }

        // Verify sẽ tự động trích xuất salt từ chuỗi hash để so sánh
        public static bool Verify(string password, string hashedPassword)
        {
            return BCrypt.Net.BCrypt.Verify(password, hashedPassword);
        }
    }
}
