//using Microsoft.Extensions.Configuration;
//using Microsoft.Extensions.Caching.Distributed;

//namespace PerfectKeyV1.Application.Common
//{
//    public interface ITenantConnectionHelper
//    {
//        string GetConnectionString(string hotelCode);
//        string GetRedisConnectionString();
//        Task<string> GetCachedConnectionStringAsync(string hotelCode);
//        Task<string> GetHotelDatabaseNameAsync(string hotelCode);
//    }

//    public class TenantConnectionHelper : ITenantConnectionHelper
//    {
//        private readonly IDistributedCache _cache;
//        private readonly IConfiguration _configuration;

//        public TenantConnectionHelper(IConfiguration configuration, IDistributedCache cache)
//        {
//            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
//            _cache = cache ?? throw new ArgumentNullException(nameof(cache));
//        }

//        public string GetConnectionString(string hotelCode)
//        {
//            if (string.IsNullOrEmpty(hotelCode))
//                throw new ArgumentException("Hotel code cannot be null or empty", nameof(hotelCode));

//            // ĐƠN GIẢN: Luôn trả về connection string mặc định
//            var baseConnection = _configuration.GetConnectionString("DefaultConnection");
//            if (string.IsNullOrEmpty(baseConnection))
//                throw new InvalidOperationException("DefaultConnection string is not configured");

//            return baseConnection;
//        }

//        public async Task<string> GetCachedConnectionStringAsync(string hotelCode)
//        {
//            // ĐƠN GIẢN: Trả về connection string không cache
//            return await Task.FromResult(GetConnectionString(hotelCode));
//        }

//        public string GetRedisConnectionString()
//        {
//            var redisConnection = _configuration.GetConnectionString("Redis");
//            return redisConnection ?? throw new InvalidOperationException("Redis connection string is not configured");
//        }

//        public async Task<string> GetHotelDatabaseNameAsync(string hotelCode)
//        {
//            // ĐƠN GIẢN: Trả về database name mặc định
//            return await Task.FromResult("PerfectKeyDB");
//        }
//    }
//}