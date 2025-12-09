// Infrastructure/ServiceCollectionExtensions.cs
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using PerfectKeyV1.Application.Interfaces;
using PerfectKeyV1.Application.Services;
using PerfectKeyV1.Infrastructure.Persistence;
using PerfectKeyV1.Infrastructure.Persistence.Repositories;

namespace PerfectKeyV1.Infrastructure
{
    public static class ServiceCollectionExtensions
    {
        public static IServiceCollection AddInfrastructure(this IServiceCollection services, IConfiguration configuration)
        {
            // Đảm bảo configuration không null
            if (configuration == null)
                throw new ArgumentNullException(nameof(configuration));

            // Database
            var defaultConnection = configuration.GetConnectionString("DefaultConnection")
                ?? "Server=.;Database=PerfectKey;Trusted_Connection=true;TrustServerCertificate=true;";

            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(defaultConnection));

            // Redis Cache với fallback
            var redisConnection = configuration.GetConnectionString("Redis");
            if (!string.IsNullOrEmpty(redisConnection))
            {
                try
                {
                    services.AddStackExchangeRedisCache(options =>
                    {
                        options.Configuration = redisConnection;
                        options.InstanceName = "PerfectKey_";
                    });
                    Console.WriteLine("Redis cache registered successfully");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Redis cache failed, using memory cache: {ex.Message}");
                    services.AddDistributedMemoryCache();
                }
            }
            else
            {
                Console.WriteLine("No Redis connection string, using memory cache");
                services.AddDistributedMemoryCache();
            }

            // HttpContext Accessor
            services.AddHttpContextAccessor();

            // REPOSITORIES
            services.AddScoped<IUserRepository, UserRepository>();
            services.AddScoped<IHotelRepository, HotelRepository>();
            services.AddScoped<IUserHotelRepository, UserHotelRepository>();
            services.AddScoped<ILoginSessionRepository, LoginSessionRepository>();
            services.AddScoped<ILayoutRepository, LayoutRepository>();
            services.AddScoped<IAreaTypeRepository, AreaTypeRepository>();

            // SERVICES
            services.AddScoped<IUserService, UserService>();
            services.AddScoped<ILayoutService, LayoutService>();
            services.AddScoped<IAuthService, AuthService>();
            services.AddScoped<ILoginSessionService, LoginSessionService>();
            services.AddScoped<IJwtService, JwtService>();
            services.AddScoped<ITwoFactorService, TwoFactorService>();
            services.AddScoped<IAreaTypeService, AreaTypeService>();

            return services;
        }
    }
}