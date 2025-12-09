// Infrastructure/Persistence/ApplicationDbContext.cs
using PerfectKeyV1.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace PerfectKeyV1.Infrastructure.Persistence
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
        {
        }

        public DbSet<User> Users { get; set; }
        public DbSet<Hotel> Hotels { get; set; }
        public DbSet<UserHotel> UserHotels { get; set; }
        public DbSet<Area> Areas { get; set; }
        public DbSet<AreaType> AreaTypes { get; set; }
        public DbSet<Element> Elements { get; set; }
        public DbSet<LoginSession> LoginSessions { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // User configuration
            modelBuilder.Entity<User>(entity =>
            {
                entity.ToTable("DATA_Users");
                entity.HasKey(e => e.Id);

                // User -> UserHotels (dùng Guid)
                entity.HasMany(e => e.UserHotels)
                      .WithOne(e => e.User)
                      .HasForeignKey(e => e.UserGuid)
                      .HasPrincipalKey(e => e.Guid);

                // User -> LoginSessions (giữ nguyên Id)
                entity.HasMany(e => e.LoginSessions)
                      .WithOne(e => e.User)
                      .HasForeignKey(e => e.UserId);
            });

            // Hotel configuration
            modelBuilder.Entity<Hotel>(entity =>
            {
                entity.ToTable("DATA_KhachSan");
                entity.HasKey(e => e.Id);

                // Hotel -> UserHotels (dùng Guid)
                entity.HasMany(e => e.UserHotels)
                      .WithOne(e => e.Hotel)
                      .HasForeignKey(e => e.HotelGuid)
                      .HasPrincipalKey(e => e.Guid);

                // Hotel -> Areas (dùng Guid)
                entity.HasMany(e => e.Areas)
                      .WithOne(e => e.Hotel)
                      .HasForeignKey(e => e.HotelGuid)
                      .HasPrincipalKey(e => e.Guid);

                // Hotel self-referencing (dùng Guid)
                entity.HasOne(e => e.Parent)
                      .WithMany(e => e.Children)
                      .HasForeignKey(e => e.ParentGuid)
                      .HasPrincipalKey(e => e.Guid)
                      .OnDelete(DeleteBehavior.Restrict);
            });

            // AreaType configuration
            modelBuilder.Entity<AreaType>(entity =>
            {
                entity.ToTable("AreaType");
                entity.HasKey(e => e.Id);
                entity.HasIndex(e => new { e.Code, e.HotelGuid }).IsUnique();

                // AreaType -> Areas relationship
                entity.HasMany(e => e.Areas)
                      .WithOne(e => e.AreaTypeNavigation)
                      .HasForeignKey(e => e.AreaTypeGuid)
                      .HasPrincipalKey(e => e.Guid)
                      .OnDelete(DeleteBehavior.Restrict);
            });

            // Area configuration
            modelBuilder.Entity<Area>(entity =>
            {
                entity.HasKey(e => e.Id);

                // Area self-referencing (dùng Guid)
                entity.HasOne(e => e.Parent)
                      .WithMany(e => e.Children)
                      .HasForeignKey(e => e.ParentGuid)
                      .HasPrincipalKey(e => e.Guid)
                      .OnDelete(DeleteBehavior.Restrict);

                // Area -> Hotel (dùng Guid)
                entity.HasOne(e => e.Hotel)
                      .WithMany(e => e.Areas)
                      .HasForeignKey(e => e.HotelGuid)
                      .HasPrincipalKey(e => e.Guid)
                      .OnDelete(DeleteBehavior.Cascade);

                // Area -> AreaType (dùng Guid)
                entity.HasOne(e => e.AreaTypeNavigation)
                      .WithMany(e => e.Areas)
                      .HasForeignKey(e => e.AreaTypeGuid)
                      .HasPrincipalKey(e => e.Guid)
                      .OnDelete(DeleteBehavior.Restrict);

                // Area -> Elements (dùng Guid)
                entity.HasMany(e => e.Elements)
                      .WithOne(e => e.Area)
                      .HasForeignKey(e => e.AreaGuid)
                      .HasPrincipalKey(e => e.Guid);
            });

            // Element configuration
            modelBuilder.Entity<Element>(entity =>
            {
                entity.HasKey(e => e.Id);

                // Element -> Area (dùng Guid)
                entity.HasOne(e => e.Area)
                      .WithMany(e => e.Elements)
                      .HasForeignKey(e => e.AreaGuid)
                      .HasPrincipalKey(e => e.Guid)
                      .OnDelete(DeleteBehavior.Cascade);
            });

            // UserHotel configuration
            modelBuilder.Entity<UserHotel>(entity =>
            {
                entity.ToTable("DATA_User_Hotels");
                entity.HasKey(e => e.Id);

                // Unique constraint dùng Guid
                entity.HasIndex(e => new { e.UserGuid, e.HotelGuid }).IsUnique();
                entity.HasIndex(e => e.HotelGuid);
            });

            // LoginSession configuration
            modelBuilder.Entity<LoginSession>(entity =>
            {
                entity.ToTable("LoginSessions");
                entity.HasKey(e => e.Id);
                entity.HasIndex(e => e.Token).IsUnique();
                entity.HasIndex(e => e.RefreshToken).IsUnique();
                entity.HasIndex(e => new { e.UserId, e.IsActive });
                entity.HasIndex(e => e.LastActivity);

                entity.Property(e => e.Token)
                      .IsRequired()
                      .HasMaxLength(500);

                entity.Property(e => e.RefreshToken)
                      .HasMaxLength(500);

                entity.Property(e => e.DeviceInfo)
                      .HasMaxLength(100);

                entity.Property(e => e.IpAddress)
                      .HasMaxLength(50);

                entity.Property(e => e.Location)
                      .HasMaxLength(200);
            });
        }
    }
}