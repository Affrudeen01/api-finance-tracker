using Auth.Core.Entities;
using Microsoft.EntityFrameworkCore;

namespace Auth.Infrastructure.Data;

public class ApplicationDbContext : DbContext
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
    {
    }

    public DbSet<User> Users { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<User>(entity =>
        {
            entity.HasKey(u => u.UserId);
            entity.Property(u => u.Username).IsRequired().HasMaxLength(20);
            entity.HasIndex(u => u.Username).IsUnique();
            entity.Property(u => u.PasswordHash).IsRequired();
            entity.Property(u => u.CreatedAt).IsRequired().HasDefaultValueSql("CURRENT_TIMESTAMP"); 
            entity.Property(u => u.LastLoginAt).IsRequired(false);
            entity.Property(u => u.RefreshToken).IsRequired(false);
               
        });
    }
}