using Auth.Models;
using Microsoft.EntityFrameworkCore;

namespace Auth.Data
{
    public class AuthContext : DbContext
    {
        private readonly IConfiguration _configuration;
        public AuthContext(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        // Entity
        public DbSet<Account> Accounts { get; set; }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            optionsBuilder.UseSqlServer(
                _configuration.GetConnectionString("Default")
            );
        }

    }
}