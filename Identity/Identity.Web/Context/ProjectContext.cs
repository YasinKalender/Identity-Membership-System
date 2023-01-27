using Identity.Web.Entities;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Identity.Web.Context
{
    public class ProjectContext : IdentityDbContext<AppUser, AppRole, string>
    {
        public ProjectContext(DbContextOptions<ProjectContext> dbContextOptions) : base(dbContextOptions) { }

    }
}
