using Microsoft.AspNetCore.Identity;

namespace Identity.Web.Entities
{
    public class AppUser : IdentityUser
    {
        public string? City { get; set; }
        public string? Picture { get; set; }
        public DateTime? BirthDay { get; set; }
        public bool? Gender { get; set; }
        public TwoFactorAuth TwoFactorAuth { get; set; }
    }
}
