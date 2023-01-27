using Identity.Web.Entities;

namespace Identity.Web.Models
{
    public class AuthViewModel
    {
        public string SharedKey { get; set; }
        public string AuthenticationUri { get; set; }
        public string AccessKey { get; set; }
        public TwoFactorAuth TwoFactorAuth { get; set; }
    }
}
