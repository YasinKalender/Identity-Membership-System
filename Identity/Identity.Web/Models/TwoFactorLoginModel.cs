using Identity.Web.Entities;

namespace Identity.Web.Models
{
    public class TwoFactorLoginModel
    {
        public string AccessKey { get; set; }
        public bool RememberMe { get; set; }
        public bool RecoverCode { get; set; }
        public TwoFactorAuth TwoFactorAuth { get; set; }
    }
}
