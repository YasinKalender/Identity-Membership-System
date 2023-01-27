namespace Identity.Web.Models
{
    public class PasswordChangeModel
    {
        public string OldPassword { get; set; }

        public string NewPassword { get; set; }
        public string NewPasswordConfirm { get; set; }
    }
}
