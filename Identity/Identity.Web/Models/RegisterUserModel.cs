namespace Identity.Web.Models
{
    public class RegisterUserModel
    {
        public string Email { get; set; }
        public string Username { get; set; }
        public string City { get; set; }
        public string Password { get; set; }
        public DateTime BirthDay { get; set; }
        public string PhoneNumber { get; set; }
        public bool Gender { get; set; }
    }
}
