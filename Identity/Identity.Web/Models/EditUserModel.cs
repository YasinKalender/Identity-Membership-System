namespace Identity.Web.Models
{
    public class EditUserModel
    {
        public string Email { get; set; }
        public string Username { get; set; }
        public string City { get; set; }
        public string PhoneNumber { get; set; }
        public IFormFile Picture { get; set; }
        public DateTime BirthDay { get; set; }
        public bool Gender { get; set; }
    }
}
