namespace Identity.Web.Services
{
    public interface IEmailService
    {
        Task SendResetEmail(string email,string emailLink);
    }
}
