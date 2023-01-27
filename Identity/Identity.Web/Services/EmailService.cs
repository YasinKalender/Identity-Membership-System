using Identity.Web.Services.EmailSettings;
using Microsoft.Extensions.Options;
using System.Net;
using System.Net.Mail;

namespace Identity.Web.Services
{
    public class EmailService : IEmailService
    {
        private readonly EmailSettingModel _emailSettingModel;

        public EmailService(IOptions<EmailSettingModel> settings)
        {
            _emailSettingModel = settings.Value;
        }

        public async Task SendResetEmail(string email, string emailLink)
        {
            var smptClient = new SmtpClient();

            smptClient.Host = _emailSettingModel.Host;
            smptClient.DeliveryMethod = SmtpDeliveryMethod.Network;
            smptClient.UseDefaultCredentials = false;
            smptClient.Port = 587;
            smptClient.Credentials = new NetworkCredential(_emailSettingModel.Email, _emailSettingModel.Password);
            smptClient.EnableSsl = true;

            var mailMessage = new MailMessage();

            mailMessage.From = new MailAddress(_emailSettingModel.Email);
            mailMessage.To.Add(email);

            mailMessage.Subject = "Şifre Sıfırlama Linki";
            mailMessage.Body =
                @$"<h4>Şifrenizi yenilemek için linke tıklayanız..</h4>
                <p><a href='{emailLink}'>Şifre Yenileme linki</a></p>";

            mailMessage.IsBodyHtml = true;

            await smptClient.SendMailAsync(mailMessage);
        }
    }
}
