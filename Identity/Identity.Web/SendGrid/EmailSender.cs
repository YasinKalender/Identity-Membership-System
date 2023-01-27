using Microsoft.Extensions.Options;
using SendGrid.Helpers.Mail;
using SendGrid;
using Identity.Web.Services.EmailSettings;
using System.Net.Mail;
using System.Net;

namespace Identity.Web.SendGrid
{
    public class EmailSender
    {
        private readonly CodeVerification _codeVerification;
        private readonly TwoFactorOptions _twoFactor;
        private readonly EmailSettingModel _emailSettingModel;

        public EmailSender(CodeVerification codeVerification, IOptions<TwoFactorOptions> options, IOptions<EmailSettingModel> settings)
        {
            _codeVerification = codeVerification;
            _twoFactor = options.Value;
            _emailSettingModel = settings.Value;
        }

        public async Task SendEmail(string email, string code)
        {
            //var apiKey = _twoFactor.Key;
            //var client = new SendGridClient(apiKey);
            //var from = new EmailAddress("ysnkalender@gmail.com", "Developer User");
            //var subject = "Two Authentication Verify";
            //var to = new EmailAddress(email);

            ////var plainTextContent = "and easy to do anywhere, even with C#";

            //var htmlContent = $"<h2>Doğrulama kodu</h2><br/><h3>Kodunuz:{code}</h3>";
            //var msg = MailHelper.CreateSingleEmail(from, to, subject, null, htmlContent);
            //var response = await client.SendEmailAsync(msg);


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

            mailMessage.Subject = "Two Authentication Verify";
            mailMessage.Body =
                $"<h2>Doğrulama kodu</h2><br/><h3>Kodunuz:{code}</h3>";

            mailMessage.IsBodyHtml = true;

            await smptClient.SendMailAsync(mailMessage);
        }
    }
}
