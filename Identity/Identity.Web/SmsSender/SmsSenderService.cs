using Identity.Web.SendGrid;
using Microsoft.Extensions.Options;

namespace Identity.Web.SmsSender
{
    public class SmsSenderService
    {
        private readonly CodeVerification _codeVerification;
        private readonly SmsProviderOptions _twoFactor;

        public SmsSenderService(CodeVerification codeVerification, IOptions<SmsProviderOptions> options)
        {
            _codeVerification = codeVerification;
            _twoFactor = options.Value;
        }

        public string Send(string phone, string code)
        {

            return null;
        }
    }
}
