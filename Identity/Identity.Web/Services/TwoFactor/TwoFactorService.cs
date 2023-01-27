using System.Text.Encodings.Web;

namespace Identity.Web.Services.TwoFactor
{
    public class TwoFactorService
    {
        private readonly UrlEncoder _urlEncoder;
        public TwoFactorService(UrlEncoder urlEncoder)
        {
            _urlEncoder = urlEncoder;
        }

        public string GenerateQrCodeUri(string email, string key)
        {
            const string format = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";

            return string.Format(format, _urlEncoder.Encode("localhost:44378"), _urlEncoder.Encode(email), key);
        }
    }
}
