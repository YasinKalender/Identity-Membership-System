using Microsoft.Extensions.Options;

namespace Identity.Web.SendGrid
{
    public class CodeVerification
    {
        private readonly TwoFactorOptions _twoFactorOptions;

        public CodeVerification(IOptions<TwoFactorOptions> options)
        {
            _twoFactorOptions = options.Value;
        }

        public int RandomCode()
        {
            var random = new Random();

            return random.Next(1, 9999);
        }

        public int TimeLeft(HttpContext httpContext)
        {
            if (httpContext.Session.GetString("time") == null)
            {
                httpContext.Session.SetString("time", DateTime.Now.AddSeconds(_twoFactorOptions.Time).ToString());
            }

            var currenTime = DateTime.Parse(httpContext.Session.GetString("time").ToString());

            int timeLeft = (int)(currenTime - DateTime.Now).TotalSeconds;

            if (timeLeft <= 0)
            {
                httpContext.Session.Remove("time");
                return 0;
            }
            else
            {
                return timeLeft;
            }


        }

    }
}
