using Identity.Web.Entities;
using Identity.Web.Models;
using Identity.Web.SendGrid;
using Identity.Web.Services.TwoFactor;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace Identity.Web.Controllers
{
    public class TwoAuthController : Controller
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly TwoFactorService _twoFactorService;
        private readonly SignInManager<AppUser> _signInManager;
        private readonly CodeVerification _codeVerification;
        private readonly EmailSender _emailSender;

        public TwoAuthController(UserManager<AppUser> userManager, TwoFactorService twoFactorService, SignInManager<AppUser> signInManager, CodeVerification codeVerification, EmailSender emailSender)
        {
            _userManager = userManager;
            _twoFactorService = twoFactorService;
            _signInManager = signInManager;
            _codeVerification = codeVerification;
            _emailSender = emailSender;
        }

        public async Task<IActionResult> TwoFactorAuth()
        {
            var user = await _userManager.FindByNameAsync(User.Identity.Name);

            return View(new AuthViewModel() { TwoFactorAuth = user.TwoFactorAuth });
        }

        [HttpPost]
        public async Task<IActionResult> TwoFactorAuth(AuthViewModel model)
        {
            var user = await _userManager.FindByNameAsync(User.Identity.Name);

            if (model.TwoFactorAuth != Entities.TwoFactorAuth.None)
            {
                if (model.TwoFactorAuth == Entities.TwoFactorAuth.GoogleAnMicrosoft)
                {
                    user.TwoFactorEnabled = true;
                    user.TwoFactorAuth = model.TwoFactorAuth;

                    await _userManager.UpdateAsync(user);

                    return RedirectToAction("TwoFactorAuthenticator");
                }

                if (model.TwoFactorAuth == Entities.TwoFactorAuth.Email)
                {
                    user.TwoFactorEnabled = true;
                    user.TwoFactorAuth = model.TwoFactorAuth;

                    await _userManager.UpdateAsync(user);

                    return RedirectToAction("TwoFactorAuthenticator");
                }

                if (model.TwoFactorAuth == Entities.TwoFactorAuth.Telephone)
                {
                    user.TwoFactorEnabled = true;
                    user.TwoFactorAuth = model.TwoFactorAuth;

                    await _userManager.UpdateAsync(user);

                    return RedirectToAction("TwoFactorAuthenticator");
                }

            }

            else
            {
                user.TwoFactorEnabled = false;
            }

            return RedirectToAction("MyProfile", "User");
        }

        public async Task<IActionResult> TwoFactorAuthenticator()
        {
            var user = await _userManager.FindByNameAsync(User.Identity.Name);

            var key = await _userManager.GetAuthenticatorKeyAsync(user);

            if (string.IsNullOrEmpty(key) || string.IsNullOrWhiteSpace(key))
            {
                await _userManager.ResetAuthenticatorKeyAsync(user);

                key = await _userManager.GetAuthenticatorKeyAsync(user);
            }

            AuthViewModel model = new() { SharedKey = key, AuthenticationUri = _twoFactorService.GenerateQrCodeUri(user.Email, key) };

            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> TwoFactorAuthenticator(AuthViewModel model)
        {
            var user = await _userManager.FindByNameAsync(User.Identity.Name);

            var accessKey = model.AccessKey.Replace(" ", string.Empty).Replace("-", string.Empty);

            var validAccessKey = await _userManager.VerifyTwoFactorTokenAsync(user, _userManager.Options.Tokens.AuthenticatorTokenProvider, accessKey);

            if (validAccessKey)
            {
                user.TwoFactorEnabled = true;
                user.TwoFactorAuth = Entities.TwoFactorAuth.GoogleAnMicrosoft;

                var recoveryCodes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 5);

                TempData["recoveryCodes"] = recoveryCodes;

                return RedirectToAction("TwoFactorAuth");

            }

            return View(model);
        }

        public async Task<IActionResult> TwoFactorLogin()
        {
            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync(); // kullanıcının cookie bilgisinden Id yi alır

            TempData["UserId"] = user.Id;

            if (user.TwoFactorAuth == Entities.TwoFactorAuth.Email)
            {
                if (_codeVerification.TimeLeft(HttpContext) == 0)
                {
                    return RedirectToAction("Login", "User");
                }

                ViewBag.left = _codeVerification.TimeLeft(HttpContext);

                var code = _codeVerification.RandomCode();

                HttpContext.Session.SetString("codeVerifacetion", code.ToString());

                await _emailSender.SendEmail(user.Email, code.ToString());

            }

            if (user.TwoFactorAuth == Entities.TwoFactorAuth.Telephone)
            {
                if (_codeVerification.TimeLeft(HttpContext) == 0)
                {
                    return RedirectToAction("Login", "User");
                }

                ViewBag.left = _codeVerification.TimeLeft(HttpContext);

                var code = _codeVerification.RandomCode();

                HttpContext.Session.SetString("codeVerifacetion", code.ToString());

                //sms yolla

            }

            return View(new TwoFactorLoginModel() { TwoFactorAuth = user.TwoFactorAuth });
        }
        [HttpPost]

        public async Task<IActionResult> TwoFactorLogin(TwoFactorLoginModel model)
        {
            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync(); // kullanıcının cookie bilgisinden Id yi alır

            if (user.TwoFactorAuth == Entities.TwoFactorAuth.GoogleAnMicrosoft)
            {
                Microsoft.AspNetCore.Identity.SignInResult result = null;

                if (model.RecoverCode)
                {
                    result = await _signInManager.TwoFactorRecoveryCodeSignInAsync(model.AccessKey);
                }
                else
                {
                    result = await _signInManager.TwoFactorAuthenticatorSignInAsync(model.AccessKey, model.RememberMe, false);
                }

                if (result.Succeeded)
                {
                    return RedirectToAction("MyProfile", "User");
                }

            }

            else if (user.TwoFactorAuth == Entities.TwoFactorAuth.Email)
            {
                if (model.AccessKey == HttpContext.Session.GetString("codeVerifacetion"))
                {
                    await _signInManager.SignOutAsync();
                    await _signInManager.SignInAsync(user, model.RememberMe);

                    HttpContext.Session.Remove("time");
                    HttpContext.Session.Remove("codeVerifacetion");

                    return RedirectToAction("MyProfile", "User");
                }
            }

            else if (user.TwoFactorAuth == Entities.TwoFactorAuth.Telephone)
            {
                if (model.AccessKey == HttpContext.Session.GetString("codeVerifacetion"))
                {
                    await _signInManager.SignOutAsync();
                    await _signInManager.SignInAsync(user, model.RememberMe);

                    HttpContext.Session.Remove("time");
                    HttpContext.Session.Remove("codeVerifacetion");

                    return RedirectToAction("MyProfile", "User");
                }
            }

            return RedirectToAction("MyProfile", "User");
        }

        [HttpGet]
        public JsonResult AgainSendEmail()
        {
            var user = _signInManager.GetTwoFactorAuthenticationUserAsync().Result;

            var code = _codeVerification.RandomCode();

            HttpContext.Session.SetString("codeVerifacetion", code.ToString());

            _emailSender.SendEmail(user.Email, code.ToString()).Wait();
            return Json(true);

        }

    }
}
