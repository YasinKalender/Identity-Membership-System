using Identity.Web.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace Identity.Web.Controllers
{
    public class SocailMediaController : Controller
    {
        private readonly SignInManager<AppUser> _signInManager;
        private readonly UserManager<AppUser> _userManager;

        public SocailMediaController(SignInManager<AppUser> signInManager, UserManager<AppUser> userManager)
        {
            _signInManager = signInManager;
            _userManager = userManager;
        }

        public IActionResult FacebookLogin(string ReturnUrl)
        {
            string redirectUrl = Url.Action("Response", "SocailMedia", new { ReturnUrl = ReturnUrl });

            var properties = _signInManager.ConfigureExternalAuthenticationProperties("Facebook", redirectUrl);

            return new ChallengeResult("Facebook", properties);   //içerisine ne alırsa kullanıcıyı oraya yönlendirir..
        }

        public IActionResult GoogleLogin(string ReturnUrl)
        {
            string redirectUrl = Url.Action("Response", "SocailMedia", new { ReturnUrl = ReturnUrl });

            var properties = _signInManager.ConfigureExternalAuthenticationProperties("Google", redirectUrl);

            return new ChallengeResult("Google", properties);   //içerisine ne alırsa kullanıcıyı oraya yönlendirir..
        }

        public IActionResult MicrosoftLogin(string ReturnUrl)
        {
            string redirectUrl = Url.Action("Response", "SocailMedia", new { ReturnUrl = ReturnUrl });

            var properties = _signInManager.ConfigureExternalAuthenticationProperties("Microsoft", redirectUrl);

            return new ChallengeResult("Microsoft", properties);   //içerisine ne alırsa kullanıcıyı oraya yönlendirir..
        }

        public async Task<IActionResult> Response(string ReturnUrl = "/")
        {
            ExternalLoginInfo externalLoginInfo = await _signInManager.GetExternalLoginInfoAsync(); // kullanıcının login olduğu bilgileri verir..

            if (externalLoginInfo == null)
                return RedirectToAction("Login");

            var result = await _signInManager.ExternalLoginSignInAsync(externalLoginInfo.LoginProvider, externalLoginInfo.ProviderKey, false);

            if (result.Succeeded)
            {
                return RedirectToAction("MyProfile", "User");
            }
            else
            {
                AppUser appUser = new();

                appUser.Email = externalLoginInfo.Principal.FindFirst(ClaimTypes.Email).Value;
                string userId = externalLoginInfo.Principal.FindFirst(ClaimTypes.NameIdentifier).Value;

                if (externalLoginInfo.Principal.HasClaim(i => i.Type == ClaimTypes.Name))
                {
                    string userName = externalLoginInfo.Principal.FindFirst(ClaimTypes.Name).Value;

                    userName = userName.Replace(' ', '-').ToLower() + userId.Substring(0, 5).ToString();

                    appUser.UserName = userName;
                }
                else
                {
                    appUser.UserName = externalLoginInfo.Principal.FindFirst(ClaimTypes.Email).Value;
                }

                var identityResult = await _userManager.CreateAsync(appUser);

                if (identityResult.Succeeded)
                {
                    var loginResult = await _userManager.AddLoginAsync(appUser, externalLoginInfo);

                    if (loginResult.Succeeded)
                    {
                        //await _signInManager.SignInAsync(appUser, false);

                        await _signInManager.ExternalLoginSignInAsync(externalLoginInfo.LoginProvider, externalLoginInfo.ProviderKey, false);

                        return RedirectToAction(ReturnUrl);
                    }
                }
            }

            return RedirectToAction("/Errors");

        }
    }
}
