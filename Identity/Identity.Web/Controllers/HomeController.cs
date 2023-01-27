using Identity.Web.Entities;
using Identity.Web.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using System.Security.Claims;

namespace Identity.Web.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly UserManager<AppUser> _userManager;
        private readonly SignInManager<AppUser> _signInManager;

        public HomeController(ILogger<HomeController> logger, SignInManager<AppUser> signInManager, UserManager<AppUser> userManager)
        {
            _logger = logger;
            _signInManager = signInManager;
            _userManager = userManager;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        [Authorize(Policy = "BirthDayPolicy")]
        public IActionResult ClaimsAccess()
        {
            return View();
        }
        public async Task<IActionResult> BeforePaymentPage()
        {
            bool result = User.HasClaim(i => i.Type == "ExpireDateExchange");

            if (!result)
            {
                Claim claim = new("ExpireDateExchange", DateTime.Now.AddDays(30).ToShortDateString(), ClaimValueTypes.String, "Internal");
                var user = await _userManager.FindByNameAsync(User.Identity.Name);

                await _userManager.AddClaimAsync(user, claim);

                await _signInManager.SignOutAsync();

                await _signInManager.SignInAsync(user, true);
            }


            return RedirectToAction(nameof(PaymentPage));
        }

        [Authorize(Policy = "ExpireDatePolicy")]
        public IActionResult PaymentPage()
        {
            return View();
        }

        public IActionResult ErrorPage()
        {
            return View();
        }
    }
}