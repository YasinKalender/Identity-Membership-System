using Identity.Web.Entities;
using Identity.Web.Models;
using Identity.Web.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.FileProviders;
using System.Text.RegularExpressions;

namespace Identity.Web.Controllers
{
    public class UserController : Controller
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly SignInManager<AppUser> _signInManager;
        private readonly IEmailService _emailService;
        private readonly IFileProvider _fileProvider;
        private readonly RoleManager<AppRole> _roleManager;
        private readonly EmailConfirmService _emailConfirmService;

        public UserController(UserManager<AppUser> userManager, SignInManager<AppUser> signInManager, IEmailService emailService, IFileProvider fileProvider, RoleManager<AppRole> roleManager, EmailConfirmService emailConfirmService)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _emailService = emailService;
            _fileProvider = fileProvider;
            _roleManager = roleManager;
            _emailConfirmService = emailConfirmService;
        }

        [Authorize]
        public IActionResult Index()
        {
            var users = _userManager.Users.ToList();

            return View(users);
        }
        public IActionResult Claims()
        {
            return View(User.Claims.ToList());
        }


        [Authorize]
        public IActionResult AuhtorizePage()
        {

            return View();
        }

        [Authorize]
        public IActionResult AccessDenied(string ReturnUrl)
        {
            if (ReturnUrl.Contains("ClaimsAccess"))
            {
                ViewBag.message = "Yaşınız bu sayfaya erişmek için uygun değildir";
            }

            return View();
        }

        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Register(RegisterUserModel registerUserDto)
        {
            if (ModelState.IsValid)
            {
                //var regex = "(5)[0-9][0-9][\\s]([0-9]){3}[\\s]([0-9]){2}[\\s]([0-9]){2}";

                //if (!Regex.Equals(regex, registerUserDto.PhoneNumber))
                //{
                //    ModelState.AddModelError("", "Bu telefon numarası uygun değildir");
                //    return View(registerUserDto);
                //}

                //Regex regex1 = new("(5)[0-9][0-9][\\s]([0-9]){3}[\\s]([0-9]){2}[\\s]([0-9]){2}");

                //if (!regex1.IsMatch(registerUserDto.PhoneNumber))
                //{
                //    ModelState.AddModelError("", "Bu telefon numarası uygun değildir");
                //    return View(registerUserDto);
                //}


                if (_userManager.Users.Any(i => i.PhoneNumber == registerUserDto.PhoneNumber))
                {
                    ModelState.AddModelError("", "Bu telefon numarası kullanılmaktadır");
                    return View(registerUserDto);
                }

                AppUser appUser = new()
                {
                    Email = registerUserDto.Email,
                    UserName = registerUserDto.Username,
                    City = registerUserDto.City,
                    PhoneNumber = registerUserDto.PhoneNumber,
                    BirthDay = registerUserDto.BirthDay,
                    Picture = "deneme",
                    Gender = registerUserDto.Gender
                };

                var identityResult = await _userManager.CreateAsync(appUser, registerUserDto.Password);

                if (identityResult.Succeeded)
                {
                    var token = await _userManager.GenerateEmailConfirmationTokenAsync(appUser);

                    var emailConfirmLink = Url.Action("ConfirmEmail", "User", new { token = token, userId = appUser.Id }, HttpContext.Request.Scheme, "localhost:44378");

                    await _emailConfirmService.SendConfirmEmail(appUser.Email, emailConfirmLink);

                    return RedirectToAction("Index", "User");
                }

                else
                {
                    foreach (var item in identityResult.Errors)
                    {
                        ModelState.AddModelError("", item.Description);
                        List<string> errors = new();
                        errors.Add(item.Code.ToString());
                        return View("~/Views/Home/ErrorPage.cshtml", errors);
                    }

                }

            }

            return View(registerUserDto);
        }

        public async Task<IActionResult> ConfirmEmail(string userId, string token)
        {
            var user = await _userManager.FindByIdAsync(userId);

            var result = await _userManager.ConfirmEmailAsync(user, token);

            if (result.Succeeded)
            {
                TempData["EmailNotConfirmSucess"] = "Email adresiniz onaylanmıştır";
                return RedirectToAction(nameof(MyProfile));
            }

            return View();
        }

        public IActionResult Login(string ReturnUrl)
        {
            TempData["ReturnUrl"] = ReturnUrl;

            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Login(LoginModel loginDto)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(loginDto.Email);

                if (user == null)
                    return View(loginDto);

                var locked = await _userManager.IsLockedOutAsync(user);

                if (locked)
                {
                    ModelState.AddModelError("", "Güvenlik sebebiyle erişiminiz engellenmiştir");
                }

                await _signInManager.SignOutAsync();

                var signInResult = await _signInManager.PasswordSignInAsync(user, loginDto.Password, loginDto.RememberMe, true);

                if (signInResult.RequiresTwoFactor)
                {

                    HttpContext.Session.Remove("time");
                    return RedirectToAction("TwoFactorLogin", "TwoAuth");
                }


                if (signInResult.Succeeded)
                {
                    await _userManager.ResetAccessFailedCountAsync(user); // Veritabanındaki AccessFailedCount alanını sıfırlar

                    if (await _userManager.IsEmailConfirmedAsync(user) == false)
                    {
                        TempData["EmailNotConfirm"] = "Email adresiniz onaylanmamıştır.";
                    }

                    if (TempData["ReturnUrl"] != null)
                    {
                        return RedirectToAction(TempData["ReturnUrl"].ToString());
                    }

                    return RedirectToAction(nameof(MyProfile));
                }

                if (signInResult.IsLockedOut)
                {
                    ModelState.AddModelError("", "Hesabınız 3 kere yanlış girdiğiniz için kitlenmiştir");
                }

                //else
                //{
                //    var countFailed = await _userManager.AccessFailedAsync(user);

                //    int failed = await _userManager.GetAccessFailedCountAsync(user);

                //    ModelState.AddModelError("", $"Hesabınıza {failed} giriş hakkınız kaldı.");

                //    if (failed >= 3)
                //    {
                //        await _userManager.SetLockoutEndDateAsync(user, DateTime.UtcNow.AddMinutes(1));
                //        ModelState.AddModelError("", "Hesabınız 3 kere yanlış girdiğiniz için kitlenmiştir");
                //    }


                //    ModelState.AddModelError("Email", "Email veya şifre alanı hatalıdır");
                //    //ModelState.AddModelError("", "Email veya şifre alanı hatalıdır");
                //}
            }

            return View(loginDto);
        }

        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction(nameof(Index));
        }

        public async Task Logout2()
        {
            await _signInManager.SignOutAsync();
        }

        public IActionResult ForgetPassword()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> ForgetPassword(ForgetPasswordModel forgetPasswordModel)
        {
            var user = await _userManager.FindByEmailAsync(forgetPasswordModel.Email);

            if (user == null)
            {
                ModelState.AddModelError(string.Empty, "Kullanıcı buluanamamıştır..");

                return View(forgetPasswordModel);
            }

            string passwordResetToken = await _userManager.GeneratePasswordResetTokenAsync(user);

            var passwordResetLink = Url.Action("ResetPassword", "User", new { token = passwordResetToken, userId = user.Id }, HttpContext.Request.Scheme, "localhost:44378");

            await _emailService.SendResetEmail(user.Email, passwordResetLink);

            TempData["Success"] = "Şifre sıfırlama email adresinize gönderilmiştir";

            return RedirectToAction(nameof(Login));
        }

        public IActionResult ResetPassword(string userId, string token)
        {
            TempData["userId"] = userId;
            TempData["token"] = token;

            return View();
        }

        [HttpPost]
        public async Task<IActionResult> ResetPassword(ResetPasswordModel resetPasswordModel)
        {
            var userId = TempData["userId"].ToString();
            var tokenId = TempData["token"].ToString();

            var user = await _userManager.FindByIdAsync(userId);

            var result = await _userManager.ResetPasswordAsync(user, tokenId, resetPasswordModel.Password);

            if (result.Succeeded)
                return RedirectToAction(nameof(Login));


            return View();
        }

        [Authorize]
        public async Task<IActionResult> MyProfile()
        {
            var data = TempData["Sucess"];

            var user = await _userManager.FindByNameAsync(User.Identity.Name);

            return View(user);
        }

        public IActionResult ChangePassword()
        {

            return View();
        }

        [HttpPost]
        [Authorize]
        public async Task<IActionResult> ChangePassword(PasswordChangeModel passwordChangeModel)
        {
            var user = await _userManager.FindByNameAsync(User.Identity.Name);


            var checkOldPassword = await _userManager.CheckPasswordAsync(user, passwordChangeModel.OldPassword);

            if (!checkOldPassword)
                return View(passwordChangeModel);

            var result = await _userManager.ChangePasswordAsync(user, passwordChangeModel.OldPassword, passwordChangeModel.NewPassword);

            if (!result.Succeeded)
            {
                ModelState.AddModelError("", result.Errors.Select(i => i.Description).ToString());
            }

            await _userManager.UpdateSecurityStampAsync(user);

            await _signInManager.SignOutAsync();
            await _signInManager.PasswordSignInAsync(user, passwordChangeModel.NewPassword, true, true);

            TempData["Sucess"] = "Şifreniz başarılı bir şekilde güncellenmiştir";

            return RedirectToAction(nameof(MyProfile));
        }

        public async Task<IActionResult> EditUser(string Id)
        {
            var user = await _userManager.FindByIdAsync(Id);

            EditUserModel model = new()
            {
                BirthDay = user.BirthDay.Value,
                City = user.City,
                Email = user.Email,
                Gender = user.Gender.Value,
                PhoneNumber = user.PhoneNumber,
                Username = user.UserName
            };

            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> EditUser(EditUserModel model)
        {
            var fileProvider = _fileProvider.GetDirectoryContents("wwwroot");
            var fileName = Guid.NewGuid().ToString() + Path.GetExtension(model.Picture.FileName);

            var path = Path.Combine(fileProvider.First(i => i.Name == "Picture").PhysicalPath, fileName);

            using var stream = new FileStream(path, FileMode.Create);
            await model.Picture.CopyToAsync(stream);

            var user = await _userManager.FindByNameAsync(User.Identity.Name);

            user.UserName = model.Username;
            user.Email = model.Email;
            user.BirthDay = model.BirthDay;
            user.City = model.City;
            user.Gender = model.Gender;
            user.PhoneNumber = model.PhoneNumber;
            user.Picture = fileName;

            var updatedUser = await _userManager.UpdateAsync(user);

            await _userManager.UpdateSecurityStampAsync(user);

            await _signInManager.SignOutAsync();

            await _signInManager.SignInAsync(user, true);

            return RedirectToAction(nameof(MyProfile));
        }


        //Rol atama işlemleri
        [Authorize(Roles = "Admin,Editör")]
        public async Task<IActionResult> RoleAssing(string Id)
        {
            var user = await _userManager.FindByIdAsync(Id);
            var roles = _roleManager.Roles.ToList();
            var existUserRole = await _userManager.GetRolesAsync(user);

            TempData["UserId"] = user.Id;

            List<RoleAssingModel> assignRoles = new();

            roles.ForEach(role =>
            assignRoles.Add(new RoleAssingModel()
            {
                RoleId = role.Id,
                RoleName = role.Name,
                HasAssign = existUserRole.Contains(role.Name),
            }));

            ViewBag.User = $"{user.UserName}";

            return View(assignRoles);
        }

        [HttpPost]
        public async Task<IActionResult> RoleAssing(List<RoleAssingModel> roleAssingModels)
        {
            var userId = TempData["UserId"].ToString();
            var user = await _userManager.FindByIdAsync(userId);

            foreach (var item in roleAssingModels)
            {
                if (item.HasAssign)
                    await _userManager.AddToRoleAsync(user, item.RoleName);
                else
                    await _userManager.RemoveFromRoleAsync(user, item.RoleName);
            }

            return RedirectToAction(nameof(Index));
        }

        public async Task<IActionResult> ResetPasswordUser(string Id)
        {
            var user = await _userManager.FindByIdAsync(Id);

            AdminPasswordResetModel model = new() { UserId = user.Id };

            return View(model);
        }

        [HttpPost]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> ResetPasswordUser(AdminPasswordResetModel model)
        {
            var user = await _userManager.FindByIdAsync(model.UserId);

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);

            await _userManager.ResetPasswordAsync(user, token, model.Password);

            await _userManager.UpdateSecurityStampAsync(user);

            return RedirectToAction(nameof(Index));

        }

    }
}
