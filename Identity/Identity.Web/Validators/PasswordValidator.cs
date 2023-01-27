using Identity.Web.Entities;
using Microsoft.AspNetCore.Identity;

namespace Identity.Web.Validators
{
    public class PasswordValidator : IPasswordValidator<AppUser>
    {
        public Task<IdentityResult> ValidateAsync(UserManager<AppUser> manager, AppUser user, string? password)
        {
            //if (string.Equals(user.UserName, password, StringComparison.OrdinalIgnoreCase))
            //{
            //    return Task.FromResult(IdentityResult.Failed(new IdentityError
            //    {
            //        Code = "UsernameAsPassword",
            //        Description = "You cannot use your username as your password"
            //    }));
            //}
            //return Task.FromResult(IdentityResult.Success);

            List<IdentityError> errors = new();

            if (password.ToLower().Contains(user.UserName.ToLower()))
            {
                errors.Add(new IdentityError() { Code = "PasswordContainsUserName", Description = "Password contains username" });
            }

            if (password.ToLower().Contains("123456"))
            {
                errors.Add(new IdentityError() { Code = "PasswordContains123456", Description = "Password ardışık sayı içeremez" });
            }

            if (errors.Count == 0)
            {
                return Task.FromResult(IdentityResult.Success);
            }

            return Task.FromResult(IdentityResult.Failed(errors.ToArray()));
        }
    }
}
