using Identity.Web.Entities;
using Microsoft.AspNetCore.Identity;

namespace Identity.Web.Validators
{
    public class UserValidator : IUserValidator<AppUser>
    {
        public Task<IdentityResult> ValidateAsync(UserManager<AppUser> manager, AppUser user)
        {
            List<IdentityError> errors = new();

            if (char.IsDigit(user.UserName[0]))
            {
                errors.Add(new IdentityError() { Code = "UsernameDontStartDigit", Description = "UserName dont start digit " });
            }

            if (errors.Count == 0)
            {
                return Task.FromResult(IdentityResult.Success);
            }

            return Task.FromResult(IdentityResult.Failed(errors.ToArray()));
        }
    }
}
