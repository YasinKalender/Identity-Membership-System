using Microsoft.AspNetCore.Identity;

namespace Identity.Web.Validators
{
    public class ErrorDescriptor : IdentityErrorDescriber
    {
        public override IdentityError DuplicateUserName(string userName)
        {
            return new IdentityError() { Code = "DuplicateUserName", Description = $"{userName} kullanıcı adı kullanılıyor" };
        }

    }
}
