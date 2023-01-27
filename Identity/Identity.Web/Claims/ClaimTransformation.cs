using Identity.Web.Entities;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace Identity.Web.Claims
{
    public class ClaimTransformation : IClaimsTransformation
    {
        private readonly UserManager<AppUser> _userManager;
        public ClaimTransformation(UserManager<AppUser> userManager)
        {
            _userManager = userManager;
        }
        public async Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
        {
            if (principal != null && principal.Identity.IsAuthenticated)
            {
                ClaimsIdentity claimsIdentity = principal.Identity as ClaimsIdentity; //Identity claimsleri aldık

                var user = await _userManager.FindByNameAsync(claimsIdentity.Name);

                if (user != null)
                {
                    if (principal.HasClaim(i => i.Type == "City"))
                    {
                        Claim claim = new Claim("City", user.City, ClaimValueTypes.String, "Internal");

                        claimsIdentity.AddClaim(claim);
                    }

                    if (user.BirthDay != null)
                    {
                        var age = DateTime.Now.Year - user.BirthDay.Value.Year;

                        if (age > 15)
                        {
                            Claim claim = new("BirthDay", age.ToString(), ClaimValueTypes.String, "Internal");
                            claimsIdentity.AddClaim(claim);
                        }

                    }
                }

            }

            return principal;
        }
    }
}
