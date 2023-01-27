using Microsoft.AspNetCore.Authorization;

namespace Identity.Web.Claims
{
    public class PaymentClaim : IAuthorizationRequirement
    {
    }

    public class PaymentClaimHandler : AuthorizationHandler<PaymentClaim>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, PaymentClaim requirement)
        {
            if (context.User != null || context.User.Identity != null)
            {
                var claims = context.User.Claims.FirstOrDefault(i => i.Type == "ExpireDateExchange" && i.Value != null);

                if (claims!=null)
                {
                    if (DateTime.Now < Convert.ToDateTime(claims.Value))
                        context.Succeed(requirement);
                    else
                        context.Fail();
                }
            }

            return Task.CompletedTask;
        }
    }
}
