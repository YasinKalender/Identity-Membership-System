using Identity.Web.Entities;
using Microsoft.AspNetCore.Html;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Razor.TagHelpers;

namespace Identity.Web.TagHelpers
{
    [HtmlTargetElement("td", Attributes = "user-roles")]
    public class UserRolesTagHelper : TagHelper
    {
        private readonly UserManager<AppUser> userManager;

        public UserRolesTagHelper(UserManager<AppUser> userManager)
        {
            this.userManager = userManager;
        }

        [HtmlAttributeName("user-roles")]
        public string UserId { get; set; }
        public override async Task ProcessAsync(TagHelperContext context, TagHelperOutput output)
        {
            var user = await userManager.FindByIdAsync(UserId);

            var userRoles = await userManager.GetRolesAsync(user);

            string html = "";

            userRoles.ToList().ForEach(i => html += $"<span class='badge badge-pill badge-danger bg-danger'>{i}</span>");

            output.Content.SetHtmlContent(html);

        }
    }
}
