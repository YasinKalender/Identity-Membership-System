using Microsoft.AspNetCore.Razor.TagHelpers;

namespace Identity.Web.TagHelpers
{
    public class UserPictureTagHalper : TagHelper
    {
        public string Picture { get; set; }
        public override void Process(TagHelperContext context, TagHelperOutput output)
        {
            output.TagName = "img";

            if (string.IsNullOrEmpty(Picture))
            {
                output.Attributes.SetAttribute("src", "https://mdbcdn.b-cdn.net/img/Photos/new-templates/bootstrap-chat/ava3.webp");
            }
            else
            {
                output.Attributes.SetAttribute("src", $"~/wwwroot/Picture/{Picture}");
            }
        }
    }
}
