using Identity.Web.Entities;
using Identity.Web.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Identity.Web.Controllers
{
    public class RoleController : Controller
    {
        private readonly RoleManager<AppRole> _roleManager;

        public RoleController(RoleManager<AppRole> roleManager)
        {
            _roleManager = roleManager;
        }

        public async Task<IActionResult> Index()
        {
            var roles = await _roleManager.Roles.ToListAsync();

            return View(roles);
        }

        public IActionResult RoleAdd()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> RoleAdd(RoleModel roleModel)
        {
            var role = new AppRole() { Name = roleModel.Name };

            var result = await _roleManager.CreateAsync(role);

            if (!result.Succeeded)
            {
                return View(roleModel);
            }

            return RedirectToAction(nameof(Index));
        }

        public async Task<IActionResult> DeleteRole(string Id)
        {
            var role = await _roleManager.FindByIdAsync(Id);

            var result = await _roleManager.DeleteAsync(role);

            return RedirectToAction(nameof(Index));
        }

        public async Task<IActionResult> EditRole(string Id)
        {
            var role = await _roleManager.FindByIdAsync(Id);

            return View(role);
        }

        [HttpPost]
        public async Task<IActionResult> EditRole(AppRole role)
        {
            var editRole = await _roleManager.FindByIdAsync(role.Id);

            editRole.Name = role.Name;

            var result = await _roleManager.UpdateAsync(editRole);

            if (!result.Succeeded)
            {
                return View(role);
            }

            return RedirectToAction(nameof(Index));
        }
    }
}
