using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using MultipleWsFedAuth.Models;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace MultipleWsFedAuth.Controllers
{
    public class AccountController : Controller
    {

        [AllowAnonymous]
        public IActionResult SignIn()
        {
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        public IActionResult SignIn(string scheme)
        {
            if (User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Index", "Home");
            }

            return Challenge(scheme);
        }

        public IActionResult SignOut()
        {
            string scheme = User.Claims.FirstOrDefault(claim => claim.Type == "local:authscheme")?.Value;
            return SignOut(new[] { CookieAuthenticationDefaults.AuthenticationScheme, scheme });
        }
    }
}
