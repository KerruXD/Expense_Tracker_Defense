using ASI.Basecode.Services.Interfaces;
using ASI.Basecode.Data.Models;
using ASI.Basecode.Services.ServiceModels;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using System.Collections.Generic;
using System.Linq;
using ASI.Basecode.Services.Manager;
using System;

namespace ASI.Basecode.WebApp.Controllers
{
    [Route("Settings")]
    public class SettingsController : Controller
    {
        private readonly IUserService _userService;

        public SettingsController(IUserService userService)
        {
            _userService = userService;
        }

        [HttpGet("Index")]
        public IActionResult Index()
        {
            var emailClaim = User.Claims.FirstOrDefault(c => c.Type == "Email")?.Value;

            if (string.IsNullOrEmpty(emailClaim))
            {
                var allClaims = string.Join(", ", User.Claims.Select(c => $"{c.Type}: {c.Value}"));
                throw new InvalidOperationException($"Email claim not found. Available claims: {allClaims}");
            }

            var user = _userService.GetUserByEmail(emailClaim);
            if (user == null)
            {
                return NotFound("User not found.");
            }

            var viewModel = new SettingsViewModel
            {
                Profile = new UpdateProfileViewModel
                {
                    FullName = user.FullName,
                    Email = user.Email
                },
                Password = new ChangePasswordViewModel()
            };

            return View(viewModel);
        }

        //[HttpPost("UpdateProfile")]
        //public IActionResult UpdateProfile([Bind("Profile")] SettingsViewModel model)
        //{
        //    if (model.Profile == null || !TryValidateModel(model.Profile))
        //    {
        //        var errors = ModelState.Values.SelectMany(v => v.Errors)
        //                                      .Select(e => e.ErrorMessage)
        //                                      .ToList();
        //        TempData["ErrorMessage"] = "Invalid input. Please check your details: " + string.Join(", ", errors);
        //        return RedirectToAction("Index");
        //    }

        //    var emailClaim = User.Claims.FirstOrDefault(c => c.Type == "Email")?.Value;
        //    if (string.IsNullOrEmpty(emailClaim))
        //    {
        //        TempData["ErrorMessage"] = "Unable to identify the logged-in user.";
        //        return RedirectToAction("Index");
        //    }

        //    var user = _userService.GetUserByEmail(emailClaim);
        //    if (user == null)
        //    {
        //        TempData["ErrorMessage"] = "User not found.";
        //        return RedirectToAction("Index");
        //    }

        //    // Check if there are changes
        //    if (user.FullName == model.Profile.FullName)
        //    {
        //        TempData["ErrorMessage"] = "No changes were made.";
        //        return RedirectToAction("Index");
        //    }

        //    user.FullName = model.Profile.FullName;
        //    _userService.UpdateUser(user);

        //    // Update the claims and re-sign the user in
        //    var claims = new List<Claim>
        //    {
        //        new Claim("Email", user.Email),
        //        new Claim("FullName", user.FullName)
        //    };

        //    var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        //    var principal = new ClaimsPrincipal(identity);

        //    // Update authentication cookie
        //    HttpContext.SignOutAsync();
        //    HttpContext.SignInAsync(principal);

        //    // Update session
        //    HttpContext.Session.SetString("FullName", user.FullName);

        //    TempData["SuccessMessage"] = "Profile updated successfully.";
        //    return RedirectToAction("Index");
        //}

        [HttpPost("ChangePassword")]
        public IActionResult ChangePassword([Bind("Password")] SettingsViewModel model)
        {
            if (model.Password == null || !TryValidateModel(model.Password))
            {
                var errors = ModelState.Values.SelectMany(v => v.Errors)
                                              .Select(e => e.ErrorMessage)
                                              .ToList();
                TempData["ErrorMessage"] = "Invalid input. Please check your details: " + string.Join(", ", errors);
                return RedirectToAction("Index");
            }

            var emailClaim = User.Claims.FirstOrDefault(c => c.Type == "Email")?.Value;
            if (string.IsNullOrEmpty(emailClaim))
            {
                TempData["ErrorMessage"] = "Unable to identify the logged-in user.";
                return RedirectToAction("Index");
            }

            var user = _userService.GetUserByEmail(emailClaim);
            if (user == null)
            {
                TempData["ErrorMessage"] = "User not found.";
                return RedirectToAction("Index");
            }

            // Check if no changes were made (all password fields are empty)
            if (string.IsNullOrEmpty(model.Password.CurrentPassword) &&
                string.IsNullOrEmpty(model.Password.NewPassword) &&
                string.IsNullOrEmpty(model.Password.ConfirmNewPassword))
            {
                TempData["ErrorMessage"] = "No changes were made.";
                return RedirectToAction("Index");
            }

            // Validate that all fields are filled
            if (string.IsNullOrEmpty(model.Password.CurrentPassword) ||
                string.IsNullOrEmpty(model.Password.NewPassword) ||
                string.IsNullOrEmpty(model.Password.ConfirmNewPassword))
            {
                TempData["ErrorMessage"] = "All password fields must be filled.";
                return RedirectToAction("Index");
            }

            // Validate the current password
            if (user.Password != PasswordManager.EncryptPassword(model.Password.CurrentPassword))
            {
                TempData["ErrorMessage"] = "The current password is incorrect.";
                return RedirectToAction("Index");
            }

            // Check if new password is the same as current
            if (model.Password.NewPassword == model.Password.CurrentPassword)
            {
                TempData["ErrorMessage"] = "The new password cannot be the same as the current password.";
                return RedirectToAction("Index");
            }

            // Validate new password matches confirmation
            if (model.Password.NewPassword != model.Password.ConfirmNewPassword)
            {
                TempData["ErrorMessage"] = "New password and confirmation password do not match.";
                return RedirectToAction("Index");
            }

            // Check if new password is identical to the stored one
            if (user.Password == PasswordManager.EncryptPassword(model.Password.NewPassword))
            {
                TempData["ErrorMessage"] = "No changes were made.";
                return RedirectToAction("Index");
            }

            // Update the password
            user.Password = PasswordManager.EncryptPassword(model.Password.NewPassword);
            _userService.UpdateUser(user);

            TempData["SuccessMessage"] = "Password updated successfully.";
            return RedirectToAction("Index");
        }

    }
}
