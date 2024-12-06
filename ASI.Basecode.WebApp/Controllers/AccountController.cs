using ASI.Basecode.Data.Models;
using ASI.Basecode.Services.Interfaces;
using ASI.Basecode.Services.Manager;
using ASI.Basecode.Services.ServiceModels;
using ASI.Basecode.WebApp.Authentication;
using ASI.Basecode.WebApp.Mvc;
using AutoMapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.IO;
using System.Net;
using System.Net.Mail;
using System.Text;
using System.Threading.Tasks;
using static ASI.Basecode.Resources.Constants.Enums;
using System.Security.Cryptography;

namespace ASI.Basecode.WebApp.Controllers
{
    public class AccountController : ControllerBase<AccountController>
    {
        private readonly SessionManager _sessionManager;
        private readonly SignInManager _signInManager;
        private readonly IConfiguration _configuration;
        private readonly IUserService _userService;

        public AccountController(
            SignInManager signInManager,
            IHttpContextAccessor httpContextAccessor,
            ILoggerFactory loggerFactory,
            IConfiguration configuration,
            IMapper mapper,
            IUserService userService) : base(httpContextAccessor, loggerFactory, configuration, mapper)
        {
            _sessionManager = new SessionManager(this._session);
            _signInManager = signInManager;
            _configuration = configuration;
            _userService = userService;
        }
        private static readonly string Key = "your-secret-key-32bytes"; // Replace with a 32-byte key for AES-256
        private static readonly string IV = "your-iv-16bytes"; // Replace with a 16-byte IV

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Login()
        {
            ViewBag.ShowSidebar = false;
            TempData["returnUrl"] = WebUtility.UrlDecode(HttpContext.Request.Query["ReturnUrl"]);
            _sessionManager.Clear();
            _session.SetString("SessionId", Guid.NewGuid().ToString());
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> Login(string email, string password)
        {
            ViewBag.ShowSidebar = false;
            _session.SetString("HasSession", "Exist");

            User user = null;
            var loginResult = _userService.AuthenticateUser(email, password, ref user);
            if (loginResult == LoginResult.Success)
            {
                await _signInManager.SignInAsync(user);
                _session.SetString("FullName", user.FullName);
                return RedirectToAction("Index", "Home");
            }

            TempData["ErrorMessage"] = "Incorrect Email or Password";
            return View();
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Register()
        {
            ViewBag.ShowSidebar = false;
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        public IActionResult Register(UserViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            try
            {
                _userService.AddUser(model);
                TempData["SuccessMessage"] = "Registration successful! Please log in.";
                return RedirectToAction("Login", "Account");
            }
            catch (InvalidDataException ex)
            {
                ModelState.AddModelError("Email", ex.Message);
            }
            catch (Exception)
            {
                TempData["ErrorMessage"] = "An unexpected error occurred. Please try again later.";
            }

            return View(model);
        }

        [AllowAnonymous]
        public async Task<IActionResult> SignOutUser()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("Login", "Account");
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult ForgotPassword()
        {
            ViewBag.ShowSidebar = false;
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        public IActionResult ForgotPassword(string email)
        {
            if (string.IsNullOrEmpty(email))
            {
                ViewBag.ErrorMessage = "Please provide a valid email address.";
                return View();
            }

            var user = _userService.GetUserByEmail(email);
            if (user == null)
            {
                ViewBag.ErrorMessage = "No user found with this email.";
                return View();
            }

            var resetToken = Guid.NewGuid().ToString();
            user.ResetPasswordToken = resetToken;
            user.ResetPasswordExpiry = DateTime.Now.AddHours(1);
            _userService.UpdateUser(user);

            var resetLink = Url.Action("ResetPassword", "Account", new { token = resetToken }, Request.Scheme);
            var subject = "Password Reset Request";
            var body = $"Click the link below to reset your password: <a href='{resetLink}'>Reset Password</a>";

            try
            {
                SendEmail(email, subject, body);
                ViewBag.SuccessMessage = "A password reset link has been sent to your email.";
            }
            catch (Exception ex)
            {
                ViewBag.ErrorMessage = $"Error sending email: {ex.Message}";
            }

            return View();
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult ResetPassword(string token)
        {
            if (string.IsNullOrEmpty(token))
            {
                ViewBag.ErrorMessage = "Invalid or expired reset token.";
                return View("Error");
            }

            var user = _userService.GetUserByResetToken(token);
            if (user == null || user.ResetPasswordExpiry < DateTime.Now)
            {
                ViewBag.ErrorMessage = "Invalid or expired reset token.";
                return View("Error");
            }

            ViewBag.Token = token;
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        public IActionResult ResetPassword(string token, string newPassword, string confirmPassword)
        {
            if (string.IsNullOrEmpty(newPassword) || string.IsNullOrEmpty(confirmPassword))
            {
                ViewBag.ErrorMessage = "All fields are required.";
                return View();
            }

            if (newPassword != confirmPassword)
            {
                ViewBag.ErrorMessage = "Passwords do not match.";
                return View();
            }

            var user = _userService.GetUserByResetToken(token);
            if (user == null || user.ResetPasswordExpiry < DateTime.Now)
            {
                ViewBag.ErrorMessage = "Invalid or expired reset token.";
                return View();
            }

            user.Password = PasswordManager.EncryptPassword(newPassword);
            user.ResetPasswordToken = null;
            user.ResetPasswordExpiry = DateTime.MinValue;
            _userService.UpdateUser(user);
            

            TempData["SuccessMessage"] = "Your password has been reset successfully.";
            return RedirectToAction("Login");
        }

        private void SendEmail(string toEmail, string subject, string body)
        {
            try
            {
                var smtpClient = new SmtpClient
                {
                    Host = _configuration["EmailSettings:SMTPServer"],
                    Port = int.Parse(_configuration["EmailSettings:Port"]),
                    EnableSsl = true,
                    Credentials = new NetworkCredential(
                        _configuration["EmailSettings:SenderEmail"],
                        _configuration["EmailSettings:SenderPassword"])
                };

                using (var message = new MailMessage(_configuration["EmailSettings:SenderEmail"], toEmail)
                {
                    Subject = subject,
                    Body = body,
                    IsBodyHtml = true
                })
                {
                    smtpClient.Send(message);
                }
            }
            catch (SmtpException smtpEx)
            {
                Console.WriteLine($"SMTP Exception: {smtpEx.Message}");
                throw new Exception($"Error sending email: {smtpEx.Message}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"General Exception: {ex.Message}");
                throw new Exception($"Error sending email: {ex.Message}");
            }
        }



        public static string Encrypt(string plainText)
        {
            if (string.IsNullOrEmpty(plainText))
                throw new ArgumentNullException(nameof(plainText));

            using (var aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(Key);
                aes.IV = Encoding.UTF8.GetBytes(IV);

                using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                {
                    var plainBytes = Encoding.UTF8.GetBytes(plainText);
                    var encryptedBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);

                    return Convert.ToBase64String(encryptedBytes);
                }
            }
        }

        public static string Decrypt(string cipherText)
        {
            if (string.IsNullOrEmpty(cipherText))
                throw new ArgumentNullException(nameof(cipherText));

            using (var aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(Key);
                aes.IV = Encoding.UTF8.GetBytes(IV);

                using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                {
                    var cipherBytes = Convert.FromBase64String(cipherText);
                    var decryptedBytes = decryptor.TransformFinalBlock(cipherBytes, 0, cipherBytes.Length);

                    return Encoding.UTF8.GetString(decryptedBytes);
                }
            }
        }
    }
}