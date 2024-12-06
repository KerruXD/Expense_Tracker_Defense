using ASI.Basecode.Data.Models;
using ASI.Basecode.Services.Interfaces;
using ASI.Basecode.Services.Services;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Linq;
using System.Security.Claims;

namespace ASI.Basecode.WebApp.Controllers
{
    public class CategoryController : Controller
    {
        private readonly ICategoryService _categoryService;
        private readonly IExpenseService _expenseService;
        private readonly IUserService _userService;

        public CategoryController(ICategoryService categoryService, IExpenseService expenseService, IUserService userService)
        {
            _categoryService = categoryService;
            _expenseService = expenseService;
            _userService = userService;
        }

        //public IActionResult Index()
        //{
        //    var categories = _categoryService.GetCategories();
        //    return View(categories);
        //}

        public IActionResult Index(int? categoryFilter)
        {
            var Email = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            User currentUser = null;

            if (Email != null)
            {
                currentUser = _userService.GetUserByEmail(Email);
            }
            var categories = _categoryService.ViewCategoriesByUserId(currentUser.Id);

            
            ViewBag.Categories = categories;

            
            if (categoryFilter.HasValue && categoryFilter.Value > 0)
            {
                categories = categories.Where(c => c.UserId==currentUser.Id && c.CategoryID == categoryFilter.Value).ToList();
            }

            return View(categories);
        }

        public IActionResult View(int id)
        {

            var Email = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            User currentUser = null;

            if (Email != null)
            {
                currentUser = _userService.GetUserByEmail(Email);
            }
            var expenses = _expenseService.ViewExpenses()
                .Where(e => e.CategoryID == id)
                .ToList();

            ViewBag.CategoryName = _categoryService.ViewCategoriesByUserId(currentUser.Id)
                .FirstOrDefault(c => c.CategoryID == id)?.CategoryName;

            return View(expenses);
        }

        public IActionResult Create()
        {
            return View();
        }

        [HttpPost]
        public IActionResult Create(Category category)

        {
            var Email = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            User currentUser = null;

            if (Email != null)
            {
                currentUser = _userService.GetUserByEmail(Email);
            }
            if (ModelState.IsValid)
            {
                _categoryService.AddCategory(category, currentUser.Id);
                return RedirectToAction("Index", "Home");
            }
            
            return PartialView("Create", category);
        }

        [HttpGet]
        public IActionResult Edit(int id)
        {
            var category = _categoryService.GetCategories().FirstOrDefault(c => c.CategoryID == id);
            if (category == null)
            {
                return NotFound();
            }
            TempData["PreviousPage"] = Request.Headers["Referer"].ToString();
            return View(category);
        }

        [HttpPost]
        public IActionResult Edit(Category category, int UserId)
        {
            var Email = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            User currentUser = null;

            if (Email != null)
            {
                currentUser = _userService.GetUserByEmail(Email);
            }
            if (ModelState.IsValid)
            {
                _categoryService.UpdateCategory(category, currentUser.Id);

                var previousPage = TempData["PreviousPage"]?.ToString();
                if (!string.IsNullOrEmpty(previousPage))
                {
                    return Redirect(previousPage); 
                }

                
            }
            return View(category);
        }

        public IActionResult Delete(int id)
        {
            var category = _categoryService.GetCategories().FirstOrDefault(c => c.CategoryID == id);
            if (category != null)
            {
                _categoryService.DeleteCategory(category);
            }
            return RedirectToAction("Index","Home");
        }
    }
}