using ASI.Basecode.Data.Interfaces;
using ASI.Basecode.Data.Models;
using ASI.Basecode.Services.Interfaces;
using ASI.Basecode.Services.Services;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Linq;
using System.Security.Claims;

namespace ASI.Basecode.WebApp.Controllers
{
    public class ExpenseController : Controller
    {
        private readonly IExpenseService _expenseService;
        private readonly ICategoryService _categoryService;
        private readonly IUserService _userService;

        public ExpenseController(IExpenseService expenseService, ICategoryService categoryService, IUserService userService)
        {
            _expenseService = expenseService;
            _categoryService = categoryService;
            _userService = userService;
        }

        public IActionResult Index(string startDate, string endDate, int? category)
        {
            var Email = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            User currentUser = null;

            if (Email != null)
            {
                currentUser = _userService.GetUserByEmail(Email);
            }
            var expenses = _expenseService.ViewExpensesByUserId(currentUser.Id);
            

            if (!string.IsNullOrWhiteSpace(startDate))
            {
                DateTime start = DateTime.Parse(startDate);
                expenses = expenses.Where(e => e.Date >= start).ToList();
            }

            if (!string.IsNullOrWhiteSpace(endDate))
            {
                DateTime end = DateTime.Parse(endDate);
                expenses = expenses.Where(e => e.Date <= end).ToList();
            }

            if (category.HasValue)
            {
                expenses = expenses.Where(e => e.CategoryID == category.Value).ToList();
            }

            ViewBag.Categories = _categoryService.ViewCategoriesByUserId(currentUser.Id); // Populate categories for the dropdown
            return View("Index", expenses);
        }

        public IActionResult Create()
        {
            ViewBag.Categories = _categoryService.GetCategories(); // Ensure categories are set
            return View();
        }

        [HttpPost]
        public IActionResult Create(Expense expense)
        {
            var Email = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            User currentUser = null;

            if (Email != null)
            {
                currentUser = _userService.GetUserByEmail(Email);
            }
            if (ModelState.IsValid)
            {
                _expenseService.AddExpense(expense, currentUser.Id);


                return RedirectToAction("Index","Home");
            }

            
            ViewBag.Categories = _categoryService.GetCategories();
            return PartialView("Create", expense);
        }

        public IActionResult Edit(int id)

        {
            var Email = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            User currentUser = null;

            if (Email != null)
            {
                currentUser = _userService.GetUserByEmail(Email);
            }
            var expense = _expenseService.ViewExpensesByUserId(currentUser.Id).FirstOrDefault(e => e.ExpenseID == id);
            if (expense == null)
            {
                return NotFound();
            }

            ViewBag.Categories = _categoryService.ViewCategoriesByUserId(currentUser.Id); // Load categories for the dropdown
            return View(expense);
        }

        
        [HttpPost]
        public IActionResult Edit(Expense expense, int UserId)

        {
            var Email = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            User currentUser = null;

            if (Email != null)
            {
                currentUser = _userService.GetUserByEmail(Email);
            }
            if (ModelState.IsValid)
            {
                _expenseService.UpdateExpense(expense, currentUser.Id);
                return RedirectToAction("Index", "Home");
            }

            ViewBag.Categories = _categoryService.GetCategories(); 
            return View(expense); 
        }


        public IActionResult Delete(int id)
        {
            var expense = _expenseService.ViewExpenses().FirstOrDefault(e => e.ExpenseID == id);
            if (expense != null)
            {
                _expenseService.DeleteExpense(expense);
            }
            return RedirectToAction("Index", "Home");
        }
    }
}