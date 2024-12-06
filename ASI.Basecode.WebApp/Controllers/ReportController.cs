using ASI.Basecode.Data.Interfaces;
using ASI.Basecode.Data.Models;
using ASI.Basecode.Services.Interfaces;
using ASI.Basecode.Services.Services;
using ASI.Basecode.WebApp.Models;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;

namespace ASI.Basecode.WebApp.Controllers
{
    public class ReportController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
        private readonly IExpenseService _expenseService;
        private readonly ICategoryService _categoryService;
        private readonly IUserService _userService;
        public ReportController(IExpenseService expenseService, ICategoryService categoryService, IUserService userService)
        {
            _expenseService = expenseService;
            _categoryService = categoryService;
            _userService = userService;
        }



        public IActionResult ExpenseSummary()
        {
            var Email = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            User currentUser = null;

            if (Email != null)
            {
                currentUser = _userService.GetUserByEmail(Email);
            }

            var categories = _categoryService.ViewCategoriesByUserId(currentUser.Id);
            var expenses = _expenseService.ViewExpensesByUserId(currentUser.Id);


            if (categories == null || expenses == null)
            {
                categories = new List<Category>();
                expenses = new List<Expense>();
            }

            var model = new ExpenseSummaryViewModel
            {
                Categories = categories,
                Expenses = expenses
            };

            return View(model); 
        }

        // Action to generate a report


        // Action to display Expense Trends
        //public IActionResult ExpenseTrends()
        //{
        //    // Fetch expenses
        //    var expenses = _expenseRepository.ViewExpenses();
        //    if (expenses == null)
        //    {
        //        expenses = new List<Expense>(); // Initialize as empty list if null
        //    }

        //    // Fetch categories using the CategoryService
        //    var categories = _categoryService.GetCategories();
        //    if (categories == null || !categories.Any())
        //    {
        //        categories = new List<Category>();  // Initialize categories if null or empty
        //    }

        //    // Prepare the trend data
        //    var trendData = categories.Select(category => new ExpenseTrendData
        //    {
        //        CategoryName = category.CategoryName,
        //        MonthlyAmounts = expenses
        //            .Where(e => e.CategoryID == category.CategoryID)
        //            .GroupBy(e => new { e.Date.Year, e.Date.Month })
        //            .OrderBy(g => g.Key.Month)
        //            .Select(g => g.Sum(e => e.Amount))
        //            .ToList()
        //    }).ToList();

        //    // Get distinct months
        //    var months = trendData.SelectMany(td => td.MonthlyAmounts.Select(m => m.ToString("MMMM yyyy"))).Distinct().ToList();

        //    // Create ViewModel
        //    var viewModel = new ExpenseTrendViewModel
        //    {
        //        Categories = categories.Select(c => c.CategoryName).ToList(),
        //        TrendData = trendData,
        //        Months = months
        //    };

        //    return View(viewModel);
        //}

        public IActionResult ExpenseTrends()
        {
            var model = new ExpenseTrendViewModel
            {
                Months = GetMonths(), // List of months
                TrendData = GetSpendingOverTime(), // List of TrendData
                CategoryTrends = GetCategoryTrends(), // List of CategoryData
                TopExpenses = GetTopExpenses() // List of TopExpenseData
            };

            return View(model);
        }


        public IActionResult GenerateReport(string startDate = null, string endDate = null, int? categoryId = null)
        {
            var Email = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            User currentUser = null;

            if (Email != null)
            {
                currentUser = _userService.GetUserByEmail(Email);
            }
            var categories = _categoryService.ViewCategoriesByUserId(currentUser.Id) ?? new List<Category>();
            var expenses = _expenseService.ViewExpensesByUserId(currentUser.Id);

            if (!string.IsNullOrWhiteSpace(startDate) && DateTime.TryParse(startDate, out var parsedStartDate))
            {
                expenses = expenses.Where(e => e.Date >= parsedStartDate).ToList();
            }

            if (!string.IsNullOrWhiteSpace(endDate) && DateTime.TryParse(endDate, out var parsedEndDate))
            {
                expenses = expenses.Where(e => e.Date <= parsedEndDate).ToList();
            }

            if (categoryId.HasValue)
            {
                expenses = expenses.Where(e => e.CategoryID == categoryId).ToList();
            }

            var model = new GenerateReportViewModel
            {
                Categories = categories,
                Expenses = expenses,
                StartDate = startDate,
                EndDate = endDate,
                SelectedCategoryId = categoryId,
                TotalAmount = expenses.Sum(e => e.Amount)
            };

            return View(model);
        }
        // Helper method: Get a list of distinct months
        private List<string> GetMonths()

        {
            var Email = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            User currentUser = null;

            if (Email != null)
            {
                currentUser = _userService.GetUserByEmail(Email);
            }
            var expenses = _expenseService.ViewExpensesByUserId(currentUser.Id) ?? new List<Expense>();

            return expenses
                .GroupBy(e => new { e.Date.Year, e.Date.Month })
                .OrderBy(g => g.Key.Year).ThenBy(g => g.Key.Month)
                .Select(g => $"{g.Key.Month:D2}/{g.Key.Year}") // Format: "MM/YYYY"
                .ToList();
        }

        
        private List<TrendData> GetSpendingOverTime()
        {
            var Email = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            User currentUser = null;

            if (Email != null)
            {
                currentUser = _userService.GetUserByEmail(Email);
            }
            var expenses = _expenseService.ViewExpensesByUserId(currentUser.Id) ?? new List<Expense>();
            var categories = _categoryService.ViewCategoriesByUserId(currentUser.Id) ?? new List<Category>();

            return categories.Select(category => new TrendData
            {
                CategoryName = category.CategoryName,
                MonthlyAmounts = expenses
                    .Where(e => e.CategoryID == category.CategoryID)
                    .GroupBy(e => new { e.Date.Year, e.Date.Month })
                    .OrderBy(g => g.Key.Year).ThenBy(g => g.Key.Month)
                    .Select(g => g.Sum(e => e.Amount))
                    .ToList()
            }).ToList();
        }

        
        private List<CategoryData> GetCategoryTrends()
        {
            var Email = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            User currentUser = null;

            if (Email != null)
            {
                currentUser = _userService.GetUserByEmail(Email);
            }
            var expenses = _expenseService.ViewExpensesByUserId(currentUser.Id) ?? new List<Expense>();
            var categories = _categoryService.ViewCategoriesByUserId(currentUser.Id) ?? new List<Category>();

            return categories.Select(category => new CategoryData
            {
                CategoryName = category.CategoryName,
                TotalAmount = expenses
                    .Where(e => e.CategoryID == category.CategoryID)
                    .Sum(e => e.Amount)
            }).ToList();
        }

       
        private List<TopExpenseData> GetTopExpenses()
        {
            var Email = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            User currentUser = null;

            if (Email != null)
            {
                currentUser = _userService.GetUserByEmail(Email);
            }
            var expenses = _expenseService.ViewExpensesByUserId(currentUser.Id) ?? new List<Expense>();

            return expenses
                .OrderByDescending(e => e.Amount)
                .Take(5) // Adjust this to return the top N expenses
                .Select(e => new TopExpenseData
                {
                    Title = e.Title,
                    Amount = e.Amount
                })
                .ToList();
        }
    }
}