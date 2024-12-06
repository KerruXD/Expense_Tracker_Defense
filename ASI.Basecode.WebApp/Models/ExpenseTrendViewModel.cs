//using ASI.Basecode.Data.Models;
//using System.Collections.Generic;

//public class ExpenseTrendViewModel
//{
//    public List<string> Categories { get; set; } = new List<string>(); // List of categories
//    public List<ExpenseTrendData> TrendData { get; set; } = new List<ExpenseTrendData>(); // Data for chart
//    public List<string> Months { get; set; } = new List<string>(); // List of months for x-axis

//    public IEnumerable<Expense> Expenses { get; set; }
//}

//public class ExpenseTrendData
//{
//    public string CategoryName { get; set; } // Name of the category (e.g. Groceries, Bills)
//    public List<decimal> MonthlyAmounts { get; set; } = new List<decimal>(); // Expenses for each month in the data
//}
using ASI.Basecode.Data.Models;
using System.Collections.Generic;

public class ExpenseTrendViewModel
{
    public List<string> Months { get; set; } // For Monthly Comparison and Spending Over Time
    public List<TrendData> TrendData { get; set; } // For Spending Over Time
    public List<CategoryData> CategoryTrends { get; set; } // For Category Trends
    public List<TopExpenseData> TopExpenses { get; set; } // For Top Expense Titles

    public ExpenseTrendViewModel()
    {
        Months = new List<string>();
        TrendData = new List<TrendData>();
        CategoryTrends = new List<CategoryData>();
        TopExpenses = new List<TopExpenseData>();
    }
}

public class TrendData
{
    public string CategoryName { get; set; }
    public List<decimal> MonthlyAmounts { get; set; }
}

public class CategoryData
{
    public string CategoryName { get; set; }
    public decimal TotalAmount { get; set; }
}

public class TopExpenseData
{
    public string Title { get; set; }
    public decimal Amount { get; set; }
}
