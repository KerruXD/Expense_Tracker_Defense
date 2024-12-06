using ASI.Basecode.Data.Models;
using System.Collections.Generic;

namespace ASI.Basecode.WebApp.Models
{
    public class ExpenseSummaryViewModel
    {
        public IEnumerable<Category> Categories { get; set; }
        public IEnumerable<Expense> Expenses { get; set; }
        public int CurrentPage { get; set; }
        public int TotalPages { get; set; }
    }
}
