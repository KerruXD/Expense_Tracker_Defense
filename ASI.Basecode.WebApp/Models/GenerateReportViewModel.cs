using ASI.Basecode.Data.Models;
using System.Collections.Generic;

namespace ASI.Basecode.WebApp.Models
{
    public class GenerateReportViewModel
    {
        public IEnumerable<Category> Categories { get; set; }
        public IEnumerable<Expense> Expenses { get; set; }
        public string StartDate { get; set; }
        public string EndDate { get; set; }
        public int? SelectedCategoryId { get; set; }
        public decimal TotalAmount { get; set; }
    }
}
