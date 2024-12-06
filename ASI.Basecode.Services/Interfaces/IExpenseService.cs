using ASI.Basecode.Data.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ASI.Basecode.Services.Interfaces
{
    public interface IExpenseService
    {
        IEnumerable<Expense> ViewExpenses();
        IEnumerable<Expense> ViewExpensesByUserId(int UserId);

        void AddExpense(Expense expense, int UserId);

        void UpdateExpense(Expense expense, int UserId);

        void DeleteExpense(Expense expense);
    }
}