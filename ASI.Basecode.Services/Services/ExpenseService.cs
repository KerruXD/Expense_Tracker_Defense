using ASI.Basecode.Data.Interfaces;
using ASI.Basecode.Data.Models;
using ASI.Basecode.Data.Repositories;
using ASI.Basecode.Services.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;

namespace ASI.Basecode.Services.Services
{
    public class ExpenseService : IExpenseService
    {
        private readonly IExpenseRepository _expenseRepository;

        
        public ExpenseService(IExpenseRepository expenseRepository)
        {
            this._expenseRepository = expenseRepository;
        }

       
        public IEnumerable<Expense> ViewExpenses()
        {
            var expenses = _expenseRepository.ViewExpenses().ToList(); // Convert IEnumerable to List
            return expenses;
        }

        
        public void AddExpense(Expense expense, int UserId)
        {
            if (expense == null)
            {
                throw new ArgumentNullException(nameof(expense), "Expense cannot be null");
            }

           
            var newExpense = new Expense
            {
                Title = expense.Title,
                UserId = UserId,
                Amount = expense.Amount,
                Date = expense.Date,
                CategoryID = expense.CategoryID,  // Assign the CategoryID foreign key here
                Description = expense.Description
            };

            _expenseRepository.AddExpense(newExpense);
        }

        // Updates an existing expense
        public void UpdateExpense(Expense expense, int UserId)
        {
            if (expense == null)
            {
                throw new ArgumentNullException(nameof(expense), "Expense cannot be null");
            }
            expense.UserId= UserId;

            _expenseRepository.UpdateExpense(expense);
        }

        // Deletes an expense
        public void DeleteExpense(Expense expense)
        {
            if (expense == null)
            {
                throw new ArgumentNullException(nameof(expense), "Expense cannot be null");
            }

            _expenseRepository.DeleteExpense(expense);
        }

        public IEnumerable<Expense> ViewExpensesByUserId(int UserId)
        {
            return _expenseRepository.ViewExpensesByUserId(UserId);
        }
    }
}