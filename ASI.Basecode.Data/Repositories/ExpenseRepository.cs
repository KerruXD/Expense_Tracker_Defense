using ASI.Basecode.Data.Interfaces;
using ASI.Basecode.Data.Models;
using Basecode.Data.Repositories;
using System.Collections.Generic;
using System.Linq;

namespace ASI.Basecode.Data.Repositories
{
    public class ExpenseRepository : BaseRepository, IExpenseRepository
    {
        private readonly AsiBasecodeDBContext _dbContext;

        public ExpenseRepository(AsiBasecodeDBContext dbContext, IUnitOfWork unitOfWork) : base(unitOfWork)
        {
            _dbContext = dbContext;
        }

        public IEnumerable<Expense> ViewExpenses()
        {
            
            return this.GetDbSet<Expense>().ToList();
        }
        public IEnumerable<Expense> ViewExpensesByUserId(int UserId)
        {

            return this.GetDbSet<Expense>().Where(expense => expense.UserId == UserId).ToList();
        }

        public void AddExpense(Expense expense)
        {
            
            this.GetDbSet<Expense>().Add(expense);
            UnitOfWork.SaveChanges();
        }

        public void UpdateExpense(Expense expense)
        {
            
            this.GetDbSet<Expense>().Update(expense);
            UnitOfWork.SaveChanges();
        }

        public void DeleteExpense(Expense expense)
        {
            
            this.GetDbSet<Expense>().Remove(expense);
            UnitOfWork.SaveChanges();
        }

        
        public IEnumerable<Category> GetCategories()
        {
            return _dbContext.Set<Category>().ToList();
        }
    }
}