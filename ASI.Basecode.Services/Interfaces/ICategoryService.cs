using ASI.Basecode.Data.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ASI.Basecode.Services.Interfaces
{
    public interface ICategoryService
    {
        List<Category> GetCategories();
        List<Category> ViewCategoriesByUserId(int UserId);
        void AddCategory(Category category, int UserId);
        void UpdateCategory(Category category, int UserId);
        void DeleteCategory(Category category);
    }
}