using ASI.Basecode.Data.Models;
using System.Collections.Generic;

namespace ASI.Basecode.Data.Interfaces
{
    public interface ICategoryRepository
    {
        List<Category> ViewCategories();
        List<Category> ViewCategoriesByUserId(int UserId);
        void AddCategory(Category category);
        void UpdateCategory(Category category);
        void DeleteCategory(Category category);
    }
}