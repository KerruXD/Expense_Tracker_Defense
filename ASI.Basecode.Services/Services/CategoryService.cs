using ASI.Basecode.Data.Interfaces;
using ASI.Basecode.Data.Models;
using ASI.Basecode.Services.Interfaces;
using System.Collections.Generic;

namespace ASI.Basecode.Services.Services
{
    public class CategoryService : ICategoryService
    {
        private readonly ICategoryRepository _categoryRepository;

        public CategoryService(ICategoryRepository categoryRepository)
        {
            _categoryRepository = categoryRepository;
        }

        public List<Category> GetCategories()
        {
            return _categoryRepository.ViewCategories();
        }

        public void AddCategory(Category category, int UserId)
        {
            category.UserId = UserId;
            _categoryRepository.AddCategory(category);
        }

        public void UpdateCategory(Category category, int UserId)
        {
            category.UserId = UserId;
            _categoryRepository.UpdateCategory(category);
        }

        public void DeleteCategory(Category category)
        {
            _categoryRepository.DeleteCategory(category);
        }

        public List<Category> ViewCategoriesByUserId(int UserId)
        {
            return _categoryRepository.ViewCategoriesByUserId(UserId);
           
          
        }
    }
}