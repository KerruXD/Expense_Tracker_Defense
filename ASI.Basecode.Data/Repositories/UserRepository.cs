using ASI.Basecode.Data.Interfaces;
using ASI.Basecode.Data.Models;
using Basecode.Data.Repositories;
using Microsoft.EntityFrameworkCore;
using System;
using System.Linq;

namespace ASI.Basecode.Data.Repositories
{
    public class UserRepository : BaseRepository, IUserRepository
    {
        private readonly DbSet<User> _users;
        private readonly IUnitOfWork _unitOfWork;

        public UserRepository(IUnitOfWork unitOfWork) : base(unitOfWork)
        {
            _unitOfWork = unitOfWork;
            _users = _unitOfWork.Database.Set<User>();
        }

        public IQueryable<User> GetUsers()
        {
            return _users;
        }

        public bool UserExists(string userEmail)
        {
            return _users.Any(x => x.Email == userEmail);
        }

        public void AddUser(User user)
        {
            _users.Add(user);
            _unitOfWork.SaveChanges();
        }

        public void UpdateUser(User user)
        {
            _users.Update(user);
            _unitOfWork.SaveChanges(); 
        }

        public User GetUserById(int id)
        {
            return _users.Find(id);
        }

        public User GetUserByEmail(string email)
        {
            return _users.Where(user => user.Email.Equals(email)).FirstOrDefault();
        }
    }
}
