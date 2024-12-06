using ASI.Basecode.Data;
using ASI.Basecode.Data.Interfaces;
using ASI.Basecode.Data.Models;
using ASI.Basecode.Services.Interfaces;
using ASI.Basecode.Services.Manager;
using ASI.Basecode.Services.ServiceModels;
using AutoMapper;
using System;
using System.Data.Entity.Infrastructure;
using System.IO;
using System.Linq;
using static ASI.Basecode.Resources.Constants.Enums;

namespace ASI.Basecode.Services.Services
{
    public class UserService : IUserService
    {
        private readonly IUserRepository _repository;
        private readonly IMapper _mapper;

        public UserService(IUserRepository repository, IMapper mapper)
        {
            _mapper = mapper;
            _repository = repository;
        }

        public LoginResult AuthenticateUser(string userEmail, string password, ref User user)
        {
            user = new User();
            var passwordKey = PasswordManager.EncryptPassword(password);
            user = _repository.GetUsers().FirstOrDefault(x => x.Email == userEmail &&
                                                              x.Password == passwordKey);

            return user != null ? LoginResult.Success : LoginResult.Failed;
        }

        public void AddUser(UserViewModel model)
        {
            var user = new User();
            if (!_repository.UserExists(model.Email))
            {
                _mapper.Map(model, user);
                user.Password = PasswordManager.EncryptPassword(model.Password);
                user.CreatedTime = DateTime.Now;
                user.UpdatedTime = DateTime.Now;
                user.CreatedBy = Environment.UserName;
                user.UpdatedBy = Environment.UserName;

                _repository.AddUser(user);
            }
            else
            {
                throw new InvalidDataException(Resources.Messages.Errors.UserExists);
            }
        }

        public User GetUserByEmail(string email)
        {
            return _repository.GetUsers().FirstOrDefault(u => u.Email == email);
        }

        public void UpdateUser(User user)
        {
            try
            {
                var existingUser = _repository.GetUsers().FirstOrDefault(u => u.Id == user.Id);

                if (existingUser != null)
                {
                    // Update user properties
                    existingUser.FullName = user.FullName;
                    existingUser.Password = user.Password;
                    existingUser.ResetPasswordToken = user.ResetPasswordToken;
                    existingUser.ResetPasswordExpiry = user.ResetPasswordExpiry;

                    _repository.UpdateUser(existingUser);
                }
                else
                {
                    throw new InvalidOperationException("User not found");
                }
            }
            catch (DbUpdateException ex)
            {
                Console.WriteLine($"DbUpdateException: {ex.Message}");
                if (ex.InnerException != null)
                {
                    Console.WriteLine($"Inner Exception: {ex.InnerException.Message}");
                }
                throw;
            }
        }

        public User GetUserNameByEmail(string email)
        {
            return _repository.GetUserByEmail(email);
        }

        public User GetUserByResetToken(string resetToken)
        {
            return _repository.GetUsers()
                .FirstOrDefault(u => u.ResetPasswordToken == resetToken && u.ResetPasswordExpiry > DateTime.Now);
        }
    }
}
