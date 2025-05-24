using Auth.Core.Entities;
using System;
using System.Threading.Tasks;

namespace Auth.Infrastructure.Interfaces;

public interface IUserRepository
{
    Task<User?> GetByUsernameAsync(string username);
    Task<User?> GetByIdAsync(Guid userId);
    Task AddAsync(User user);
    Task UpdateAsync(User user);
    Task<bool> UsernameExistsAsync(string username);
}