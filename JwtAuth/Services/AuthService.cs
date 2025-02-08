using JwtAuth.Data;
using JwtAuth.Entities;
using JwtAuth.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JwtAuth.Services
{
  public class AuthService(IConfiguration configuration, UserDbContext context)
    : IAuthService
  {
    public async Task<string?> LoginAsync(UserDto request)
    {
      var user = await context.Users.FirstOrDefaultAsync(u => u.Username == request.Username);

      if (user is null)
      {
        return null;
      }

      if (new PasswordHasher<User>()
        .VerifyHashedPassword(user, user.PasswordHash, request.Password) == PasswordVerificationResult.Failed)
      {
        return null;
      }

      return CreateToken(user);
    }

    public async Task<User?> RegisterAsync(UserDto request)
    {
      if(await context.Users.AnyAsync(u => u.Username == request.Username))
      {
        return null;
      }

      var user = new User();

      var hashedPassword = new PasswordHasher<User>()
        .HashPassword(user, request.Password);

      user.Username = request.Username;
      user.PasswordHash = hashedPassword;
      user.Role = "User";

      context.Users.Add(user);

      await context.SaveChangesAsync();

      return user;
    }

    private string CreateToken(User user)
    {
      var claims = new List<Claim>
      {
        new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
        new Claim(ClaimTypes.Name, user.Username),
        new Claim(ClaimTypes.Role, user.Role)
      };

      var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration.GetValue<string>("Jwt:Key")!));

      var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512);

      var tokenDescriptor = new JwtSecurityToken(
        issuer: configuration.GetValue<string>("Jwt:Issuer"),
        audience: configuration.GetValue<string>("Jwt:Audience"),
        claims: claims,
        expires: DateTime.Now.AddMinutes(30),
        signingCredentials: creds
      );

      var tokenHandler = new JwtSecurityTokenHandler();
      var token = tokenHandler.WriteToken(tokenDescriptor);
      return token;
    }
  }
}
