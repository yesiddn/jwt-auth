using JwtAuth.Data;
using JwtAuth.Entities;
using JwtAuth.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace JwtAuth.Services
{
  public class AuthService(IConfiguration configuration, UserDbContext context)
    : IAuthService
  {
    public async Task<TokenResponseDto?> LoginAsync(UserDto request)
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

      return await CreateTokenResponse(user);
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

    public async Task<TokenResponseDto?> RefreshTokenAsync(RefreshTokenRequestDto request)
    {
      var user = await ValidateRefreshTokenAsyn(request.UserId, request.RefreshToken);
      if (user is null)
        return null;

      return await CreateTokenResponse(user);
    }

    private async Task<User?> ValidateRefreshTokenAsyn(Guid userId, string refreshToken)
    {
      var user = await context.Users.FindAsync(userId);
      if (user is null || user.RefreshToken != refreshToken ||
        user.RefreshTokenExpiryTime < DateTime.Now
      )
      {
        return null;
      }

      return user;
    }

    private async Task<TokenResponseDto> CreateTokenResponse(User user)
    {
      return new TokenResponseDto
      {
        AccessToken = CreateToken(user),
        RefreshToken = await GenerateAndSaveRefreshTokenAsync(user)
      };
    }

    private string GenerateRefreshToken()
    {
      var randomNumber = new byte[32];
      using var rng = RandomNumberGenerator.Create();
      rng.GetBytes(randomNumber);
      return Convert.ToBase64String(randomNumber);
    }

    private async Task<string> GenerateAndSaveRefreshTokenAsync(User user)
    {
      var refreshToken = GenerateRefreshToken();
      user.RefreshToken = refreshToken;
      user.RefreshTokenExpiryTime = DateTime.Now.AddDays(7);
      await context.SaveChangesAsync();

      return refreshToken; 
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
