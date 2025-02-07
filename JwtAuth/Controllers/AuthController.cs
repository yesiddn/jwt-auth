using JwtAuth.Entities;
using JwtAuth.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JwtAuth.Controllers
{
  [Route("api/[controller]")]
  [ApiController]
  public class AuthController(IConfiguration configuration)
    : ControllerBase
  {
    public static User user = new();

    [HttpPost("register")]
    public ActionResult<User> Register(UserDto request)
    {
      var hashedPassword = new PasswordHasher<User>()
        .HashPassword(user, request.Password);

      user.Username = request.Username;
      user.PasswordHash = hashedPassword;

      return Ok(user);
    }

    [HttpPost("login")]
    public ActionResult<string> Login(UserDto request)
    {
      if (user.Username != request.Username)
      {
        return BadRequest("Invalid username or password");
      }

      if (new PasswordHasher<User>()
        .VerifyHashedPassword(user, user.PasswordHash, request.Password) == PasswordVerificationResult.Failed)
      {
        return BadRequest("Invalid username or password");
      }

      string token = CreateToken(user);
      return Ok(token);
    }

    private string CreateToken(User user)
    {
      var claims = new List<Claim>
      {
        new Claim(ClaimTypes.Name, user.Username)
      };

      var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration.GetValue<string>("Jwt:Key")));

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
