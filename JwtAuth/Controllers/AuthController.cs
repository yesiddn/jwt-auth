﻿using JwtAuth.Entities;
using JwtAuth.Models;
using JwtAuth.Services;
using Microsoft.AspNetCore.Authorization;
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
  public class AuthController(IAuthService authService)
    : ControllerBase
  {
    public static User user = new();

    [HttpPost("register")]
    public async Task<ActionResult<User>> Register(UserDto request)
    {
      var user = await authService.RegisterAsync(request);

      if(user is null)
        return BadRequest("Username already exists.");

      return Ok(user);
    }

    [HttpPost("login")]
    public async Task<ActionResult<TokenResponseDto>> Login(UserDto request)
    {
      var response = await authService.LoginAsync(request);

      if(response is null) 
        return BadRequest("Invalid username or password.");

      return Ok(response);
    }

    [HttpPost("refresh-token")]
    public async Task<ActionResult<TokenResponseDto>> RefreshToken(RefreshTokenRequestDto request)
    {
      var response = await authService.RefreshTokenAsync(request);

      if (response is null || response.AccessToken is null || response.RefreshToken is null)
        return Unauthorized("Invalid refresh token.");

      return Ok(response);
    }

    [Authorize]
    [HttpGet("authenticated-only")]
    public IActionResult AuthenticatedOnlyEndPoint()
    {
      return Ok("You are authenticated.");
    }

    [Authorize(Roles = "Admin")] // to add more than one role, use comma separated values -> [Authorize(Roles = "Admin, User")]
    [HttpGet("admin-only")]
    public IActionResult AdminOnlyEndPoint()
    {
      return Ok("You are authenticated as an admin.");
    }
  }
}
