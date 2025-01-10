using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.VisualStudio.Web.CodeGenerators.Mvc.Templates.BlazorIdentity.Pages;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using PracticeApp.Models;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Register = PracticeApp.Models.Register;
using Login = PracticeApp.Models.Login;

namespace PracticeApp.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;

        public AccountController(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }

        /*  [HttpPost("register")]
          public async Task<IActionResult> Register([FromBody] Register model)
          {
              var user = new IdentityUser { UserName = model.Username };
              *//*var email = new *//*
              var result = await _userManager.CreateAsync(user, model.Password);*/

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] Register model)
        {
            if (model == null)
            {
                return BadRequest("Model cannot be null");
            }

            var user = new IdentityUser
            {
                UserName = model.Username,
                Email = model.Email // Ensure you are setting the email here
            };

            var result = await _userManager.CreateAsync(user, model.Password);

            if (result.Succeeded)
            {
                return Ok(new {message = "User Register Successfully!"});
            }

            // Log errors
            foreach (var error in result.Errors)
            {
                Console.WriteLine($"Error: {error.Description}");
            }

            return BadRequest(result.Errors);
        }

        /* [HttpPost("login")]
         public async Task<IActionResult> Login([FromBody] Login model)
         {
             var user = await _userManager.FindByNameAsync(model.Username);
             if(user != null && await _userManager.CheckPasswordAsync(user, model.Password)){
                 var userRoles = await _userManager.GetRolesAsync(user);

                 var authClaims = new List<Claim>
                 {
                     new Claim(JwtRegisteredClaimNames.Sub, user.UserName!),
                     new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                 };

                 authClaims.AddRange(userRoles.Select(role => new Claim(ClaimTypes.Role, role)));

                 *//*authClaims.AddRange(UserRole.Select(role => new Claim(ClaimTypes.Role, role)));
                  * 
                  * 
 *//*
                 var expiryMinutesString = _configuration["Jwt:ExpiryMinutes"];
                 if (string.IsNullOrEmpty(expiryMinutesString) || !int.TryParse(expiryMinutesString, out int expiryMinutes))
                 {
                     // Handle the error, e.g., return a bad request response
                     return BadRequest("Invalid JWT expiry minutes configuration.");
                 }

                 var token = new JwtSecurityToken(
                     issuer: _configuration["Jwt:Issuer"],
                     expires: DateTime.Now.AddMinutes(expiryMinutes),
                     claims: authClaims,
                     signingCredentials: new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt: Key"]!)),
                     SecurityAlgorithms.HmacSha256
                     )
                     );

                 return Ok(new {token = new JwtSecurityTokenHandler().WriteToken(token) });

             }

             Console.WriteLine($"Login failed for user: {model.Username}");

             return Unauthorized();

         }*/

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] Login model)
        {
            if (model == null)
            {
                return BadRequest("Invalid login request.");
            }

            // Find the user by username
            var user = await _userManager.FindByNameAsync(model.Username);
            if (user == null)
            {
                Console.WriteLine($"Login failed: User '{model.Username}' not found.");
                return Unauthorized("Invalid username or password.");
            }

            // Check the password
            if (!await _userManager.CheckPasswordAsync(user, model.Password))
            {
                Console.WriteLine($"Login failed: Incorrect password for user '{model.Username}'.");
                return Unauthorized("Invalid username or password.");
            }

            // Get user roles
            var userRoles = await _userManager.GetRolesAsync(user);

            // Create claims for the token
            var authClaims = new List<Claim>
    {
        new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
    };

            // Add user roles to claims
            authClaims.AddRange(userRoles.Select(role => new Claim(ClaimTypes.Role, role)));

            // Get JWT expiry minutes from configuration
            var expiryMinutesString = _configuration["Jwt:ExpiryMinutes"];
            if (string.IsNullOrEmpty(expiryMinutesString) || !int.TryParse(expiryMinutesString, out int expiryMinutes))
            {
                return BadRequest("Invalid JWT expiry minutes configuration.");
            }

            // Create the token
            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"], // Ensure you have this in your config
                expires: DateTime.Now.AddMinutes(expiryMinutes),
                claims: authClaims,
                signingCredentials: new SigningCredentials(
                    new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"])), // Remove space in "Jwt: Key"
                    SecurityAlgorithms.HmacSha256)
            );

            // Return the token
            return Ok(new { token = new JwtSecurityTokenHandler().WriteToken(token) });
        }

        [HttpPost("add-role")]
        public async Task<IActionResult> AddRole([FromBody]string role)
        {
            if(!await _roleManager.RoleExistsAsync(role))
            {
                var result = await _roleManager.CreateAsync(new IdentityRole(role));
                if (result.Succeeded)
                {
                    return Ok(new { message = "Role added successfully !" });
                };
                return BadRequest(result.Errors);
            }
            return BadRequest("Role already exist!"); 

        }

        [HttpPost("assign-role")]
        public async Task<IActionResult> AssignRole([FromBody] UserRole model)
        {
            var user = await _userManager.FindByNameAsync(model.Username);

            if(user == null)
            {
                return BadRequest("user not found");
            }

            var result = await _userManager.AddToRoleAsync(user, model.Role);

            if (result.Succeeded)
            {
                return Ok(new { message = "Role assigned successfully" });
            }
            return BadRequest(result.Errors);
        }

    }
}
