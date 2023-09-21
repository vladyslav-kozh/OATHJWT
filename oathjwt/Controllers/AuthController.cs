using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.IdentityModel.Tokens;

[Route("api/auth")]
[ApiController]
public class AuthController : ControllerBase
{
    private readonly IConfiguration _configuration;
    private readonly UserManager<IdentityUser> _userManager;

    public AuthController(IConfiguration configuration, UserManager<IdentityUser> userManager)
    {
        _configuration = configuration;
        _userManager = userManager;
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginModel model)
    {
        // Authenticate the user using OAuth 2.0 with Google
        var googleAuthenticationResult = await AuthenticateWithGoogleAsync(model.GoogleAccessToken);

        if (!googleAuthenticationResult.Succeeded)
        {
            return BadRequest("Failed to authenticate with Google.");
        }

        // Check if the user exists, and if not, create a new user
        var user = await _userManager.FindByEmailAsync(model.Email);
        if (user == null)
        {
            user = new IdentityUser { UserName = model.Email, Email = model.Email };
            var result = await _userManager.CreateAsync(user);
            if (!result.Succeeded)
            {
                return BadRequest("Failed to create a new user.");
            }
        }

        // Generate a JWT token
        var token = GenerateJwtToken(user);

        return Ok(new { token });
    }

    private async Task<SignInResult> AuthenticateWithGoogleAsync(string googleAccessToken)
    {
        // You can use an HTTP client to send a request to Google's OAuth 2.0 API to validate the access token.
        using (var httpClient = new HttpClient())
        {
            // Set the base URL for Google's token info endpoint
            var tokenInfoEndpoint = "https://www.googleapis.com/oauth2/v3/tokeninfo";

            // Create a dictionary to hold the parameters for the request
            var parameters = new Dictionary<string, string>
        {
            { "access_token", googleAccessToken }
        };

            // Build the request URL with query parameters
            var requestUrl = tokenInfoEndpoint + "?" + string.Join("&", parameters.Select(kvp => $"{kvp.Key}={kvp.Value}"));

            // Send a GET request to Google's token info endpoint
            var response = await httpClient.GetAsync(requestUrl);

            if (response.IsSuccessStatusCode)
            {
                // Parse the response JSON to get user information
                var responseContent = await response.Content.ReadAsStringAsync();
                var tokenInfo = JsonConvert.DeserializeObject<TokenInfo>(responseContent);

                // Check if the token is valid and has the expected audience (client ID)
                if (tokenInfo != null && tokenInfo.Audience == "your-google-client-id")
                {
                    // Authentication with Google succeeded
                    return SignInResult.Success;
                }
            }

            // Authentication with Google failed
            return SignInResult.Failed;
        }
    }

    private string GenerateJwtToken()
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes("your-secret-key"); // Use the same key as configured in Startup.cs
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new Claim[]
            {
                new Claim(ClaimTypes.Name, "exampleuser"),
                // Add any other claims as needed
            }),
            Expires = DateTime.UtcNow.AddHours(1), // Token expiration time
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
        };
        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }
}
