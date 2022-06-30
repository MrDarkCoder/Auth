using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Auth.Data;
using Auth.Helper;
using Auth.Models;
using Auth.Repository.Interfaces;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Auth.Repository.Services
{
    public class JwtUtillService : IJwtUtillRepository
    {
        private readonly AuthContext _authContext;
        private readonly AppSettings _appSettings;
        public JwtUtillService(AuthContext authContext, IOptions<AppSettings> appSettings)
        {
            _authContext = authContext;
            _appSettings = appSettings.Value;
        }

        public string GenerateJwtToken(Account account)
        {
            // Token handler by System.IdentityModel.Tokens.Jwt
            var tokenHandler = new JwtSecurityTokenHandler();

            // User Claims
            var claims = new List<Claim>{
                new Claim(JwtRegisteredClaimNames.NameId, account.Id.ToString())
            };

            // Secret key 64bytes - base64 string
            byte[] key = Encoding.ASCII.GetBytes(_appSettings.Secret);

            // signing credentials secertkey+algotype
            var credentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature);

            // Token Descriptor by Microsoft.IdentityModel.Tokens
            var tokenDescriptor = new SecurityTokenDescriptor()
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.Now.AddMinutes(10),
                SigningCredentials = credentials
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);

            // Serializes a JwtSecurityToken into a JWT in Compact Serialization Format.

            return tokenHandler.WriteToken(token);
        }

        public RefreshToken GetRefreshToken(string ipAddress)
        {
            var refreshToken = new RefreshToken()
            {
                // token is a cryptographically strong random sequence of values
                Token = Convert.ToHexString(RandomNumberGenerator.GetBytes(64)),
                // Expiration Time
                Expires = DateTime.UtcNow.AddMinutes(15),
                Created = DateTime.UtcNow,
                // Created by which person (ip)
                CreatedByIP = ipAddress
            };

            var uniqueToken = !_authContext.Accounts.Any(r => r.RefreshTokens.Any(rt => rt.Token == refreshToken.Token));

            if (!uniqueToken) return GetRefreshToken(ipAddress);

            return refreshToken;
        }

        public int? ValidateJwtToken(string accessToken)
        {
            if (accessToken == null) return null;

            var tokenHandler = new JwtSecurityTokenHandler();
            byte[] key = Encoding.ASCII.GetBytes(_appSettings.Secret);

            try
            {
                tokenHandler.ValidateToken(accessToken, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    // set clockskew to zero so tokens expire exactly at token expiration time (instead of 5 minutes later)
                    ClockSkew = TimeSpan.Zero
                }, out SecurityToken validatedAccessToken);

                var jwtToken = (JwtSecurityToken)validatedAccessToken;
                var accountId = int.Parse(jwtToken.Claims.First(x => x.Type == JwtRegisteredClaimNames.NameId).Value);
                return accountId;
            }
            catch
            {
                return null;
            }
        }
    }
}