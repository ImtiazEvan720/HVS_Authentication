using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Principal;
using System.DirectoryServices;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace HVS_Authentication.Src
{
    class JWTService
    {
        public static string SecurityKey = Constants.SecurityKey;
        public static string Audience = Constants.ReceiverAppID;
        public static string Issuer = Constants.SenderAppID;        

        public static string GenerateToken(string sessionToken,string sid)
        {            
            var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(SecurityKey));
            var signingCredentials = new SigningCredentials(signingKey,
                SecurityAlgorithms.HmacSha256Signature, SecurityAlgorithms.Sha256Digest);

            var claimsIdentity = new ClaimsIdentity(new List<Claim>()
            {
                new Claim(ClaimTypes.Authentication, sessionToken),
                new Claim(ClaimTypes.Sid, sid),
            }, "Custom");

            var securityTokenDescriptor = new SecurityTokenDescriptor();

            securityTokenDescriptor.Audience = Audience;
            securityTokenDescriptor.Issuer = Issuer;
            securityTokenDescriptor.Subject = claimsIdentity;
            securityTokenDescriptor.SigningCredentials = signingCredentials;

            var tokenHandler = new JwtSecurityTokenHandler();
            var plainToken = tokenHandler.CreateToken(securityTokenDescriptor);
            var signedAndEncodedToken = tokenHandler.WriteToken(plainToken);

            return signedAndEncodedToken;
        }

        public static bool ValidateToken(string signedAndEncodedToken)
        {
            var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(SecurityKey));
            var tokenHandler = new JwtSecurityTokenHandler();   

            var tokenValidationParameters = new TokenValidationParameters()
            {
                ValidAudiences = new string[]
                {
                    Audience
                },
                ValidIssuers = new string[]
                {
                    Issuer
                },

                IssuerSigningKey = signingKey                
            };

            SecurityToken validatedToken;
            var claims = tokenHandler.ValidateToken(signedAndEncodedToken,
                tokenValidationParameters, out validatedToken);
            if (claims.HasClaim(ClaimTypes.Sid, GetComputerSid().Value))
            {                
                return true;
            }
            else
            {                
                return false;
            }
                        
        }


        public static SecurityIdentifier GetComputerSid()
        {
            return new SecurityIdentifier((byte[])new DirectoryEntry(string.Format("WinNT://{0},Computer", Environment.MachineName)).Children.Cast<DirectoryEntry>().First().InvokeGet("objectSID"), 0).AccountDomainSid;
        }



    }
}
