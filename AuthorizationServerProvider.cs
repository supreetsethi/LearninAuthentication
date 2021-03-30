using LearninAuthentication.DbContext;
using LearninAuthentication.Models;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OAuth;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace LearninAuthentication
{
    public class AuthorizationServerProvider : OAuthAuthorizationServerProvider
    {
        public override async Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            //string clientId;
            //string clientSecret;

            //if (context.TryGetBasicCredentials(out clientId, out clientSecret))
            //{
            await Task.Run(() => context.Validated());
            //}
            //else
            //{
            //    context.SetError("invalid_client", "Client credentials could not be retrieved from the Authorization header");
            //    context.Rejected();
            //}
        }
        public async override Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            UserManager<ApplicationUser> userManager = context.OwinContext.GetUserManager<UserManager<ApplicationUser>>();
            
            var roles = context.OwinContext.GetUserManager<RoleManager<IdentityRole>>();
            
            ApplicationUser user;
            try
            {
                user = await userManager.FindAsync(context.UserName, context.Password);
                if (user != null)
                {
                    ClaimsIdentity identity = await userManager.CreateIdentityAsync(user, DefaultAuthenticationTypes.ExternalBearer);
                    identity.AddClaim(new Claim(ClaimTypes.Role, "Admin"));
                    identity.AddClaim(new Claim(ClaimTypes.Name, user.UserName));
                    identity.AddClaim(new Claim("LoggedOn", DateTime.Now.ToString()));
                    await Task.Run(() => context.Validated(identity));
                    //using (var db = new OwinAuthDbContext())
                    //{
                    //    if (db != null) 
                    //    {
                    //    var user = db.Roles
                    //    }
                    //}
                    //context.Validated(identity);
                }
                else
                {
                    context.SetError("invalid_grant", "Invalid User Id or Password");
                    context.Rejected();
                }


            }
            catch (Exception)
            {
                context.SetError("Server_error");
                context.Rejected();
                return;
            }
        }


        public override Task GrantRefreshToken(OAuthGrantRefreshTokenContext context)
        {
            var newIdentity = new ClaimsIdentity(context.Ticket.Identity);
            newIdentity.AddClaim(new Claim("newClaim", "newValue"));
            var newTicket = new AuthenticationTicket(newIdentity, context.Ticket.Properties);
            context.Validated(newTicket);
            return Task.FromResult<object>(null);
        }

        public override Task TokenEndpoint(OAuthTokenEndpointContext context)
        {
            foreach (KeyValuePair<string, string> item in context.Properties.Dictionary)
            {
                context.AdditionalResponseParameters.Add(item.Key, item.Value);
            }
            return Task.FromResult<object>(null);
        }
    }
}
