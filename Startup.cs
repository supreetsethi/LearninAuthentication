using LearninAuthentication.DbContext;
using LearninAuthentication.Models;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security.Infrastructure;
using Microsoft.Owin.Security.OAuth;
using Owin;
using System;
using System.Web.Http;

[assembly: OwinStartup(typeof(LearninAuthentication.Startup))]
namespace LearninAuthentication
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureOAuth(app);

        }

        private void ConfigureOAuth(IAppBuilder app)
        {
           // app.UseCors(Microsoft.Owin.Cors.CorsOptions.AllowAll);
            app.CreatePerOwinContext<OwinAuthDbContext>(() => new OwinAuthDbContext());
            app.CreatePerOwinContext<UserManager<ApplicationUser>>(CreateManager);

            app.UseOAuthAuthorizationServer(new OAuthAuthorizationServerOptions
            {
                TokenEndpointPath = new PathString("/token"),
                Provider = new AuthorizationServerProvider(),
                AccessTokenExpireTimeSpan = TimeSpan.FromMinutes(1),
#if DEBUG
                AllowInsecureHttp = true,
#endif
                RefreshTokenProvider = new RefreshTokenProvider()
                //{
                //    OnCreate = CreateRefreshToken,
                //    OnReceiveAsync = RecieveRefreshToken
                //},
                //AuthorizeEndpointPath = new PathString("/api/Account/ExternalLogin"),
            }); 


            app.UseOAuthBearerAuthentication(new OAuthBearerAuthenticationOptions());
          //  HttpConfiguration config = new HttpConfiguration();
          //  WebApiApplication.RegisterModule(config);
        }

        private static void RecieveRefreshToken(AuthenticationTokenReceiveContext obj)
        {
            //throw new NotImplementedException();  
            obj.DeserializeTicket(obj.Token);
        }

        private static void CreateRefreshToken(AuthenticationTokenCreateContext obj)
        {
            // throw new NotImplementedException();  
            obj.SetToken(obj.SerializeTicket());
        }
        private static UserManager<ApplicationUser> CreateManager(IdentityFactoryOptions<UserManager<ApplicationUser>> options, IOwinContext context)
        {
            var userStore = new UserStore<ApplicationUser>
                (context.Get<OwinAuthDbContext>());


            var owinManager = new UserManager<ApplicationUser>(userStore);

            return owinManager;
        }

        
    }
}