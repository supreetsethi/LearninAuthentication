using LearninAuthentication.Models;
using Microsoft.AspNet.Identity.EntityFramework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace LearninAuthentication.DbContext
{
    public class OwinAuthDbContext : IdentityDbContext<ApplicationUser>
    {
        public OwinAuthDbContext() :
            base("OwinAuthDbContext")
        {

        }
    }
}