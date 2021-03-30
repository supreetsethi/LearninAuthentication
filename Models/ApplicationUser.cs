using Microsoft.AspNet.Identity.EntityFramework;

namespace LearninAuthentication.Models
{
    public class ApplicationUser : IdentityUser
    {
        public string Gender { get; set; }
    }
}