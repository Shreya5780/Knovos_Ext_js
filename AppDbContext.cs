using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;


/*using Microsoft.AspNetCore.Identity.EntityFrameworkCore;*/
using Microsoft.VisualStudio.Web.CodeGenerators.Mvc.Templates.General;

namespace PracticeApp.Data
{
    public class AppDbContext : IdentityDbContext<IdentityUser>
    {
        public AppDbContext(DbContextOptions options) : base(options)
        {

        }

       
    }
}
