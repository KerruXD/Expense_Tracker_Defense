using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ASI.Basecode.Services.ServiceModels
{
    public class UpdateProfileViewModel
    {
        public string Email { get; set; }

        [RegularExpression(@"^[A-Za-z\s]+$", ErrorMessage = "Name must not contain numbers or special characters.")]
        public string FullName { get; set; }
    }
}
