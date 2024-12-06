using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ASI.Basecode.Services.ServiceModels
{
    public class SettingsViewModel
    {
        public UpdateProfileViewModel Profile { get; set; } = new UpdateProfileViewModel();
        public ChangePasswordViewModel Password { get; set; } = new ChangePasswordViewModel();
    }
}
