using System.ComponentModel.DataAnnotations;
using System;

public class User
{
    public int Id { get; set; }
    public string Email { get; set; }
    public string FullName { get; set; }
    [MaxLength(100)]
    public string Password { get; set; }
    public string CreatedBy { get; set; }
    public DateTime CreatedTime { get; set; }
    public string UpdatedBy { get; set; }
    public DateTime UpdatedTime { get; set; }
    public string ResetPasswordToken { get; set; }
    public DateTime? ResetPasswordExpiry { get; set; }
}
