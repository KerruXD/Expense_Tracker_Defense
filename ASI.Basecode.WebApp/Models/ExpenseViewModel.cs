using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;
using System;
using Microsoft.AspNetCore.Http;
using System.ComponentModel.DataAnnotations.Schema;
public class ExpenseViewModel
{ 
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public string ID { get; set; }

    [Required(ErrorMessage = "Title is required")]
    public string Title { get; set; }

    [Required(ErrorMessage = "Amount is required")]
    public decimal Amount { get; set; }

    [Required(ErrorMessage = "Date is required")]
    public DateTime Date { get; set; }

    [Required(ErrorMessage = "Category is required")]
    public string Category { get; set; }

    [Required(ErrorMessage = "Description is required")]
    public string Description { get; set; }
}
