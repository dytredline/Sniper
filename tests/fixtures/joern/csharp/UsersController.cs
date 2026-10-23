// ASP.NET Core kaynak/hedef modelleri: olumlu (EXPECT) ve olumsuz örnekler.
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using Microsoft.AspNetCore.Mvc;

public class UsersController : Controller
{
    public IActionResult Show()
    {
        string id = Request.Query["id"];
        var cmd = new SqlCommand("SELECT * FROM Users WHERE Id = '" + id + "'"); // EXPECT: sql
        var safe = new SqlCommand("SELECT * FROM Users WHERE Id = @id");
        safe.Parameters.AddWithValue("@id", id);
        Process.Start("cmd.exe", "/c ping " + Request.Form["host"]); // EXPECT: command
        Process.Start("cmd.exe", "/c ping localhost");
        File.ReadAllText(Request.Query["file"]); // EXPECT: path
        File.ReadAllText("config.json");
        Response.Redirect(Request.Query["next"]); // EXPECT: redirect
        new BinaryFormatter().Deserialize(Request.Body); // EXPECT: deserialize
        return View();
    }

    public IActionResult Search(string q, int page)
    {
        var cmd = new SqlCommand("SELECT * FROM Items WHERE Name = '" + q + "'"); // EXPECT: sql
        var paged = new SqlCommand("SELECT * FROM Items OFFSET " + page);
        return View();
    }
}
