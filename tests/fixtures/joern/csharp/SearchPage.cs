// ASP.NET WebForms: süslü parantezsiz denetim yapısı gövdeleri (csharpsrc2cpg bunları düşürür; Sniper sarar).
using System;
using System.Data.SqlClient;
using System.IO;

public partial class SearchPage : System.Web.UI.Page
{
    protected System.Web.UI.WebControls.Label lblOutput;

    protected void Page_Load(object sender, EventArgs e)
    {
        if (Request["city"] != null)
            ShowCity(Request["city"]); // EXPECT: xss
        foreach (var part in Request.QueryString["files"].Split(','))
            File.ReadAllText(part); // EXPECT: path
        string id = Request.QueryString["id"];
        if (!int.TryParse(id, out var n)) return;
        new SqlCommand("SELECT * FROM Items WHERE Id = " + id);
    }

    void ShowCity(String city)
    {
        lblOutput.Text = "Şehir: " + city;
    }
}
