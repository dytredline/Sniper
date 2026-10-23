// ASP.NET WebForms: lock (x) { … } gövdesi (csharpsrc2cpg süslü parantezliyse bile düşürür; Sniper "_ = (x);" yapar).
using System;
using System.Data.SqlClient;
using System.IO;

public partial class LockPage : System.Web.UI.Page
{
    private static readonly object Sync = new object();

    protected void Page_Load(object sender, EventArgs e)
    {
        string name = Request.QueryString["name"];
        lock (Sync)
        {
            File.ReadAllText(name); // EXPECT: path
        }
        string id = Request.QueryString["id"];
        lock (Sync)
        {
            if (!int.TryParse(id, out var n)) return;
            new SqlCommand("SELECT * FROM Items WHERE Id = " + id);
        }
        lock (Sync)
            new SqlCommand("SELECT * FROM Logs WHERE Tag = '" + Request["tag"] + "'"); // EXPECT: sql
    }
}
