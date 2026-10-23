// Joern derin analiz fikstürü (Java): beklenen bulgular satır sonunda EXPECT ile işaretli.
import java.io.File;
import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class App extends HttpServlet {
    private Connection conn;

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String id = req.getParameter("id");
        String name = req.getParameter("name");
        try {
            Statement st = conn.createStatement();
            st.executeQuery("SELECT * FROM users WHERE id = '" + id + "'"); // EXPECT: sql
            PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
            ps.setString(1, id);
            ps.executeQuery();
        } catch (SQLException e) {
            throw new IOException(e);
        }
        Runtime.getRuntime().exec("ping -c 1 " + name); // EXPECT: command
        Runtime.getRuntime().exec("uptime");
        File target = new File("/srv/files/" + name); // EXPECT: path
        resp.getWriter().println("<p>" + name + "</p>"); // EXPECT: xss
        Helper.load(req.getParameter("blob"));
    }
}
