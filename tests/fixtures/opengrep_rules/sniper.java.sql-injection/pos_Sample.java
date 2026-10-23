import java.io.*;
import java.sql.*;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.servlet.http.HttpServletRequest;

class Repo {
  void find(Connection c, String name) throws Exception {
    Statement st = c.createStatement();
    st.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
  }
}
