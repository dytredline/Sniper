import java.io.*;
import java.sql.*;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.servlet.http.HttpServletRequest;

class Repo {
  void find(Connection c, String name) throws Exception {
    PreparedStatement ps = c.prepareStatement("SELECT * FROM users WHERE name = ?");
    ps.setString(1, name);
    ps.executeQuery();
  }
}
