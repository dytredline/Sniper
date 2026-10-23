import java.io.*;
import java.sql.*;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.servlet.http.HttpServletRequest;

class Dl {
  void get(HttpServletRequest request) throws Exception {
    String name = request.getParameter("file");
    FileInputStream in = new FileInputStream("/srv/files/" + name);
  }
}
