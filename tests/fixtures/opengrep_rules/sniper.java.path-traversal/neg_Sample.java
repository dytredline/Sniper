import java.io.*;
import java.sql.*;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.servlet.http.HttpServletRequest;

class Dl {
  void get(HttpServletRequest request) throws Exception {
    String id = request.getParameter("id");
    FileInputStream in = new FileInputStream("/srv/files/report.txt");
  }
}
