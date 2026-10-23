import java.io.*;
import java.sql.*;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.servlet.http.HttpServletRequest;

class Run {
  void run(String arg) throws Exception {
    Runtime.getRuntime().exec("uptime");
    new ProcessBuilder("ls", arg).start();
  }
}
