import java.io.*;
import java.sql.*;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.servlet.http.HttpServletRequest;

class H {
  byte[] h(byte[] b) throws Exception {
    return MessageDigest.getInstance("SHA-256").digest(b);
  }
}
