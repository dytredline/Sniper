import java.io.*;
import java.sql.*;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.servlet.http.HttpServletRequest;

class C {
  Cipher c() throws Exception {
    return Cipher.getInstance("AES/GCM/NoPadding");
  }
}
