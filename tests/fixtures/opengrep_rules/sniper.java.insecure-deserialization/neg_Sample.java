import java.io.*;
import java.sql.*;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.servlet.http.HttpServletRequest;

class Load {
  int load(DataInputStream in) throws Exception {
    return in.readInt();
  }
}
