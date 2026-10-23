package fixture;

import javax.servlet.http.*;

// Yeni modeller için olumlu (EXPECT) ve olumsuz örnekler.
public class Models extends HttpServlet {
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String param = request.getParameter("p");
    request.getSession().setAttribute("user", param); // EXPECT: trustbound
    request.getSession().setAttribute("const", "sabit");
    javax.xml.xpath.XPath xp = javax.xml.xpath.XPathFactory.newInstance().newXPath();
    xp.evaluate("/users/user[@name='" + param + "']", (Object) null); // EXPECT: xpath
    xp.evaluate("/users/user[@name='sabit']", (Object) null);
    int num = 106;
    String dead = (7 * 18) + num > 200 ? "sabit" : param;
    Runtime.getRuntime().exec(dead);
    String live = (7 * 42) - num > 200 ? "sabit" : param;
    Runtime.getRuntime().exec(live); // EXPECT: command
    java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>();
    map.put("a", "sabit");
    map.put("b", param);
    new java.io.File((String) map.get("a"));
    new java.io.File((String) map.get("b")); // EXPECT: path
    String guess = "ABC";
    char target = guess.charAt(1);
    String chosen;
    switch (target) {
      case 'A': chosen = param; break;
      case 'B': chosen = "sabit"; break;
      default: chosen = param; break;
    }
    Runtime.getRuntime().exec(chosen);
    response.getWriter().println(org.owasp.esapi.ESAPI.encoder().encodeForHTML(param));
    response.getWriter().println(param.split(" ")[0]); // EXPECT: xss
    javax.crypto.Cipher.getInstance("DES/CBC/PKCS5Padding"); // EXPECT: weakcipher
    javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
    java.security.MessageDigest.getInstance("MD5"); // EXPECT: weakhash
    java.security.MessageDigest.getInstance("SHA-256");
    java.util.Properties props = new java.util.Properties();
    String alg = props.getProperty("hashAlgWeak", "SHA-256");
    java.security.MessageDigest.getInstance(alg); // EXPECT: weakhash
    double weak = new java.util.Random().nextDouble(); // EXPECT: weakrand
    java.util.Random secure = java.security.SecureRandom.getInstance("SHA1PRNG");
    double strong = secure.nextDouble();
    Cookie insecure = new Cookie("a", "b"); insecure.setSecure(false); // EXPECT: insecurecookie
    Cookie safe = new Cookie("a", "b"); safe.setSecure(true);
  }
}
