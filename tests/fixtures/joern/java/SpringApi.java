package fixture;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.net.URL;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import lombok.Data;
import org.apache.ibatis.annotations.Select;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.SimpleEvaluationContext;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

// Spring MVC / JAX-RS / MyBatis kaynak ve hedef modelleri (Lombok'lu sınıf da içerir).
@RestController
@RequestMapping("/api")
public class SpringApi {
  private static final Logger logger = LoggerFactory.getLogger(SpringApi.class);
  private UserMapper mapper;

  @GetMapping("/cmd")
  public String cmd(String host, int count) throws Exception {
    Runtime.getRuntime().exec("ping " + host); // EXPECT: command
    Runtime.getRuntime().exec("ping -c " + count);
    return "ok";
  }

  @GetMapping("/echo")
  public String echo(@RequestParam("q") String q) {
    logger.info("q=" + q); // EXPECT: log
    return "<p>" + q + "</p>"; // EXPECT: xss
  }

  @GetMapping("/fetch")
  public String fetch(String url) throws Exception {
    new URL(url).openStream(); // EXPECT: ssrf
    new URL(url).getHost();
    return "ok";
  }

  @PostMapping("/xml")
  public String xml(@RequestBody String body) throws Exception {
    DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
    db.parse(new ByteArrayInputStream(body.getBytes())); // EXPECT: xxe
    return "ok";
  }

  @PostMapping("/xmlsafe")
  public String xmlSafe(@RequestBody String body) throws Exception {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    factory.newDocumentBuilder().parse(new ByteArrayInputStream(body.getBytes()));
    return "ok";
  }

  @GetMapping("/spel")
  public String spel(String expr) {
    new SpelExpressionParser().parseExpression(expr).getValue(); // EXPECT: eval
    return "ok";
  }

  @GetMapping("/spelsafe")
  public String spelSafe(String expr) {
    Object context = SimpleEvaluationContext.forReadOnlyDataBinding().build();
    new SpelExpressionParser().parseExpression(expr).getValue(context);
    return "ok";
  }

  @GetMapping("/user")
  public String user(String name) {
    mapper.byName(name); // EXPECT: sql
    mapper.byNameSafe(name);
    mapper.byNameXml(name); // EXPECT: sql
    return "ok";
  }

  @GetMapping("/file")
  public String file(String name) throws Exception {
    if (!checkFileName(name)) {
      return "bad";
    }
    new FileInputStream(name);
    return "ok";
  }

  @GetMapping("/file2")
  public String file2(String name) throws Exception {
    new FileInputStream(pathFilter(name));
    new FileInputStream("/data/" + name.trim()); // EXPECT: path
    return "ok";
  }

  private boolean checkFileName(String n) {
    return !n.contains("..");
  }

  private static String pathFilter(String n) {
    return n.replace("..", "");
  }
}

interface UserMapper {
  @Select("select name from users where name = '${name}'")
  java.util.List<String> byName(String name);

  @Select("select name from users where name = #{name}")
  java.util.List<String> byNameSafe(String name);

  java.util.List<String> byNameXml(String name);
}

@Controller
class Pages {
  @GetMapping("/go")
  public String go(String target) {
    return "redirect:" + target; // EXPECT: redirect
  }

  @GetMapping("/loc")
  public void loc(String target, HttpServletResponse response) throws Exception {
    response.setHeader("Location", target); // EXPECT: redirect
    response.setHeader("X-Name", target); // EXPECT: crlf
    response.sendRedirect(target); // EXPECT: redirect
  }
}

@javax.ws.rs.Path("/rs")
class RsApi {
  @javax.ws.rs.GET
  public String get(@javax.ws.rs.QueryParam("id") String id, @javax.ws.rs.core.Context javax.ws.rs.core.UriInfo info) throws Exception {
    Runtime.getRuntime().exec(id); // EXPECT: command
    return "ok";
  }
}

@Data
class Dto {
  private String name;
}
