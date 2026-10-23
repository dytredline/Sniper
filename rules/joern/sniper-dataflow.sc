// Sniper derin analiz sorgusu (Joern, Apache-2.0 API'si; sorgular Sniper'a aittir).
// Girdi: --param cpgFile=<cpg.bin> --param outFile=<jsonl> --param maxFlows=<n>
// Çıktı: satır başına bir JSON kayıt:
//   veri akışı: {"kind","label":"request|external","language","source","sink","steps":[[dosya, satır, metot], ...]}
//   kalıp:      {"kind","label":"pattern","language","source","sink","steps":[[...]],"detail":{...}}
// Kaynak kod satırı yazılmaz; yalnız konum, kaynak ve hedef çağrı adları ile algoritma adı gibi
// kısa sabitler.
//
// Kesinlik için genel (programa özgü olmayan) eleme kuralları:
//  * Sabit koşullu ölü dallar: `if`, `?:` ve sabit seçicili `switch` içinde hiç çalışmayacak
//    daldan geçen akış raporlanmaz (tam sayı/karakter sabitleri ve tek atamalı yerel değişkenler).
//  * Koleksiyonlar: sabit anahtarlı Map.put/get ve sabit indisli List.add/remove/get dizileri
//    yöntem içinde izlenir; akış, girdinin konmadığı anahtar/indisten okunuyorsa elenir.
//  * Türe özgü arındırıcılar (ör. XSS için encodeForHTML/htmlEscape, LDAP için encodeForLDAP).

import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.language.operatorextension.*
import io.joern.dataflowengineoss.language.*
import io.joern.dataflowengineoss.queryengine.{EngineConfig, EngineContext}
import io.joern.dataflowengineoss.DefaultSemantics
import io.joern.dataflowengineoss.semanticsloader.FlowSemantic

def jsonString(value: String): String = {
  val builder = new StringBuilder("\"")
  value.foreach {
    case '"'  => builder.append("\\\"")
    case '\\' => builder.append("\\\\")
    case '\n' => builder.append("\\n")
    case '\r' => builder.append("\\r")
    case '\t' => builder.append("\\t")
    case c if c < ' ' => builder.append(f"\\u${c.toInt}%04x")
    case c => builder.append(c)
  }
  builder.append('"').toString
}

def argAt(call: Call, index: Int): Option[Expression] = call.argument.l.find(_.argumentIndex == index)

def literalText(e: Expression): Option[String] = e match {
  case l: Literal if l.code.startsWith("\"") && l.code.endsWith("\"") && l.code.length >= 2 =>
    Some(l.code.substring(1, l.code.length - 1))
  case _ => None
}

// Yöntemdeki tek atamanın kaynağı (yalnız bir kez atanan yerel değişkenler için).
def singleAssignment(id: Identifier): Option[Expression] = {
  val assigns = id.method.assignment.l.filter(a => a.target.code == id.name)
  if (assigns.size == 1) Some(assigns.head.source) else None
}

// --- sabit değerlendirme -----------------------------------------------------------
def constNum(e: Expression, depth: Int = 0): Option[Long] = if (depth > 8) None else e match {
  case l: Literal =>
    val code = l.code
    if (code.length == 3 && code.startsWith("'") && code.endsWith("'")) Some(code.charAt(1).toLong)
    else scala.util.Try(code.stripSuffix("L").stripSuffix("l").toLong).toOption
  case id: Identifier => singleAssignment(id).flatMap(constNum(_, depth + 1))
  case c: Call =>
    def a(i: Int) = argAt(c, i).flatMap(constNum(_, depth + 1))
    c.name match {
      case "<operator>.addition"       => for (x <- a(1); y <- a(2)) yield x + y
      case "<operator>.subtraction"    => for (x <- a(1); y <- a(2)) yield x - y
      case "<operator>.multiplication" => for (x <- a(1); y <- a(2)) yield x * y
      case "<operator>.division"       => for (x <- a(1); y <- a(2) if y != 0) yield x / y
      case "<operator>.modulo"         => for (x <- a(1); y <- a(2) if y != 0) yield x % y
      case "<operator>.minus"          => a(1).map(-_)
      case "<operator>.cast"           => argAt(c, 2).flatMap(constNum(_, depth + 1))
      case "charAt" =>
        // "ABC".charAt(1) veya tek atamalı dize değişkeni üzerinde
        val text = argAt(c, 0).flatMap {
          case id: Identifier => singleAssignment(id).flatMap(literalText)
          case other => literalText(other)
        }
        for (s <- text; i <- a(1) if i >= 0 && i < s.length) yield s.charAt(i.toInt).toLong
      case _ => None
    }
  case _ => None
}

def constBool(e: Expression, depth: Int = 0): Option[Boolean] = if (depth > 8) None else e match {
  case l: Literal if l.code == "true" => Some(true)
  case l: Literal if l.code == "false" => Some(false)
  case c: Call =>
    def n(i: Int) = argAt(c, i).flatMap(constNum(_, depth + 1))
    def b(i: Int) = argAt(c, i).flatMap(constBool(_, depth + 1))
    c.name match {
      case "<operator>.greaterThan"       => for (x <- n(1); y <- n(2)) yield x > y
      case "<operator>.lessThan"          => for (x <- n(1); y <- n(2)) yield x < y
      case "<operator>.greaterEqualsThan" => for (x <- n(1); y <- n(2)) yield x >= y
      case "<operator>.lessEqualsThan"    => for (x <- n(1); y <- n(2)) yield x <= y
      case "<operator>.equals"            => for (x <- n(1); y <- n(2)) yield x == y
      case "<operator>.notEquals"         => for (x <- n(1); y <- n(2)) yield x != y
      case "<operator>.logicalNot"        => b(1).map(!_)
      case "<operator>.logicalAnd"        => (b(1), b(2)) match {
        case (Some(false), _) | (_, Some(false)) => Some(false)
        case (Some(true), Some(true)) => Some(true)
        case _ => None
      }
      case "<operator>.logicalOr"         => (b(1), b(2)) match {
        case (Some(true), _) | (_, Some(true)) => Some(true)
        case (Some(false), Some(false)) => Some(false)
        case _ => None
      }
      case _ => None
    }
  case _ => None
}

// switch: sabit seçicide çalışacak durum blokları (düşme/fallthrough dahil).
def liveSwitchBlocks(cs: ControlStructure): Option[Set[Long]] = {
  val selector = cs.condition.l.headOption.flatMap(c => constNum(c))
  selector.flatMap { value =>
    cs.astChildren.isBlock.l.headOption.map { body =>
      val children = body.astChildren.l.sortBy(_.order)
      // (etiketler, blok) grupları
      val groups = scala.collection.mutable.ListBuffer[(List[String], Block)]()
      var labels = List.empty[String]
      children.foreach {
        case jt: JumpTarget => labels = labels :+ jt.code
        case blk: Block => groups += ((labels, blk)); labels = Nil
        case _ =>
      }
      def matches(label: String): Boolean = {
        val lit = label.trim
        if (lit.length == 3 && lit.startsWith("'") && lit.endsWith("'")) lit.charAt(1).toLong == value
        else scala.util.Try(lit.toLong).toOption.contains(value)
      }
      val start = groups.indexWhere(_._1.exists(matches)) match {
        case -1 => groups.indexWhere(_._1.exists(_.trim == "default"))
        case i => i
      }
      if (start < 0) Set.empty[Long]
      else {
        val live = scala.collection.mutable.Set[Long]()
        var i = start
        var stop = false
        while (i < groups.size && !stop) {
          val blk = groups(i)._2
          live += blk.id()
          stop = blk.astChildren.isControlStructure.controlStructureType("BREAK|RETURN|THROW").nonEmpty ||
            blk.astChildren.isReturn.nonEmpty
          i += 1
        }
        live.toSet
      }
    }
  }
}

// Düğüm sabit koşul nedeniyle hiç çalışmayacak bir dalda mı?
def isDead(node: StoredNode): Boolean = node match {
  case start: AstNode =>
    var child: AstNode = start
    var dead = false
    var steps = 0
    while (!dead && steps < 60 && !child.isInstanceOf[Method]) {
      val parentOpt = scala.util.Try(child.astParent).toOption
      parentOpt match {
        case None => steps = 60
        case Some(parent) =>
          parent match {
            case cs: ControlStructure if cs.controlStructureType == "IF" =>
              cs.condition.l.headOption.flatMap(c => constBool(c)) match {
                case Some(true) if cs.whenFalse.id.l.contains(child.id()) => dead = true
                case Some(false) if cs.whenTrue.id.l.contains(child.id()) => dead = true
                case _ =>
              }
            case c: Call if c.name == "<operator>.conditional" =>
              val index = child match { case e: Expression => e.argumentIndex; case _ => -1 }
              argAt(c, 1).flatMap(x => constBool(x)) match {
                case Some(true) if index == 3 => dead = true
                case Some(false) if index == 2 => dead = true
                case _ =>
              }
            case blk: Block =>
              child match {
                case caseBlock: Block =>
                  scala.util.Try(blk.astParent).toOption.collect { case cs: ControlStructure if cs.controlStructureType == "SWITCH" => cs }
                    .flatMap(liveSwitchBlocks).foreach { live => if (!live.contains(caseBlock.id())) dead = true }
                case _ =>
              }
            case _ =>
          }
          child = parent
          steps += 1
      }
    }
    dead
  case _ => false
}

// Akış, sabit koşullu ?: çağrısından geçiyor ve canlı dal yalnız sabitse (girdi taşıyamaz) true.
// Joern akış yolunda argüman yerine koşul çağrısının kendisini gösterebildiği için gerekli.
def constantConditionalBlocks(elements: List[StoredNode]): Boolean = elements.exists {
  case c: Call if c.name == "<operator>.conditional" =>
    argAt(c, 1).flatMap(x => constBool(x)) match {
      case Some(cond) => argAt(c, if (cond) 2 else 3).exists(_.isInstanceOf[Literal])
      case None => false
    }
  case _ => false
}

// Değer yalnız ?: koşulundan geçiyorsa (x = girdi == 'a' ? 'a' : 'b') sonuç girdiyi taşımaz: koşulda olan
// bir yol düğümünden doğrudan koşul çağrısına geçiş.
def onlyThroughCondition(elements: List[StoredNode]): Boolean = elements.sliding(2).exists {
  case List(a, c: Call) if c.name == "<operator>.conditional" =>
    argAt(c, 1).exists(cond => cond.id() == a.id() || cond.ast.id.l.contains(a.id())) &&
      List(2, 3).forall(i => argAt(c, i).forall(_.isInstanceOf[Literal]))
  case _ => false
}

// Bilinmeyen dış çağrıda Joern argümanlar arası yayılım varsayar: mysqli_real_escape_string($conn, $x) sonrası $conn
// "kirli" sayılır ve sonraki deyimlerdeki her $conn kullanımı girdi taşır. Köprü (ikinci derece) yazma yollarında, değer
// bir kardeş argümana geçip aynı değişkenin başka satırdaki kullanımına devam ediyorsa yol kabul edilmez. (Joern yolu
// dönüş değerine giderken de kardeş argümandan geçebildiği için bu geçişlerin kendisi reddedilmez.)
def crossArgument(elements: List[StoredNode]): Boolean = elements.indices.dropRight(2).exists { i =>
  (elements(i), elements(i + 1), elements(i + 2)) match {
    case (a: Expression, b: Expression, next: Expression) =>
      (scala.util.Try(a.astParent).toOption, scala.util.Try(b.astParent).toOption) match {
        case (Some(pa: Call), Some(pb: Call)) => pa.id() == pb.id() && !pa.name.startsWith("<operator>") &&
          a.argumentIndex != b.argumentIndex && next.code == b.code && next.lineNumber != b.lineNumber
        case _ => false
      }
    case _ => false
  }
}

// Ölü düğüm bir atamanın (hedefi veya kaynağı) parçasıysa: (yöntem, hedef değişken adı).
def assignmentTargetName(node: StoredNode): Option[(Method, String)] = {
  var current: Option[AstNode] = node match { case a: AstNode => Some(a); case _ => None }
  var result: Option[(Method, String)] = None
  var steps = 0
  while (result.isEmpty && current.nonEmpty && steps < 6) {
    current.get match {
      case c: Call if c.name == "<operator>.assignment" =>
        argAt(c, 1).collect { case id: Identifier => id.name }.foreach(n => result = Some((c.method, n)))
      case _ =>
    }
    current = current.flatMap(n => scala.util.Try(n.astParent).toOption)
    steps += 1
  }
  result
}

// Koleksiyon: akış sabit anahtar/indisli bir okumadan geçiyor ama girdi oraya konmamışsa true.
def wrongCollectionSlot(elements: List[StoredNode]): Boolean = {
  val ids = elements.map(_.id()).toSet
  def receiverName(c: Call): Option[String] = argAt(c, 0).collect { case id: Identifier => id.name }
  // Yalnız dönüş değeri yolda olan okumalar: get çağrısının kendisi ya da onu doğrudan saran
  // (ör. tür dönüşümü) yol düğümü. Yalnız alıcısı yolda geçen başka get'ler sayılmaz.
  val callsOnPath = elements.collect { case c: Call => c }
  val gets = (callsOnPath.filter(_.name == "get") ++
    callsOnPath.flatMap(_.argument.l.collect { case g: Call if g.name == "get" => g })).distinctBy(_.id())
  gets.exists { get =>
    receiverName(get) match {
      case None => false
      case Some(name) =>
        val method = get.method
        val calls = method.call.l.filter(c => receiverName(c).contains(name)).sortBy(c => (c.lineNumber.map(_.intValue).getOrElse(0), c.columnNumber.map(_.intValue).getOrElse(0)))
        argAt(get, 1) match {
          case Some(keyLit) if literalText(keyLit).nonEmpty =>
            // Map: girdiyi taşıyan put çağrılarının anahtarları
            val key = literalText(keyLit).get
            val puts = calls.filter(c => c.name == "put")
            val onPath = puts.filter(c => argAt(c, 2).exists(a => ids.contains(a.id())))
            // Yolda put argümanı görünmüyorsa sabit olmayan her değer girdi taşıyabilir sayılır.
            val taintedPuts = if (onPath.nonEmpty) onPath else puts.filter(c => argAt(c, 2).exists(a => !a.isInstanceOf[Literal]))
            taintedPuts.nonEmpty && taintedPuts.forall(p => argAt(p, 1).flatMap(literalText).exists(_ != key))
          case Some(indexExpr) =>
            constNum(indexExpr) match {
              case None => false
              case Some(index) =>
                // List: get öncesindeki add/remove dizisini canlandır
                val before = calls.filter(c => c.lineNumber.map(_.intValue).getOrElse(0) <= get.lineNumber.map(_.intValue).getOrElse(0) && c.id() != get.id())
                val addArgs = before.filter(_.name == "add").flatMap(c => argAt(c, 1))
                val anyOnPath = addArgs.exists(a => ids.contains(a.id()))
                // (argüman kimliği, girdi taşıyabilir mi)
                val items = scala.collection.mutable.ArrayBuffer[(Long, Boolean)]()
                var known = true
                before.foreach { c =>
                  c.name match {
                    case "add" if c.argument.l.count(_.argumentIndex >= 1) == 1 =>
                      argAt(c, 1).foreach { a =>
                        items += ((a.id(), if (anyOnPath) ids.contains(a.id()) else !a.isInstanceOf[Literal]))
                      }
                    case "remove" => argAt(c, 1).flatMap(constNum(_)) match {
                      case Some(i) if i >= 0 && i < items.size => items.remove(i.toInt)
                      case _ => known = false
                    }
                    case "add" | "set" | "clear" | "addAll" => known = false
                    case _ =>
                  }
                }
                known && index >= 0 && index < items.size && !items(index.toInt)._2
            }
          case None => false
        }
    }
  }
}

val SANITIZERS: Map[String, scala.util.matching.Regex] = Map(
  "xss" -> "(?i)encodeForHTML|encodeForHTMLAttribute|encodeForJavaScript|htmlEscape|escapeHtml|escapeHtml4|escapeXml|forHtml|sanitize".r,
  "ldap" -> "(?i)encodeForLDAP|encodeForDN".r,
  "xpath" -> "(?i)encodeForXPath".r,
  "sql" -> "(?i)encodeForSQL".r,
  "command" -> "(?i)encodeForOS".r,
)

// SANITIZERS (Java/ESAPI adları, kısmi eşleşme) yalnız Java/C'de; dinamik dillerde dile özgü tam ad listesi ve
// koşullu uygulama denetimi (throughCall) kullanılır.
def sanitized(kind: String, elements: List[StoredNode]): Boolean = !dynamicLanguage && SANITIZERS.get(kind).exists { re =>
  elements.exists {
    case c: Call => re.findFirstIn(c.name).nonEmpty
    case e: Expression => scala.util.Try(e.astParent).toOption.exists {
      case c: Call => re.findFirstIn(c.name).nonEmpty && c.name != "<operator>.assignment"
      case _ => false
    }
    case _ => false
  }
} || projectSanitized(kind, elements) || guarded(kind, elements) || runtimeGuarded(kind, elements) ||
  languageSanitized(kind, elements)

// PHP / Go / Ruby / C# kütüphane arındırıcıları (tam ad eşleşmesi; dönüş değeri yolda olmalı).
// Sayısal dönüşüm her tür için arındırıcıdır.
val NUMERIC_CONVERSION = "intval|floatval|boolval|absint|Atoi|ParseInt|ParseUint|ParseFloat|ParseBool|to_i|to_f|to_r|Integer|Float|ToInt16|ToInt32|ToInt64|ToDouble|ToDecimal|" +
  // Özet/onaltılık çıktılar da enjeksiyon için zararsızdır.
  "md5|sha1|crc32|hash|hash_hmac|password_hash|bin2hex|uniqid|md5_file|sha1_file|hexdigest|HexEncode"
val LANGUAGE_SANITIZERS: Map[String, String] = Map(
  "xss" -> "htmlspecialchars|htmlentities|strip_tags|esc_html|esc_attr|HTMLEscapeString|JSEscapeString|EscapeString|QueryEscape|PathEscape|html_escape|escape_html|escape_once|h|sanitize|HtmlEncode|HtmlAttributeEncode|JavaScriptStringEncode|UrlEncode|urlencode|rawurlencode",
  "sql" -> "mysqli_real_escape_string|mysql_real_escape_string|real_escape_string|pg_escape_string|pg_escape_literal|sqlite_escape_string|addslashes|quote|sanitize_sql|sanitize_sql_array|sanitize_sql_like|quote_string",
  "command" -> "escapeshellarg|escapeshellcmd|shellescape|shelljoin",
  "path" -> "basename|GetFileName",
  "redirect" -> "url_for",
)
// Kaçışlama (sayısal olmayan) SQL arındırıcıları yalnız değer sorguda tırnak içindeyse etkilidir.
val QUOTING_SQL = "mysqli_real_escape_string|mysql_real_escape_string|real_escape_string|pg_escape_string|sqlite_escape_string|addslashes|quote_string"
val CONCAT_CALLS = "<operator>\\.(concat|addition|formatString|formattedValue|plus)|encaps|Sprintf|sprintf|format"
def quotedInQuery(elements: List[StoredNode]): Boolean = {
  val ids = elements.map(_.id()).toSet
  elements.collect { case e: Expression => e }.flatMap(c => scala.util.Try(c.astParent).toOption.collect { case p: Call => (p, c) })
    .exists { case (parent, child) =>
      parent.name.matches(CONCAT_CALLS) && parent.argument.l.find(_.argumentIndex == child.argumentIndex - 1)
        .exists(prev => prev.code.replaceAll("[\"]+$", "").replace("\\'", "'").endsWith("'"))
    }
}
// JavaScript/TypeScript ve Python kütüphane arındırıcıları (yalnız bu dillerde; diğer dillerin sonuçları değişmesin).
// Python'da şablon/JSON üreticileri (render_template, jsonify) çıktıyı kendisi kaçışlar ya da HTML üretmez.
val SCRIPT_NUMERIC = "int|float|bool|len|parseInt|parseFloat|Number|Boolean|isNaN|toFixed|uuid4|UUID"
val SCRIPT_SANITIZERS: Map[String, String] = Map(
  "xss" -> "escape|escapeHtml|escapeHTML|escape_html|html_escape|encodeURIComponent|encodeURI|encodeForHTML|sanitize|sanitizeHtml|clean|linkify|xss|filterXSS|inHTMLData|quote|quote_plus|urlencode|render_template|render|render_to_string|jsonify|dumps|json|stringify|tojson|url_for|redirect|abort|send_file|send_from_directory|JsonResponse",
  "sql" -> "escape|escapeId|literal|quote_ident|quote_literal|format_ident|format_literal|mogrify|Identifier|Literal",
  "command" -> "quote|shlex_quote|shellescape|shellQuote|escapeShellArg",
  "path" -> "basename|secure_filename|safe_join|sanitize_filename|sanitizeFilename",
  "redirect" -> "url_for|url_has_allowed_host_and_scheme|is_safe_url|safe_url",
  "ssrf" -> "url_for",
  "ssti" -> "escape",
  "eval" -> "literal_eval",
)
// Değeri girdiden bağımsız sonuç üreten çağrılar (JS/Python; bilinmeyen çağrılarda Joern argümanı dönüşe taşır):
// imzası doğrulanan JWT içeriği, parola/özet karşılaştırması, veritabanı sorgu sonuçları, dosya varlık denetimi.
// Kayıtlı veri (ikinci derece) akışları hızlı motorun işidir.
val SCRIPT_BARRIERS = "verify|compare|compareSync|hash|hashSync|check_password|check_password_hash|find|findOne|findById|" +
  "findAll|findAndCountAll|findByPk|toArray|countDocuments|aggregate|existsSync|exists|get_object_or_404|fetchone|fetchall|" +
  "fetchmany|first|one_or_none|scalar|scalars|get_or_404|first_or_404|login|authenticate|" +
  // Dosya içeriği (yolu girdiden olsa bile içerik saldırganın değil; açık yol aşımı hedefinde raporlanır).
  "read|readline|readlines|read_text|read_bytes|readFileSync"
def scriptLanguage: Boolean = Set("javascript", "python").contains(LANG)
// JS/Python: Joern yolu hedef ifadesinin içindeki arındırıcı çağrısını atlayabiliyor ('<p>' + escapeHtml(x) yolunda
// x → this → hedef). Hedeften önceki yol düğümünden hedefe kadar AST ataları arasında arındırıcı varsa akış arındırılmıştır.
def scriptAstSanitized(kind: String, elements: List[StoredNode]): Boolean = scriptLanguage && elements.size >= 2 && {
  val sinkId = elements.last.id()
  elements.dropRight(1).exists { e =>
    val chain = Iterator.iterate(Option(e))(_.flatMap(n => scala.util.Try(n.asInstanceOf[AstNode].astParent: StoredNode).toOption))
      .drop(1).take(12).flatten.toList
    val idx = chain.indexWhere(_.id() == sinkId)
    idx >= 0 && chain.take(idx + 1).exists {
      case c: Call => c.name.matches(SCRIPT_NUMERIC) || SCRIPT_SANITIZERS.get(kind).exists(re => c.name.matches(re))
      case _ => false
    }
  }
}
// Yönlendirme: yoldaki bir yöntemde, yoldaki değişkeni güvenli URL denetleyicisine veren bir çağrı varsa (sonucu
// koşulda doğrudan ya da bir değişken üzerinden kullanılabilir) akış korunmuş sayılır.
val SAFE_URL_CHECKS = "url_has_allowed_host_and_scheme|is_safe_url|is_safe_redirect|isSafeUrl|isSafeRedirect|isLocalUrl|is_local_url"
def scriptRedirectChecked(kind: String, elements: List[StoredNode]): Boolean = scriptLanguage && kind == "redirect" && {
  val byMethod = elements.collect { case e: CfgNode => e }.groupBy(_.method)
  byMethod.exists { case (method, nodes) =>
    val names = nodes.collect { case id: Identifier => id.name; case p: MethodParameterIn => p.name }.toSet
    method.call.name(SAFE_URL_CHECKS).l.exists(_.argument.ast.isIdentifier.name.l.exists(names.contains))
  }
}
def languageSanitized(kind: String, elements: List[StoredNode]): Boolean = scriptAstSanitized(kind, elements) ||
  scriptRedirectChecked(kind, elements) || throughCall(elements, c =>
  (scriptLanguage && (c.name.matches(SCRIPT_NUMERIC) || c.name.matches(SCRIPT_BARRIERS) ||
    SCRIPT_SANITIZERS.get(kind).exists(re => c.name.matches(re)))) ||
  c.name.matches(NUMERIC_CONVERSION) || c.code.matches("(?s)^\\((int|integer|float|double|bool|boolean)\\).*") ||
    (kind == "path" && c.methodFullName.matches("path(/filepath)?\\.Base(:.*)?")) ||
    LANGUAGE_SANITIZERS.get(kind).exists(re => c.name.matches(re) && (!c.name.matches(QUOTING_SQL) || quotedInQuery(elements))))

// Çalışma zamanı koruması: yoldaki bir yöntemde, sonucu kullanılmayan (deyim olarak çağrılan) ve adı
// hedef türüne özgü sözcükle birlikte hook/guard/protect içeren proje yöntemi (ör. startSSRFHook()).
def runtimeGuarded(kind: String, elements: List[StoredNode]): Boolean = KIND_WORDS.get(kind).exists { words =>
  elements.collect { case e: CfgNode => e.method }.distinct.exists(_.call.l.exists(c =>
    isProjectMethod(c) && c.name.matches(words) && c.name.matches("(?i).*(hook|guard|protect).*") &&
      scala.util.Try(c.astParent).toOption.exists(_.isInstanceOf[Block])))
}

// Projede tanımlı (dış kütüphane olmayan) arındırıcı: adı filter/sanitize/escape/encode/clean/valid…
// içerir ve ya hedef türüne özgü bir anahtar sözcük taşır (cmdFilter, sqlFilter, pathFilter, …) ya da
// alana özgü sözcük taşımayan genel bir addır (encode, escape) — genel adlar yalnız XSS/günlük için.
val SANITIZER_NAME = "(?i).*(filter|sanitiz|sanitis|escape|encode|clean|valid|whitelist|allowlist).*"
val KIND_WORDS: Map[String, String] = Map(
  "command" -> "(?i).*(cmd|command|shell|exec|os).*", "sql" -> "(?i).*(sql|query).*", "path" -> "(?i).*(path|file|dir).*",
  "ssrf" -> "(?i).*(url|uri|host|ssrf|domain).*", "redirect" -> "(?i).*(url|uri|host|redirect|domain).*",
  "xss" -> "(?i).*(html|xss|script).*", "log" -> "(?i).*(log|crlf|newline).*", "crlf" -> "(?i).*(crlf|header|newline).*",
  "ldap" -> "(?i).*ldap.*", "xpath" -> "(?i).*xpath.*", "eval" -> "(?i).*(expr|script|spel|eval).*")
val DOMAIN_WORDS = "(?i).*(cmd|command|shell|sql|query|path|file|dir|url|uri|host|ssrf|domain|redirect|html|xss|script|log|crlf|header|ldap|xpath|expr|spel|eval).*"
def isProjectMethod(c: Call): Boolean = c.callee.l.exists(m => !m.isExternal)
def sanitizerFor(kind: String, c: Call): Boolean =
  isProjectMethod(c) && c.name.matches(SANITIZER_NAME) && (
    KIND_WORDS.get(kind).exists(c.name.matches(_)) ||
    (!c.name.matches(DOMAIN_WORDS) && Set("xss", "log", "crlf").contains(kind)))
// Değer yolda bir arındırıcıdan geçiyor mu? Yalnız arındırıcı ÇAĞRISI (dönüş değeri) yoldaysa: yoldaki bir
// ifadenin arındırıcıya argüman olması yetmez, çünkü Joern yolları aynı değişkenin ardışık kullanımlarından
// (ve gövdeli yöntemlerde parametre çıkışından) geçer: pathFilter(name); f(name) → ham değer f'ye ulaşır.
def throughCall(elements: List[StoredNode], pred: Call => Boolean): Boolean = elements.zipWithIndex.exists {
  case (c: Call, i) if pred(c) =>
    // Arındırıcı, hedefin yönteminden çağrılan bir yöntemin gövdesindeyse koşul denetimi o yönteme yapılan
    // çağrı noktasına uygulanır; aksi hâlde (aynı yöntem ya da PHP dosyalar arası küresel önek) arındırıcının
    // kendi yönteminde yapılır.
    val sinkMethod = scala.util.Try(elements.last.asInstanceOf[CfgNode].method).toOption
    val anchor = if (sinkMethod.contains(c.method)) c
      else elements.drop(i + 1).collectFirst {
        case k: Call if sinkMethod.contains(k.method) && k.callee.l.exists(_.id() == c.method.id()) => k
      }.getOrElse(c)
    !conditionallyApplied(anchor, elements.last)
  case _ => false
}
// Dinamik dillerde arındırıcı yalnız bir if dalında uygulanıp hedef o dalın dışındaysa
// (if level == high { x = escape(x) } … sink(x)) diğer dalda ham değer hedefe ulaşır. Arındırılmış değerin
// atandığı değişkenin dal dışında başka tanımı yoksa (if (isset($_GET['x'])) { $x = escape($_GET['x']); … })
// arındırma bu veri için koşulsuzdur.
// (Java/C'de Joern'ün yol seçimi ve sabit katlama kuralları korunur.)
def conditionallyApplied(c: Call, sink: StoredNode): Boolean = dynamicLanguage && scala.util.Try {
  val assignment = Iterator.iterate(Option(c: AstNode))(_.flatMap(n => scala.util.Try(n.astParent).toOption)).take(8).flatten
    .collectFirst { case a: Call if a.name.startsWith("<operator>.assignment") => a }
  val target = assignment.flatMap(a => argAt(a, 1)).collect { case id: Identifier => id }
  c.method.controlStructure.isIf.l.exists { cs =>
    List(cs.whenTrue.ast.l, cs.whenFalse.ast.l).exists { branch =>
      val inBranch = branch.map(_.id()).toSet
      inBranch.contains(c.id()) && !inBranch.contains(sink.id()) && (target match {
        case Some(v) =>
          c.method.call.name("<operator>\\.assignment.*").l.exists(o => !inBranch.contains(o.id()) &&
            argAt(o, 1).exists(_.code == v.code)) || c.method.parameter.nameExact(v.name).nonEmpty
        case None => true
      })
    }
  }
}.getOrElse(false)
def projectSanitized(kind: String, elements: List[StoredNode]): Boolean = throughCall(elements, c => sanitizerFor(kind, c))

// Koruma koşulu: yoldaki bir yöntemde, yoldaki değişkeni bir doğrulayıcıya (check*/valid*/verify*/
// *Filter/*White*/*Allow*) veren ve dallarından biri dönen/atan bir if varsa akış korunmuş sayılır.
// Yalnız şema denetleyen (isHttp) gibi adlar doğrulayıcı sayılmaz.
val GUARD_NAME = "(?i).*(check|valid|verify|filter|white|allow|safe).*"
// Betiğin çözümlediği dil (main içinde atanır); dinamik dil kuralları Java/C sonuçlarını değiştirmesin.
var LANG = "java"
// PHP/Go/Ruby/C# yerleşik doğrulayıcıları (Java'da yalnız proje içi doğrulayıcılar sayılır).
val BUILTIN_VALIDATORS = "(?i)(is_numeric|ctype_\\w+|filter_var|is_int|is_integer|in_array|preg_match|MatchString|IsMatch|TryParse|match\\?|include\\?|valid\\w*|is_?valid\\w*|check\\w*|verify\\w*|allowed\\w*|(white|allow)list\\w*)"
def dynamicLanguage: Boolean = Set("php", "go", "ruby", "csharp", "javascript", "python").contains(LANG)
// JS/Python yerleşik ve yaygın kütüphane doğrulayıcıları (str.isdigit, re.fullmatch, validator.js isInt …).
val SCRIPT_VALIDATORS = "(?i)(isdigit|isnumeric|isdecimal|isalnum|isalpha|isidentifier|fullmatch|match|test|isInteger|isSafeInteger|isFinite|includes|has|startsWith|startswith|url_has_allowed_host_and_scheme|is_safe_url|is(Int|Numeric|Alphanumeric|UUID|Email|URL|MongoId|Hexadecimal))"
def validatorCall(c: Call): Boolean =
  (c.name.matches(GUARD_NAME) && isProjectMethod(c)) || (dynamicLanguage && c.name.matches(BUILTIN_VALIDATORS)) ||
    (scriptLanguage && c.name.matches(SCRIPT_VALIDATORS))
def guarded(kind: String, elements: List[StoredNode]): Boolean = {
  if (!Set("ssrf", "redirect", "path", "command", "sql", "xss", "eval", "ssti").contains(kind)) false
  else {
    val byMethod = elements.collect { case e: CfgNode => e }.groupBy(_.method)
    byMethod.exists { case (method, nodes) =>
      val names = nodes.collect { case id: Identifier => id.name; case p: MethodParameterIn => p.name }.toSet
      method.controlStructure.isIf.l.exists { cs =>
        val terminates = (cs.whenTrue.ast ++ cs.whenFalse.ast).l.exists(n => n.isInstanceOf[Return] ||
          (n.isInstanceOf[ControlStructure] && n.asInstanceOf[ControlStructure].controlStructureType == "THROW") ||
          (dynamicLanguage && n.isInstanceOf[Call] && n.asInstanceOf[Call].name.matches("exit|die")) ||
          (scriptLanguage && n.isInstanceOf[Call] && n.asInstanceOf[Call].name.matches("abort|<operator>\\.throw|raise|sys\\.exit")))
        terminates && cs.condition.ast.isCall.l.exists(c => validatorCall(c) &&
          c.argument.ast.isIdentifier.name.l.exists(names.contains))
      } || (dynamicLanguage && dominatedByValidation(method, names, nodes))
    }
  }
}
// Hedef, koşulu yoldaki değişkeni doğrulayan bir if'in DOĞRU dalında mı (if (is_numeric($x)) { sink($x) })?
def dominatedByValidation(method: Method, names: Set[String], nodes: List[CfgNode]): Boolean = {
  val ids = nodes.map(_.id()).toSet
  method.controlStructure.isIf.l.exists { cs =>
    cs.whenTrue.ast.l.exists(n => ids.contains(n.id())) &&
      cs.condition.ast.isCall.l.exists(c => validatorCall(c) && c.argument.ast.isIdentifier.name.l.exists(names.contains) &&
        !scala.util.Try(c.astParent).toOption.exists { case p: Call => p.name == "<operator>.logicalNot"; case _ => false })
  }
}

// Yöntem içinde XML ayrıştırıcı sertleştirmesi (DOCTYPE/dış varlık kapatma) var mı?
val XXE_HARDENING = "(?i).*(disallow-doctype-decl|external-general-entities|external-parameter-entities|load-external-dtd|ACCESS_EXTERNAL_DTD|ACCESS_EXTERNAL_SCHEMA|SUPPORT_DTD|IS_SUPPORTING_EXTERNAL_ENTITIES|FEATURE_SECURE_PROCESSING).*"
def xxeHardened(method: Method): Boolean =
  method.call.name("setFeature|setProperty|setAttribute|setExpandEntityReferences").l.exists { c =>
    c.argument.l.exists(a => a.code.matches(XXE_HARDENING)) ||
    (c.name == "setExpandEntityReferences" && argAt(c, 1).exists(_.code == "false"))
  }

// Hedef çağrısının bulunduğu yöntemde türe özgü güvenli yapılandırma (yanlış alarm önleme).
def safeConfiguration(kind: String, sinkCall: Option[Call]): Boolean = sinkCall.exists { call =>
  val method = call.method
  val code = call.methodFullName
  kind match {
    case "xxe" => xxeHardened(method)
    case "eval" if code.contains("expression") =>
      method.ast.isCall.code(".*SimpleEvaluationContext.*").nonEmpty
    case "eval" if code.contains("ExpressRunner") =>
      method.call.name("setForbidInvokeSecurityRiskMethods").l.exists(c => argAt(c, 1).exists(_.code == "true")) ||
        method.call.name("addSecureMethod|setSecureMethods").nonEmpty
    // resolveClass'ı geçersiz kılan (sınıf allowlist/denylist) ObjectInputStream alt sınıfının super(...) çağrısı.
    case "deserialize" if code.startsWith("java.io.ObjectInputStream.<init>") =>
      method.definingTypeDecl.method.name("resolveClass|resolveProxyClass").nonEmpty
    case "deserialize" if code.contains("snakeyaml") =>
      argAt(call, 0).collect { case id: Identifier => id }.exists(id =>
        id.method.assignment.l.exists(a => a.target.code == id.name && a.source.code.contains("SafeConstructor")))
    case "deserialize" if code.contains("ObjectMapper") =>
      !method.call.name("enableDefaultTyping|activateDefaultTyping|activateDefaultTypingAsProperty").nonEmpty
    case _ => false
  }
}

// Rastgele sayı üreteci gerçekte SecureRandom mı? (bildirilen tür java.util.Random olsa da
// atanan değer veya tüm çağıranların geçirdiği değer SecureRandom olabilir)
def isSecureRandom(e: Expression, depth: Int = 0): Boolean = if (depth > 4) false else {
  val secureType = (t: String) => t.contains("SecureRandom")
  e.evalType.l.exists(secureType) || (e match {
    case c: Call => c.methodFullName.contains("SecureRandom") || c.code.contains("SecureRandom")
    case id: Identifier =>
      val sources = id.method.assignment.l.filter(a => a.target.code == id.name).map(_.source)
      val params = id.method.parameter.nameExact(id.name).l
      if (sources.nonEmpty) sources.forall(s => isSecureRandom(s, depth + 1))
      else if (params.nonEmpty) {
        val index = params.head.index
        val callers = id.method.callIn.l
        callers.nonEmpty && callers.forall(call => argAt(call, index).exists(a => isSecureRandom(a, depth + 1)))
      } else false
    case _ => false
  })
}

// Alıcının türü: çözümlenemeyen kütüphane çağrılarında (jar yok) alan/yerel değişken
// bildirimindeki tür adına bakılır (ör. "DatabaseHelper.JDBCtemplate" → JdbcTemplate).
def receiverType(c: Call): List[String] = argAt(c, 0).toList.flatMap { r =>
  val direct = r.evalType.l.filterNot(t => t == "ANY" || t.contains("unresolved"))
  if (direct.nonEmpty) direct
  else r match {
    case fa: Call if fa.name == "<operator>.fieldAccess" =>
      val field = fa.argument.l.lastOption.map(_.code).getOrElse("")
      cpg.member.nameExact(field).typeFullName.l
    case id: Identifier =>
      id.method.local.nameExact(id.name).typeFullName.l ++ id.method.parameter.nameExact(id.name).typeFullName.l
    case _ => Nil
  }
}

val HANDLER_ANNOTATIONS = "RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|MessageMapping|GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS"
// İstek girdisi olmayan işleyici parametre türleri (yanıt, model, oturum, kimlik, sayısal türler…).
val NON_INPUT_PARAM_TYPES = "(?i)(.*(HttpServletResponse|ServletResponse|ServerHttpResponse|Model|ModelMap|ModelAndView|RedirectAttributes|BindingResult|Errors|HttpSession|WebSession|Principal|Authentication|Locale|TimeZone|ZoneId|SessionStatus|UriComponentsBuilder|WebRequest|HttpServletRequest|ServletRequest|ServerHttpRequest|ServerWebExchange|HttpEntity|HttpMethod|InputStream|OutputStream|Writer|Reader|Pageable|Sort)|int|long|short|byte|double|float|boolean|char|java\\.lang\\.(Integer|Long|Short|Byte|Double|Float|Boolean|Character|Number)|java\\.math\\..*|java\\.util\\.(UUID|Date)|java\\.time\\..*)"

// Algoritma argümanının tanımı: sabit, özellik (anahtar+varsayılan) veya bilinmeyen.
def algorithmDetail(e: Expression, depth: Int = 0): String = if (depth > 4) "{}" else e match {
  case _ if literalText(e).nonEmpty => s"""{"literal":${jsonString(literalText(e).get)}}"""
  case id: Identifier => singleAssignment(id).map(algorithmDetail(_, depth + 1)).getOrElse("{}")
  case c: Call if c.name == "getProperty" =>
    val key = argAt(c, 1).flatMap(literalText).getOrElse("")
    val default = argAt(c, 2).flatMap(literalText)
    s"""{"property":${jsonString(key)}""" + default.map(d => s""","default":${jsonString(d)}""").getOrElse("") + "}"
  case _ => "{}"
}

@main def main(cpgFile: String, outFile: String, maxFlows: Int = 200): Unit = {
  importCpg(cpgFile)
  val graph = cpg
  if (graph.metaData.overlays.toList.forall(_ != "dataflowOss")) {
    run.ossdataflow
  }
  // Varsayılan semantik düzeltmeleri:
  //  * java.lang.String.split: Joern varsayılanında alıcıdan dönüş değerine akış yok (yalnız 0→0);
  //    parçalar alıcıdan gelir → 0→-1 eklenir.
  //  * Gövdesi olmayan soyut/arayüz metotları (dinamik dağıtım): argüman ve alıcı → dönüş
  //    (bilinmeyen çağrılardaki ihtiyatlı varsayım; uygulamalar ayrıca analiz edilmez).
  val abstractMethods = graph.method.isExternal(false)
    .filter(m => m.modifier.modifierType.l.contains("ABSTRACT") && m.parameter.size > 0).l
  val extraSemantics: List[FlowSemantic] =
    List(
      FlowSemantic.from("java.lang.String.split:java.lang.String[](java.lang.String)", List((0, 0), (0, -1), (1, 1))),
      FlowSemantic.from("java.lang.String.split:java.lang.String[](java.lang.String,int)", List((0, 0), (0, -1), (1, 1), (2, 2))),
    ) ++ abstractMethods.map(m => FlowSemantic.from(m.fullName, (0 until m.parameter.size).toList.flatMap(i => List((i, i), (i, -1)))))
  implicit val engineContext: EngineContext = EngineContext(DefaultSemantics().plus(extraSemantics), EngineConfig())

  val language = graph.metaData.language.headOption.getOrElse("").toUpperCase
  val isJava = (language.contains("JAVA") && !language.contains("JAVASCRIPT")) || language.contains("KOTLIN")
  LANG =
    if (language.contains("KOTLIN")) "kotlin" else if (language.contains("JAVA") && !language.contains("JAVASCRIPT")) "java"
    else if (language.contains("PHP")) "php" else if (language.contains("GO")) "go"
    else if (language.contains("RUBY")) "ruby" else if (language.contains("CSHARP")) "csharp"
    else if (language.contains("JSSRC") || language.contains("JAVASCRIPT")) "javascript"
    else if (language.contains("PYTHON")) "python" else "c"
  val lang = LANG

  // (hedef türü, hedef adı) ← düğüm kimliği
  val sinkInfo = scala.collection.mutable.Map[Long, (String, String)]()
  def sink(kind: String, calls: Iterator[Call], argIndexes: Seq[Int], dropLiterals: Boolean = false): List[Expression] = {
    calls.l.flatMap { call =>
      val args = if (argIndexes.isEmpty) call.argument.l.filter(_.argumentIndex >= 1)
                 else call.argument.l.filter(a => argIndexes.contains(a.argumentIndex))
      // Yapıcılar "<init>" yerine "new Sınıf" olarak adlandırılır.
      val label =
        if (call.name == "<init>") "new " + call.methodFullName.takeWhile(_ != ':').stripSuffix(".<init>").split('.').last
        else if (call.name == "<operator>.fieldAccess") call.argument.l.lastOption.map(_.code).getOrElse("alan")
        else if (call.name.startsWith("<operator>.")) call.name.stripPrefix("<operator>.")
        else call.name
      args.filterNot(a => dropLiterals && a.isInstanceOf[Literal]).map { arg =>
        sinkInfo(arg.id()) = (kind, label)
        arg
      }
    }
  }
  // İşleyicinin dönüş değeri: @ResponseBody / @RestController + String dönüşü → yanıt gövdesi (XSS);
  // "redirect:" + girdi → yönlendirme.
  def handlerMethods: List[Method] = graph.method.where(_.annotation.name(HANDLER_ANNOTATIONS)).l
  def returnExpressions(m: Method): List[Expression] = m.ast.isReturn.astChildren.collect { case e: Expression => e }.l
  def xssReturns(): List[Expression] = handlerMethods.filter { m =>
    val restful = m.annotation.name.l.contains("ResponseBody") ||
      m.definingTypeDecl.annotation.name.l.exists(n => n == "RestController" || n == "Path")
    restful && m.methodReturn.typeFullName.matches("java\\.lang\\.(String|Object|CharSequence)")
  }.flatMap(m => returnExpressions(m).filterNot(_.isInstanceOf[Literal]).map { e =>
    sinkInfo(e.id()) = ("xss", "yanıt gövdesi (@ResponseBody)"); e
  })
  def redirectReturns(): List[Expression] = handlerMethods.flatMap(m => returnExpressions(m).filter(e =>
    e.code.contains("\"redirect:") && !e.isInstanceOf[Literal]).map { e =>
      sinkInfo(e.id()) = ("redirect", "\"redirect:\" dönüşü"); e
    })
  // MyBatis XML eşleyicilerinde ${} içeren ifadelerin nitelikli adları (Python tarafından yazılır).
  val mybatisUnsafe: List[String] = {
    val file = new java.io.File(outFile + ".mybatis")
    if (file.isFile && file.length < 2000000)
      scala.io.Source.fromFile(file, "UTF-8").getLines().map(_.trim).filter(_.matches("[\\w.$]{1,300}")).toList
    else Nil
  }
  val sourceInfo = scala.collection.mutable.Map[Long, String]()
  def remember[T <: CfgNode](nodes: List[T], name: T => String): List[T] = {
    nodes.foreach(n => sourceInfo(n.id()) = name(n)); nodes
  }

  // ---- PHP / Go / Ruby / C# / JavaScript-TypeScript / Python modelleri ----
  def fieldName(c: Call): String = c.argument.l.lastOption.map(_.code.stripPrefix("@")).getOrElse("")
  def fieldAccesses: List[Call] = graph.call.nameExact("<operator>.fieldAccess").l
  def assignTarget(a: Call): Expression = argAt(a, 1).getOrElse(a)
  def fieldAssignments(field: String): List[Call] = graph.assignment.l.filter(a => a.target match {
    case fa: Call if fa.name == "<operator>.fieldAccess" => fieldName(fa).matches(field)
    case _ => false
  })
  def assignSink(kind: String, assignments: List[Call]): List[Expression] = assignments.flatMap { a =>
    argAt(a, 2).filterNot(_.isInstanceOf[Literal]).map { src =>
      sinkInfo(src.id()) = (kind, assignTarget(a).code.split('.').lastOption.getOrElse("alan") + " ="); src
    }
  }
  // Alanın/yerelin bildirilen türü (C# WebForms denetimleri, Go istek nesnesi …).
  def declaredType(e: Expression): String = e match {
    case fa: Call if fa.name == "<operator>.fieldAccess" => graph.member.nameExact(fieldName(fa)).typeFullName.headOption.getOrElse("")
    case id: Identifier => (id.method.local.nameExact(id.name).typeFullName.l ++ id.method.parameter.nameExact(id.name).typeFullName.l ++
      graph.member.nameExact(id.name).typeFullName.l).headOption.getOrElse("")
    case _ => ""
  }
  def receiverCode(c: Call): String = c.code.takeWhile(_ != '(')
  val CSHARP_NON_INPUT = "(?i)(System\\.)?(u?int\\d*|long|short|byte|sbyte|bool(ean)?|double|single|float|decimal|char|DateTime(Offset)?|Guid|TimeSpan)\\??|.*(CancellationToken|HttpContext|HttpResponse|ILogger.*|IFormCollection)"

  // Sabit göreli yolla başlayan yönlendirme ("/urun/" + id, `/login?u=${x}`): hedef ana makine sabittir.
  def fixedPathPrefix(e: Expression): Boolean = e.code.matches("(?s)^(<operator>\\.formatString\\()?[\"'`]/[^/\\\\].*") || fixedHost(e)
  // Sabit şema + ana makineyle başlayan adres ("https://api.x.com/v1/" + id, `http://h?x=${y}`): yalnız yol/sorgu
  // girdiden gelir; SSRF/açık yönlendirme değildir (kısmi SSRF hızlı motorda ayrı sınıftır).
  def fixedHost(e: Expression): Boolean = e.code.matches("(?s)^(<operator>\\.formatString\\()?(f)?[\"'`]https?://[^/?#\"'`$\\{}]+[/?#].*")
  def otherLanguageModel(lang: String): (List[CfgNode], List[CfgNode], List[Expression]) = lang match {
    case "php" =>
      val request: List[CfgNode] =
        // Süper küreseller: Joern akışı tanımlayıcıdan değil, $_GET["x"] erişiminden başlatabiliyor.
        remember(graph.identifier.name("_GET|_POST|_REQUEST|_COOKIE|_FILES|_SERVER").l.map(i =>
          scala.util.Try(i.astParent).toOption.collect { case c: Call if c.name == "<operator>.indexAccess" => c: CfgNode }.getOrElse(i: CfgNode)),
          (n: CfgNode) => n.code.takeWhile(_ != '[')) ++
        remember((graph.call.name("getallheaders|apache_request_headers|filter_input|filter_input_array").l ++
          graph.call.name("file_get_contents").filter(c => argAt(c, 1).exists(_.code.contains("php://input"))).l), (c: Call) => c.name)
      val external: List[CfgNode] =
        remember(graph.identifier.name("argv").l, (i: Identifier) => "$argv") ++
        remember(graph.call.name("getenv").l, (c: Call) => c.name)
      def fn(names: String) = graph.call.name(names).filter(c => argAt(c, 0).isEmpty)
      def method(names: String) = graph.call.name(names).filter(c => argAt(c, 0).nonEmpty)
      val sinks =
        sink("sql", fn("mysqli_query|mysqli_multi_query|mysqli_real_query|mysqli_prepare|odbc_exec|db2_exec|sqlsrv_query|oci_parse"), Seq(2)) ++
        sink("sql", fn("mysql_query|mysql_unbuffered_query|sqlite_query|pg_query|pg_send_query|pg_prepare|mssql_query"), Seq.empty) ++
        sink("sql", method("query|exec|prepare|multi_query|real_query|execute_query|unprepared|statement|raw|whereRaw|orderByRaw|selectRaw|havingRaw"), Seq(1)) ++
        sink("command", fn("system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|expect_popen"), Seq(1)) ++
        sink("eval", fn("eval|assert"), Seq(1)) ++
        sink("eval", fn("create_function"), Seq(2)) ++
        sink("path", fn("include|include_once|require|require_once|fopen|file_get_contents|file_put_contents|readfile|file|unlink|copy|rename|opendir|scandir|highlight_file|show_source|parse_ini_file|mkdir|rmdir|glob"), Seq(1)) ++
        sink("path", fn("move_uploaded_file"), Seq(2)) ++
        sink("xss", graph.call.name("echo|print|printf|vprintf|print_r|exit|die"), Seq.empty, dropLiterals = true) ++
        sink("redirect", fn("header").filter(c => argAt(c, 1).exists(_.code.matches("(?is)^\\s*['\"]\\s*location\\s*:.*"))), Seq(1)) ++
        sink("deserialize", fn("unserialize|yaml_parse"), Seq(1)) ++
        sink("ssrf", fn("curl_init|fsockopen|get_headers"), Seq(1)) ++
        sink("ssrf", fn("curl_setopt").filter(c => argAt(c, 2).exists(_.code.contains("CURLOPT_URL"))), Seq(3)) ++
        sink("ldap", fn("ldap_search|ldap_list|ldap_read"), Seq(3)) ++
        sink("xpath", graph.call.methodFullName("DOMXPath\\.(query|evaluate)|SimpleXMLElement\\.xpath"), Seq(1))
      (request, external, sinks)

    case "go" =>
      def requestTyped(e: Expression): Boolean = e.evalType.l.exists(_.contains("net/http.Request")) || declaredType(e).contains("net/http.Request")
      val request: List[CfgNode] =
        remember(graph.call.methodFullName(
          "net/http\\.Request\\..*|.*gin-gonic/gin\\.Context\\.(Query|DefaultQuery|PostForm|DefaultPostForm|Param|GetHeader|Cookie|GetQuery|GetPostForm|QueryArray|PostFormArray|QueryMap|PostFormMap|FormFile|GetRawData)(:.*)?|" +
          ".*labstack/echo.*Context\\.(QueryParam|QueryParams|FormValue|FormParams|Param|Cookie)(:.*)?|.*httprouter\\.Params\\.ByName.*|.*gorilla/mux\\.Vars.*")
          .filterNot(_.name.matches("Context|WithContext|Clone|ParseForm|ParseMultipartForm|ProtoAtLeast|Write|WriteProxy|AddCookie|SetBasicAuth")).l,
          (c: Call) => s"request.${c.name}") ++
        remember(fieldAccesses.filter(fa => fieldName(fa).matches("Body|Header|Form|PostForm|URL|Host|RequestURI|MultipartForm") &&
          argAt(fa, 1).exists(requestTyped)), (c: Call) => s"request.${fieldName(c)}")
      val external: List[CfgNode] =
        remember(graph.call.methodFullName("os\\.(Getenv|LookupEnv)(:.*)?").l, (c: Call) => s"os.${c.name}") ++
        remember(fieldAccesses.filter(fa => fa.code == "os.Args"), (c: Call) => "os.Args")
      def responseWriter(c: Call): Boolean = argAt(c, 1).exists(w => w.evalType.l.exists(_.contains("ResponseWriter")) || declaredType(w).contains("ResponseWriter"))
      val shell = (c: Call) => argAt(c, 2).exists(_.code.matches("\"(-c|/c|/C)\""))
      val sinks =
        sink("sql", graph.call.methodFullName("database/sql\\.(DB|Tx|Conn)\\.(Query|QueryRow|Exec|Prepare)(:.*)?|.*sqlx\\.(DB|Tx)\\.(Query|Queryx|QueryRow|QueryRowx|Exec|Select|Get|MustExec)(:.*)?|.*gorm.*\\.(Raw|Exec|Where|Order|Having|Group|Joins)(:.*)?"), Seq(1)) ++
        sink("sql", graph.call.methodFullName("database/sql\\.(DB|Tx|Conn)\\.(QueryContext|QueryRowContext|ExecContext|PrepareContext)(:.*)?"), Seq(2)) ++
        sink("command", graph.call.methodFullName("os/exec\\.Command(:.*)?").filterNot(shell), Seq(1)) ++
        sink("command", graph.call.methodFullName("os/exec\\.Command(:.*)?").filter(shell), Seq(3)) ++
        sink("command", graph.call.methodFullName("os/exec\\.CommandContext(:.*)?"), Seq(2)) ++
        sink("command", graph.call.methodFullName("syscall\\.Exec(:.*)?"), Seq(1)) ++
        sink("path", graph.call.methodFullName("os\\.(Open|OpenFile|ReadFile|WriteFile|Create|Remove|RemoveAll|Mkdir|MkdirAll|Rename|ReadDir|Chmod)(:.*)?|io/ioutil\\.(ReadFile|WriteFile|ReadDir)(:.*)?"), Seq(1)) ++
        sink("path", graph.call.methodFullName("net/http\\.ServeFile(:.*)?"), Seq(3)) ++
        sink("redirect", graph.call.methodFullName("net/http\\.Redirect(:.*)?"), Seq(3)) ++
        sink("xss", graph.call.methodFullName("html/template\\.(HTML|HTMLAttr|JS|JSStr|URL|CSS|Srcset)(:.*)?"), Seq(1)) ++
        sink("xss", graph.call.methodFullName("fmt\\.(Fprintf|Fprint|Fprintln)(:.*)?|io\\.WriteString(:.*)?").filter(responseWriter),
          2 to 12, dropLiterals = true) ++
        sink("xss", graph.call.methodFullName("net/http\\.ResponseWriter\\.Write(:.*)?"), Seq(1)) ++
        sink("ssrf", graph.call.methodFullName("net/http\\.(Get|Post|Head|PostForm)(:.*)?|net/http\\.Client\\.(Get|Post|Head|PostForm)(:.*)?"), Seq(1)) ++
        sink("ssrf", graph.call.methodFullName("net/http\\.NewRequest(:.*)?"), Seq(2)) ++
        sink("ssrf", graph.call.methodFullName("net/http\\.NewRequestWithContext(:.*)?"), Seq(3)) ++
        sink("eval", graph.call.name("Parse").filter(c => c.methodFullName.contains("template")), Seq(1))
      (request, external, sinks)

    case "ruby" =>
      val REQUEST_FIELDS = "(self\\.)?(params|cookies|request\\.(params|query_parameters|request_parameters|parameters|headers|body|raw_post|url|referer|referrer|path|fullpath|query_string|env|cookies|user_agent))"
      val request: List[CfgNode] =
        remember(fieldAccesses.filter(_.code.matches(REQUEST_FIELDS)), (c: Call) => c.code.stripPrefix("self."))
      val external: List[CfgNode] =
        remember(graph.call.nameExact("<operator>.indexAccess").filter(c => argAt(c, 1).exists(_.code.matches("(::)?ENV"))).l, (c: Call) => "ENV") ++
        remember(graph.identifier.nameExact("ARGV").l, (i: Identifier) => "ARGV")
      def onReceiver(names: String, receiver: String) =
        graph.call.name(names).filter(c => c.code.matches(s"(?s)^\\(?(<tmp-\\d+> = )?(::)?($receiver)\\)?\\..*"))
      def interpolated(c: Call): Boolean = argAt(c, 1).exists {
        case a: Call => a.name.matches("<operator>\\.(formatString|addition|plus)|\\+|<<|%")
        case _ => false
      }
      val sinks =
        sink("sql", graph.call.name("find_by_sql|count_by_sql|execute|exec_query|exec_update|exec_delete|exec_insert|select_all|select_one|select_value|select_values|select_rows|order|reorder|pluck|group|from|joins|lock|calculate|update_all|delete_all|destroy_all"), Seq(1)) ++
        sink("sql", graph.call.name("where|not|having|find_by|exists\\?|select|rewhere|or|find").filter(interpolated), Seq(1)) ++
        sink("command", graph.call.name("system|exec|spawn|syscall|popen|capture2|capture2e|capture3|popen2|popen2e|popen3|pipeline"), Seq(1)) ++
        sink("command", graph.call.name("<operator>\\.backticks|`|%x"), Seq.empty) ++
        sink("eval", graph.call.name("eval|instance_eval|class_eval|module_eval|instance_exec"), Seq(1)) ++
        sink("redirect", graph.call.name("redirect_to|redirect_back"), Seq(1)) ++
        sink("xss", fieldAccesses.filter(fa => fieldName(fa) == "html_safe").iterator, Seq(1)) ++
        sink("xss", graph.call.name("html_safe|raw|safe_concat"), Seq(0, 1)) ++
        sink("path", graph.call.name("send_file|render_file"), Seq(1)) ++
        sink("path", onReceiver("open|read|readlines|write|binread|binwrite|delete|unlink|new|foreach|rm|rm_rf|cp|mv|copy|entries|glob", "File|IO|Pathname|FileUtils|Dir"), Seq(1)) ++
        sink("deserialize", onReceiver("load|unsafe_load|restore|load_file", "Marshal|YAML|Psych|Oj"), Seq(1)) ++
        sink("ssrf", onReceiver("get|post|put|delete|head|patch|get_response|start|open", "Net::HTTP|HTTParty|RestClient|Faraday|Excon|HTTP|URI"), Seq(1))
      (request, external, sinks)

    case "javascript" =>
      // Express/Koa/Fastify/Next.js işleyicileri: istek nesnesinin girdi alanları (req.query, ctx.request.body …),
      // AWS Lambda olay alanları ve req.get()/req.header()/req.param() çağrıları.
      val JS_REQUEST = "(req|request)\\.(query|params|body|headers|cookies|signedCookies|files|file|hostname|ip|ips|path|url|originalUrl|baseUrl)|" +
        "ctx\\.(query|params|querystring|headers|header|cookies|url|path|href|host|request\\.(body|query|headers|files|rawBody))|" +
        "(event|evt)\\.(body|queryStringParameters|multiValueQueryStringParameters|pathParameters|headers)"
      // jssrc2cpg'de iç alan erişimi (req.query) akış başlatmıyor; varsa onu taşıyan dış erişim (req.query.x,
      // req.query["x"]) kaynak düğümüdür.
      def outermost(c: Call): Call = scala.util.Try(c.astParent).toOption.collect {
        case p: Call if (p.name == "<operator>.fieldAccess" || p.name == "<operator>.indexAccess") && argAt(p, 1).exists(_.id() == c.id()) => p
      }.getOrElse(c)
      val jsBases = fieldAccesses.filter(_.code.matches(JS_REQUEST))
      val jsNames: Map[Long, String] = jsBases.map(b => outermost(b).id() -> b.code).toMap
      val request: List[CfgNode] =
        remember(jsBases.map(outermost).distinctBy(_.id()), (c: Call) => jsNames.getOrElse(c.id(), c.code)) ++
        remember(graph.call.name("get|header|param|cookie").filter(c => argAt(c, 0).exists(_.code.matches("req|request|ctx\\.cookies"))).l,
          (c: Call) => receiverCode(c)) ++
        // NestJS: @Query/@Param/@Body/@Headers… dekoratörlü parametreler (sayı/mantıksal türlüler girdi sayılmaz).
        remember(graph.method.isExternal(false).parameter.where(_.annotation.name("Query|Param|Body|Headers|Cookies|UploadedFile|UploadedFiles|HostParam|Ip")).l
          .filterNot(_.typeFullName.matches("__ecma\\.(Number|Boolean)|number|boolean")),
          (p: MethodParameterIn) => s"@${p.annotation.name.headOption.getOrElse("")}:${p.name}")
      // Ortam değişkenleri (yapılandırma) dış girdi sayılmaz; JS/Python'da gürültüydü (Lambda/sunucu ayarları).
      val external: List[CfgNode] =
        remember(fieldAccesses.filter(_.code.matches("process\\.argv")), (c: Call) => c.code)
      def module(re: String) = graph.call.methodFullName(re)
      def onResponse(names: String) = graph.call.name(names).filter(c => argAt(c, 0).exists(_.code.matches("(?s)(res|response|reply|h)(\\.status\\(.*\\))?")))
      // Yanıta yalnız metin üreten argüman (birleştirme, şablon dizesi) ya da doğrudan istek alanı XSS hedefidir;
      // nesne/dizi/değişken (res.send(rows), res.send(obj)) Express'te JSON yazılır ya da türü belirsizdir.
      val htmlText = (e: Expression) => e match {
        case c: Call => c.name.matches("<operator>\\.(addition|formatString)|concat|join|replace|toString") ||
          ((c.name == "<operator>.fieldAccess" || c.name == "<operator>.indexAccess") && c.code.matches(s"(?s)($JS_REQUEST)\\b.*"))
        case _ => false
      }
      val sinks =
        sink("command", module("(node:)?child_process:(exec|execSync|spawn|spawnSync|execFile|execFileSync)|shelljs:exec|execa(:command|:commandSync)?"), Seq(1)) ++
        sink("eval", module("eval|Function|(node:)?vm:(runInNewContext|runInThisContext|runInContext|compileFunction|Script)"), Seq(1)) ++
        sink("eval", graph.call.nameExact("<operator>.new").filter(_.code.matches("(?s)^new\\s+(Function|vm\\.Script)\\(.*")), 1 to 8, dropLiterals = true) ++
        sink("eval", graph.call.name("setTimeout|setInterval").filter(c => argAt(c, 1).exists(a => !a.isInstanceOf[MethodRef] && !a.code.contains("=>") && !a.code.startsWith("function"))), Seq(1)) ++
        sink("sql", graph.call.name("query|raw|whereRaw|orWhereRaw|orderByRaw|havingRaw|joinRaw|groupByRaw|selectRaw|\\$queryRawUnsafe|\\$executeRawUnsafe|unsafe|literal")
          .filterNot(c => isProjectMethod(c) || c.methodFullName.startsWith("__ecma") || c.methodFullName.matches("(node:)?(url|querystring|http|https)(:.*)?")), Seq(1)) ++
        sink("xss", onResponse("send|write|end"), Seq(1)).filter(htmlText) ++
        assignSink("xss", graph.assignment.l.filter(a => assignTarget(a).code.matches("ctx\\.body|ctx\\.response\\.body|\\w+\\.innerHTML|\\w+\\.outerHTML"))) ++
        sink("path", module("(node:)?fs(/promises|-extra)?(:promises)?:(readFile|readFileSync|createReadStream|createWriteStream|writeFile|writeFileSync|appendFile|appendFileSync|unlink|unlinkSync|rm|rmSync|readdir|readdirSync|open|openSync|copyFile|copyFileSync|rename|renameSync|mkdir|mkdirSync|access|accessSync|stat|statSync|lstat|readJson|readJSON|outputFile|remove)"), Seq(1)) ++
        sink("path", onResponse("sendFile|download|attachment").filterNot(c => argAt(c, 2).exists(_.code.contains("root"))), Seq(1)) ++
        sink("redirect", onResponse("redirect") ++ graph.call.name("redirect").filter(c => argAt(c, 0).exists(_.code.matches("ctx|this"))), Seq(1, 2), dropLiterals = true)
          .filterNot(fixedPathPrefix) ++
        sink("ssrf", module("axios(:(get|post|put|delete|head|patch|request|options))?|node-fetch|got(:(get|post|put|delete|head|patch|stream))?|needle(:.*)?|superagent(:.*)?|undici:(request|fetch)|request(:(get|post))?|(node:)?https?:(get|request)|fetch"), Seq(1))
          .filterNot(fixedHost) ++
        sink("deserialize", module("node-serialize:unserialize|serialize-to-js:deserialize|funcster:deepDeserialize"), Seq(1))
      (request, external, sinks)

    case "python" =>
      // Flask/Django/FastAPI/Starlette istek nesnesi alanları ve rota işleyicilerinin yol/sorgu parametreleri
      // (@app.route("/u/<name>") def f(name)). <int:…> dönüştürücülü ve int/float/bool/UUID tür ipuçlu
      // parametreler girdi sayılmaz.
      val PY_REQUEST = "(self\\.)?request\\.(args|form|values|json|cookies|headers|data|files|GET|POST|COOKIES|META|FILES|body|query_params|path_params|query_string|full_path|url|path|stream|environ|view_args)"
      val ROUTE_DECORATOR = "(?s)^[\\w.]+\\.(route|get|post|put|delete|patch|api_route|websocket|add_url_rule)\\(.*"
      val routeRefs = graph.methodRef.l.flatMap(r => scala.util.Try(r.astParent).toOption.collect {
        case c: Call if c.code.matches(ROUTE_DECORATOR) => (r.methodFullName, c.code)
      })
      val routeMethods: Map[String, String] = routeRefs.toMap
      // FastAPI/Starlette dosyaları: dönüş değeri JSON'a serileştirilir (HTMLResponse dışında XSS hedefi değil).
      val fastapiFiles: Set[String] = graph.call.nameExact("<operator>.import")
        .filter(c => argAt(c, 1).exists(_.code.matches("fastapi(\\..*)?|starlette(\\..*)?"))).l
        .flatMap(c => scala.util.Try(c.method.filename).toOption).toSet
      def converted(route: String, param: String): Boolean =
        route.matches(s"(?s).*<(int|float|uuid):$param>.*")
      val routeParams = graph.method.isExternal(false).filter(m => routeMethods.contains(m.fullName)).l.flatMap { m =>
        m.parameter.l.filter(p => !p.name.matches("self|cls|request|req|args|kwargs|db|session|background_tasks|response|current_user|settings|config|credentials|token_data|auth") &&
          !p.typeFullName.matches("(?i).*\\b(int|float|bool|UUID|Request|Session|Response|BackgroundTasks|Depends)\\b.*") &&
          !converted(routeMethods(m.fullName), p.name))
      }
      // Yalnız metin üreten dönüşler (birleştirme, f-string, %, format, join) ve doğrudan değişken; çağrı sonuçları
      // (render_template, jsonify, dosya içeriği, ağ yanıtı) yanıt gövdesine girdi yansıtması sayılmaz.
      val routeReturns: List[Expression] = graph.method.isExternal(false).filter(m => routeMethods.contains(m.fullName) &&
          !fastapiFiles.contains(m.filename)).l
        .flatMap(m => m.ast.isReturn.astChildren.collect {
          case id: Identifier => id
          case c: Call if c.name.matches("<operator>\\.(addition|formatString|formattedValue|modulo)|format|join") => c
        }.l)
      val request: List[CfgNode] =
        remember(fieldAccesses.filter(_.code.matches(PY_REQUEST)), (c: Call) => c.code.stripPrefix("self.")) ++
        remember(graph.call.name("get_json|get_data|getlist").filter(c => argAt(c, 0).exists(_.code.matches("(self\\.)?request(\\.\\w+)?"))).l,
          (c: Call) => receiverCode(c)) ++
        remember(routeParams, (p: MethodParameterIn) => s"rota:${p.name}")
      val external: List[CfgNode] =
        remember(fieldAccesses.filter(_.code.matches("sys\\.argv")), (c: Call) => c.code) ++
        remember(graph.call.methodFullName("__builtin\\.input").l, (c: Call) => c.name)
      def module(re: String) = graph.call.methodFullName(re)
      def keyword(c: Call, name: String): Option[Expression] = c.argument.l.find(a => a.argumentName.contains(name))
      val shellTrue = (c: Call) => keyword(c, "shell").exists(_.code == "True")
      val listArg = (c: Call) => argAt(c, 1).exists(a => a.code.trim.startsWith("[") || a.code.trim.startsWith("("))
      val sinks =
        sink("command", module("os\\.py:<module>\\.(system|popen|popen2|popen3|execl|execlp|execle|execv|execvp|execvpe|spawnl|spawnlp|spawnv|spawnvp)|" +
          "subprocess\\.py:<module>\\.(getoutput|getstatusoutput)|commands\\.py:<module>\\.getoutput|asyncio\\.py:<module>\\.create_subprocess_shell|pty\\.py:<module>\\.spawn"), Seq(1)) ++
        sink("command", module("subprocess\\.py:<module>\\.(call|run|Popen|check_output|check_call)").filter(c => shellTrue(c) || !listArg(c)), Seq(1)) ++
        sink("sql", graph.call.name("execute|executemany|executescript|raw|extra|read_sql|read_sql_query|RawSQL")
          .filterNot(c => isProjectMethod(c) || c.methodFullName.matches("(subprocess|os|asyncio)\\.py:.*")), Seq(1)) ++
        sink("sql", module("sqlalchemy(/sql)?\\.py:<module>\\.text"), Seq(1)) ++
        sink("path", module("__builtin\\.open|io\\.py:<module>\\.open|codecs\\.py:<module>\\.open|flask\\.py:<module>\\.send_file|" +
          "os\\.py:<module>\\.(remove|unlink|rmdir|removedirs|listdir|makedirs|mkdir|rename|scandir)|shutil\\.py:<module>\\.(rmtree|copy|copyfile|copy2|move|copytree)"), Seq(1)) ++
        sink("path", graph.call.name("FileResponse").filterNot(c => c.methodFullName.startsWith("__")), Seq(1)) ++
        sink("eval", module("__builtin\\.(eval|exec|compile)"), Seq(1)) ++
        sink("ssti", module("flask\\.py:<module>\\.render_template_string|jinja2\\.py:<module>\\.(Template|Environment\\.from_string)(\\.__init__)?|" +
          "mako(/template)?\\.py:<module>\\.Template(\\.__init__)?") ++ graph.call.name("from_string|render_template_string"), Seq(1)) ++
        sink("deserialize", module("(c?[pP]ickle|_pickle|dill|marshal|shelve|jsonpickle)\\.py:<module>\\.(loads|load|open|decode)"), Seq(1)) ++
        sink("deserialize", module("yaml\\.py:<module>\\.(load|load_all|unsafe_load|full_load)")
          .filterNot(c => keyword(c, "Loader").exists(_.code.contains("Safe")) || argAt(c, 2).exists(_.code.contains("Safe"))), Seq(1)) ++
        (sink("ssrf", module("(requests|httpx)\\.py:<module>\\.(get|post|put|delete|head|patch|options)"), Seq(1)) ++
          sink("ssrf", module("(requests|httpx)\\.py:<module>\\.request"), Seq(2)) ++
          sink("ssrf", graph.call.name("urlopen|urlretrieve"), Seq(1))).filterNot(fixedHost) ++
        sink("redirect", graph.call.name("redirect|HttpResponseRedirect|HttpResponsePermanentRedirect|RedirectResponse")
          .filterNot(c => c.methodFullName.startsWith("__")), Seq(1), dropLiterals = true).filterNot(fixedPathPrefix) ++
        sink("xss", graph.call.name("Markup|mark_safe|HTMLResponse").filterNot(c => c.methodFullName.startsWith("__")),
          Seq(1), dropLiterals = true) ++
        // Açık içerik türü (content_type/mimetype) verilen yanıt HTML değildir.
        sink("xss", graph.call.name("HttpResponse|make_response").filterNot(c => c.methodFullName.startsWith("__") ||
          c.argument.l.exists(a => a.argumentName.exists(_.matches("content_type|mimetype|media_type")))), Seq(1), dropLiterals = true) ++
        // Rota işleyicisinin döndürdüğü metin (Flask: str dönüşü text/html yanıt gövdesidir).
        routeReturns.filterNot(_.isInstanceOf[Literal]).map { e =>
          sinkInfo(e.id()) = ("xss", "return"); e
        }
      (request, external, sinks)

    case _ => // csharp
      val REQUEST_MEMBERS = "(?s)(this\\.)?((HttpContext|Context)\\.(Current\\.)?)?Request\\.(Query|Form|Cookies|Headers|QueryString|Params|ServerVariables|RouteValues|Body|Path|RawUrl|Url|UrlReferrer|UserAgent|InputStream|Files|PathInfo)"
      val WEBFORM_INPUTS = "(?i).*(TextBox|HtmlInputText|HtmlInputHidden|HtmlTextArea|HiddenField|DropDownList|ListBox|RadioButtonList|CheckBoxList).*"
      val controllerMethods = graph.method.filter(m => m.modifier.modifierType.l.contains("PUBLIC") && !m.name.matches("<init>|<clinit>|\\.ctor|\\.cctor") &&
        (m.definingTypeDecl.name.l.exists(_.endsWith("Controller")) ||
          m.definingTypeDecl.inheritsFromTypeFullName.l.exists(_.matches(".*(Controller|ControllerBase|ApiController|PageModel)")))).l
      val request: List[CfgNode] =
        remember(fieldAccesses.filter(_.code.matches(REQUEST_MEMBERS)), (c: Call) => c.code.stripPrefix("this.")) ++
        remember(graph.call.nameExact("<operator>.indexAccess").filter(c => argAt(c, 1).exists(_.code.matches("(this\\.)?((HttpContext|Context)\\.(Current\\.)?)?Request"))).l,
          (c: Call) => "Request[]") ++
        remember(controllerMethods.flatMap(_.parameter.l).filter(p => p.name != "this" && !p.typeFullName.matches(CSHARP_NON_INPUT)),
          (p: MethodParameterIn) => s"istek parametresi ${p.name}") ++
        remember(graph.method.parameter.where(_.annotation.name("FromQuery|FromBody|FromForm|FromRoute|FromHeader")).l,
          (p: MethodParameterIn) => s"[${p.annotation.name.headOption.getOrElse("From")}] ${p.name}") ++
        // ASP.NET WebForms: kullanıcı girdisi alan denetimlerin Text/Value özellikleri.
        remember(fieldAccesses.filter(fa => fieldName(fa).matches("Text|Value|SelectedValue") &&
          argAt(fa, 1).exists(r => declaredType(r).matches(WEBFORM_INPUTS))), (c: Call) => c.code.stripPrefix("this.")) ++
        remember(fieldAccesses.filter(fa => fieldName(fa).matches("FileName|PostedFile") &&
          argAt(fa, 1).exists(r => declaredType(r).matches("(?i).*(FileUpload|HttpPostedFile|IFormFile).*"))), (c: Call) => c.code.stripPrefix("this."))
      val external: List[CfgNode] =
        remember(graph.call.name("GetEnvironmentVariable|ReadLine").l, (c: Call) => c.name)
      def ctor(types: String) = graph.call.nameExact("<init>").filter(c => c.methodFullName.matches(s".*\\b($types)\\.<init>.*"))
      def staticOn(names: String, receiver: String) = graph.call.name(names).filter(c => c.code.matches(s"(?s)^(this\\.)?(System\\.[\\w.]*)?($receiver)\\..*"))
      val outputControls = fieldAssignments("Text").filter(a => assignTarget(a) match {
        case fa: Call => argAt(fa, 1).exists(r => declaredType(r).matches("(?i).*(Label|Literal).*"))
        case _ => false
      })
      val sinks =
        sink("sql", ctor("SqlCommand|OleDbCommand|OdbcCommand|MySqlCommand|NpgsqlCommand|SQLiteCommand|SqliteCommand|OracleCommand|SqlCeCommand|\\w*DataAdapter"), Seq(1)) ++
        sink("sql", graph.call.name("ExecuteSqlRaw|ExecuteSqlRawAsync|FromSqlRaw|ExecuteSqlCommand|ExecuteSqlCommandAsync|FromSql|SqlQuery|ExecuteQuery|ExecuteStoreQuery|ExecuteStoreCommand"), Seq(1)) ++
        assignSink("sql", fieldAssignments("CommandText")) ++
        sink("command", staticOn("Start", "Process"), Seq.empty) ++
        sink("command", ctor("ProcessStartInfo"), Seq.empty) ++
        assignSink("command", fieldAssignments("Arguments|FileName").filter(a => declaredType(assignTarget(a) match { case fa: Call => argAt(fa, 1).getOrElse(fa); case e => e }).contains("ProcessStartInfo"))) ++
        sink("path", staticOn("ReadAllText|ReadAllBytes|ReadAllLines|ReadLines|WriteAllText|WriteAllBytes|WriteAllLines|AppendAllText|OpenRead|OpenWrite|OpenText|Open|Delete|Copy|Move|Create|CreateText|GetFiles|GetDirectories|EnumerateFiles|CreateDirectory", "File|Directory"), Seq(1)) ++
        sink("path", ctor("FileStream|StreamReader|StreamWriter|FileInfo|DirectoryInfo"), Seq(1)) ++
        sink("path", graph.call.name("WriteFile|TransmitFile|PhysicalFile|SaveAs"), Seq(1)) ++
        sink("redirect", graph.call.name("Redirect|RedirectPermanent|RedirectPreserveMethod|RedirectPermanentPreserveMethod"), Seq(1)) ++
        sink("xss", staticOn("Write", "(HttpContext\\.(Current\\.)?)?Response"), Seq(1)) ++
        sink("xss", staticOn("Raw", "Html"), Seq(1)) ++
        sink("xss", ctor("HtmlString|MvcHtmlString"), Seq(1)) ++
        assignSink("xss", fieldAssignments("InnerHtml") ++ outputControls) ++
        sink("deserialize", graph.call.name("Deserialize|UnsafeDeserialize|ReadObject").filter(c =>
          (c.methodFullName + " " + c.code).matches("(?s).*(BinaryFormatter|SoapFormatter|NetDataContractSerializer|LosFormatter|ObjectStateFormatter).*")), Seq(1)) ++
        sink("ssrf", graph.call.name("DownloadString|DownloadData|DownloadFile|UploadString|GetAsync|GetStringAsync|GetByteArrayAsync|GetStreamAsync|PostAsync|PutAsync|DeleteAsync")
          .filter(c => argAt(c, 0).nonEmpty), Seq(1)) ++
        sink("ssrf", staticOn("Create|CreateHttp", "(Http)?WebRequest"), Seq(1)) ++
        sink("ldap", ctor("DirectorySearcher"), Seq(1, 2)) ++
        assignSink("ldap", fieldAssignments("Filter")) ++
        sink("xpath", graph.call.name("SelectNodes|SelectSingleNode"), Seq(1))
      (request, external, sinks)
  }

  val (requestSources, externalSources, baseSinks) =
    if (Set("php", "go", "ruby", "csharp", "javascript", "python").contains(lang)) otherLanguageModel(lang)
    else if (!isJava) {
      val external: List[CfgNode] =
        remember(graph.method.nameExact("main").parameter.l, (p: MethodParameterIn) => s"main:${p.name}") ++
        remember(graph.call.name("getenv|secure_getenv").l, (c: Call) => c.name) ++
        remember(graph.call.name("gets|fgets|fgetws|read|pread|recv|recvfrom|recvmsg|fread|scanf|fscanf|sscanf|getline|getdelim")
          .argument.l.filter(_.argumentIndex >= 1), (e: Expression) => e.inCall.name.headOption.getOrElse("girdi"))
      val sinkNodes =
        sink("command", graph.call.name("system|popen"), Seq(1)) ++
        sink("command", graph.call.name("execl|execlp|execle|execv|execvp|execve|execvpe"), Seq.empty) ++
        sink("sql", graph.call.name("sqlite3_exec|sqlite3_prepare|sqlite3_prepare_v2|sqlite3_prepare_v3|mysql_query|mysql_real_query|PQexec"), Seq(2)) ++
        sink("path", graph.call.name("fopen|open|openat|freopen|opendir|unlink|remove|creat|access|truncate|chmod|chown"), Seq(1)) ++
        sink("path", graph.call.name("rename|link|symlink"), Seq(1, 2)) ++
        sink("format", graph.call.name("printf|vprintf"), Seq(1), dropLiterals = true) ++
        sink("format", graph.call.name("fprintf|vfprintf|dprintf|sprintf|vsprintf|syslog"), Seq(2), dropLiterals = true) ++
        sink("format", graph.call.name("snprintf|vsnprintf"), Seq(3), dropLiterals = true) ++
        sink("overflow", graph.call.name("strcpy|strcat|wcscpy|wcscat|stpcpy"), Seq(2)) ++
        sink("overflow", graph.call.name("memcpy|memmove|strncpy|strncat"), Seq(3))
      (List.empty[CfgNode], external, sinkNodes)
    } else {
      val request: List[CfgNode] =
        remember(graph.call.name("getParameter|getParameterValues|getParameterMap|getParameterNames|getHeader|getHeaders|getHeaderNames|getQueryString|getCookies|getInputStream|getReader|getPathInfo|getRequestURI|getRequestURL|getPart|getParts").l,
          (c: Call) => s"request.${c.name}") ++
        // İsteği argüman olarak alan kütüphane yardımcıları (Spring WebUtils.getCookie,
        // ServletRequestUtils.getStringParameter …); proje içi gövdeli yöntemler akışla izlenir.
        remember(graph.call.name("getCookie|findParameterValue|getParametersStartingWith|get\\w*Parameter\\w*").l.filter(c =>
          !isProjectMethod(c) && c.argument.l.exists(a => a.argumentIndex >= 1 &&
            (a.evalType.l ++ (a match { case id: Identifier => id.refsTo.collect { case l: Local => l.typeFullName; case p: MethodParameterIn => p.typeFullName }.l; case _ => Nil }))
              .exists(_.matches("(javax|jakarta)\\.servlet\\.(http\\.Http)?ServletRequest")))),
          (c: Call) => s"request.${c.name}") ++
        remember(graph.method.parameter.where(_.annotation.name("RequestParam|PathVariable|RequestBody|RequestHeader|CookieValue|QueryParam|PathParam|FormParam|HeaderParam|CookieParam|MatrixParam|ModelAttribute|RequestPart|BeanParam")).l,
          (p: MethodParameterIn) => s"@${p.annotation.name.headOption.getOrElse("Param")} ${p.name}") ++
        // Spring MVC/WebFlux ve JAX-RS işleyici yöntemleri: açıklamasız basit parametreler de istek
        // girdisidir (Spring'de varsayılan @RequestParam/@ModelAttribute; JAX-RS'te gövde).
        remember(graph.method.where(_.annotation.name(HANDLER_ANNOTATIONS)).parameter.l.filter(p =>
          p.index > 0 && p.name != "this" && p.annotation.name.l.forall(n => !Set("Context", "Value", "Autowired").contains(n)) &&
          !p.typeFullName.matches(NON_INPUT_PARAM_TYPES)),
          (p: MethodParameterIn) => s"istek parametresi ${p.name}")
      val external: List[CfgNode] =
        remember(graph.method.nameExact("main").parameter.nameExact("args").l, (p: MethodParameterIn) => "main:args") ++
        // System.getProperty (user.dir, os.name …) işletmecinin/JVM'in denetiminde: kaynak sayılmaz.
        remember(graph.call.methodFullName("java\\.lang\\.System\\.getenv.*").l, (c: Call) => s"System.${c.name}") ++
        remember(graph.call.name("readLine|nextLine").l.filter(c => c.methodFullName.startsWith("java.io.Console") || c.code.contains("System.in")), (c: Call) => c.name)
      val jdbcNames = "execute|executeQuery|executeUpdate|executeLargeUpdate|addBatch|prepareStatement|prepareCall|query|queryForList|queryForObject|queryForMap|queryForLong|queryForInt|queryForRowSet|queryForStream|update|batchUpdate|createQuery|createNativeQuery|createSQLQuery"
      val sinkNodes =
        sink("command", graph.call.methodFullName("java\\.lang\\.Runtime\\.exec.*|java\\.lang\\.ProcessBuilder\\.(<init>|command).*"), Seq.empty) ++
        sink("sql", graph.call.methodFullName(s"(java\\.sql|javax\\.persistence|jakarta\\.persistence|org\\.hibernate)\\..*\\.($jdbcNames):.*"), Seq(1)) ++
        sink("sql", graph.call.name("executeQuery|executeUpdate|executeLargeUpdate|prepareStatement|prepareCall|createNativeQuery").filter(_.methodFullName.contains("unresolved")), Seq(1)) ++
        sink("sql", graph.call.methodFullName(s".*[Jj]dbc[Tt]emplate.*\\.($jdbcNames):.*"), Seq(1)) ++
        sink("sql", graph.call.name(jdbcNames).filter(c => c.methodFullName.contains("unresolved") &&
          receiverType(c).exists(t => t.matches("(?i).*(JdbcTemplate|java\\.sql\\.(Statement|Connection|PreparedStatement|CallableStatement)|EntityManager|hibernate\\.Session).*"))), Seq(1)) ++
        sink("path", graph.call.methodFullName("java\\.io\\.(File|FileInputStream|FileOutputStream|FileReader|FileWriter|RandomAccessFile|PrintWriter)\\.<init>.*"), Seq(1, 2)) ++
        sink("path", graph.call.methodFullName("java\\.nio\\.file\\.(Paths\\.get|Path\\.of|Path\\.resolve|Files\\.(newInputStream|newOutputStream|readAllBytes|readAllLines|readString|write|writeString|delete|deleteIfExists|lines|newBufferedReader|newBufferedWriter|copy|move)):.*"), Seq.empty) ++
        sink("deserialize", graph.call.methodFullName("java\\.io\\.ObjectInputStream\\.<init>.*|java\\.beans\\.XMLDecoder\\.<init>.*|.*snakeyaml\\.Yaml\\.load.*|.*XStream\\.fromXML.*"), Seq(1)) ++
        // URL/URI nesnesi oluşturmak istek yapmaz (ana makine ayrıştırma/allowlist kodunda da kullanılır):
        // hedef, bağlantıyı açan çağrının alıcısı veya isteği kuran API'dir.
        sink("ssrf", graph.call.methodFullName("java\\.net\\.URL\\.(openConnection|openStream|getContent):.*"), Seq(0)) ++
        sink("ssrf", graph.call.name("openConnection|openStream").filter(_.methodFullName.contains("unresolved")), Seq(0)) ++
        sink("ssrf", graph.call.methodFullName("java\\.net\\.http\\.HttpRequest\\.newBuilder.*|javax\\.imageio\\.ImageIO\\.read:.*\\(java\\.net\\.URL\\).*|" +
          "org\\.apache\\.commons\\.io\\.FileUtils\\.copyURLToFile.*"), Seq(1)) ++
        sink("ssrf", graph.call.methodFullName("org\\.apache\\.commons\\.io\\.IOUtils\\.(toString|toByteArray|copy):.*").filter(c =>
          c.methodFullName.matches(".*\\(java\\.net\\.(URL|URI).*") || argAt(c, 1).exists(a =>
            a.evalType.l.exists(_.matches("java\\.net\\.(URL|URI)")) || a.code.matches("(?s)(URI\\.create|new\\s+(java\\.net\\.)?(URL|URI))\\b.*"))), Seq(1)) ++
        sink("xss", graph.call.methodFullName("java\\.io\\.PrintWriter\\.(print|println|write|printf|format|append):.*"), Seq.empty) ++
        sink("xss", graph.call.name("print|println|write|printf|format|append").where(_.receiver.isCall.name("getWriter|getOutputStream")), Seq.empty) ++
        sink("eval", graph.call.methodFullName("javax\\.script\\.ScriptEngine\\.eval.*|.*expression.*\\.parseExpression.*|ognl\\.Ognl\\.(getValue|parseExpression).*|groovy\\.lang\\.GroovyShell\\.(evaluate|parse).*"), Seq(1)) ++
        sink("ldap", graph.call.methodFullName("javax\\.naming\\.directory\\.(DirContext|InitialDirContext)\\.search.*"), Seq(2)) ++
        sink("ldap", graph.call.name("search").filter(c => c.methodFullName.contains("unresolved") && c.argument.l.count(_.argumentIndex >= 1) >= 3), Seq(2)) ++
        sink("xpath", graph.call.methodFullName("javax\\.xml\\.xpath\\.XPath\\.(evaluate|compile|evaluateExpression).*"), Seq(1)) ++
        sink("trustbound", graph.call.name("setAttribute|putValue").where(_.receiver.isCall.name("getSession")), Seq(1, 2)) ++
        sink("trustbound", graph.call.methodFullName("javax\\.servlet\\.http\\.HttpSession\\.(setAttribute|putValue).*|jakarta\\.servlet\\.http\\.HttpSession\\.(setAttribute|putValue).*"), Seq(1, 2)) ++
        // MyBatis: ${} içeren @Select/@Update/@Insert/@Delete veya XML eşleyici ifadeleri (Python tarafı
        // XML'i güvenli biçimde tarayıp nitelikli yöntem adlarını outFile.mybatis dosyasına yazar).
        sink("sql", graph.call.filter(c => c.callee.l.exists(m => m.annotation.name("Select|Update|Insert|Delete|SelectProvider").l.nonEmpty &&
          m.annotation.code.l.exists(_.contains("${")))), Seq.empty) ++
        sink("sql", graph.call.filter(c => mybatisUnsafe.exists(n => c.methodFullName.startsWith(n + ":"))), Seq.empty) ++
        sink("ssrf", graph.call.methodFullName(
          "org\\.apache\\.http\\.client\\.methods\\.Http(Get|Post|Put|Delete|Head|Patch|Options)\\.<init>.*|" +
          "org\\.apache\\.http\\.client\\.fluent\\.Request\\.(Get|Post|Put|Delete|Head|Patch|Options):.*|" +
          "org\\.apache\\.commons\\.httpclient\\.methods\\.(Get|Post|Put|Delete|Head)Method\\.<init>.*|" +
          "org\\.jsoup\\.Jsoup\\.connect:.*|cn\\.hutool\\.http\\.HttpUtil\\.(get|post|createGet|createPost|createRequest|downloadString|downloadBytes|downloadFile):.*|" +
          "cn\\.hutool\\.http\\.HttpRequest\\.(get|post):.*|.*RestTemplate\\.(getForObject|getForEntity|postForObject|postForEntity|postForLocation|exchange|execute|headForHeaders|put|delete|patchForObject):.*|" +
          ".*WebClient.*\\.uri:.*|feign.*|okhttp3?\\.HttpUrl\\.(parse|get):.*"), Seq(1)) ++
        sink("ssrf", graph.call.name("url").filter(c => c.code.contains("Builder")), Seq(1)) ++
        sink("redirect", graph.call.methodFullName(".*(HttpServletResponse|ServletResponse)\\.sendRedirect.*"), Seq(1)) ++
        sink("redirect", graph.call.name("sendRedirect").filter(_.methodFullName.contains("unresolved")), Seq(1)) ++
        sink("redirect", graph.call.name("setHeader|addHeader").filter(c => argAt(c, 1).exists(_.code.matches("(?i)\"location\"|.*HttpHeaders\\.LOCATION"))), Seq(2)) ++
        sink("redirect", graph.call.name("getRequestDispatcher|forward").filter(c => c.name == "getRequestDispatcher"), Seq(1)) ++
        sink("redirect", graph.call.methodFullName(".*ModelAndView\\.<init>.*|.*RedirectView\\.<init>.*").filter(c =>
          argAt(c, 1).exists(a => a.code.contains("\"redirect:") || c.methodFullName.contains("RedirectView"))), Seq(1)) ++
        redirectReturns() ++
        sink("crlf", graph.call.name("setHeader|addHeader").filter(c => !argAt(c, 1).exists(_.code.matches("(?i)\"location\"|.*HttpHeaders\\.LOCATION"))), Seq(2)) ++
        sink("xxe", graph.call.methodFullName(
          "org\\.xml\\.sax\\.XMLReader\\.parse.*|javax\\.xml\\.parsers\\.(DocumentBuilder|SAXParser)\\.parse.*|" +
          "org\\.jdom2?\\.input\\.SAXBuilder\\.build.*|org\\.dom4j\\.io\\.SAXReader\\.read.*|org\\.dom4j\\.DocumentHelper\\.parseText.*|" +
          "org\\.apache\\.commons\\.digester3?\\.Digester\\.parse.*|javax\\.xml\\.stream\\.XMLInputFactory\\.create(XMLStreamReader|XMLEventReader).*|" +
          "javax\\.xml\\.bind\\.Unmarshaller\\.unmarshal.*|javax\\.xml\\.transform\\.Transformer\\.transform.*|javax\\.xml\\.validation\\.Validator\\.validate.*|" +
          "org\\.apache\\.poi\\.xssf\\.usermodel\\.XSSFWorkbook\\.<init>.*|org\\.apache\\.poi\\.ss\\.usermodel\\.WorkbookFactory\\.create.*"), Seq.empty) ++
        sink("xxe", graph.call.name("open").filter(c => c.code.contains("StreamingReader") ||
          argAt(c, 0).exists(_.ast.isCall.methodFullName(".*StreamingReader.*").nonEmpty) ||
          argAt(c, 0).exists(r => r.ast.isCall.name("builder").nonEmpty && r.method.file.ast.isImport.importedEntity(".*StreamingReader").nonEmpty)), Seq(1)) ++
        sink("deserialize", graph.call.methodFullName("com\\.alibaba\\.fastjson2?\\.JSON\\.(parse|parseObject|parseArray):.*|.*ObjectMapper\\.(readValue|readerFor|convertValue):.*|" +
          "com\\.esotericsoftware\\.kryo\\.Kryo\\.readClassAndObject.*|org\\.ho\\.yaml\\.Yaml\\.load.*|com\\.caucho\\.hessian.*readObject.*"), Seq(1)) ++
        sink("eval", graph.call.methodFullName("org\\.apache\\.velocity\\.app\\.(Velocity|VelocityEngine)\\.evaluate.*"), Seq(4)) ++
        sink("eval", graph.call.methodFullName("freemarker\\.template\\.Template\\.<init>.*"), Seq(2)) ++
        sink("eval", graph.call.methodFullName("com\\.ql\\.util\\.express\\.ExpressRunner\\.execute.*|org\\.mvel2\\.MVEL\\.(eval|compileExpression).*|" +
          "javax\\.el\\.ExpressionFactory\\.createValueExpression.*|org\\.thymeleaf.*\\.process.*"), Seq(1)) ++
        xssReturns() ++
        sink("log", graph.call.name("trace|debug|info|warn|error|fatal|log").filter(c =>
          c.methodFullName.matches("(org\\.slf4j|org\\.apache\\.(log4j|logging\\.log4j|commons\\.logging)|java\\.util\\.logging|ch\\.qos\\.logback).*") ||
          receiverType(c).exists(_.matches("(?i).*(Logger|Log)$"))), Seq.empty)
      (request, external, sinkNodes)
    }

  // Joern motoru tabanı tanımlayıcı olmayan dizi erişimlerinde (ör. param.split(" ")[0],
  // { param }[0]) akışı kaybediyor; tabanı kaynaktan beslenen bu erişimler ek kaynak düğümü
  // olarak eklenir (motor sonrasını kendisi izler; kaynak adı ilk kaynaktan gelir).
  def indexSeeds(base: List[CfgNode]): List[CfgNode] = if (base.isEmpty) Nil else {
    val baseIds = base.map(_.id()).toSet
    graph.call.nameExact("<operator>.indexAccess").l
      .filter(c => argAt(c, 1).exists(a => !a.isInstanceOf[Identifier] && !a.isInstanceOf[Literal]))
      .flatMap { access =>
        argAt(access, 1).toList.flatMap { arrayExpr =>
          // İç içe erişim (params[:a][:b]): kaynak dizi ifadesinin AST'sinde ise doğrudan tohumdur.
          val nested = arrayExpr.ast.l.filter(n => baseIds.contains(n.id()))
          val origins = if (nested.nonEmpty) nested else arrayExpr.reachableBy(base.iterator).l
          origins.headOption.map { origin =>
            sourceInfo(access.id()) = sourceInfo.getOrElse(origin.id(), "girdi")
            access
          }
        }
      }
  }
  // Sanal çağrı özetleri: arayüz/soyut yöntem ya da çözülemeyen alıcı üzerinden yapılan çağrıda, aynı adlı ve
  // aynı argüman sayılı proje uygulamalarından birinde ilgili parametre (arındırılmadan) bir hedefe ulaşıyorsa
  // çağrı argümanı da o türün hedefidir (IDbProvider.GetEmailByName(name) → MySqlDbProvider … new MySqlCommand).
  // Sanal çağrı hedeflerinde uygulama içindeki yol (bulgu adımlarına eklenir).
  val sinkTail = scala.collection.mutable.Map[Long, List[StoredNode]]()
  val virtualSinks: List[Expression] = {
    val sinkByMethod = baseSinks.filter(s => scala.util.Try(s.method != null).getOrElse(false)).groupBy(_.method)
    // Kapanışlar: METHOD_REF ile ya da (Ruby blokları) "<yöntem>.<lambda>N" adlı TYPE_REF ile bağlanır.
    val lambdasByOwner: Map[String, List[Method]] = graph.method.fullName(".*\\.<lambda>\\d+.*").l
      .groupBy(l => l.fullName.substring(0, l.fullName.indexOf(".<lambda>")))
    def closures(m: Method): List[Method] = (m.ast.isMethodRef.referencedMethod.l ++ lambdasByOwner.getOrElse(m.fullName, Nil)).distinct
    // Proje türünde bildirildiğini söyleyen ama gövdesiz "dış" kopya (C# ön ucunda tür adı uyuşmazlığı:
    // ResponseFile(HttpRequest,…) çağrısı ResponseFile(System.Web.HttpRequest,…) yöntemine bağlanmıyor).
    val projectTypes = graph.typeDecl.isExternal(false).fullName.toSet
    def declaringType(fullName: String): String = { val n = fullName.takeWhile(_ != ':'); n.substring(0, math.max(0, n.lastIndexOf('.'))) }
    def projectStub(m: Method): Boolean = m.isExternal && projectTypes.contains(declaringType(m.fullName))
    def virtualCallee(m: Method): Boolean =
      (!m.isExternal && (m.modifier.modifierType.l.contains("ABSTRACT") || m.block.astChildren.isEmpty)) ||
        m.fullName.contains("unresolved") || m.fullName.contains("<unknown") || projectStub(m)
    val implsByKey = graph.method.isExternal(false).filter(m => m.block.astChildren.nonEmpty && !m.name.startsWith("<")).l
      .groupBy(m => (m.name, m.parameter.count(_.index >= 1)))
    // Rails `scope :ad, ->(a, b) { … }`: Model.ad(x, y) çağrısının gövdesi lambdadır.
    val rubyScopes: Map[(String, Int), List[Method]] = if (lang != "ruby") Map.empty else
      graph.call.nameExact("scope").l.flatMap { c =>
        for {
          name <- argAt(c, 1).map(_.code.stripPrefix(":")).filter(_.matches("\\w+"))
          ref <- argAt(c, 2).collect { case t: TypeRef => t }
          m <- graph.method.fullNameExact(ref.typeFullName.stripSuffix("&Proc")).l.headOption
        } yield (name, m.parameter.count(_.index >= 1)) -> m
      }.groupBy(_._1).map { case (k, v) => k -> v.map(_._2) }
    def implementations(c: Call): List[Method] =
      if (c.name.startsWith("<") || !c.callee.l.forall(virtualCallee)) Nil   // çağrılan yok = çözülemedi
      else {
        val declared = c.callee.l.filterNot(_.isExternal).flatMap(_.definingTypeDecl.fullName.l).toSet ++
          c.callee.l.filter(projectStub).map(m => declaringType(m.fullName))
        val key = (c.name, c.argument.count(_.argumentIndex >= 1))
        (implsByKey.getOrElse(key, Nil) ++ rubyScopes.getOrElse(key, Nil)).filter(m => declared.isEmpty ||
          m.definingTypeDecl.fullName.l.exists(declared.contains) ||
          m.definingTypeDecl.inheritsFromTypeFullName.l.exists(t => declared.contains(t) || declared.exists(_.endsWith("." + t)))).take(8)
      }
    // (tür, hedef adı, uygulamadaki yol düğümleri: parametre … gerçek hedef) — yol, bulgu adımlarına eklenir.
    val cache = scala.collection.mutable.Map[(Long, Int), Option[(String, String, List[StoredNode])]]()
    // Bir parametre birden çok hedefe ulaşıyorsa en ağır tür seçilir.
    val KIND_PRIORITY = List("command", "deserialize", "eval", "sql", "xxe", "ldap", "xpath", "ssrf", "path", "redirect", "xss", "trustbound", "crlf", "log")
    def mostSevere(found: List[(String, String, List[StoredNode])]): Option[(String, String, List[StoredNode])] =
      found.sortBy { case (kind, _, _) => val i = KIND_PRIORITY.indexOf(kind); if (i < 0) 99 else i }.headOption
    val visiting = scala.collection.mutable.Set[(Long, Int)]()
    // (tür, hedef adı): m'nin index'inci parametresi arındırılmadan bir hedefe ulaşıyor mu? Gövdedeki sanal
    // çağrılara (en çok 3 düzey) özyinelemeli olarak bakılır.
    def summary(m: Method, index: Int, depth: Int): Option[(String, String, List[StoredNode])] = {
      val key = (m.id(), index)
      cache.get(key) match {
        case Some(result) => result
        case None if visiting.contains(key) || depth > 3 => None
        case None =>
          visiting += key
          val result = m.parameter.filter(_.index == index).l.headOption.flatMap { p =>
            // Kapsam: yöntem, çözülmüş proje içi çağrılanları ve gövdesindeki kapanışlar (Ruby blokları, lambdalar).
            val local = (m :: m.call.callee.isExternal(false).l ++ closures(m)).distinct
              .flatMap(sm => sinkByMethod.getOrElse(sm, Nil))
            val direct =
              if (local.isEmpty) None
              else local.reachableByFlows(Iterator(p)).l.flatMap { f =>
                val nodes = f.elements.map(_.asInstanceOf[StoredNode])
                sinkInfo.get(f.elements.last.id()).filter { case (kind, _) => !sanitized(kind, nodes) }
                  .map { case (kind, name) => (kind, name, List(nodes.head, nodes.last)) }
              }
            // Kapanış içindeki hedef, yakalanan parametreyi adıyla kullanıyorsa (Joern yakalanan değişken akışını
            // her dilde izlemiyor): system("cp #{file.original_filename}") bloğu.
            val viaClosures = closures(m).flatMap(sm => sinkByMethod.getOrElse(sm, Nil)).flatMap { sk =>
              sk.ast.isIdentifier.nameExact(p.name).l.headOption.flatMap { id =>
                val chain = Iterator.iterate(id: StoredNode)(n => scala.util.Try(n.asInstanceOf[AstNode].astParent: StoredNode).getOrElse(sk))
                  .takeWhile(_.id() != sk.id()).take(50).toList :+ (sk: StoredNode)
                sinkInfo.get(sk.id()).filter { case (kind, _) => !sanitized(kind, chain) }
                  .map { case (kind, name) => (kind, name, List(p: StoredNode, sk: StoredNode)) }
              }
            }
            val viaCalls = m.call.l.flatMap { inner =>
              val impls = implementations(inner)
              if (impls.isEmpty) Nil
              else inner.argument.l.filter(_.argumentIndex >= 1).filter(a => a.reachableBy(Iterator(p)).nonEmpty).flatMap { a =>
                impls.flatMap(im => summary(im, a.argumentIndex, depth + 1)).map { case (kind, name, tail) =>
                  (kind, s"${inner.name} → $name", (p: StoredNode) :: (inner: StoredNode) :: tail) }
              }
            }
            mostSevere(direct.toList ++ viaClosures ++ viaCalls.toList)
          }
          visiting -= key
          cache(key) = result
          result
      }
    }
    graph.call.l.flatMap { c =>
      val impls = implementations(c)
      if (impls.isEmpty) Nil
      else c.argument.l.filter(_.argumentIndex >= 1).flatMap { a =>
        mostSevere(impls.flatMap(m => summary(m, a.argumentIndex, 1))).map { case (kind, sinkName, tail) =>
          sinkInfo(a.id()) = (kind, s"${c.name} → $sinkName")
          sinkTail(a.id()) = tail.take(12)
          a
        }
      }
    }
  }
  val sinks = baseSinks ++ virtualSinks
  val sinkCallIds: Set[Long] = sinks.flatMap(s => scala.util.Try(s.astParent).toOption.map(_.id())).toSet
  val baseRequestSeeds = requestSources ++ indexSeeds(requestSources)
  val baseExternalSeeds = externalSources ++ indexSeeds(externalSources)

  // ---- PHP: dosyalar arası küresel değişkenler, oturum ve veritabanı üzerinden ikinci derece akış ----
  // Joern her dosyanın üst düzey kodunu ayrı "<global>" yöntemi olarak modelliyor; include/require ile
  // paylaşılan küresel kapsamı, `global $x`, $GLOBALS['x'], $_SESSION['k'] ve tabloya yazılıp başka yerde
  // okunan veriyi izlemiyor. Bu köprüler ek kaynak düğümleri (tohum) olarak eklenir; tohuma ulaşan önceki
  // yol ("önek") bulgu adımlarının başına konur ve arındırma/koruma denetimleri birleşik yolda yapılır.
  //  * Küresel: A dosyasında üst düzeyde (ya da `global`/$GLOBALS ile) yazılan $x, A ile aynı include
  //    kapanışında bulunan B dosyasında okunur (B, okumadan önce $x'e düz atama yapmıyorsa).
  //    include hedefi sabit parçalarından çözülür ("vulnerabilities/x/source/{$f}" → o dizindeki dosyalar).
  //  * Oturum: $_SESSION['k'] = girdi → herhangi bir dosyada $_SESSION['k'] okuması (etiket "stored").
  //  * Veritabanı: girdi INSERT/UPDATE/REPLACE ile T tablosuna yazılır (HTML arındırması olmadan) →
  //    T'den SELECT eden sorgunun sonucu (etiket "stored", kalıcı XSS vb.).
  val prefixes = scala.collection.mutable.Map[Long, List[List[StoredNode]]]()
  val MAX_PREFIXES = 12
  def prefixesOf(n: StoredNode): List[List[StoredNode]] = prefixes.getOrElse(n.id(), List(Nil))
  // Kaynak adı: köprü tohumunda asıl kaynak öneğin başındadır; ikinci derece (oturum/veritabanı) için
  // "oturum $_SESSION['k'] ← $_POST" biçiminde.
  def sourceNameFor(label: String, first: StoredNode, prefix: List[StoredNode]): String = {
    val own = sourceInfo.getOrElse(first.id(), "girdi")
    prefix.headOption.flatMap(h => sourceInfo.get(h.id())) match {
      case Some(origin) if label == "stored" => s"$own ← $origin"
      case Some(origin) => origin
      case None => own
    }
  }
  // Önek sırası belirleyici olsun (Joern yol seçimi koşudan koşuya değişebilir): kısa olan, sonra ilk konum.
  def prefixRank(p: List[StoredNode]): (Int, Int, Long) =
    (p.size, p.headOption.flatMap { case c: CfgNode => c.lineNumber.map(_.intValue); case _ => None }.getOrElse(0), p.headOption.map(_.id()).getOrElse(0L))
  // Aynı yazma düğümü (önek sonu) için tek önek tutulur: aynı yazmaya birden çok kaynak satırından gelen yollar
  // yerine en kısası; böylece farklı dosyalardaki yazmalar (low/medium/high) sınırı paylaşmaz.
  def mergePrefixes(existing: List[List[StoredNode]], fresh: List[List[StoredNode]]): List[List[StoredNode]] =
    (existing ++ fresh).groupBy(_.lastOption.map(_.id()).getOrElse(0L)).values.map(_.minBy(prefixRank)).toList
      .sortBy(prefixRank).take(MAX_PREFIXES)
  def addPrefix(target: CfgNode, origin: StoredNode, path: List[StoredNode]): Boolean = {
    val existing = prefixes.getOrElse(target.id(), Nil)
    val merged = mergePrefixes(existing, prefixesOf(origin).map(_ ++ path))
    if (merged == existing) false
    else {
      prefixes(target.id()) = merged
      if (!sourceInfo.contains(target.id())) sourceInfo(target.id()) = sourceInfo.getOrElse(origin.id(), "girdi")
      true
    }
  }
  // Dinamik dillerde çözülemeyen argümansız yardımcı çağrısı (Rails `user_params`, `custom_fields`): aynı
  // sınıftaki aynı adlı yöntemin dönüş değeri kaynaktan geliyorsa çağrı da kaynaktır (yöntem içindeki yol önektir).
  def helperSeeds(seeds: List[CfgNode]): List[CfgNode] = if (!dynamicLanguage || lang == "php" || seeds.isEmpty) Nil else {
    def owner(fullName: String): String = { val n = fullName.takeWhile(_ != ':'); n.substring(0, math.max(0, n.lastIndexOf('.'))) }
    val calls = graph.call.l.filter(c => !c.name.startsWith("<") && c.callee.isEmpty && c.argument.count(_.argumentIndex >= 1) == 0)
      .groupBy(_.name)
    val targets = graph.method.isExternal(false).filter(m => calls.contains(m.name) && m.parameter.count(_.index >= 1) == 0 &&
      m.block.astChildren.nonEmpty).l
    if (targets.isEmpty) Nil
    else targets.map(_.methodReturn).reachableByFlows(seeds.iterator).l.flatMap { flow =>
      val nodes = flow.elements.map(_.asInstanceOf[StoredNode])
      val m = flow.elements.last.asInstanceOf[MethodReturn].method
      calls.getOrElse(m.name, Nil).filter(c => scala.util.Try(owner(c.method.fullName) == owner(m.fullName) ||
        owner(c.method.fullName).startsWith(owner(m.fullName) + ".")).getOrElse(false))
        .filter(c => addPrefix(c, nodes.head, nodes.dropRight(1)))
    }.distinctBy(_.id())
  }
  val helperRequestSeeds = baseRequestSeeds ++ helperSeeds(baseRequestSeeds)
  val (requestSeeds, externalSeeds, storedSeeds): (List[CfgNode], List[CfgNode], List[CfgNode]) =
    if (lang != "php") (helperRequestSeeds, baseExternalSeeds, List.empty[CfgNode])
    else {
      val SUPERGLOBALS = Set("_GET", "_POST", "_REQUEST", "_COOKIE", "_FILES", "_SERVER", "_SESSION", "_ENV", "GLOBALS", "this", "argv", "argc")
      def anyLiteral(e: Expression): Option[String] = e match {
        case l: Literal if l.code.length >= 2 && (l.code.head == '"' || l.code.head == '\'') && l.code.last == l.code.head =>
          Some(l.code.substring(1, l.code.length - 1))
        case _ => None
      }
      def fileOf(n: CfgNode): String = scala.util.Try(n.method.filename).getOrElse("")
      def isTop(m: Method): Boolean = m.name == "<global>"
      // `global $x;` → yöntemde kapanış bağlı yerel (adsız işlevlerin `use` bağları hariç).
      val globalDecls: Map[Long, Set[String]] = graph.method.isExternal(false).filterNot(m => isTop(m) || m.name.startsWith("<") ||
        m.name.toLowerCase.contains("closure") || m.name.toLowerCase.contains("lambda")).l
        .map(m => m.id() -> m.local.l.filter(_.closureBindingId.exists(_.nonEmpty)).map(_.name).toSet).filter(_._2.nonEmpty).toMap
      def globalIn(m: Method, name: String): Boolean = isTop(m) || globalDecls.get(m.id()).exists(_.contains(name))
      def isAssignmentTarget(e: Expression): Boolean = scala.util.Try(e.astParent).toOption.exists {
        case c: Call => c.name.startsWith("<operator>.assignment") && e.argumentIndex == 1
        case _ => false
      }
      // Hedef ifadenin kök küresel adı: $x, $x['a'], $x->a, $GLOBALS['x'].
      def rootGlobal(target: Expression, m: Method, depth: Int = 0): Option[String] = if (depth > 4) None else target match {
        case id: Identifier if !SUPERGLOBALS.contains(id.name) && globalIn(m, id.name) => Some(id.name)
        case c: Call if c.name == "<operator>.indexAccess" || c.name == "<operator>.fieldAccess" =>
          argAt(c, 1) match {
            case Some(base: Identifier) if base.name == "GLOBALS" => argAt(c, 2).flatMap(anyLiteral)
            case Some(base) => rootGlobal(base, m, depth + 1)
            case None => None
          }
        case _ => None
      }
      // --- include grafiği ---
      val files = graph.method.isExternal(false).filename.l.filterNot(f => f.isEmpty || f.startsWith("<")).distinct
      def pathParts(e: Expression, depth: Int = 0): List[Option[String]] = if (depth > 6) List(None) else e match {
        case l: Literal => List(anyLiteral(l).orElse(Some(l.code)))
        case c: Call if c.name.matches("<operator>\\.concat|encaps") =>
          c.argument.l.sortBy(_.argumentIndex).flatMap(a => pathParts(a, depth + 1))
        case _ => List(None)
      }
      def includeTargets(call: Call): List[String] = argAt(call, 1).toList.flatMap { arg =>
        val parts = pathParts(arg).foldLeft(List.empty[Option[String]]) {
          case (acc, None) if acc.lastOption.contains(None) => acc
          case (acc, part) => acc :+ part
        }
        val literal = parts.flatten.mkString
        // Yalnız uzantı (".php") ya da dizin ayırıcıları sabitse hedef çözülemez (tümüyle dinamik include).
        if (literal.replaceAll("(?i)\\.(php\\d?|inc|phtml)$", "").replaceAll("[./]", "").length < 3) Nil
        else {
          val body = parts.zipWithIndex.map {
            case (Some(text), i) =>
              val cleaned = if (i == 0 || parts(i - 1).isEmpty) text.replaceAll("^(\\.{1,2}/|/)+", "") else text
              java.util.regex.Pattern.quote(cleaned)
            case (None, _) => ".*"
          }.mkString
          val re = ("(?:^|.*/)" + body.stripPrefix(".*") + "$").r
          val hits = files.filter(f => re.findFirstIn(f).nonEmpty)
          if (hits.size > 30) Nil else hits
        }
      }
      val includeSites: List[(String, List[String])] = graph.call.name("include|include_once|require|require_once").l
        .map(c => fileOf(c) -> includeTargets(c))
      val includes: Map[String, Set[String]] = includeSites.flatMap { case (f, ts) => ts.map(f -> _) }
        .groupBy(_._1).map { case (k, v) => k -> v.map(_._2).toSet }
      // Aynı değişken yollu include'un adayları (source/{$seviye}.php) birbirinin seçeneğidir: aynı istekte
      // birlikte yüklenmez, küresel kapsam paylaşmaz.
      val alternatives: List[Set[String]] = includeSites.collect { case (_, ts) if ts.size > 1 => ts.toSet }
      val closureOf: Map[String, Set[String]] = files.map { f =>
        val seen = scala.collection.mutable.Set(f)
        var frontier = List(f)
        while (frontier.nonEmpty && seen.size < 500) {
          frontier = frontier.flatMap(x => includes.getOrElse(x, Set.empty)).filterNot(seen.contains)
          seen ++= frontier
        }
        f -> seen.toSet
      }.toMap
      val containers: Map[String, Set[String]] = closureOf.toList.flatMap { case (e, members) => members.map(_ -> e) }
        .groupBy(_._1).map { case (k, v) => k -> v.map(_._2).toSet }
      def shareScope(a: String, b: String): Boolean =
        a == b || (containers.getOrElse(a, Set.empty).exists(e => containers.getOrElse(b, Set.empty).contains(e)) &&
          !alternatives.exists(set => set.contains(a) && set.contains(b)))

      // --- küresel yazma / okuma ---
      val assignments = graph.call.name("<operator>\\.assignment.*").l.filter(a => scala.util.Try(a.method != null).getOrElse(false))
      case class Write(name: String, call: Call, rhs: Expression)
      val writes: List[Write] = assignments.flatMap(a => for {
        target <- argAt(a, 1); rhs <- argAt(a, 2) if !rhs.isInstanceOf[Literal]; name <- rootGlobal(target, a.method)
      } yield Write(name, a, rhs))
      val plainAssigns: Map[(Long, String), List[Int]] = assignments.filter(_.name == "<operator>.assignment")
        .flatMap(a => argAt(a, 1).collect { case id: Identifier => ((a.method.id(), id.name), a.lineNumber.map(_.intValue).getOrElse(0)) })
        .groupBy(_._1).map { case (k, v) => k -> v.map(_._2) }
      val writtenNames = writes.map(_.name).toSet
      val reads: Map[String, List[CfgNode]] = (
        graph.identifier.l.filter(id => writtenNames.contains(id.name) && !isAssignmentTarget(id) &&
          scala.util.Try(globalIn(id.method, id.name)).getOrElse(false)).map(id => id.name -> (id: CfgNode)) ++
        graph.call.nameExact("<operator>.indexAccess").l.filter(c => !isAssignmentTarget(c) &&
          argAt(c, 1).exists { case b: Identifier => b.name == "GLOBALS"; case _ => false })
          .flatMap(c => argAt(c, 2).flatMap(anyLiteral).filter(writtenNames.contains).map(n => n -> (c: CfgNode)))
      ).groupBy(_._1).map { case (k, v) => k -> v.map(_._2) }
      // Okuma, kendi yönteminde daha önceki bir düz atamayla örtülüyorsa (yerel değer) köprü kurulmaz.
      def shadowed(r: CfgNode, name: String): Boolean = {
        val line = r.lineNumber.map(_.intValue).getOrElse(0)
        plainAssigns.getOrElse((r.method.id(), name), Nil).exists(_ < line)
      }
      def path(flow: Path): List[StoredNode] = flow.elements.map(_.asInstanceOf[StoredNode])
      // Küresel köprüleri sabit noktaya kadar (en çok 3 tur) uygula; yeni tohumları döndür.
      def bridgeGlobals(seeds: List[CfgNode]): List[CfgNode] = {
        val all = scala.collection.mutable.LinkedHashMap[Long, CfgNode]()
        var frontier = seeds
        var round = 0
        val byRhs = writes.groupBy(_.rhs.id())
        val rhsList = writes.map(_.rhs).take(5000)
        while (frontier.nonEmpty && round < 3 && rhsList.nonEmpty && all.size < 2000) {
          val next = scala.collection.mutable.ListBuffer[CfgNode]()
          rhsList.reachableByFlows(frontier.iterator).l.foreach { flow =>
            val nodes = path(flow)
            if (!crossArgument(nodes) && !onlyThroughCondition(nodes)) byRhs.getOrElse(flow.elements.last.id(), Nil).filterNot(w => isDead(w.call)).foreach { w =>
              val wFile = fileOf(w.call)
              reads.getOrElse(w.name, Nil).foreach { r =>
                if (r.method.id() != w.call.method.id() && shareScope(wFile, fileOf(r)) && !shadowed(r, w.name) &&
                    !(nodes.head.id() == r.id()) && addPrefix(r, nodes.head, nodes ++ argAt(w.call, 1).toList)) {
                  if (!all.contains(r.id())) { all(r.id()) = r; next += r }
                }
              }
            }
          }
          frontier = next.toList
          round += 1
        }
        all.values.toList
      }
      val requestBridged = baseRequestSeeds ++ bridgeGlobals(baseRequestSeeds)
      val externalBridged = baseExternalSeeds ++ bridgeGlobals(baseExternalSeeds)

      // --- oturum ---
      def sessionKey(e: Expression, depth: Int = 0): Option[String] = if (depth > 3) None else e match {
        case c: Call if c.name == "<operator>.indexAccess" => argAt(c, 1) match {
          case Some(b: Identifier) if b.name == "_SESSION" => argAt(c, 2).flatMap(anyLiteral)
          case Some(inner) => sessionKey(inner, depth + 1)
          case None => None
        }
        case _ => None
      }
      val sessionWrites: List[(String, Call, Expression)] = assignments.flatMap(a => for {
        target <- argAt(a, 1); rhs <- argAt(a, 2) if !rhs.isInstanceOf[Literal]; key <- sessionKey(target)
      } yield (key, a, rhs))
      val sessionReads: Map[String, List[CfgNode]] = graph.call.nameExact("<operator>.indexAccess").l
        .filter(c => argAt(c, 1).exists { case b: Identifier => b.name == "_SESSION"; case _ => false } &&
          !isAssignmentTarget(c) && !scala.util.Try(c.astParent).toOption.exists {
            case p: Call => p.name == "<operator>.indexAccess" && isAssignmentTarget(p); case _ => false })
        .flatMap(c => argAt(c, 2).flatMap(anyLiteral).map(_ -> (c: CfgNode))).groupBy(_._1).map { case (k, v) => k -> v.map(_._2) }
      val storedNew = scala.collection.mutable.LinkedHashMap[Long, CfgNode]()
      if (sessionWrites.nonEmpty && requestBridged.nonEmpty) {
        val byRhs = sessionWrites.groupBy(_._3.id())
        sessionWrites.map(_._3).reachableByFlows(requestBridged.iterator).l.foreach { flow =>
          val nodes = path(flow)
          if (!crossArgument(nodes) && !onlyThroughCondition(nodes)) byRhs.getOrElse(flow.elements.last.id(), Nil).filterNot(w => isDead(w._2)).foreach { case (key, call, _) =>
            sessionReads.getOrElse(key, Nil).foreach { r =>
              if (addPrefix(r, nodes.head, nodes ++ argAt(call, 1).toList)) {
                sourceInfo(r.id()) = "oturum $_SESSION['" + key + "']"
                storedNew(r.id()) = r
              }
            }
          }
        }
      }

      // --- veritabanı (kalıcı) ---
      // Sorgu metni: argümandaki sabitler + argümandaki yerel değişkenlerin aynı yöntemdeki atamalarındaki sabitler.
      def sqlText(e: Expression): String = (e.ast.isLiteral.code.l ++ e.ast.isIdentifier.l.flatMap(id =>
        id.method.assignment.l.filter(a => a.target.code == id.code).flatMap(a => argAt(a, 2).toList.flatMap(_.ast.isLiteral.code.l)))).mkString(" ")
      val WRITE_RE = "(?is).*?\\b(?:insert\\s+(?:ignore\\s+)?into|replace\\s+into|update)\\s+[`\"\\[]?(\\w+).*".r
      val READ_RE = "(?is)\\b(?:from|join)\\s+[`\"\\[]?(\\w+)".r
      val sqlSinks = sinks.filter(s => sinkInfo.get(s.id()).exists(_._1 == "sql"))
      val writesByArg: Map[Long, String] = sqlSinks.flatMap(s => sqlText(s) match {
        case WRITE_RE(table) => Some(s.id() -> table.toLowerCase)
        case _ => None
      }).toMap
      // Hazırlanmış ifadeler (PDO / mysqli): $st = $db->prepare("INSERT INTO t …") ya da mysqli_prepare($c, "…");
      // ardından $st->execute([...]) / bindParam / bindValue / bind_param ya da mysqli_stmt_bind_param($st, …).
      // Sorgu metni sabit olduğundan SQL enjeksiyonu değildir; bağlanan değerler t tablosuna yazılır.
      def preparedWriteTable(stmtVar: Expression, at: Call): Option[String] = stmtVar match {
        case id: Identifier => at.method.assignment.l.filter(a => a.target.code == id.code).flatMap(a => argAt(a, 2).toList)
          .collect { case p: Call if p.name == "prepare" => argAt(p, 1); case p: Call if p.name == "mysqli_prepare" => argAt(p, 2) }
          .flatten.flatMap(q => sqlText(q) match { case WRITE_RE(table) => Some(table.toLowerCase); case _ => None }).headOption
        case _ => None
      }
      val preparedWrites: Map[Long, String] = (
        graph.call.name("execute|bindParam|bindValue|bind_param").l.flatMap(c => argAt(c, 0).flatMap(preparedWriteTable(_, c))
          .toList.flatMap(table => c.argument.l.filter(_.argumentIndex >= 1).map(_.id() -> table))) ++
        graph.call.name("mysqli_stmt_bind_param|mysqli_stmt_execute").filter(c => argAt(c, 0).isEmpty).l.flatMap(c =>
          argAt(c, 1).flatMap(preparedWriteTable(_, c)).toList.flatMap(table =>
            c.argument.l.filter(_.argumentIndex >= 2).map(_.id() -> table)))
      ).toMap
      val dbWriters = scala.collection.mutable.Map[String, List[List[StoredNode]]]()
      def recordWrite(flow: Path, table: String): Unit = {
        val nodes = path(flow)
        val full = prefixesOf(nodes.head).map(_ ++ nodes)
        val clean = full.filterNot(p => sanitized("xss", p) || isDead(flow.elements.last) || crossArgument(nodes) || onlyThroughCondition(nodes))
        if (clean.nonEmpty) dbWriters(table) = mergePrefixes(dbWriters.getOrElse(table, Nil), clean)
      }
      if (writesByArg.nonEmpty && requestBridged.nonEmpty) {
        sqlSinks.filter(s => writesByArg.contains(s.id())).reachableByFlows(requestBridged.iterator).l.foreach { flow =>
          recordWrite(flow, writesByArg(flow.elements.last.id()))
        }
      }
      if (preparedWrites.nonEmpty && requestBridged.nonEmpty) {
        graph.call.name("execute|bindParam|bindValue|bind_param|mysqli_stmt_bind_param|mysqli_stmt_execute").argument
          .filter(a => preparedWrites.contains(a.id())).l.reachableByFlows(requestBridged.iterator).l.foreach { flow =>
            preparedWrites.get(flow.elements.last.id()).foreach(table => recordWrite(flow, table))
          }
      }
      if (dbWriters.nonEmpty) {
        sqlSinks.filterNot(s => writesByArg.contains(s.id())).foreach { s =>
          val text = sqlText(s)
          val tables = READ_RE.findAllMatchIn(text).map(_.group(1).toLowerCase).toSet
          if (text.matches("(?is).*\\bselect\\b.*")) tables.flatMap(t => dbWriters.getOrElse(t, Nil)).foreach { writer =>
            scala.util.Try(s.astParent).toOption.collect { case c: Call => c }.foreach { queryCall =>
              prefixes(queryCall.id()) = mergePrefixes(prefixes.getOrElse(queryCall.id(), Nil), List(writer))
              sourceInfo(queryCall.id()) = s"veritabanı (${tables.mkString(",")})"
              storedNew(queryCall.id()) = queryCall
            }
          }
        }
      }
      val storedBase = storedNew.values.toList
      (requestBridged, externalBridged, storedBase ++ bridgeGlobals(storedBase))
    }

  // Satır başına boşaltılır: süre bütçesinde süreç durdurulursa o ana kadar yazılan akışlar kısmi sonuçtur.
  val writer = new java.io.PrintWriter(new java.io.OutputStreamWriter(new java.io.FileOutputStream(outFile), "UTF-8"), true)
  var written = 0
  def location(n: StoredNode): String = {
    val (file, methodName) = n match {
      case node: CfgNode => (node.method.filename, node.method.name)
      case _ => ("", "")
    }
    val line = n match { case node: CfgNode => node.lineNumber.map(_.intValue).getOrElse(-1); case _ => -1 }
    s"[${jsonString(file)},$line,${jsonString(methodName)}]"
  }
  // Sanal çağrı hedefi: çağrılan uygulamadaki yol ("tail"; bulgunun konumu çağrı noktası kalır).
  def tailJson(sinkNode: StoredNode): String = sinkTail.get(sinkNode.id()).filter(_.nonEmpty)
    .map(t => ""","tail":""" + t.map(location).mkString("[", ",", "]")).getOrElse("")
  def pattern(kind: String, call: Call, sinkName: String, detail: String): Unit = {
    if (written < maxFlows && !isDead(call)) {
      writer.println(
        s"""{"kind":${jsonString(kind)},"label":"pattern","language":"java","source":"","sink":${jsonString(sinkName)},""" +
        s""""steps":[${location(call)}],"detail":$detail}"""
      )
      written += 1
    }
  }
  try {
    // JS/Python: hedefler türe göre gruplanıp sırayla sorulur (kısmi sonuç için akışlar erken yazılır);
    // diğer dillerde tek sorgu (sonuçlar ve sıra değişmesin).
    val sinkGroups: List[List[Expression]] =
      if (scriptLanguage) sinks.groupBy(s => sinkInfo.get(s.id()).map(_._1).getOrElse("")).toList.sortBy(_._1).map(_._2)
      else List(sinks)
    for ((label, sources) <- Seq("request" -> requestSeeds, "external" -> externalSeeds, "stored" -> storedSeeds);
         group <- sinkGroups if sources.nonEmpty && group.nonEmpty) {
      val flows = group.reachableByFlows(sources).l
      flows.foreach { flow =>
        val elements = flow.elements
        if (written < maxFlows && elements.nonEmpty) {
          val last = elements.last
          val first = elements.head
          sinkInfo.get(last.id()).foreach { case (kind, sinkName) =>
            val nodes = elements.map(_.asInstanceOf[StoredNode])
            val deadNodes = nodes.filter(isDead)
            // Joern bir kaynak–hedef çifti için tek yol döndürebilir: yol ölü daldan geçiyorsa aynı
            // değişkenin canlı, sabit olmayan bir atamasının kaynaktan beslenip hedefe ulaşıp
            // ulaşmadığı ayrıca sorulur (kurtarma).
            val rescuedVia: Option[StoredNode] =
              if (deadNodes.isEmpty) None
              else deadNodes.iterator.flatMap(assignmentTargetName).take(1).toList.headOption.flatMap { case (method, name) =>
                method.assignment.l.filter(a => a.target.code == name && !isDead(a) && !a.source.isInstanceOf[Literal])
                  .find { live =>
                    live.source.reachableBy(sources.iterator).nonEmpty &&
                    last.asInstanceOf[Expression].reachableBy(Iterator(live.target)).nonEmpty
                  }
              }
            val pathOk = (deadNodes.isEmpty || rescuedVia.nonEmpty) &&
              // self.params gibi alan kaynaklarında Joern alıcıyı (self/this) da kirletir; dinamik dillerde
              // self/this üzerinden geçen yol başka bir alana (self.root_path) taşınmış sayılmaz.
              (lang != "ruby" || !nodes.drop(1).exists { case id: Identifier => id.name == "self"; case _ => false }) &&
              // Python/JS: aynı kural self/this için (Django sınıf görünümlerinde self.request alanı tüm nesneyi kirletiyordu).
              (!scriptLanguage || !nodes.drop(1).exists { case id: Identifier => id.name == "self" || id.name == "this"; case _ => false }) &&
              // Bilinmeyen dış çağrılarda Joern argümanlar arası yayılım varsayar; bir hedef çağrısı (mysqli_query,
              // db.Query …) diğer argümanlarını (bağlantı nesnesi) kirletmez.
              (isJava || lang == "c" || !nodes.sliding(2).exists {
                case List(a: Expression, b: Expression) =>
                  val pa = scala.util.Try(a.astParent).toOption
                  pa.exists(p => sinkCallIds.contains(p.id())) && scala.util.Try(b.astParent).toOption.exists(_.id() == pa.get.id()) &&
                    a.argumentIndex != b.argumentIndex
                case _ => false
              })
            val sinkCall = scala.util.Try(last.asInstanceOf[Expression].astParent).toOption.collect { case c: Call => c }
            if (pathOk && !constantConditionalBlocks(nodes) && !onlyThroughCondition(nodes) && !wrongCollectionSlot(nodes) &&
                !safeConfiguration(kind, sinkCall)) {
              val sourceName = sourceInfo.getOrElse(first.id(), "girdi")
              val stepNodes = rescuedVia match {
                case Some(via) => List(first.asInstanceOf[StoredNode], via, last.asInstanceOf[StoredNode])
                case None => nodes
              }
              // Köprü tohumları (PHP küresel/oturum/veritabanı): her önek ayrı kayıt; arındırma birleşik yolda.
              prefixesOf(first).foreach { prefix =>
                if (written < maxFlows && !sanitized(kind, prefix ++ nodes)) {
                  val steps = (prefix ++ stepNodes).map(location).mkString("[", ",", "]")
                  writer.println(
                    s"""{"kind":${jsonString(kind)},"label":${jsonString(label)},"language":${jsonString(lang)},""" +
                    s""""source":${jsonString(sourceNameFor(label, first, prefix))},"sink":${jsonString(sinkName)},"steps":$steps${tailJson(last)}}"""
                  )
                  written += 1
                }
              }
            }
          }
        }
      }
    }
    if (!isJava && lang != "c") {
      // Dinamik dillerde Joern'ün kaçırabildiği iki kısa yol (sözdizimsel, yöntem içi):
      //  1) kaynak doğrudan hedef ifadesinin içinde: fmt.Fprintf(w, "%s", r.URL.Path);
      //  2) hedefteki yerel değişken yöntemde TEK kez ve kaynağı içeren bir ifadeyle atanmış:
      //     file = params[:x] … (Ruby `unless … return end` sonrası CFG kopukluğu) … save(file).
      def ancestors(from: StoredNode, until: StoredNode): List[StoredNode] =
        Iterator.iterate(from)(n => scala.util.Try(n.asInstanceOf[AstNode].astParent: StoredNode).getOrElse(until))
          .takeWhile(_.id() != until.id()).take(50).toList :+ until
      for ((label, seeds) <- Seq("request" -> requestSeeds, "external" -> externalSeeds, "stored" -> storedSeeds)) {
        val seedIds = seeds.map(_.id()).toSet
        val seededAssignments: Map[(Long, String), (Call, StoredNode)] =
          graph.assignment.l.map(a => a: Call).filter(a => scala.util.Try(a.method != null).getOrElse(false))
            .groupBy(a => (a.method.id(), assignTarget(a) match { case id: Identifier => id.name; case t => t.code })).collect {
            case (key, List(a)) if assignTarget(a).isInstanceOf[Identifier] =>
              argAt(a, 2).toList.flatMap(_.ast.l.find(n => seedIds.contains(n.id()))).headOption.map(seed => key -> (a, seed: StoredNode))
          }.flatten.toMap
        def emit(kind: String, sinkName: String, s: Expression, src: StoredNode, chain: List[StoredNode]): Unit =
          prefixesOf(src).foreach { prefix =>
            if (written < maxFlows && !isDead(s) && !onlyThroughCondition(chain) && !sanitized(kind, prefix ++ chain)) {
              writer.println(
                s"""{"kind":${jsonString(kind)},"label":${jsonString(label)},"language":${jsonString(lang)},""" +
                s""""source":${jsonString(sourceNameFor(label, src, prefix))},"sink":${jsonString(sinkName)},"steps":${(prefix ++ List(src, s: StoredNode)).map(location).mkString("[", ",", "]")}${tailJson(s)}}"""
              )
              written += 1
            }
          }
        sinks.foreach { s =>
          sinkInfo.get(s.id()).foreach { case (kind, sinkName) =>
            s.ast.l.find(n => seedIds.contains(n.id())) match {
              case Some(src) => emit(kind, sinkName, s, src, ancestors(src, s))
              case None =>
                s.ast.isIdentifier.l.iterator.flatMap(id => scala.util.Try(id.method.id()).toOption
                  .flatMap(mid => seededAssignments.get((mid, id.name))).map(found => (id, found)))
                  .take(1).foreach { case (id, (assignment, seed)) =>
                    emit(kind, sinkName, s, seed, ancestors(seed, assignment) ++ ancestors(id, s))
                  }
            }
          }
        }
      }
    }
    if (isJava) {
      // Kalıp kontrolleri (veri akışı gerektirmeyen zayıf kriptografi / rastgelelik / çerez).
      graph.call.methodFullName("javax\\.crypto\\.Cipher\\.getInstance.*").l.foreach { c =>
        argAt(c, 1).foreach(a => pattern("weakcipher", c, "Cipher.getInstance", algorithmDetail(a)))
      }
      graph.call.methodFullName("java\\.security\\.MessageDigest\\.getInstance.*").l.foreach { c =>
        argAt(c, 1).foreach(a => pattern("weakhash", c, "MessageDigest.getInstance", algorithmDetail(a)))
      }
      graph.call.name("md5|md5Hex|md2|md2Hex|sha|sha1|sha1Hex|shaHex").filter(_.methodFullName.contains("DigestUtils")).l.foreach { c =>
        pattern("weakhash", c, "DigestUtils." + c.name, s"""{"literal":${jsonString(if (c.name.startsWith("md5")) "MD5" else if (c.name.startsWith("md2")) "MD2" else "SHA1")}}""")
      }
      graph.call.name("next|nextInt|nextLong|nextFloat|nextDouble|nextGaussian|nextBoolean|nextBytes|ints|longs|doubles").l
        .filter(c => argAt(c, 0).exists(r => r.evalType.l.exists(t => t == "java.util.Random" || t == "java.util.concurrent.ThreadLocalRandom") && !isSecureRandom(r)))
        .foreach(c => pattern("weakrand", c, "Random." + c.name, "{}"))
      graph.call.methodFullName("java\\.lang\\.(Math|StrictMath)\\.random.*").l.foreach(c => pattern("weakrand", c, "Math.random", "{}"))
      // Güvenli olmayan çerez: setSecure(false) ya da hiç setSecure(true) yok.
      graph.call.nameExact("<init>").l.filter(c => c.code.matches("(?s)new\\s+(javax\\.servlet\\.http\\.|jakarta\\.servlet\\.http\\.)?Cookie\\s*\\(.*")).foreach { c =>
        argAt(c, 0).collect { case id: Identifier => id.name }.foreach { name =>
          val setters = c.method.call.name("setSecure").l.filter(s => argAt(s, 0).exists(_.code == name))
          val secure = setters.exists(s => argAt(s, 1).exists(_.code == "true"))
          val insecure = setters.isEmpty || setters.exists(s => argAt(s, 1).exists(_.code == "false"))
          if (insecure && !secure) pattern("insecurecookie", c, "new Cookie", "{}")
        }
      }
    }
  } finally {
    writer.close()
  }
}
