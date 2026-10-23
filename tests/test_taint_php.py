"""PHP hızlı taint motoru (taint_clike): süper küreseller, ara değerli dizgeler, include zinciri, oturum/tablo
ikinci derece akışı, tırnak bağlamlı SQL kaçışı, korumalar, Laravel/Symfony/WordPress kalıpları."""
from pathlib import Path
import sys
import tempfile
import textwrap
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import taint_clike  # noqa: E402


def flows(files: dict[str, str], labels=("request",)) -> list[tuple[str, str, int]]:
    results = taint_clike.analyze_files({k: textwrap.dedent(v).lstrip("\n") for k, v in files.items()})
    return sorted((f.file, f.sink_kind, f.line) for a in results.values() for f in a.flows if f.source_label in labels)


class PhpCore(unittest.TestCase):
    def test_superglobals_sinks_and_escaping(self):
        src = """
        <?php
        $id = $_GET['id'];
        mysqli_query($c, "SELECT * FROM u WHERE id = '$id'");
        $e = mysqli_real_escape_string($c, $_POST['x']);
        mysqli_query($c, "SELECT * FROM u WHERE id = $e");
        mysqli_query($c, "SELECT * FROM u WHERE id = '$e'");
        echo htmlspecialchars($_GET['n']);
        echo "<p>" . $_GET['n'] . "</p>";
        shell_exec('ping ' . $_REQUEST['ip']);
        `ls {$_GET['d']}`;
        header("Location: " . $_GET['r']);
        header("Location: /panel?x=" . $_GET['r']);
        unserialize($_COOKIE['s']);
        unserialize($_COOKIE['s'], ['allowed_classes' => false]);
        $ids = array_map('intval', (array) $_REQUEST['ids']);
        mysqli_query($c, "DELETE FROM t WHERE id IN (" . implode(',', $ids) . ")");
        ?>
        <p><?= $_GET['z'] ?></p>
        """
        self.assertEqual([(k, l) for _f, k, l in flows({"a.php": src})],
                         [("command", 9), ("command", 10), ("deserialize", 13), ("html", 8), ("html", 18),
                          ("redirect", 11), ("sql", 3), ("sql", 5)])

    def test_guards(self):
        src = """
        <?php
        $file = $_GET['page'];
        if ($file != "a.php" && $file != "b.php") { echo "yok"; exit; }
        include($file);
        $o = explode(".", $_REQUEST['ip']);
        if (is_numeric($o[0]) && is_numeric($o[1])) { shell_exec('ping ' . $o[0] . '.' . $o[1]); }
        if (!in_array($_GET['t'], array('a', 'b'), true)) { die('x'); }
        echo $_GET['t'];
        if (validate_file($_GET['f'])) { wp_die('bad'); }
        readfile($_GET['f']);
        """
        self.assertEqual(flows({"g.php": src}), [])

    def test_include_chain_and_function_summary(self):
        files = {
            "vuln/index.php": """
            <?php
            require_once ROOT . 'lib/page.inc.php';
            $level = 'low.php';
            require_once ROOT . "vuln/source/{$level}";
            $page['body'] .= "<div>{$html}</div>";
            page_echo($page);
            if (isset($file)) include($file);
            """,
            "vuln/source/low.php": """
            <?php
            $html = '<pre>Merhaba ' . $_GET['name'] . '</pre>';
            $file = $_GET['page'];
            """,
            "lib/page.inc.php": """
            <?php
            function page_echo($p) {
              echo "<html>{$p['body']}</html>";
            }
            """,
        }
        self.assertEqual(flows(files), [("lib/page.inc.php", "html", 3), ("vuln/index.php", "path", 7)])

    def test_second_order_session_and_table(self):
        files = {
            "set.php": "<?php\n$_SESSION['id'] = $_POST['id'];\n",
            "use.php": "<?php\n$q = \"SELECT * FROM u WHERE id = '\" . $_SESSION['id'] . \"'\";\nmysqli_query($c, $q);\n",
            "add.php": ("<?php\n$m = mysqli_real_escape_string($c, $_POST['m']);\n"
                        "mysqli_query($c, \"INSERT INTO guestbook (comment) VALUES ('$m')\");\n"),
            "show.php": ("<?php\n$r = mysqli_query($c, \"SELECT comment FROM guestbook\");\n"
                         "while ($row = mysqli_fetch_assoc($r)) { echo $row['comment']; }\n"),
        }
        self.assertEqual(flows(files), [("use.php", "sql", 3)])
        stored = taint_clike.analyze_files(files)["show.php"].flows
        self.assertEqual([(f.sink_kind, f.line, f.source_label, f.source_file) for f in stored],
                         [("html", 3, "stored", "add.php")])

    def test_frameworks(self):
        files = {
            "app/Http/Controllers/UserController.php": """
            <?php
            class UserController extends Controller {
              public function show(Request $request, $slug) {
                DB::select("select * from users where name = '" . $request->input('name') . "'");
                DB::select('select * from users where name = ?', [$request->input('name')]);
                User::whereRaw("slug = '$slug'")->first();
                return redirect()->away($request->query('next'));
              }
            }
            """,
            "wp-plugin.php": """
            <?php
            global $wpdb;
            $rows = $wpdb->get_results($wpdb->prepare("SELECT * FROM t WHERE a = %s", $_GET['a']));
            $wpdb->query("DELETE FROM t WHERE a = '" . $_GET['a'] . "'");
            wp_redirect(add_query_arg(array('done' => $_GET['x']), admin_url('options.php')));
            wp_redirect($_GET['to']);
            $v = apply_filters('my_filter', 'sabit', $_GET['ctx']);
            echo $v;
            echo esc_html($_GET['q']);
            """,
        }
        self.assertEqual(flows(files), [
            ("app/Http/Controllers/UserController.php", "redirect", 7),
            ("app/Http/Controllers/UserController.php", "sql", 4),
            ("app/Http/Controllers/UserController.php", "sql", 6),
            ("wp-plugin.php", "redirect", 6), ("wp-plugin.php", "sql", 4)])

    def test_mature_code_precision_rules(self):
        src = """
        <?php
        function admin_page() {
          if ( ! current_user_can( 'manage_options' ) ) { wp_die( 'no' ); }
          echo $_GET['x'];
        }
        function widget($value) {
          $d = base64_decode( $_POST['enc'] );
          if ( ! hash_equals( wp_hash( $d ), $_POST['h'] ) ) { return null; }
          return unserialize( $d );
        }
        function order_by() {
          $o = strtolower( $_GET['orderby'] );
          switch ( $o ) { case 'name': break; default: $o = 'id'; }
          mysqli_query( $c, "SELECT * FROM t ORDER BY $o" );
          $p = trim( $_POST['prefix'] );
          if ( preg_match( '|[^a-z0-9_]|i', $p ) ) { wp_die( 'bad' ); }
          mysqli_query( $c, "SELECT * FROM {$p}users" );
          $f = '/up/' . str_replace( '..', '', $_GET['file'] );
          readfile( $f );
          $cb = false;
          if ( isset( $_GET['cb'] ) ) { $cb = $_GET['cb']; }
          if ( $cb ) { if ( ! wp_check_jsonp_callback( $cb ) ) { return; } }
          echo $cb;
          echo wp_json_encode( $_GET['data'] );
          wp_redirect( 'https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'] );
          mysqli_query( $c, "SELECT * FROM t ORDER BY " . $_GET['raw'] );
        }
        class Lib { public function send($request) { echo $request['url']; } }
        """
        self.assertEqual(flows({"m.php": src}), [("m.php", "sql", 26)])

    def test_project_analyzer_reports_php(self):
        import project_analyzer

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "proj"
            root.mkdir()
            (root / "a.php").write_text("<?php\nsystem('ls ' . $_GET['d']);\n")
            result = project_analyzer.analyze_project(str(root), allowed_roots=(Path(tmp),))
        refs = [(f["reference"], f["line"], f["title"].split(":")[0]) for f in result["findings"] if f.get("taint_flow")]
        self.assertEqual(refs, [("CWE-78", 2, "Doğrulanmış veri akışı")])

    def test_joern_overlap_marking(self):
        import joern_active

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.php").write_text("<?php\nsystem('ls ' . $_GET['d']);\n")
            findings = [{"reference": "CWE-78", "file": "a.php", "line": 2},
                        {"reference": "CWE-89", "file": "a.php", "line": 9}]
            stats = joern_active.mark_fast_engine_overlap(root, {"php": [root / "a.php"]}, findings)
        self.assertEqual(stats, {"available": True, "both": 1, "joern_only": 1, "fast_only": 0})
        self.assertTrue(findings[0].get("also_in_project_analysis"))
        self.assertNotIn("also_in_project_analysis", findings[1])


if __name__ == "__main__":
    unittest.main()
