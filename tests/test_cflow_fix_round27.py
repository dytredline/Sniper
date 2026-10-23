"""27. tur düzeltmesi: C kirlilik modelinde yardımcı fonksiyon çıkış parametresi / dönüş aktarımları, kanıt izleme
(Origin.weak) ve "Olası" → "Doğrulanmış" yükseltme kuralı, komut hedefleri için izin listesi/doğrulayıcı/kaçışlama
arındırıcıları.

Kök neden (cdiag/x, gerçekçi tek dosyalı ping sunucusu): yardımcının çıkış parametresinden geri gelen değer
(query_param, url_decode) çağrı derinliğine sayılıyordu; main → handle_request → handle_ping zinciri iki aktarımla
via=4 olup REMOTE_MAX_VIA=3 sınırında "belirsiz" sayılıp atılıyordu. h örneğinde bir çağrı katmanı eksik olduğundan
via=3 ile sınırın içinde kalıyordu.
"""
from __future__ import annotations

import os
import tempfile
import textwrap
import unittest
from pathlib import Path

import project_analyzer
import taint_cfamily
import taint_native_core

FIX = Path(__file__).resolve().parent / "fixtures" / "cflow_fix_round27"

HDR = "#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n#include <ctype.h>\n#include <unistd.h>\n" \
      "#include <sys/socket.h>\n"
MAIN = ("int main(void){int s=socket(2,1,0);int c=accept(s,0,0);char buf[512];ssize_t n=read(c,buf,511);"
        "if(n<=0)return 1;buf[n]=0;%s return 0;}\n")
HANDLE_POPEN = 'static void handle(const char*q){char cmd[600];snprintf(cmd,sizeof cmd,"ping %%s",q);popen(cmd,"r");}\n'


def d(s: str) -> str:
    return textwrap.dedent(s).lstrip("\n")


def c_prog(helpers: str, main_body: str) -> str:
    return HDR + helpers + MAIN % main_body


def flows(files: dict[str, str]) -> list:
    res = taint_cfamily.analyze_files(files, {})
    return sorted((f for an in res.values() for f in an.flows), key=lambda f: (f.file, f.line, f.sink_kind))


def cmd_flows(files: dict[str, str]) -> list:
    return [f for f in flows(files) if f.sink_kind == "command"]


class _ProjectMixin:
    """Ürün hattı (project_analyzer) ile tek/çok dosyalı C projesi tarar; yalnız C bulgu başlıklarını döndürür."""

    def setUp(self) -> None:  # noqa: D401
        self._env = os.environ.get("SNIPER_CLANG_ANALYZER")
        os.environ["SNIPER_CLANG_ANALYZER"] = "0"

    def tearDown(self) -> None:
        if self._env is None:
            os.environ.pop("SNIPER_CLANG_ANALYZER", None)
        else:
            os.environ["SNIPER_CLANG_ANALYZER"] = self._env

    def scan(self, files: dict[str, str]) -> list[tuple[int, str, str]]:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "proj"
            root.mkdir()
            for name, text in files.items():
                p = root / name
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(text)
            rep = project_analyzer.analyze_project(str(root), allowed_roots=(Path(tmp),))
        return sorted((f.get("line") or 0, f["title"], f.get("reference") or "") for f in rep["findings"]
                      if str(f.get("file", "")).endswith(".c") and "veri akışı" in f["title"])

    def verified_cmd(self, files: dict[str, str]) -> list[int]:
        return [ln for ln, t, ref in self.scan(files) if t.startswith("Doğrulanmış veri akışı") and ref == "CWE-78"]

    def any_cmd(self, files: dict[str, str]) -> list[tuple[int, str]]:
        return [(ln, t) for ln, t, ref in self.scan(files) if ref == "CWE-78"]


class CdiagFixtureTests(_ProjectMixin, unittest.TestCase):
    """Teşhis örnekleri: önce d/f/g/h "Olası", x hiç bulgu yoktu; şimdi hepsi "Doğrulanmış"."""

    def fixture(self, name: str) -> dict[str, str]:
        return {"s.c": (FIX / name).read_text()}

    def test_d_out_param_loop_copy(self) -> None:
        self.assertEqual(self.verified_cmd(self.fixture("cdiag_d.c")), [6])

    def test_f_ternary_strchr_two_calls(self) -> None:
        self.assertEqual(self.verified_cmd(self.fixture("cdiag_f.c")), [5])

    def test_g_out_param_memcpy(self) -> None:
        self.assertEqual(self.verified_cmd(self.fixture("cdiag_g.c")), [6])

    def test_h_out_param_and_url_decode(self) -> None:
        self.assertEqual(self.verified_cmd(self.fixture("cdiag_h.c")), [7])

    def test_x_realistic_server_root_cause(self) -> None:
        files = {"main.c": (FIX / "ping_server.c").read_text()}
        fs = cmd_flows(files)
        self.assertEqual(len(fs), 1)
        f = fs[0]
        # main → handle_request → handle_ping (+ query_param, url_decode aktarımları)
        self.assertEqual(f.via, ("handle_request", "handle_ping", "query_param", "url_decode"))
        self.assertEqual(f.xfer, 2)
        self.assertFalse(f.weak)
        self.assertEqual(self.verified_cmd(files), [246])

    def test_x_variant_snprintf_body(self) -> None:
        text = (FIX / "ping_server.c").read_text()
        start = text.index("\tsize_t i = 0;\n\n\twhile (*src && i < dst_size - 1)")
        end = text.index("\tdst[i] = '\\0';\n}", start) + len("\tdst[i] = '\\0';\n")
        x1 = text[:start] + '\tsnprintf(dst, dst_size, "%s", src);\n' + text[end:]
        self.assertNotEqual(x1, text)
        self.assertEqual(len(self.verified_cmd({"main.c": x1})), 1)

    def test_x_variant_without_null_check(self) -> None:
        text = (FIX / "ping_server.c").read_text().replace(
            "if (!query || !query_param(query,", "if (!query_param(query,")
        self.assertEqual(self.verified_cmd({"main.c": text}), [246])


class HelperOutParamTests(_ProjectMixin, unittest.TestCase):
    """Yardımcı dst'ye src'den kopyalıyorsa çağrı yerinde dst kirli; yerel zincir "Doğrulanmış"."""

    def helper(self, helper: str, call: str, dst_decl: str = "char h[256];") -> dict[str, str]:
        handle = ('static void handle(const char*q){%s char cmd[700];%s snprintf(cmd,sizeof cmd,"ping %%s",h);'
                  'popen(cmd,"r");}\n' % (dst_decl, call))
        return {"s.c": c_prog(helper + handle, "handle(buf);")}

    def test_index_loop_copy(self) -> None:
        files = self.helper('static void cp(char*v,const char*p,size_t n){size_t i=0;while(p[i]&&p[i]!=\'&\'&&'
                            'i+1<n){v[i]=p[i];i++;}v[i]=0;}\n', "cp(h,q,sizeof h);")
        self.assertEqual(len(self.verified_cmd(files)), 1)

    def test_pointer_loop_copy(self) -> None:
        files = self.helper("static void cp(char*d,const char*s,size_t n){while(*s&&n-->1)*d++=*s++;*d=0;}\n",
                            "cp(h,q,sizeof h);")
        self.assertEqual(len(self.verified_cmd(files)), 1)

    def test_memcpy(self) -> None:
        files = self.helper('static void cp(char*d,const char*s,size_t n){size_t l=strcspn(s,"&");if(l>=n)l=n-1;'
                            'memcpy(d,s,l);d[l]=0;}\n', "cp(h,q,sizeof h);")
        self.assertEqual(len(self.verified_cmd(files)), 1)

    def test_strncpy(self) -> None:
        files = self.helper("static void cp(char*d,const char*s,size_t n){strncpy(d,s,n-1);d[n-1]=0;}\n",
                            "cp(h,q,sizeof h);")
        self.assertEqual(len(self.verified_cmd(files)), 1)

    def test_snprintf(self) -> None:
        files = self.helper('static void cp(char*d,size_t n,const char*s){snprintf(d,n,"%s",s);}\n',
                            "cp(h,sizeof h,q);")
        self.assertEqual(len(self.verified_cmd(files)), 1)

    def test_strcpy(self) -> None:
        files = self.helper("static void cp(char*d,const char*s){strcpy(d,s);}\n", "cp(h,q);", "char h[600];")
        self.assertEqual(len(self.verified_cmd(files)), 1)

    def test_sscanf_out(self) -> None:
        files = self.helper('static int w2(const char*s,char*o){return sscanf(s,"%*s %255s",o);}\n',
                            "if(w2(q,h)!=1)return;")
        self.assertEqual(len(self.verified_cmd(files)), 1)

    def test_returned_pointer_arith(self) -> None:
        helper = "static const char*after(const char*s){const char*e=strchr(s,'=');return e?e+1:s;}\n"
        handle = ('static void handle(const char*q){char cmd[600];snprintf(cmd,sizeof cmd,"ping %s",after(q));'
                  'popen(cmd,"r");}\n')
        self.assertEqual(len(self.verified_cmd({"s.c": c_prog(helper + handle, "handle(buf);")})), 1)

    def test_url_unescape_is_not_sanitizer(self) -> None:
        files = self.helper("static void url_unescape(char*d,const char*s,size_t n){size_t i=0;while(*s&&i+1<n){"
                            "if(*s=='%'&&s[1]&&s[2]){char hx[3]={s[1],s[2],0};d[i++]=(char)strtol(hx,NULL,16);s+=3;}"
                            "else d[i++]=*s++;}d[i]=0;}\n", "url_unescape(h,q,sizeof h);")
        self.assertEqual(len(self.verified_cmd(files)), 1)

    def test_decode_returning_heap_is_not_sanitizer(self) -> None:
        helper = ("static char*decode(const char*s){char*d=malloc(strlen(s)+1);char*o=d;"
                  "while(*s){*o++=(*s=='+')?' ':*s;s++;}*o=0;return d;}\n")
        handle = ('static void handle(const char*q){char cmd[600];char*h=decode(q);'
                  'snprintf(cmd,sizeof cmd,"ping %s",h);popen(cmd,"r");free(h);}\n')
        self.assertEqual(len(self.verified_cmd({"s.c": c_prog(helper + handle, "handle(buf);")})), 1)


class PointerAndTokenTests(_ProjectMixin, unittest.TestCase):
    def test_ternary_strchr(self) -> None:
        route = "static void route(const char*path){const char*query=strchr(path,'?');handle(query?query+1:\"x\");}\n"
        self.assertEqual(len(self.verified_cmd({"s.c": c_prog(HANDLE_POPEN + route, "route(buf);")})), 1)

    def test_strtok(self) -> None:
        files = {"s.c": c_prog(HANDLE_POPEN, 'char*t=strtok(buf," ");t=strtok(NULL," ");if(t)handle(t);')}
        self.assertEqual(len(self.verified_cmd(files)), 1)

    def test_strstr_plus_offset(self) -> None:
        files = {"s.c": c_prog(HANDLE_POPEN, 'char*h=strstr(buf,"host=");if(h)handle(h+5);')}
        self.assertEqual(len(self.verified_cmd(files)), 1)

    def test_three_direct_calls(self) -> None:
        helpers = ('static void run(const char*h){char cmd[600];snprintf(cmd,sizeof cmd,"ping %s",h);popen(cmd,"r");}\n'
                   "static void handle(const char*q){run(q);}\nstatic void route(const char*q){handle(q);}\n")
        self.assertEqual(len(self.verified_cmd({"s.c": c_prog(helpers, "route(buf);")})), 1)


class NegativeTests(_ProjectMixin, unittest.TestCase):
    """Olumsuz örnekler: sabit komut, izin listesi/doğrulayıcı, sayıya çevrilen girdi, kaçışlama yardımcısı."""

    def test_constant_command(self) -> None:
        handle = 'static void handle(const char*q){char cmd[600];(void)q;snprintf(cmd,sizeof cmd,"ping %s","127.0.0.1");popen(cmd,"r");}\n'
        self.assertEqual(self.any_cmd({"s.c": c_prog(handle, "handle(buf);")}), [])

    def test_helper_writes_constant(self) -> None:
        helper = 'static void cp(char*d,const char*s,size_t n){(void)s;snprintf(d,n,"%s","localhost");}\n'
        handle = ('static void handle(const char*q){char h[256];char cmd[600];cp(h,q,sizeof h);'
                  'snprintf(cmd,sizeof cmd,"ping %s",h);popen(cmd,"r");}\n')
        self.assertEqual(self.any_cmd({"s.c": c_prog(helper + handle, "handle(buf);")}), [])

    def test_atoi_percent_d(self) -> None:
        handle = ('static void handle(const char*q){char cmd[600];int cnt=atoi(q);'
                  'snprintf(cmd,sizeof cmd,"ping -c %d 127.0.0.1",cnt);popen(cmd,"r");}\n')
        self.assertEqual(self.any_cmd({"s.c": c_prog(handle, "handle(buf);")}), [])

    def test_atoi_in_helper_out_param(self) -> None:
        # önceki sürümde çıkış parametresindeki sayısal köken dize olarak taşınıyordu ("Olası" yanlış pozitif)
        helper = 'static void cp(char*d,size_t n,const char*s){snprintf(d,n,"%d",atoi(s));}\n'
        handle = ('static void handle(const char*q){char h[64];char cmd[600];cp(h,sizeof h,q);'
                  'snprintf(cmd,sizeof cmd,"ping -c %s 127.0.0.1",h);popen(cmd,"r");}\n')
        self.assertEqual(self.any_cmd({"s.c": c_prog(helper + handle, "handle(buf);")}), [])

    def test_validator_early_return(self) -> None:
        helper = ("static int is_valid_host(const char*h){for(;*h;h++)if(!isalnum((unsigned char)*h)&&*h!='.'"
                  "&&*h!='-')return 0;return 1;}\n")
        handle = ('static void handle(const char*q){char cmd[600];if(!is_valid_host(q))return;'
                  'snprintf(cmd,sizeof cmd,"ping %s",q);popen(cmd,"r");}\n')
        self.assertEqual(self.any_cmd({"s.c": c_prog(helper + handle, "handle(buf);")}), [])

    def test_validator_in_caller_of_sink_function(self) -> None:
        helpers = ("static int is_valid_host(const char*h){for(;*h;h++)if(!isalnum((unsigned char)*h)&&*h!='.')"
                   "return 0;return 1;}\n"
                   'static void run(const char*q){char cmd[600];snprintf(cmd,sizeof cmd,"ping %s",q);popen(cmd,"r");}\n'
                   'static void handle(const char*q){char h[256];snprintf(h,sizeof h,"%s",q);'
                   "if(!is_valid_host(h))return;run(h);}\n")
        self.assertEqual(self.any_cmd({"s.c": c_prog(helpers, "handle(buf);")}), [])

    def test_strspn_allowlist(self) -> None:
        handle = ('static void handle(const char*q){char cmd[600];'
                  'if(strspn(q,"abcdefghijklmnopqrstuvwxyz0123456789.-")!=strlen(q))return;'
                  'snprintf(cmd,sizeof cmd,"ping %s",q);popen(cmd,"r");}\n')
        self.assertEqual(self.any_cmd({"s.c": c_prog(handle, "handle(buf);")}), [])

    def test_strspn_index_allowlist(self) -> None:
        handle = ('static void handle(const char*q){char cmd[600];if(q[strspn(q,"abc.-")]!=\'\\0\')return;'
                  'snprintf(cmd,sizeof cmd,"ping %s",q);popen(cmd,"r");}\n')
        self.assertEqual(self.any_cmd({"s.c": c_prog(handle, "handle(buf);")}), [])

    def test_strcmp_allowlist(self) -> None:
        handle = ('static void handle(const char*q){char cmd[600];'
                  'if(strcmp(q,"localhost")!=0&&strcmp(q,"127.0.0.1")!=0)return;'
                  'snprintf(cmd,sizeof cmd,"ping %s",q);popen(cmd,"r");}\n')
        self.assertEqual(self.any_cmd({"s.c": c_prog(handle, "handle(buf);")}), [])

    def test_strcmp_partial_allowlist_is_not_sanitizer(self) -> None:
        # || içinde tek terim: q "localhost" değilse de başka koşul yanlışsa akış sürer → arındırıcı değil
        handle = ('static void handle(const char*q,int k){char cmd[600];'
                  'if(strcmp(q,"localhost")!=0&&k)return;'
                  'snprintf(cmd,sizeof cmd,"ping %s",q);popen(cmd,"r");}\n')
        self.assertEqual(len(self.verified_cmd({"s.c": c_prog(handle, "handle(buf,c);")})), 1)

    def test_strncmp_prefix_is_not_allowlist(self) -> None:
        handle = ('static void handle(const char*q){char cmd[600];if(strncmp(q,"host",4)!=0)return;'
                  'snprintf(cmd,sizeof cmd,"ping %s",q);popen(cmd,"r");}\n')
        self.assertEqual(len(self.verified_cmd({"s.c": c_prog(handle, "handle(buf);")})), 1)

    def test_shell_escape_helper(self) -> None:
        helper = ("static void shell_escape(char*d,const char*s,size_t n){size_t i=0;if(n<3)return;d[i++]='\\'';"
                  "while(*s&&i+5<n){if(*s=='\\''){d[i++]='\\'';d[i++]='\\\\';d[i++]='\\'';d[i++]='\\'';}"
                  "else d[i++]=*s;s++;}d[i++]='\\'';d[i]=0;}\n")
        handle = ('static void handle(const char*q){char h[600];char cmd[700];shell_escape(h,q,sizeof h);'
                  'snprintf(cmd,sizeof cmd,"ping %s",h);popen(cmd,"r");}\n')
        self.assertEqual(self.any_cmd({"s.c": c_prog(helper + handle, "handle(buf);")}), [])

    def test_dotdot_check_is_path_not_command_sanitizer(self) -> None:
        handle = ('static void handle(const char*q){char cmd[600];if(strstr(q,".."))return;'
                  'snprintf(cmd,sizeof cmd,"cat %s",q);popen(cmd,"r");fopen(q,"r");}\n')
        res = self.scan({"s.c": c_prog(handle, "handle(buf);")})
        self.assertTrue(any(ref == "CWE-78" and t.startswith("Doğrulanmış") for _ln, t, ref in res))
        self.assertFalse(any(ref == "CWE-22" for _ln, t, ref in res))


class ProofTrackingTests(_ProjectMixin, unittest.TestCase):
    """Kanıtsız adımlar zinciri "Olası"da bırakır."""

    def test_ambiguous_cross_file_resolution_is_weak(self) -> None:
        run = 'void run(const char*h){char cmd[600];snprintf(cmd,sizeof cmd,"ping %s",h);popen(cmd,"r");}\n'
        files = {
            "a/run.c": HDR + run,
            "b/run.c": HDR + run,
            "main.c": HDR + "void run(const char*h);\nstatic void handle(const char*q){run(q);}\n"
                      + MAIN % "handle(buf);",
        }
        fs = cmd_flows(files)
        self.assertTrue(fs)
        self.assertTrue(all(f.weak for f in fs if len(f.via) >= 2))
        titles = [t for _ln, t, ref in self.scan(files) if ref == "CWE-78"]
        self.assertTrue(titles)
        self.assertTrue(all(t.startswith("Olası veri akışı") for t in titles))

    def test_unique_cross_file_definition_is_proven(self) -> None:
        files = {
            "run.c": HDR + 'void run(const char*h){char cmd[600];snprintf(cmd,sizeof cmd,"ping %s",h);popen(cmd,"r");}\n',
            "main.c": HDR + "void run(const char*h);\nstatic void handle(const char*q){run(q);}\n"
                      + MAIN % "handle(buf);",
        }
        self.assertEqual(len(self.verified_cmd(files)), 1)

    def test_function_pointer_is_weak(self) -> None:
        helpers = ('static void run(const char*h){char cmd[600];snprintf(cmd,sizeof cmd,"ping %s",h);popen(cmd,"r");}\n'
                   "struct route{const char*p;void(*fn)(const char*);};\n"
                   'static struct route routes[]={{"/ping",run}};\n'
                   "static void handle(const char*q){routes[0].fn(q);}\n")
        files = {"s.c": c_prog(helpers, "handle(buf);")}
        titles = [t for _ln, t, ref in self.scan(files) if ref == "CWE-78"]
        self.assertFalse(any(t.startswith("Doğrulanmış") for t in titles))

    def test_unknown_function_passthrough_is_weak(self) -> None:
        helpers = ("const char*ext_trim(const char*s);\n"
                   'static void run(const char*h){char cmd[600];snprintf(cmd,sizeof cmd,"ping %s",h);popen(cmd,"r");}\n'
                   "static void handle(const char*q){run(ext_trim(q));}\n")
        fs = cmd_flows({"s.c": c_prog(helpers, "handle(buf);")})
        self.assertTrue(fs and all(f.weak for f in fs))
        titles = [t for _ln, t, ref in self.scan({"s.c": c_prog(helpers, "handle(buf);")}) if ref == "CWE-78"]
        self.assertTrue(titles and all(t.startswith("Olası") for t in titles))

    def test_name_only_socket_source_is_weak(self) -> None:
        text = HDR + HANDLE_POPEN + "static void route(const char*q){handle(q);}\n" \
            "void serve(int client){char buf[512];ssize_t n=read(client,buf,511);if(n<=0)return;buf[n]=0;route(buf);}\n"
        fs = cmd_flows({"s.c": text})
        self.assertTrue(fs and all(f.weak for f in fs))

    def test_global_variable_is_weak(self) -> None:
        helpers = ("static char g_host[256];\n"
                   'static void run(void){char cmd[600];snprintf(cmd,sizeof cmd,"ping %s",g_host);popen(cmd,"r");}\n'
                   "static void handle(void){run();}\n")
        files = {"s.c": c_prog(helpers, 'snprintf(g_host,sizeof g_host,"%s",buf);handle();')}
        fs = cmd_flows(files)
        # küresel okuma kanıtsız adımdır; zincir kısa (via ≤ 1) olduğundan eski kural gereği raporlama değişmez,
        # ama bu köken daha derin zincirde "Doğrulanmış"a yükseltilmez
        self.assertTrue(fs and all(f.weak for f in fs))

    def test_helper_internal_validation_not_upgraded(self) -> None:
        # yardımcı çıkışı kendi içinde doğruluyor ve sonucu dönüş değeriyle bildiriyor: model dönüşü izlemez
        helpers = ("static int path_is_sane(const char*p){return strstr(p,\"..\")==NULL;}\n"
                   "static int to_path(const char*u,char*out,size_t n){snprintf(out,n,\"www/%s\",u);"
                   "if(!path_is_sane(out))return 0;return 1;}\n"
                   "static void serve_file(const char*p){FILE*f=fopen(p,\"r\");if(f)fclose(f);}\n"
                   "static void handle(const char*q){char p[300];if(!to_path(q,p,sizeof p))return;serve_file(p);}\n")
        res = self.scan({"s.c": c_prog(helpers, "handle(buf);")})
        self.assertFalse(any(ref == "CWE-22" and t.startswith("Doğrulanmış") for _ln, t, ref in res))

    def test_memory_class_not_upgraded_through_helper(self) -> None:
        # yardımcının parametre hedefindeki strcpy: çağrı yerindeki kabın boyutu özetle kanıtlanmaz
        helper = "static void cp(char*d,const char*s){strcpy(d,s);}\n"
        handle = "static void handle(const char*q){char h[600];cp(h,q);puts(h);}\n"
        res = self.scan({"s.c": c_prog(helper + handle, "handle(buf);")})
        mem = [t for _ln, t, ref in res if ref in ("CWE-120", "CWE-787", "CWE-121", "CWE-122")]
        self.assertFalse(any(t.startswith("Doğrulanmış") for t in mem))


class EscaperNameTests(unittest.TestCase):
    def test_escaper_names(self) -> None:
        yes = ["shell_escape", "html_escape", "escape_html", "quote_arg", "shellEscape", "escapeShellArg",
               "sanitize_host", "json_escape_string"]
        no = ["url_decode", "url_unescape", "unescape", "decode", "unquote", "dequote", "is_quoted",
              "parse_quoted_string", "query_param", "skip_quote"]
        for n in yes:
            self.assertTrue(taint_cfamily._is_escaper(n), n)
        for n in no:
            self.assertFalse(taint_cfamily._is_escaper(n), n)


class CoreSemanticsTests(unittest.TestCase):
    def test_through_keeps_weak_when_via_full(self) -> None:
        o = taint_native_core.Origin("request", "x", 1, "a.c", via=tuple(f"f{i}" for i in range(taint_native_core.MAX_VIA)))
        o2 = o.through("g", weak=True)
        self.assertTrue(o2.weak)
        self.assertEqual(o2.via, o.via)

    def test_transfer_counts(self) -> None:
        o = taint_native_core.Origin("request", "x", 1, "a.c")
        o2 = o.through("helper", xfer=True).through("call")
        self.assertEqual(o2.via, ("helper", "call"))
        self.assertEqual(o2.xfer, 1)

    def test_rust_engine_does_not_track_proof(self) -> None:
        import taint_rust

        self.assertFalse(getattr(taint_rust.RustBody, "TRACK_PROOF", False))
        self.assertTrue(taint_cfamily.CBody.TRACK_PROOF)


if __name__ == "__main__":
    unittest.main()
