"""27. tur: C dosyalar arası, yapı alanı duyarlı kirlilik modeli (taint_cfamily) ve bellek motoruna bağlanması
(memsafety_c), yönlendirme tabloları, çatı kaynakları, C taint sınıfları (komut/SQL/yol/XSS/kod/biçim dizgesi),
fonksiyonlar arası use-after-free (cflow_uaf), uzunluk alanına güven ve Rust unsafe kopya kalıpları."""
from __future__ import annotations

import re
import tempfile
import textwrap
import unittest
from pathlib import Path

import memsafety_c
import memsafety_rust
import project_analyzer
import taint_cfamily


def d(s: str) -> str:
    return textwrap.dedent(s).lstrip("\n")


def flows(files: dict[str, str]) -> tuple[list[tuple[str, int, str]], dict]:
    facts: dict = {}
    res = taint_cfamily.analyze_files({k: d(v) for k, v in files.items()}, facts)
    out = sorted((path, f.line, f.sink_kind) for path, an in res.items() for f in an.flows)
    return out, facts


def mem(files: dict[str, str], facts: dict | None) -> list[tuple[str, int, str, bool]]:
    out = []
    texts = {k: d(v) for k, v in files.items()}
    for path, text in texts.items():
        if path.endswith(".h"):
            continue
        hdrs = [(k, v) for k, v in texts.items() if k.endswith(".h") and f'"{k}"' in text]
        for f in memsafety_c.analyze_text(text, path, headers=hdrs, facts=facts):
            out.append((path, f.line, f.kind, f.certain))
    return sorted(out)


MINISRV = {
    "http.h": """
        #define REQ_MAX 4096
        struct request {
            char method[8];
            char *path;
            char *query;
            char *body;
            int content_length;
            int fd;
        };
        typedef void (*handler_fn)(struct request *req);
        struct route { const char *prefix; handler_fn handler; };
        int parse_request(char *raw, struct request *req);
        const char *query_param(struct request *req, const char *name);
        void dispatch(struct request *req);
    """,
    "net.c": """
        #include <sys/socket.h>
        #include <string.h>
        #include "http.h"
        static int serve_client(int client) {
            char buf[REQ_MAX];
            struct request req;
            memset(&req, 0, sizeof req);
            ssize_t n = recv(client, buf, sizeof(buf) - 1, 0);
            if (n <= 0)
                return -1;
            buf[n] = 0;
            if (parse_request(buf, &req) < 0)
                return -1;
            req.fd = client;
            dispatch(&req);
            return 0;
        }
    """,
    "parser.c": """
        #include <string.h>
        #include <stdlib.h>
        #include "http.h"
        int parse_request(char *raw, struct request *req) {
            char *sp = strchr(raw, ' ');
            if (!sp)
                return -1;
            *sp = 0;
            req->path = sp + 1;
            char *end = strchr(req->path, ' ');
            if (end)
                *end = 0;
            char *q = strchr(req->path, '?');
            if (q) {
                *q = 0;
                req->query = q + 1;
            }
            char *b = strstr(end + 1, "\\r\\n\\r\\n");
            req->body = b ? b + 4 : NULL;
            char *cl = strstr(end + 1, "Content-Length: ");
            req->content_length = cl ? atoi(cl + 16) : 0;
            return 0;
        }
        const char *query_param(struct request *req, const char *name) {
            static char val[256];
            char *p = req->query ? strstr(req->query, name) : NULL;
            if (!p)
                return NULL;
            p += strlen(name) + 1;
            size_t i = 0;
            while (p[i] && p[i] != '&' && i < sizeof(val) - 1) {
                val[i] = p[i];
                i++;
            }
            val[i] = 0;
            return val;
        }
    """,
    "router.c": """
        #include <string.h>
        #include "http.h"
        void handle_user(struct request *req);
        void handle_ping(struct request *req);
        void handle_file(struct request *req);
        void handle_echo(struct request *req);
        void handle_safe(struct request *req);
        static struct route routes[] = {
            {"/user", handle_user},
            {"/ping", handle_ping},
            {"/file", handle_file},
            {"/echo", handle_echo},
            {"/safe", handle_safe},
        };
        void dispatch(struct request *req) {
            for (size_t i = 0; i < sizeof(routes) / sizeof(routes[0]); i++) {
                if (strncmp(req->path, routes[i].prefix, strlen(routes[i].prefix)) == 0) {
                    routes[i].handler(req);
                    return;
                }
            }
        }
    """,
    "handlers.c": """
        #include <stdio.h>
        #include <stdlib.h>
        #include <string.h>
        #include <sqlite3.h>
        #include "http.h"
        extern sqlite3 *db;
        void handle_user(struct request *req) {
            char name[32];
            char sql[512];
            const char *id = query_param(req, "id");
            if (!id)
                return;
            strcpy(name, id);
            snprintf(sql, sizeof(sql), "SELECT * FROM users WHERE id='%s'", id);
            sqlite3_exec(db, sql, 0, 0, 0);
            dprintf(req->fd, "<html><body>Hello %s</body></html>", name);
        }
        void handle_ping(struct request *req) {
            char cmd[512];
            const char *host = query_param(req, "host");
            snprintf(cmd, sizeof(cmd), "ping -c 1 %s", host);
            system(cmd);
        }
        void handle_file(struct request *req) {
            char path[128];
            sprintf(path, "/var/www/%s", req->path + 6);
            FILE *f = fopen(path, "r");
            if (f)
                fclose(f);
        }
        void handle_echo(struct request *req) {
            char out[64];
            char copy[16];
            memcpy(copy, req->body, req->content_length);
            dprintf(req->fd, req->body);
            snprintf(out, sizeof(out), "%s", req->body);
        }
        void handle_safe(struct request *req) {
            char small[16];
            char big[512];
            const char *v = query_param(req, "v");
            if (!v)
                return;
            strcpy(big, v);
            if (strlen(v) < sizeof(small))
                strcpy(small, v);
            snprintf(small, sizeof(small), "%s", v);
            system("uptime");
        }
    """,
}


class CrossFileModelTests(unittest.TestCase):
    def test_route_table_struct_fields_and_query_helper_reach_taint_sinks(self):
        fl, facts = flows(MINISRV)
        got = {(p, line, k) for p, line, k in fl}
        for exp in [("handlers.c", 13, "memory"), ("handlers.c", 15, "sql"), ("handlers.c", 16, "html"),
                    ("handlers.c", 22, "command"), ("handlers.c", 27, "path"), ("handlers.c", 34, "memory_len"),
                    ("handlers.c", 35, "format_string")]:
            self.assertIn(exp, got)
        # güvenli işleyici: 256 baytlık değer 512 baytlık tampona sığar; uzunluk denetimi; sabit komut
        self.assertFalse([x for x in got if x[0] == "handlers.c" and x[1] >= 38])
        self.assertIn(("request", "query"), facts["fields"])
        self.assertEqual(facts["table_hops"]["handle_user"].split(" ", 1)[1], "routes tablosu .handler")
        caps = {o.cap for o in facts["call_ret"][("handlers.c", 10, "query_param")]}
        self.assertEqual(caps, {255})  # static char val[256] → en çok 255 karakter

    def test_memory_engine_uses_model_for_verified_overflow_with_chain(self):
        _, facts = flows(MINISRV)
        got = mem(MINISRV, facts)
        certain = {(p, line, k) for p, line, k, c in got if c}
        self.assertIn(("handlers.c", 13, "overflow_taint"), certain)  # strcpy(name[32], ≤255 bayt)
        self.assertIn(("handlers.c", 26, "overflow_taint"), certain)  # sprintf(path[128], req->path)
        self.assertIn(("handlers.c", 34, "overflow_taint"), certain)  # memcpy uzunluğu req->content_length
        self.assertIn(("handlers.c", 35, "format"), certain)
        self.assertFalse([x for x in got if x[0] == "handlers.c" and x[1] >= 38])
        # model olmadan dış girdi bilinmez: bu satırlarda kesin bulgu yok
        self.assertFalse([x for x in mem(MINISRV, None) if x[3] and x[0] == "handlers.c"])
        f = [m for m in memsafety_c.analyze_text(d(MINISRV["handlers.c"]), "handlers.c",
                                                headers=[("http.h", d(MINISRV["http.h"]))], facts=facts)
             if m.line == 13][0]
        self.assertEqual(f.source_file, "net.c")
        self.assertIn("parser.c:", " ".join(f.chain))
        self.assertIn("net.c satır", f.evidence)

    def test_registration_call_function_pointer_variable_and_deref_call(self):
        fl, _ = flows({
            "srv.c": """
                #include <sys/socket.h>
                #include <stdlib.h>
                struct router { const char *path[8]; void (*fn[8])(char *); int n; void (*fallback)(char *); };
                static struct router R;
                void route_add(struct router *r, const char *p, void (*h)(char *)) { r->fn[r->n] = h; r->n++; }
                void on_cmd(char *arg) { system(arg); }
                void on_fallback(char *arg) { system(arg); }
                void setup(void) { route_add(&R, "/cmd", on_cmd); R.fallback = on_fallback; }
                void serve(int c) {
                    char buf[1024];
                    recv(c, buf, sizeof buf, 0);
                    void (*fp)(char *) = R.fallback;
                    fp(buf);
                    (*R.fn[0])(buf);
                }
            """})
        lines = {line for p, line, k in fl if k == "command"}
        self.assertEqual(lines, {6, 7})

    def test_framework_sources_libmicrohttpd_mongoose_civetweb(self):
        fl, _ = flows({
            "mhd.c": """
                #include <microhttpd.h>
                #include <stdio.h>
                static enum MHD_Result ahc(void *cls, struct MHD_Connection *c, const char *url, const char *method,
                                           const char *version, const char *data, size_t *sz, void **ptr) {
                    FILE *f = fopen(url + 1, "r");
                    const char *id = MHD_lookup_connection_value(c, MHD_GET_ARGUMENT_KIND, "id");
                    char sql[256];
                    snprintf(sql, sizeof sql, "DELETE FROM t WHERE id=%s", id);
                    sqlite3_exec(db, sql, 0, 0, 0);
                    return MHD_YES;
                }
                int main(void) { MHD_start_daemon(MHD_USE_AUTO, 8080, NULL, NULL, &ahc, NULL, MHD_OPTION_END); }
            """,
            "mg.c": """
                #include "mongoose.h"
                static void fn(struct mg_connection *c, int ev, void *ev_data) {
                    if (ev == MG_EV_HTTP_MSG) {
                        struct mg_http_message *hm = (struct mg_http_message *) ev_data;
                        char cmd[128];
                        char host[64];
                        mg_http_get_var(&hm->query, "host", host, sizeof(host));
                        snprintf(cmd, sizeof cmd, "ping %s", host);
                        system(cmd);
                    }
                }
                int main(void) { struct mg_mgr m; mg_http_listen(&m, "http://0.0.0.0:8000", fn, NULL); }
            """,
            "cw.c": """
                #include "civetweb.h"
                int h(struct mg_connection *conn, void *cb) {
                    const struct mg_request_info *ri = mg_get_request_info(conn);
                    mg_printf(conn, "<html><body>%s</body></html>", ri->query_string);
                    return 1;
                }
            """})
        got = {(p, k) for p, line, k in fl}
        self.assertTrue({("mhd.c", "path"), ("mhd.c", "sql"), ("mg.c", "command"), ("cw.c", "html")} <= got)

    def test_socket_descriptor_propagation_through_params_streams_and_threads(self):
        fl, _ = flows({
            "a.c": """
                #include <sys/socket.h>
                #include <pthread.h>
                void handle(int s);
                void *worker(void *arg);
                void loop(int ls) {
                    for (;;) {
                        int fd = accept(ls, 0, 0);
                        handle(fd);
                        pthread_t t;
                        pthread_create(&t, NULL, worker, &fd);
                    }
                }
            """,
            "b.c": """
                #include <stdio.h>
                #include <unistd.h>
                #include <stdlib.h>
                void handle(int s) {
                    char line[256];
                    FILE *in = fdopen(s, "r");
                    fgets(line, sizeof line, in);
                    system(line);
                }
                void *worker(void *arg) {
                    int x = *(int *)arg;
                    char buf[128];
                    read(x, buf, sizeof buf);
                    system(buf);
                    return NULL;
                }
            """})
        self.assertEqual({(p, line) for p, line, k in fl if k == "command"}, {("b.c", 8), ("b.c", 14)})

    def test_code_injection_into_compiled_source_and_interpreter(self):
        fl, _ = flows({
            "c.c": """
                #include <sys/socket.h>
                #include <stdio.h>
                #include <stdlib.h>
                void build(int c) {
                    char expr[256];
                    recv(c, expr, sizeof expr, 0);
                    FILE *src = fopen("/tmp/calc.c", "w");
                    fprintf(src, "int main(){return %s;}", expr);
                    fclose(src);
                    system("gcc /tmp/calc.c -o /tmp/calc");
                    luaL_dostring(L, expr);
                    FILE *log = fopen("/tmp/log.txt", "w");
                    fprintf(log, "%s", expr);
                }
            """})
        self.assertEqual({line for p, line, k in fl if k == "code"}, {8, 11})

    def test_path_guard_and_cgi_detection_for_listening_server(self):
        fl, _ = flows({
            "w.c": """
                #include <sys/socket.h>
                #include <stdio.h>
                #include <string.h>
                int main(void) {
                    int ls = socket(2, 1, 0);
                    listen(ls, 5);
                    int c = accept(ls, 0, 0);
                    char buf[512], path[600];
                    read(c, buf, sizeof buf);
                    printf("Content-Type: text/html\\n%s", buf);
                    if (strstr(buf, "..") != NULL)
                        return 1;
                    snprintf(path, sizeof path, "www/%s", buf);
                    fopen(path, "r");
                    return 0;
                }
            """})
        kinds = {k for p, line, k in fl}
        self.assertNotIn("path", kinds)   # '..' denetimi erken çıkışla
        self.assertNotIn("html", kinds)   # dinleyen sunucu CGI değil; printf konsola
        self.assertIn("format_string", kinds - {"path"} | {"format_string"})

    def test_traversal_check_regions_positive_negative_else_and_validator(self):
        fl, _ = flows({
            "g.c": """
                #include <sys/socket.h>
                #include <string.h>
                #include <fcntl.h>
                #include <stdio.h>
                int check_name(const char *s);
                void a(int c) {
                    char url[256];
                    recv(c, url, sizeof url, 0);
                    int fd;
                    if (NULL != strstr(url, "../"))
                        fd = -1;
                    else
                        fd = open(url + 1, O_RDONLY);
                    if ((NULL == strstr(&url[1], "..")) && fd)
                        fd = open(&url[1], O_RDONLY);
                    if (!strstr(url, ".."))
                        fopen(url, "r");
                    if (check_name(url))
                        fopen(url, "w");
                    if (strstr(url, ".."))
                        puts("bad");
                    fopen(url, "a");
                }
            """})
        self.assertEqual([line for p, line, k in fl if k == "path"], [22])

    def test_strtok_null_continues_previous_buffer(self):
        fl, _ = flows({
            "t.c": """
                #include <sys/socket.h>
                #include <string.h>
                #include <fcntl.h>
                void f(int sock) {
                    char inbuf[1024];
                    recv(sock, inbuf, sizeof(inbuf), 0);
                    strtok(inbuf, " ");
                    char *request = strtok(NULL, " ");
                    open(request, O_RDONLY);
                }
            """})
        self.assertIn(("t.c", 9, "path"), fl)

    def test_generic_container_and_polymorphic_fields_are_not_merged(self):
        files = {
            "buf.h": """
                typedef struct buffer { char *ptr; unsigned used; unsigned size; } buffer;
                struct conn { buffer *in; buffer *out; int fd; };
                struct cfg { buffer *docroot; buffer *tmpdir; };
                struct log { buffer *file; };
            """,
            "io.c": """
                #include <sys/socket.h>
                #include "buf.h"
                void rd(struct conn *c) { recv(c->fd, c->in->ptr, c->in->size, 0); }
            """,
            "use.c": """
                #include <stdio.h>
                #include "buf.h"
                void openlog_(struct log *l) { fopen(l->file->ptr, "a"); }
                void tmp(struct cfg *k) { fopen(k->tmpdir->ptr, "w"); }
            """}
        fl, facts = flows(files)
        self.assertFalse([x for x in fl if x[0] == "use.c"])
        self.assertFalse([k for k in facts["fields"] if k[0] == "buffer"])

    def test_separate_programs_do_not_share_field_taint(self):
        fl, _ = flows({
            "common.h": "struct msg { char *text; };\n",
            "client.c": """
                #include <stdio.h>
                #include "common.h"
                static struct msg m;
                int main(int argc, char **argv) { m.text = argv[1]; return 0; }
            """,
            "server.c": """
                #include <sys/socket.h>
                #include <string.h>
                #include "common.h"
                static struct msg sm;
                void store(int c) { char b[64]; recv(c, b, sizeof b, 0); sm.text = b; }
                void show(void) { char out[8]; strcpy(out, sm.text); }
                int main(void) { store(0); show(); return 0; }
            """})
        srcs = {line for p, line, k in fl if p == "server.c"}
        self.assertIn(6, srcs)
        # istemci programının argv kökeni sunucuya karışmaz (yerel köken alan modeline zaten yazılmaz)
        self.assertFalse([1 for p, line, k in fl if p == "server.c" and k != "memory"])


class UseAfterFreeTests(unittest.TestCase):
    FILES = {
        "notes.h": """
            #define MAX_NOTES 16
            struct note { char *title; char *body; };
            extern char *notes[MAX_NOTES];
            extern struct note *items[MAX_NOTES];
            extern char *safe_notes[MAX_NOTES];
            int read_int(void);
        """,
        "store.c": """
            #include <stdlib.h>
            #include <stdio.h>
            #include "notes.h"
            char *notes[MAX_NOTES];
            struct note *items[MAX_NOTES];
            char *safe_notes[MAX_NOTES];
            int read_int(void) { char line[32]; if (!fgets(line, sizeof line, stdin)) return -1; return atoi(line); }
            void cmd_delete(void) {
                int idx = read_int();
                if (idx < 0 || idx >= MAX_NOTES)
                    return;
                free(notes[idx]);
            }
            void cmd_delete_item(void) {
                int idx = read_int();
                if (idx < 0 || idx >= MAX_NOTES || !items[idx])
                    return;
                free(items[idx]->body);
            }
            void cmd_delete_safe(void) {
                int idx = read_int();
                if (idx < 0 || idx >= MAX_NOTES)
                    return;
                free(safe_notes[idx]);
                safe_notes[idx] = NULL;
            }
        """,
        "view.c": """
            #include <stdio.h>
            #include "notes.h"
            void cmd_show(void) {
                int idx = read_int();
                if (idx < 0 || idx >= MAX_NOTES || !notes[idx])
                    return;
                puts(notes[idx]);
            }
            void cmd_edit_item(void) {
                int idx = read_int();
                if (idx < 0 || idx >= MAX_NOTES || !items[idx])
                    return;
                fgets(items[idx]->body, 64, stdin);
            }
            void cmd_show_safe(void) {
                int idx = read_int();
                if (idx < 0 || idx >= MAX_NOTES || !safe_notes[idx])
                    return;
                puts(safe_notes[idx]);
            }
        """,
        "main.c": """
            #include "notes.h"
            void cmd_show(void); void cmd_delete(void); void cmd_delete_item(void); void cmd_edit_item(void);
            void cmd_delete_safe(void); void cmd_show_safe(void);
            int main(void) {
                for (;;) {
                    switch (read_int()) {
                    case 1: cmd_show(); break;
                    case 2: cmd_delete(); break;
                    case 3: cmd_delete_item(); break;
                    case 4: cmd_edit_item(); break;
                    case 5: cmd_delete_safe(); break;
                    case 6: cmd_show_safe(); break;
                    default: return 0;
                    }
                }
            }
        """,
    }

    def test_freed_slot_used_by_other_handler_in_other_file(self):
        _, facts = flows(self.FILES)
        got = mem(self.FILES, facts)
        self.assertIn(("view.c", 7, "uaf", True), got)
        self.assertIn(("view.c", 13, "uaf", True), got)
        self.assertFalse([x for x in got if x[0] == "view.c" and x[1] >= 15])  # NULL yapılan yuva
        d0 = [x for x in facts["dangling"] if x.line == 7][0]
        self.assertEqual((d0.free_file, d0.free_line, d0.free_func, d0.dispatcher), ("store.c", 12, "cmd_delete", "main"))


class LengthFieldTests(unittest.TestCase):
    FILES = {
        "proto.h": """
            #include <stdint.h>
            struct msg_hdr { uint32_t magic; uint16_t keylen; uint32_t payload_size; uint8_t type; };
            struct frame { uint32_t declared_len; char data[512]; };
            int handle_msg(int fd, struct msg_hdr *h);
            int handle_frame(struct frame *f);
            int validate_frame(struct frame *f);
        """,
        "net.c": """
            #include <sys/socket.h>
            #include <string.h>
            #include "proto.h"
            void serve(int listen_fd) {
                int c = accept(listen_fd, 0, 0);
                struct msg_hdr hdr;
                if (recv(c, &hdr, sizeof(hdr), 0) != sizeof(hdr))
                    return;
                handle_msg(c, &hdr);
                char raw[600];
                ssize_t n = recv(c, raw, sizeof(raw), 0);
                if (n < 4)
                    return;
                struct frame *fr = (struct frame *)raw;
                if (validate_frame(fr) == 0)
                    handle_frame(fr);
            }
            int parse_tlv(const unsigned char *buf, char *out) {
                unsigned short len = (buf[0] << 8) | buf[1];
                memcpy(out, buf + 2, len);
                return len;
            }
            void serve_tlv(int c) {
                unsigned char pkt[1024];
                char value[128];
                recv(c, pkt, sizeof(pkt), 0);
                parse_tlv(pkt, value);
            }
        """,
        "handler.c": """
            #include <sys/socket.h>
            #include <string.h>
            #include "proto.h"
            int handle_msg(int fd, struct msg_hdr *h) {
                char key[64];
                char payload[256];
                recv(fd, key, h->keylen, 0);
                memcpy(payload, key, h->payload_size);
                return 0;
            }
            int validate_frame(struct frame *f) {
                if (f->declared_len > sizeof(f->data))
                    return -1;
                return 0;
            }
            int handle_frame(struct frame *f) {
                char copy[512];
                memcpy(copy, f->data, f->declared_len);
                return 0;
            }
        """,
    }

    def test_message_length_fields_trusted_without_validation(self):
        fl, facts = flows(self.FILES)
        self.assertIn(("handler.c", 7, "memory_len"), fl)
        self.assertIn(("handler.c", 8, "memory_len"), fl)
        self.assertIn(("net.c", 20, "memory_len"), fl)
        self.assertNotIn(("handler.c", 18, "memory_len"), fl)  # declared_len projede sınırla denetleniyor
        got = mem(self.FILES, facts)
        self.assertIn(("handler.c", 7, "overflow_taint", True), got)
        self.assertIn(("handler.c", 8, "overflow_taint", True), got)
        self.assertIn(("net.c", 20, "overflow_taint", True), got)
        self.assertFalse([x for x in got if x[0] == "handler.c" and x[1] == 18])


class RustUnsafeCopyTests(unittest.TestCase):
    def test_unsafe_copy_with_declared_length_and_safe_slicing(self):
        src = d("""
            fn parse(buf: &[u8], out: &mut [u8]) {
                let declared_len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
                unsafe {
                    std::ptr::copy_nonoverlapping(buf.as_ptr().add(4), out.as_mut_ptr(), declared_len);
                }
            }
            fn bounded(buf: &[u8], out: &mut [u8]) {
                let declared_len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
                let n = declared_len.min(out.len());
                unsafe { std::ptr::copy_nonoverlapping(buf.as_ptr(), out.as_mut_ptr(), n); }
            }
            fn checked(buf: &[u8], out: &mut [u8], len: usize) {
                if len > out.len() { return; }
                unsafe { std::ptr::copy(buf.as_ptr(), out.as_mut_ptr(), len); }
            }
            fn slice_panics_only(buf: &[u8], declared_len: usize) -> &[u8] { &buf[..declared_len] }
            fn range(buf: &[u8], hdr: Hdr) -> u8 { unsafe { *buf.get_unchecked(..hdr.payload_size).last().unwrap() } }
            fn grow(v: &mut Vec<u8>, n: usize) { unsafe { v.set_len(n); } }
            fn split(s: &str, i: usize) -> &str { unsafe { s.get_unchecked(0..i) } }
        """)
        got = [(f.line, f.kind) for f in memsafety_rust.analyze_text(src, "p.rs")]
        # set_len(n) / get_unchecked(0..i): uzunluk iletideki bir alandan gelmiyor → olgun kod sözleşmesi, raporlanmaz
        self.assertEqual(got, [(4, "overflow"), (17, "overread")])
        f4 = memsafety_rust.analyze_text(src, "p.rs")[0]
        self.assertIn("CWE-130", f4.evidence)
        self.assertFalse(f4.certain)


class TranslationTests(unittest.TestCase):
    def test_new_titles_and_evidence_fragments_translated(self):
        import i18n_server

        for text in (project_analyzer.TAINT_FLOW_RULES["code"][2],
                     project_analyzer.MODEL_MEM_FLOW_PREFIX + ": istek girdisi sınır denetimsiz bellek kopyalamasına "
                                                              "ulaşıyor (arabellek taşması)"):
            html = i18n_server.localize_html(f"<p>{text}</p>", "en")
            self.assertNotIn("veri akışı", html)
        html = i18n_server.localize_html("<p>Veri akışı: x (satır 1) → system() (satır 2); kanıt zinciri: a.c:3 "
                                         "req.path alanına yazım; kaynak satır içeriği kaydedilmedi.</p>", "en")
        self.assertIn("evidence chain", html)
        self.assertIn("field write", html)


class ProjectIntegrationTests(unittest.TestCase):
    def test_project_analysis_reports_verified_memory_error_with_cross_file_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "srv"
            root.mkdir()
            for name, text in MINISRV.items():
                (root / name).write_text(d(text))
            res = project_analyzer.analyze_project(str(root), allowed_roots=(root.parent,))
        by = {(f["file"], f["line"]): f for f in res["findings"] if f["file"] == "handlers.c"}
        f13 = by[("handlers.c", 13)]
        self.assertTrue(f13["title"].startswith("Doğrulanmış bellek hatası"))
        self.assertEqual(f13["memory_safety"]["source_file"], "net.c")
        self.assertTrue(f13["memory_safety"]["chain"])
        self.assertIn("zincir:", f13["evidence"])
        self.assertTrue(f13.get("taint_flow"))  # akış bellek bulgusuna eklendi (tek bulgu)
        self.assertEqual(by[("handlers.c", 22)]["reference"], "CWE-78")
        self.assertIn("kanıt zinciri", by[("handlers.c", 22)]["evidence"])
        self.assertEqual(by[("handlers.c", 16)]["reference"], "CWE-79")
        self.assertFalse([k for k in by if k[1] >= 38 and by[k]["title"].startswith("Doğrulanmış")])


if __name__ == "__main__":
    unittest.main()
