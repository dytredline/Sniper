"""17. tur C/C++ derinliği: işaretçi takma adları, ham okunan yapıların tamsayı alanları, soket tanımlayıcıları,
CGI POST gövdesi, okuma uzunluğu hedefleri, sabit boyutlu yığın/yapı alanı hedefleri, snprintf dönüş değeri birikimi,
dosyadan sınırsız fscanf ve üçlü işleç."""
from __future__ import annotations

import textwrap
import unittest

import taint_cfamily


def flows(files: dict[str, str]) -> list[tuple[str, int, str]]:
    res = taint_cfamily.analyze_files({k: textwrap.dedent(v) for k, v in files.items()})
    return sorted((f.sink_kind, f.line, f.source_label) for a in res.values() for f in a.flows)


class PointerAliasTests(unittest.TestCase):
    def test_byte_by_byte_receive_through_pointer_alias_reaches_strcat_and_open(self):
        got = flows({"srv.c": """
            int receive_line(int s, char *buffer) {
                char ch;
                char *ptr = buffer;
                int n = recv(s, (void *)&ch, 1, 0);
                while (n > 0) {
                    *ptr = ch;
                    n = recv(s, (void *)&ch, 1, 0);
                    ptr++;
                }
                return n;
            }
            void serve(int s, char *req) {
                char *path;
                char filename[100];
                path = req[0] == 'G' ? req + 4 : req + 5;
                strcpy(filename, "public_html");
                strcat(filename, path);
                open(filename, 0);
            }
            int main(void) {
                char line[128];
                int c = accept(3, 0, 0);
                receive_line(c, line);
                serve(c, line);
                return 0;
            }
        """})
        self.assertIn(("memory", 18, "request"), got)
        self.assertIn(("path", 19, "request"), got)

    def test_recv_wrapper_with_cast_alias_taints_struct_and_logger_overflow(self):
        got = flows({"fs.c": """
            #include <stdint.h>
            typedef struct { char magic[4]; uint16_t dir_len; uint16_t name_len; } Header;
            static long recv_all(int sock, void *buf, unsigned long len) {
                unsigned long total = 0;
                char *p = (char *)buf;
                while (total < len) {
                    long n = recv(sock, p + total, len - total, 0);
                    if (n <= 0) return n;
                    total += n;
                }
                return total;
            }
            static void log_query(const char *dir) {
                char line[128];
                sprintf(line, "path=%s", dir);
                puts(line);
            }
            void handle(int client) {
                Header h;
                char dir[1025];
                char copy[64];
                recv_all(client, &h, sizeof(h));
                uint16_t dl = ntohs(h.dir_len);
                if (dl > 1024) return;
                recv_all(client, dir, dl);
                dir[dl] = 0;
                log_query(dir);
                memcpy(copy, dir, h.name_len);
            }
        """})
        self.assertIn(("memory", 16, "request"), got)       # sprintf %s → sabit tampon (log_query üzerinden)
        self.assertIn(("memory_len", 29, "request"), got)   # ham okunan yapının tamsayı alanı uzunluk
        self.assertNotIn("memory_index", [k for k, _, _ in got])  # dl üst sınırla denetlendi

    def test_counter_fields_of_struct_with_written_buffer_are_program_state(self):
        got = flows({"conn.c": """
            struct conn { char buf[4096]; int len; int used; };
            void pump(struct conn *c, int fd) {
                char out[64];
                recv(fd, c->buf + c->len, sizeof(c->buf) - c->len, 0);
                memcpy(out, c->buf, c->used);
            }
        """})
        self.assertNotIn("memory_len", [k for k, _, _ in got])


class SourceTests(unittest.TestCase):
    def test_accepted_descriptor_is_network_source_even_with_unusual_name(self):
        got = flows({"cmd.c": """
            int main(int argc, char **argv) {
                char str[200];
                char cmd[100];
                int lfd = socket(2, 1, 0);
                int comm_x = accept(lfd, 0, 0);
                read(comm_x, str, 200);
                snprintf(cmd, sizeof(cmd), "echo %s", str);
                system(cmd);
                return 0;
            }
        """})
        self.assertIn(("command", 9, "request"), got)

    def test_cgi_post_body_on_stdin_is_request_and_reflected_output_is_xss(self):
        got = flows({"cgi-bin/login.c": """
            void login(void) {
                char buf[512];
                char user[128];
                gets(buf);
                strcpy(user, buf);
                printf("<h1>Hello ");
                printf(user);
            }
            int main(void) {
                printf("Content-type: text/html\\n\\n");
                login();
                return 0;
            }
        """})
        self.assertIn(("memory", 5, "request"), got)
        self.assertIn(("html", 8, "request"), got)
        self.assertIn(("format_string", 8, "request"), got)

    def test_non_cgi_console_program_keeps_local_label(self):
        got = flows({"tool.c": """
            int main(void) {
                char buf[64];
                gets(buf);
                printf(buf);
                return 0;
            }
        """})
        self.assertTrue(got)
        self.assertEqual({s for _, _, s in got}, {"local"})


class LengthSinkTests(unittest.TestCase):
    def test_length_prefix_reinterpreted_as_int_reaches_read_and_index(self):
        got = flows({"net.c": """
            char *receive_message(int socket_fd) {
                char length_buf[4];
                read(socket_fd, length_buf, 4);
                int msg_len = *(int *)length_buf;
                char *buffer = malloc(256);
                read(socket_fd, buffer, msg_len);
                buffer[msg_len] = 0;
                return buffer;
            }
        """})
        self.assertIn(("memory_len", 7, "request"), got)
        self.assertIn(("memory_index", 8, "request"), got)

    def test_checked_or_same_size_allocation_is_not_reported(self):
        got = flows({"ok.c": """
            char *checked(int socket_fd) {
                char length_buf[4];
                char fixed[256];
                read(socket_fd, length_buf, 4);
                int n = *(int *)length_buf;
                if (n < 0 || n > 255) return 0;
                read(socket_fd, fixed, n);
                return 0;
            }
            char *sized(int socket_fd) {
                char length_buf[4];
                read(socket_fd, length_buf, 4);
                unsigned int n = *(unsigned int *)length_buf;
                char *b = malloc(n);
                read(socket_fd, b, n);
                return b;
            }
            int hashed(int socket_fd) {
                char buf[16];
                int table[16];
                read(socket_fd, buf, 16);
                int h = buf[0];
                return table[h];
            }
        """})
        self.assertEqual([k for k, _, _ in got if k in ("memory_len", "memory_index")], [])

    def test_snprintf_return_value_accumulation(self):
        got = flows({"acc.c": """
            void bad(int s) {
                char in[512];
                char out[128];
                int n = 0;
                recv(s, in, 511, 0);
                n += snprintf(out + n, sizeof(out) - n, "a=%s;", in);
                n += snprintf(out + n, sizeof(out) - n, "b=%s;", in);
            }
            void good(int s) {
                char in[512];
                char out[128];
                int n = 0;
                recv(s, in, 511, 0);
                n += snprintf(out + n, sizeof(out) - n, "a=%s;", in);
                if (n >= (int)sizeof(out)) return;
                n += snprintf(out + n, sizeof(out) - n, "b=%s;", in);
            }
        """})
        lens = [line for kind, line, _ in got if kind == "memory_len"]
        self.assertEqual(lens, [7, 8])


class DestinationTests(unittest.TestCase):
    def test_constant_heap_and_struct_array_field_are_fixed_buffers(self):
        got = flows({"heap.c": """
            struct data { char name[64]; };
            struct item { int prio; char *name; };
            int main(int argc, char **argv) {
                struct data *d = malloc(sizeof(struct data));
                struct item *i1 = malloc(sizeof(struct item));
                char *dyn;
                i1->name = malloc(8);
                strcpy(d->name, argv[1]);
                char *small = malloc(8);
                strcpy(small, argv[2]);
                dyn = malloc(strlen(argv[3]) + 1);
                strcpy(dyn, argv[3]);
                return 0;
            }
        """})
        lines = [line for kind, line, _ in got if kind == "memory"]
        self.assertIn(9, lines)
        self.assertIn(11, lines)
        self.assertNotIn(13, lines)

    def test_unbounded_fscanf_from_file_into_stack_buffer(self):
        got = flows({"f.c": """
            int main(int argc, char **argv) {
                char buf[10];
                char ok[10];
                FILE *fin = fopen(argv[1], "r");
                fscanf(fin, "%s", buf);
                fscanf(fin, "%9s", ok);
                return 0;
            }
        """})
        self.assertEqual([(k, l) for k, l, _ in got], [("memory", 6)])


if __name__ == "__main__":
    unittest.main()
