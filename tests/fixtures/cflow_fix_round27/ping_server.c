// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026, Timo Pallach (timo@pallach.de)

/*
 * Network Diagnostic Tool — a simple web-based ping utility.
 *
 * This program implements a minimal HTTP/1.1 server that provides
 * a browser-friendly interface for running ping commands against
 * remote hosts.  Enter a hostname or IP address in the form and
 * the server executes "ping -c 3 <host>" and returns the output.
 *
 * ROUTES
 *   GET /               HTML page with a form to enter a hostname.
 *   GET /ping?host=X    Runs ping against the supplied host and
 *                       returns the command output as plain text.
 *   (all other paths)   Returns 404 Not Found.
 *   (non-GET methods)   Returns 405 Method Not Allowed.
 *
 * COMMAND-LINE OPTIONS
 *   -v, --verbose   Log each request and response to stderr
 *                   with timestamps.
 *   -h, --help      Print usage information and exit.
 *
 * BUILD
 *   cc -Wall -Wextra -O2 -o a.out main.c
 *
 * DEPENDENCIES
 *   None beyond POSIX — uses sockets, popen(), getopt_long().
 *   Compiles with cc (clang on macOS, gcc on Linux, any C99 compiler).
 */

#include <arpa/inet.h> /* inet_ntoa, sockaddr_in           */
#include <getopt.h> /* getopt_long, struct option        */
#include <netinet/in.h> /* INADDR_ANY, htons                */
#include <signal.h> /* signal, SIG_IGN, SIGPIPE          */
#include <stdio.h> /* printf, fprintf, snprintf, popen  */
#include <stdlib.h> /* strtol, exit                      */
#include <string.h> /* memset, strcmp, strncmp, strlen    */
#include <sys/socket.h> /* socket, bind, listen, accept      */
#include <time.h> /* time, localtime, strftime          */
#include <unistd.h> /* read, write, close                */

/* ------------------------------------------------------------------ */
/* Configuration constants                                             */
/* ------------------------------------------------------------------ */

#define PORT 8081 /* TCP port the server listens on.            */
#define BACKLOG 10 /* Max queued connections for listen().        */
#define BUF_SIZE 4096 /* Read buffer for incoming HTTP requests.     */
#define CMD_SIZE 512 /* Max length of the constructed shell command.*/
#define RESP_SIZE 65536 /* Max captured output from popen().           */

/* ------------------------------------------------------------------ */
/* Global state                                                        */
/* ------------------------------------------------------------------ */

static int verbose = 0;

/*
 * log_timestamp - Print an ISO-style timestamp prefix to stderr.
 *
 * Output format: [YYYY-MM-DD HH:MM:SS]
 */
static void log_timestamp(void)
{
	time_t now;
	struct tm* tm;
	char buf[32];

	time(&now);
	tm = localtime(&now);
	strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm);
	fprintf(stderr, "[%s] ", buf);
}

/*
 * usage - Print command-line help to stderr.
 */
static void usage(const char* prog)
{
	fprintf(stderr, "Usage: %s [-v|--verbose]\n", prog);
	fprintf(stderr, "  -v, --verbose  Enable verbose request logging\n");
}

/* ------------------------------------------------------------------ */
/* HTML served at GET /                                                */
/* ------------------------------------------------------------------ */

static const char* INDEX_HTML
    = "<!DOCTYPE html>\n"
      "<html lang=\"en\">\n"
      "<head>\n"
      "  <meta charset=\"utf-8\">\n"
      "  <title>Network Diagnostic Tool</title>\n"
      "  <style>\n"
      "    body { font-family: sans-serif; max-width: 600px; margin: 40px "
      "auto; }\n"
      "    h1   { color: #333; }\n"
      "    form { margin: 20px 0; }\n"
      "    input[type=text] { padding: 8px; width: 300px; }\n"
      "    button { padding: 8px 16px; cursor: pointer; }\n"
      "    pre  { background: #f4f4f4; padding: 16px; overflow-x: auto; }\n"
      "  </style>\n"
      "</head>\n"
      "<body>\n"
      "  <h1>Network Diagnostic Tool</h1>\n"
      "  <p>Enter a hostname or IP address to ping:</p>\n"
      "  <form action=\"/ping\" method=\"get\">\n"
      "    <input type=\"text\" name=\"host\" placeholder=\"e.g. 127.0.0.1\">\n"
      "    <button type=\"submit\">Ping</button>\n"
      "  </form>\n"
      "</body>\n"
      "</html>\n";

/* ------------------------------------------------------------------ */
/* URL / query-string helpers                                          */
/* ------------------------------------------------------------------ */

/*
 * url_decode - Decode a percent-encoded URL string.
 *
 * Converts %XX hex sequences to their byte values and '+' to space.
 * The result is written to dst (up to dst_size - 1 bytes) and always
 * NUL-terminated.
 */
static void url_decode(char* dst, const char* src, size_t dst_size)
{
	size_t i = 0;

	while (*src && i < dst_size - 1) {
		if (*src == '%' && src[1] && src[2]) {
			char hex[3] = { src[1], src[2], '\0' };
			dst[i++] = (char)strtol(hex, NULL, 16);
			src += 3;
		} else if (*src == '+') {
			dst[i++] = ' ';
			src++;
		} else {
			dst[i++] = *src++;
		}
	}
	dst[i] = '\0';
}

/*
 * query_param - Extract a named parameter from a URL query string.
 *
 * Searches the query string for "key=value" and copies the value
 * into the provided buffer.
 *
 * Returns 1 if found, 0 otherwise.
 */
static int query_param(
    const char* query, const char* key, char* value, size_t value_size)
{
	char search[128];
	const char* p;

	snprintf(search, sizeof(search), "%s=", key);
	p = strstr(query, search);
	if (!p)
		return 0;

	p += strlen(search);

	size_t i = 0;
	while (*p && *p != '&' && *p != ' ' && i < value_size - 1)
		value[i++] = *p++;
	value[i] = '\0';
	return 1;
}

/* ------------------------------------------------------------------ */
/* HTTP response helpers                                               */
/* ------------------------------------------------------------------ */

/*
 * send_response - Write an HTTP/1.1 response to a client socket.
 */
static void send_response(
    int fd, const char* status, const char* content_type, const char* body)
{
	char header[512];
	int hlen;

	if (verbose) {
		log_timestamp();
		fprintf(stderr, "  -> %s (%s, %lu bytes)\n", status, content_type,
		    (unsigned long)strlen(body));
	}

	hlen = snprintf(header, sizeof(header),
	    "HTTP/1.1 %s\r\n"
	    "Content-Type: %s\r\n"
	    "Content-Length: %lu\r\n"
	    "Connection: close\r\n"
	    "\r\n",
	    status, content_type, (unsigned long)strlen(body));

	write(fd, header, hlen);
	write(fd, body, strlen(body));
}

static void send_404(int fd)
{
	send_response(fd, "404 Not Found", "text/plain", "404 Not Found\n");
}

static void send_400(int fd, const char* msg)
{
	send_response(fd, "400 Bad Request", "text/plain", msg);
}

/* ------------------------------------------------------------------ */
/* GET /ping?host=<hostname>                                          */
/* ------------------------------------------------------------------ */

static void handle_ping(int fd, const char* query)
{
	char raw_host[256];
	char host[256];
	char cmd[CMD_SIZE];
	char result[RESP_SIZE];
	size_t total = 0;
	FILE* fp;

	if (!query || !query_param(query, "host", raw_host, sizeof(raw_host))) {
		send_400(fd, "Missing required parameter: host\n");
		return;
	}

	url_decode(host, raw_host, sizeof(host));

	if (strlen(host) == 0) {
		send_400(fd, "Parameter 'host' must not be empty\n");
		return;
	}

	snprintf(cmd, sizeof(cmd), "ping -c 3 %s 2>&1", host);

	if (verbose) {
		log_timestamp();
		fprintf(stderr, "  exec: %s\n", cmd);
	}

	fp = popen(cmd, "r");
	if (!fp) {
		send_response(fd, "500 Internal Server Error", "text/plain",
		    "Failed to execute ping command\n");
		return;
	}

	while (total < sizeof(result) - 1) {
		size_t n = fread(result + total, 1, sizeof(result) - 1 - total, fp);
		if (n == 0)
			break;
		total += n;
	}
	result[total] = '\0';
	pclose(fp);

	send_response(fd, "200 OK", "text/plain", result);
}

/* ------------------------------------------------------------------ */
/* Request router                                                      */
/* ------------------------------------------------------------------ */

static void handle_request(int fd, const char* method, const char* path)
{
	const char* query;

	if (strcmp(method, "GET") != 0) {
		send_response(fd, "405 Method Not Allowed", "text/plain",
		    "Only GET is supported\n");
		return;
	}

	query = strchr(path, '?');

	if (strncmp(path, "/ping", 5) == 0 && (path[5] == '?' || path[5] == '\0')) {
		handle_ping(fd, query ? query + 1 : NULL);
	} else if (strcmp(path, "/") == 0) {
		send_response(fd, "200 OK", "text/html; charset=utf-8", INDEX_HTML);
	} else {
		send_404(fd);
	}
}

/* ------------------------------------------------------------------ */
/* Main: TCP socket server                                             */
/* ------------------------------------------------------------------ */

int main(int argc, char* argv[])
{
	int server_fd, client_fd, opt = 1;
	struct sockaddr_in addr;
	socklen_t addrlen = sizeof(addr);
	char buf[BUF_SIZE];
	ssize_t n;
	int ch;

	static struct option longopts[] = { { "verbose", no_argument, NULL, 'v' },
		{ "help", no_argument, NULL, 'h' }, { NULL, 0, NULL, 0 } };

	while ((ch = getopt_long(argc, argv, "vh", longopts, NULL)) != -1) {
		switch (ch) {
		case 'v':
			verbose = 1;
			break;
		case 'h':
			usage(argv[0]);
			return 0;
		default:
			usage(argv[0]);
			return 1;
		}
	}

	signal(SIGPIPE, SIG_IGN);

	server_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (server_fd < 0) {
		perror("socket");
		return 1;
	}

	setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(PORT);

	if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		perror("bind");
		close(server_fd);
		return 1;
	}

	if (listen(server_fd, BACKLOG) < 0) {
		perror("listen");
		close(server_fd);
		return 1;
	}

	printf("Listening on http://localhost:%d\n", PORT);

	for (;;) {
		client_fd = accept(server_fd, (struct sockaddr*)&addr, &addrlen);
		if (client_fd < 0) {
			perror("accept");
			continue;
		}

		n = read(client_fd, buf, sizeof(buf) - 1);
		if (n > 0) {
			char method[16], path[2048];

			buf[n] = '\0';
			if (sscanf(buf, "%15s %2047s", method, path) == 2) {
				if (verbose) {
					log_timestamp();
					fprintf(stderr, "%s %s\n", method, path);
				}
				handle_request(client_fd, method, path);
			}
		}

		close(client_fd);
	}

	close(server_fd);
	return 0;
}
