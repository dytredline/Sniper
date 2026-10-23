#include <functional>
#include <sys/socket.h>
#include <cstdio>
void print_value(char *value) { printf("%s", value); }
void log_value(char *value) { fprintf(stderr, "%s", value); }
void dispatch(int socket_fd, bool verbose) {
    char request[128];
    recv(socket_fd, request, 127, 0);
    std::function<void(char *)> handler = verbose ? log_value : print_value;
    handler(request);
}
