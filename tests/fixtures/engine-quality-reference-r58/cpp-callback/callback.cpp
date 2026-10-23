#include <functional>
#include <sys/socket.h>
#include <cstdlib>
void dangerous(char *value) { system(value); }
void harmless(char *value) { printf("%s", value); }
void dispatch(int socket_fd, bool privileged) {
    char request[128];
    recv(socket_fd, request, 127, 0);
    std::function<void(char *)> handler = privileged ? dangerous : harmless;
    handler(request);
}
