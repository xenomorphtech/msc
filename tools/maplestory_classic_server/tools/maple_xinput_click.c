#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <xorg/xf86-input-inputtest-protocol.h>

static void write_all(int fd, const void *buffer, size_t length) {
    const char *bytes = buffer;
    while (length > 0) {
        ssize_t count = write(fd, bytes, length);
        if (count <= 0) {
            perror("write");
            exit(EXIT_FAILURE);
        }
        bytes += count;
        length -= (size_t)count;
    }
}

static void read_all(int fd, void *buffer, size_t length) {
    char *bytes = buffer;
    while (length > 0) {
        ssize_t count = read(fd, bytes, length);
        if (count == 0) {
            fputs("unexpected end of Xorg input socket\n", stderr);
            exit(EXIT_FAILURE);
        }
        if (count < 0) {
            perror("read");
            exit(EXIT_FAILURE);
        }
        bytes += count;
        length -= (size_t)count;
    }
}

static void emit_click(int input_fd) {
    for (uint32_t pressed = 1;; pressed = 0) {
        xf86ITEventButton event;
        memset(&event, 0, sizeof(event));
        event.header.length = sizeof(event);
        event.header.type = XF86IT_EVENT_BUTTON;
        event.button = 1;
        event.is_press = pressed;
        write_all(input_fd, &event, sizeof(event));
        if (pressed == 0) {
            break;
        }
        usleep(300000);
    }

    xf86ITEventWaitForSync sync = {
        .header = {
            .length = sizeof(sync),
            .type = XF86IT_EVENT_WAIT_FOR_SYNC,
        },
    };
    xf86ITResponseSyncFinished response;
    write_all(input_fd, &sync, sizeof(sync));
    read_all(input_fd, &response, sizeof(response));
}

int main(int argc, char **argv) {
    const char *socket_path = argc > 1 ? argv[1] : "/opt/maple-vast/run/inputtest.sock";
    long port = argc > 2 ? strtol(argv[2], NULL, 10) : 19099;
    if (port < 1 || port > 65535) {
        fprintf(stderr, "invalid trigger port: %ld\n", port);
        return EXIT_FAILURE;
    }

    int input_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (input_fd < 0) {
        perror("create Xorg input socket");
        return EXIT_FAILURE;
    }
    struct sockaddr_un input_address = {.sun_family = AF_UNIX};
    strncpy(input_address.sun_path, socket_path, sizeof(input_address.sun_path) - 1);
    if (connect(input_fd, (struct sockaddr *)&input_address, sizeof(input_address)) < 0) {
        perror("connect to Xorg inputtest socket");
        return EXIT_FAILURE;
    }

    xf86ITEventClientVersion version = {
        .header = {
            .length = sizeof(version),
            .type = XF86IT_EVENT_CLIENT_VERSION,
        },
        .major = XF86IT_PROTOCOL_VERSION_MAJOR,
        .minor = XF86IT_PROTOCOL_VERSION_MINOR,
    };
    xf86ITResponseServerVersion version_response;
    write_all(input_fd, &version, sizeof(version));
    read_all(input_fd, &version_response, sizeof(version_response));

    int listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) {
        perror("create click trigger socket");
        return EXIT_FAILURE;
    }
    int reuse = 1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    struct sockaddr_in listen_address = {
        .sin_family = AF_INET,
        .sin_port = htons((uint16_t)port),
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };
    if (bind(listener, (struct sockaddr *)&listen_address, sizeof(listen_address)) < 0 ||
        listen(listener, 4) < 0) {
        perror("listen for click triggers");
        return EXIT_FAILURE;
    }

    for (;;) {
        int trigger_fd = accept(listener, NULL, NULL);
        if (trigger_fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("accept click trigger");
            return EXIT_FAILURE;
        }
        char command;
        if (read(trigger_fd, &command, 1) == 1 && command == 'x') {
            emit_click(input_fd);
            write_all(trigger_fd, "ok\n", 3);
        }
        close(trigger_fd);
    }
}
