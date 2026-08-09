#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <linux/input-event-codes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <wayland-client.h>
#include <xkbcommon/xkbcommon.h>

#include "virtual-keyboard-unstable-v1-client-protocol.h"

struct globals {
    struct wl_seat *seat;
    struct zwp_virtual_keyboard_manager_v1 *manager;
};

static void registry_global(void *data, struct wl_registry *registry,
                            uint32_t name, const char *interface,
                            uint32_t version) {
    struct globals *globals = data;

    if (strcmp(interface, wl_seat_interface.name) == 0) {
        uint32_t bind_version = version < 7 ? version : 7;
        globals->seat = wl_registry_bind(
            registry, name, &wl_seat_interface, bind_version);
    } else if (strcmp(interface,
                      zwp_virtual_keyboard_manager_v1_interface.name) == 0) {
        globals->manager = wl_registry_bind(
            registry, name, &zwp_virtual_keyboard_manager_v1_interface, 1);
    }
}

static void registry_global_remove(void *data, struct wl_registry *registry,
                                   uint32_t name) {
    (void)data;
    (void)registry;
    (void)name;
}

static const struct wl_registry_listener registry_listener = {
    .global = registry_global,
    .global_remove = registry_global_remove,
};

static int parse_unsigned(const char *text, unsigned long maximum,
                          unsigned long *result) {
    char *end = NULL;
    errno = 0;
    unsigned long value = strtoul(text, &end, 0);
    if (errno != 0 || text[0] == '\0' || *end != '\0' || value > maximum) {
        return -1;
    }
    *result = value;
    return 0;
}

static int write_all(int fd, const char *bytes, size_t size) {
    while (size > 0) {
        ssize_t written = write(fd, bytes, size);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            return -1;
        }
        bytes += written;
        size -= (size_t)written;
    }
    return 0;
}

static uint32_t monotonic_milliseconds(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return 0;
    }
    uint64_t milliseconds = (uint64_t)now.tv_sec * 1000;
    milliseconds += (uint64_t)now.tv_nsec / 1000000;
    return (uint32_t)milliseconds;
}

int main(int argc, char **argv) {
    if (argc < 2 || argc > 3) {
        fprintf(stderr, "usage: %s EVDEV_KEYCODE [HOLD_MS]\n", argv[0]);
        return 2;
    }

    unsigned long keycode = 0;
    unsigned long hold_ms = 100;
    if (parse_unsigned(argv[1], KEY_MAX, &keycode) != 0) {
        fprintf(stderr, "invalid evdev keycode (expected 0..%u)\n", KEY_MAX);
        return 2;
    }
    if (argc == 3 &&
        parse_unsigned(argv[2], 10000, &hold_ms) != 0) {
        fprintf(stderr, "invalid hold duration (expected 0..10000 ms)\n");
        return 2;
    }

    int status = 1;
    int keymap_fd = -1;
    char *keymap_text = NULL;
    struct xkb_context *xkb_context = NULL;
    struct xkb_keymap *xkb_keymap = NULL;
    struct wl_display *display = wl_display_connect(NULL);
    struct wl_registry *registry = NULL;
    struct zwp_virtual_keyboard_v1 *keyboard = NULL;
    struct globals globals = {0};

    if (display == NULL) {
        fprintf(stderr, "could not connect to the selected Wayland display\n");
        goto cleanup;
    }
    registry = wl_display_get_registry(display);
    if (registry == NULL) {
        fprintf(stderr, "could not obtain the Wayland registry\n");
        goto cleanup;
    }
    wl_registry_add_listener(registry, &registry_listener, &globals);
    if (wl_display_roundtrip(display) < 0) {
        fprintf(stderr, "Wayland registry roundtrip failed\n");
        goto cleanup;
    }
    if (globals.seat == NULL || globals.manager == NULL) {
        fprintf(stderr, "virtual keyboard protocol or seat unavailable\n");
        goto cleanup;
    }

    keyboard = zwp_virtual_keyboard_manager_v1_create_virtual_keyboard(
        globals.manager, globals.seat);
    xkb_context = xkb_context_new(XKB_CONTEXT_NO_FLAGS);
    if (keyboard == NULL || xkb_context == NULL) {
        fprintf(stderr, "could not create the virtual keyboard context\n");
        goto cleanup;
    }
    const struct xkb_rule_names names = {
        .rules = "evdev",
        .model = "pc105",
        .layout = "us",
    };
    xkb_keymap = xkb_keymap_new_from_names(
        xkb_context, &names, XKB_KEYMAP_COMPILE_NO_FLAGS);
    if (xkb_keymap == NULL) {
        fprintf(stderr, "could not compile the evdev XKB keymap\n");
        goto cleanup;
    }
    keymap_text = xkb_keymap_get_as_string(
        xkb_keymap, XKB_KEYMAP_FORMAT_TEXT_V1);
    if (keymap_text == NULL) {
        fprintf(stderr, "could not serialize the evdev XKB keymap\n");
        goto cleanup;
    }

    size_t keymap_size = strlen(keymap_text) + 1;
    char filename[] = "/tmp/maple-wayland-keymap-XXXXXX";
    keymap_fd = mkstemp(filename);
    if (keymap_fd < 0) {
        fprintf(stderr, "could not create keymap file: %s\n", strerror(errno));
        goto cleanup;
    }
    unlink(filename);
    if (write_all(keymap_fd, keymap_text, keymap_size) != 0 ||
        lseek(keymap_fd, 0, SEEK_SET) < 0) {
        fprintf(stderr, "could not write keymap: %s\n", strerror(errno));
        goto cleanup;
    }
    zwp_virtual_keyboard_v1_keymap(
        keyboard, WL_KEYBOARD_KEYMAP_FORMAT_XKB_V1, keymap_fd, keymap_size);
    if (wl_display_roundtrip(display) < 0) {
        fprintf(stderr, "Wayland keymap roundtrip failed\n");
        goto cleanup;
    }

    uint32_t timestamp = monotonic_milliseconds();
    zwp_virtual_keyboard_v1_key(
        keyboard, timestamp, (uint32_t)keycode,
        WL_KEYBOARD_KEY_STATE_PRESSED);
    if (wl_display_roundtrip(display) < 0) {
        fprintf(stderr, "Wayland key-press roundtrip failed\n");
        goto cleanup;
    }
    struct timespec delay = {
        .tv_sec = (time_t)(hold_ms / 1000),
        .tv_nsec = (long)(hold_ms % 1000) * 1000000,
    };
    while (nanosleep(&delay, &delay) != 0 && errno == EINTR) {
    }
    zwp_virtual_keyboard_v1_key(
        keyboard, monotonic_milliseconds(), (uint32_t)keycode,
        WL_KEYBOARD_KEY_STATE_RELEASED);
    if (wl_display_roundtrip(display) < 0) {
        fprintf(stderr, "Wayland key-release roundtrip failed\n");
        goto cleanup;
    }
    status = 0;

cleanup:
    if (keymap_fd >= 0) {
        close(keymap_fd);
    }
    free(keymap_text);
    if (xkb_keymap != NULL) {
        xkb_keymap_unref(xkb_keymap);
    }
    if (xkb_context != NULL) {
        xkb_context_unref(xkb_context);
    }
    if (keyboard != NULL) {
        zwp_virtual_keyboard_v1_destroy(keyboard);
    }
    if (globals.manager != NULL) {
        zwp_virtual_keyboard_manager_v1_destroy(globals.manager);
    }
    if (globals.seat != NULL) {
        wl_seat_destroy(globals.seat);
    }
    if (registry != NULL) {
        wl_registry_destroy(registry);
    }
    if (display != NULL) {
        wl_display_disconnect(display);
    }
    return status;
}
