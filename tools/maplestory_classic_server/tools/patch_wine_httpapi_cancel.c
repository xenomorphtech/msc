#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Patch Wine's x86-64 HttpCancelHttpRequest unimplemented-export stub into a
 * successful no-op.  This is deliberately narrow: the target bytes must match
 * the Wine 10.12 stub exactly, and a sibling .pre-cancel-patch backup is made
 * before the first write.
 */

static const long patch_offset = 0x1018;
static const uint8_t expected[] = {
    0x48, 0x83, 0xec, 0x28, 0x48, 0x8d, 0x0d, 0xdd,
    0x4f, 0x00, 0x00, 0x48, 0x8d, 0x15, 0xf9, 0x4f,
    0x00, 0x00, 0xe8, 0x01, 0x2e, 0x00, 0x00, 0x90,
};
static const uint8_t replacement[] = {
    0x31, 0xc0, 0xc3, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
};

static void fail(const char *message)
{
    fprintf(stderr, "%s: %s\n", message, strerror(errno));
    exit(EXIT_FAILURE);
}

static void copy_file(const char *source, const char *destination)
{
    FILE *input = fopen(source, "rb");
    if (!input)
        fail("open source backup");
    FILE *output = fopen(destination, "wbx");
    if (!output) {
        if (errno == EEXIST) {
            fclose(input);
            return;
        }
        fail("create backup");
    }

    uint8_t buffer[65536];
    size_t count;
    while ((count = fread(buffer, 1, sizeof(buffer), input)) != 0) {
        if (fwrite(buffer, 1, count, output) != count)
            fail("write backup");
    }
    if (ferror(input) || fclose(input) != 0 || fclose(output) != 0)
        fail("finish backup");
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s PATH_TO_HTTPAPI_DLL\n", argv[0]);
        return EXIT_FAILURE;
    }

    size_t backup_length = strlen(argv[1]) + sizeof(".pre-cancel-patch");
    char *backup = malloc(backup_length);
    if (!backup)
        fail("allocate backup path");
    snprintf(backup, backup_length, "%s.pre-cancel-patch", argv[1]);

    FILE *file = fopen(argv[1], "r+b");
    if (!file)
        fail("open target");
    if (fseek(file, patch_offset, SEEK_SET) != 0)
        fail("seek target");

    uint8_t actual[sizeof(expected)];
    if (fread(actual, 1, sizeof(actual), file) != sizeof(actual))
        fail("read target bytes");
    if (memcmp(actual, replacement, sizeof(actual)) == 0) {
        puts("HttpCancelHttpRequest stub is already patched");
        fclose(file);
        free(backup);
        return EXIT_SUCCESS;
    }
    if (memcmp(actual, expected, sizeof(actual)) != 0) {
        fprintf(stderr, "refusing to patch: target stub bytes do not match\n");
        fclose(file);
        free(backup);
        return EXIT_FAILURE;
    }

    fclose(file);
    copy_file(argv[1], backup);
    file = fopen(argv[1], "r+b");
    if (!file)
        fail("reopen target");
    if (fseek(file, patch_offset, SEEK_SET) != 0)
        fail("seek patch offset");
    if (fwrite(replacement, 1, sizeof(replacement), file) != sizeof(replacement))
        fail("write replacement");
    if (fclose(file) != 0)
        fail("finish target");

    puts("patched HttpCancelHttpRequest to return success");
    free(backup);
    return EXIT_SUCCESS;
}
