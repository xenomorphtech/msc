/* Binary test protocol: operation:u8, length:u32, iv:u32, payload[length].
 * Operations: AES block (48-byte key+block), shuffle, additive separate/in-place,
 * full packet AES OFB. This adapter is handwritten; bodies remain unchanged. */
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

static void cw_packet(unsigned char *output, const unsigned char *input, size_t length, uint iv) {
    uint key[32] = {0}, context[65] = {0};
    static const byte key_bytes[8] = {15, 27, 197, 70, 243, 190, 255, 117};
    for (int i = 0; i < 8; i++) key[i * 4] = key_bytes[i];
    FUN_140cc1970(key, context + 1);
    size_t offset = 0, chunk = length <= 0xff00 ? 0x5b0 : 0x5ac;
    while (offset < length) {
        size_t end = offset + chunk < length ? offset + chunk : length;
        uint block[4] = {iv, iv, iv, iv};
        for (size_t pos = offset; pos < end; pos += 16) {
            FUN_140cc1af0((longlong)(intptr_t)context, block);
            const byte *stream = (const byte *)block;
            for (size_t j = 0; j < 16 && pos + j < end; j++) output[pos + j] = input[pos + j] ^ stream[j];
        }
        offset = end; chunk = 0x5b4;
    }
}

int main(void) {
#ifdef _WIN32
    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);
#endif
    for (;;) {
        unsigned char header[9];
        size_t got = fread(header, 1, sizeof(header), stdin);
        if (!got && !ferror(stdin)) return 0;
        if (got != sizeof(header)) return 2;
        uint length, iv;
        memcpy(&length, header + 1, 4); memcpy(&iv, header + 5, 4);
        if (length > 4 * 1024 * 1024) return 3;
        unsigned char *input = malloc((size_t)length + 16), *output = malloc((size_t)length + 16);
        if (!input || !output) return 4;
        if (fread(input, 1, length, stdin) != length) return 5;
        uint result_length = length;
        if (header[0] == 0) {
            if (length != 48) return 6;
            uint key[32] = {0}, context[65] = {0}, block[4];
            for (int i = 0; i < 8; i++) memcpy(&key[i * 4], input + i * 4, 4);
            memcpy(block, input + 32, 16);
            FUN_140cc1970(key, context + 1);
            FUN_140cc1af0((longlong)(intptr_t)context, block);
            memcpy(output, block, 16); result_length = 16;
        } else if (header[0] == 1) {
            FUN_140cc3f30((longlong)(intptr_t)input, (int)length, &iv);
            memcpy(output, &iv, 4); result_length = 4;
        } else if (header[0] == 2 || header[0] == 3) {
            if (header[0] == 3) memcpy(output, input, length);
            FUN_1407475e0((ulonglong)(uintptr_t)output,
                         (ulonglong)(uintptr_t)(header[0] == 3 ? output : input), length, (char *)&iv, 1);
        } else if (header[0] == 4) {
            cw_packet(output, input, length, iv);
        } else return 7;
        if (fwrite(output, 1, result_length, stdout) != result_length) return 8;
        free(input); free(output);
    }
}
