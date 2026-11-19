/* File-input driver for the AFL targets: runs the harness once on the file named by argv[1]
 * (Mayhemfile `@@`). The harness is compiled with its libFuzzer entry points renamed to
 * fuzz_initialize/fuzz_one_input (build.sh), so the binary is a plain AFL program. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int fuzz_initialize(int *argc, char ***argv);
int fuzz_one_input(const uint8_t *data, size_t size);

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <input file>\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror(argv[1]); return 2; }
    size_t cap = 4096, len = 0;
    uint8_t *buf = malloc(cap);
    size_t n;
    while (buf && (n = fread(buf + len, 1, cap - len, f)) > 0) {
        len += n;
        if (len == cap) buf = realloc(buf, cap *= 2);
    }
    fclose(f);
    if (!buf) abort();
    fuzz_initialize(&argc, &argv);
    fuzz_one_input(buf, len);
    free(buf);
    return 0;
}
