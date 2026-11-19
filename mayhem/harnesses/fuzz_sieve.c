/* Sieve script compiler (sieve/: sieve.y grammar, sieve-lex.l, addr.y, tree building,
 * bytecode generation/emission), as timsieved PUTSCRIPT and sievec compile untrusted
 * user scripts; the emitted bytecode is then loaded back with sieve_script_load. */
#include <config.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sieve/sieve_interface.h"
#include "lib/util.h"

#include "fuzz_common.h"

static sieve_interp_t *interp;
static char bc_path[4096];

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc; (void)argv;
    fuzz_config_init(NULL);
    interp = sieve_build_nonexec_interp();
    if (!interp) abort();
    snprintf(bc_path, sizeof(bc_path), "%s/script.bc", fuzz_tmpdir());
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *s = fuzz_cstr(data, size);
    char *errors = NULL;
    sieve_script_t *script = NULL;

    if (sieve_script_parse_string(interp, s, &errors, &script) == SIEVE_OK && script) {
        bytecode_info_t *bc = NULL;
        if (sieve_generate_bytecode(&bc, script) != -1) {
            int fd = open(bc_path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
            if (fd >= 0) {
                int r = sieve_emit_bytecode(fd, bc);
                close(fd);
                if (r != -1) {
                    sieve_execute_t *exe = NULL;
                    if (sieve_script_load(bc_path, &exe) == SIEVE_OK)
                        sieve_script_unload(&exe);
                }
            }
        }
        sieve_free_bytecode(&bc);
    }
    sieve_script_free(&script);
    free(errors);
    free(s);
    return 0;
}
