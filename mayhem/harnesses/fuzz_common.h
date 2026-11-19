/* Shared setup for the cyrus-imapd libFuzzer harnesses (mayhem/ layer, not upstream code). */
#ifndef MAYHEM_FUZZ_COMMON_H
#define MAYHEM_FUZZ_COMMON_H

#include <stddef.h>
#include <stdint.h>

/* NUL-terminated heap copy of the fuzz input (caller frees). */
char *fuzz_cstr(const uint8_t *data, size_t size);

/* Load a minimal imapd.conf (configdirectory + partition-default under a private
 * mkdtemp() directory in $TMPDIR), as every cyrus tool does before using the libraries.
 * 'extra' is appended verbatim (may be NULL). Call once, from LLVMFuzzerInitialize. */
void fuzz_config_init(const char *extra);

/* The private scratch directory created by fuzz_config_init() (or created on demand). */
const char *fuzz_tmpdir(void);

#endif
