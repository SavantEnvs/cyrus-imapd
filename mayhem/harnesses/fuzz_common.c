/* Shared setup for the cyrus-imapd libFuzzer harnesses (mayhem/ layer, not upstream code). */
#include <config.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <ftw.h>

#include "lib/libconfig.h"
#include "lib/libcyr_cfg.h"
#include "lib/util.h"
#include "lib/xmalloc.h"

#include "fuzz_common.h"

#include <sysexits.h>

#ifndef FUZZ_PROTOCOL_EXIT
#define FUZZ_PROTOCOL_EXIT 0
#endif

/* Every cyrus program supplies fatal(); the libraries call it on internal invariant
 * failures (cyrus's assert() lands here too). A fatal reached from fuzz input is a
 * finding, so it aborts with the message, like sievec's fatal() under
 * `config_fatals_abort`. The one exception is EX_PROTOCOL, the code the protocol
 * parsers use to drop a client that sent an oversized literal or number: in the
 * file-input (AFL) protocol targets that exits like the daemon does (sieve/sievec.c). */
void fatal(const char *s, int code)
{
    fprintf(stderr, "Fatal error: %s (%d)\n", s ? s : "(null)", code);
    if (FUZZ_PROTOCOL_EXIT && code == EX_PROTOCOL) exit(code);
    abort();
}

char *fuzz_cstr(const uint8_t *data, size_t size)
{
    char *s = malloc(size + 1);
    if (!s) abort();
    memcpy(s, data, size);
    s[size] = '\0';
    return s;
}

static char *tmpdir;

static int rm_entry(const char *path, const struct stat *sb, int flag, struct FTW *ftw)
{
    (void)sb; (void)flag; (void)ftw;
    return remove(path);
}

/* A process-per-input (AFL) target removes its scratch directory when it exits. */
static void rm_tmpdir(void)
{
    if (tmpdir) nftw(tmpdir, rm_entry, 16, FTW_DEPTH | FTW_PHYS);
}

const char *fuzz_tmpdir(void)
{
    if (!tmpdir) {
        const char *t = getenv("TMPDIR");
        if (!t || !*t) t = "/tmp";
        size_t n = strlen(t) + 32;
        tmpdir = malloc(n);
        snprintf(tmpdir, n, "%s/cyrus-fuzz-XXXXXX", t);
        if (!mkdtemp(tmpdir)) { perror("mkdtemp"); abort(); }
        if (FUZZ_PROTOCOL_EXIT) atexit(rm_tmpdir);
    }
    return tmpdir;
}

void fuzz_config_init(const char *extra)
{
    const char *dir = fuzz_tmpdir();
    char conf[4096], part[4096];
    snprintf(conf, sizeof(conf), "%s/imapd.conf", dir);
    snprintf(part, sizeof(part), "%s/partition", dir);
    mkdir(part, 0700);

    FILE *f = fopen(conf, "w");
    if (!f) { perror("fopen imapd.conf"); abort(); }
    fprintf(f, "configdirectory: %s\npartition-default: %s\n%s", dir, part, extra ? extra : "");
    fclose(f);

    struct buf err = BUF_INITIALIZER;
    if (config_read(conf, 0, &err)) {
        fprintf(stderr, "config_read: %s\n", buf_cstring(&err));
        abort();
    }
    buf_free(&err);
    libcyrus_config_setstring(CYRUSOPT_CONFIG_DIR, config_dir);
}
