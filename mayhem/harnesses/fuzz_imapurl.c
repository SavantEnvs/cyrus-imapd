/* IMAP URL parsing (lib/imapurl.c, RFC 5092 URLAUTH/CATENATE/BURL) with modified-UTF-7
 * mailbox conversion, plus sequence-set parsing (lib/seqset.c) of FETCH/STORE/UID set
 * arguments. Byte 0 selects which. */
#include <config.h>
#include <stdlib.h>
#include <string.h>

#include "lib/imapurl.h"
#include "lib/imparse.h"
#include "lib/seqset.h"
#include "lib/util.h"

#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1) return -1;
    unsigned char mode = data[0];
    char *s = fuzz_cstr(data + 1, size - 1);

    if (mode & 1) {
        struct imapurl url;
        memset(&url, 0, sizeof(url));
        if (!imapurl_fromURL(&url, s)) {
            struct buf out = BUF_INITIALIZER;
            imapurl_toURL(&out, &url);
            buf_free(&out);
        }
        free(url.freeme);
    }
    else if (imparse_issequence(s)) {
        /* seqset_parse() fatal()s on malformed sets by contract: every caller (imapd FETCH/
         * STORE/COPY/..., imap/imapd.c) validates the argument with imparse_issequence()
         * first, so the harness does the same and also fuzzes that validator. */
        seqset_t *set = seqset_parse(s, NULL, (mode >> 1) ? (mode >> 1) * 1000u : 0);
        if (set) {
            free(seqset_cstring(set));
            seqset_ismember(set, 1);
            seqset_free(&set);
        }
    }
    free(s);
    return 0;
}
