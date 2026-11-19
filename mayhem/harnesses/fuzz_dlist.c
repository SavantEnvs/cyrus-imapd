/* dlist wire format (imap/dlist.c): the replication protocol (sync_server/sync_client)
 * and stored annotation/mailbox records. First byte selects parsekeys. */
#include <config.h>
#include <stdlib.h>

#include "imap/dlist.h"
#include "lib/util.h"

#include "fuzz_common.h"

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc; (void)argv;
    fuzz_config_init(NULL);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1) return -1;
    int parsekeys = data[0] & 1;
    struct dlist *dl = NULL;
    if (!dlist_parsemap(&dl, parsekeys, (const char *)data + 1, size - 1) && dl) {
        struct buf out = BUF_INITIALIZER;
        dlist_printbuf(dl, parsekeys, &out);
        buf_free(&out);
    }
    dlist_free(&dl);
    return 0;
}
