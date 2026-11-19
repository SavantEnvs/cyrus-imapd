/* HTTP/1.1 message reading (imap/http_client.c): http_read_headers + http_read_body
 * (framing, Content-Length, chunked transfer coding incl. chunk extensions, content
 * decoding), as httpd and the backend proxy read requests/responses off the wire.
 * First byte selects request vs response body flags. */
#include <config.h>
#include <stdlib.h>
#include <string.h>

#include "imap/http_client.h"
#include "imap/spool.h"
#include "lib/prot.h"
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
    unsigned char mode = data[0];
    data++; size--;

    struct protstream *pin = prot_readmap((const char *)data, size);
    hdrcache_t hdrs = NULL;
    const char *err = NULL;
    if (!http_read_headers(pin, 1, &hdrs, &err) && hdrs) {
        struct body_t body;
        memset(&body, 0, sizeof(body));
        if (mode & 1) body.flags |= BODY_RESPONSE;
        if (mode & 2) body.flags |= BODY_DECODE;
        if (mode & 4) body.flags |= BODY_CLOSE;
        body.max = 1 << 20;
        http_read_body(pin, hdrs, &body, &err);
        buf_free(&body.payload);
    }
    if (hdrs) spool_free_hdrcache(hdrs);
    prot_free(pin);

    /* the chunk-size line parser on its own */
    char *line = fuzz_cstr(data, size);
    uint64_t chunk;
    http_parse_chunk_size(line, &chunk);
    free(line);
    return 0;
}
