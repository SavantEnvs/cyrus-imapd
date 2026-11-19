/* RFC 5322 / MIME message parser: message_parse_mapped() (the parser lmtpd/append/
 * reconstruct run on every delivered message) and the message_t accessors
 * (message_new_from_data, as imap/message_test.c and the JMAP/Sieve layers use it). */
#include <config.h>
#include <stdlib.h>
#include <string.h>

#include "imap/message.h"
#include "lib/charset.h"
#include "lib/util.h"

#include "fuzz_common.h"

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc; (void)argv;
    fuzz_config_init(NULL);
    charset_lib_init();
    return 0;
}

static int section_cb(int isbody, charset_t charset, int encoding,
                      const char *type, const char *subtype,
                      const struct param *type_params,
                      const char *disposition,
                      const struct param *disposition_params,
                      const struct message_guid *content_guid,
                      const char *part, struct buf *data, void *rock)
{
    (void)isbody; (void)type; (void)subtype; (void)type_params; (void)disposition;
    (void)disposition_params; (void)content_guid; (void)part; (void)rock;
    struct buf out = BUF_INITIALIZER;
    charset_to_utf8(&out, buf_base(data), buf_len(data), charset, encoding);
    buf_free(&out);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* message_parse_mapped: the full body-structure parse */
    struct body body;
    memset(&body, 0, sizeof(body));
    if (!message_parse_mapped((const char *)data, size, &body, NULL)) {
        struct buf bs = BUF_INITIALIZER;
        message_write_body(&bs, &body, 1);
        message_write_body(&bs, &body, 0);
        buf_free(&bs);
    }
    message_free_body(&body);

    /* message_t accessors over the same bytes */
    message_t *m = message_new_from_data((const char *)data, size);
    struct buf buf = BUF_INITIALIZER;
    static const char *fields[] = { "From", "To", "Subject", "Content-Type",
                                    "Message-ID", "References", "Date", NULL };
    for (int i = 0; fields[i]; i++) {
        message_get_field(m, fields[i], MESSAGE_DECODED, &buf); buf_reset(&buf);
        message_get_field(m, fields[i], MESSAGE_SEARCH, &buf); buf_reset(&buf);
        message_get_field(m, fields[i], MESSAGE_SNIPPET|MESSAGE_MULTIPLE, &buf); buf_reset(&buf);
    }
    message_get_from(m, &buf); buf_reset(&buf);
    message_get_to(m, &buf); buf_reset(&buf);
    message_get_cc(m, &buf); buf_reset(&buf);
    message_get_subject(m, &buf); buf_reset(&buf);
    message_get_messageid(m, &buf); buf_reset(&buf);
    message_get_inreplyto(m, &buf); buf_reset(&buf);
    message_get_references(m, &buf); buf_reset(&buf);
    message_get_listid(m, &buf); buf_reset(&buf);
    message_get_mailinglist(m, &buf); buf_reset(&buf);
    message_get_priority(m, &buf); buf_reset(&buf);
    time_t t;
    message_get_sentdate(m, &t);
    message_foreach_section(m, section_cb, NULL);
    buf_free(&buf);
    message_unref(&m);
    return 0;
}
