/* vCard parsing for CardDAV PUT bodies (imap/vcard_support.c vcard_parse_string over
 * libicalvcard), serialised back and with every property value decoded. */
#include <config.h>
#include <stdlib.h>

#include <libical/vcard.h>

#include "imap/vcard_support.h"
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
    char *s = fuzz_cstr(data, size);
    vcardcomponent *card = vcard_parse_string(s);
    if (card) {
        struct buf *out = vcard_as_buf(card);
        if (out) { buf_free(out); free(out); }
        for (vcardproperty *p = vcardcomponent_get_first_property(card, VCARD_ANY_PROPERTY);
             p; p = vcardcomponent_get_next_property(card, VCARD_ANY_PROPERTY)) {
            struct buf v = BUF_INITIALIZER;
            char *ctype = NULL;
            struct message_guid guid;
            vcard_prop_decode_value(p, &v, &ctype, &guid);
            free(ctype);
            buf_free(&v);
        }
        vcardcomponent_free(card);
    }
    free(s);
    return 0;
}
