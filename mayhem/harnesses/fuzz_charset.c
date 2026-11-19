/* Character-set layer (lib/charset.c): RFC 2047 encoded-word header decoding, RFC 2231
 * parameter values, charset conversion (ICU + built-in tables) with QP/base64 transfer
 * decoding, and search-form canonicalisation, applied to every header and body part.
 * Byte 0 picks the charset, byte 1 the transfer encoding and flags. */
#include <config.h>
#include <stdlib.h>
#include <string.h>

#include "lib/charset.h"
#include "lib/util.h"

#include "fuzz_common.h"

static const char *charsets[] = {
    "us-ascii", "utf-8", "iso-8859-1", "iso-8859-2", "windows-1252", "koi8-r",
    "iso-2022-jp", "shift_jis", "euc-jp", "gb2312", "big5", "utf-7", "imap-mailbox-name",
    "utf-16", "euc-kr", "x-unknown",
};

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc; (void)argv;
    fuzz_config_init(NULL);
    charset_lib_init();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 2) return -1;
    const char *csname = charsets[data[0] % (sizeof(charsets)/sizeof(charsets[0]))];
    int encoding = (data[1] & 3) == 3 ? ENCODING_BASE64URL : (data[1] & 3);
    int flags = (data[1] & 0x80) ? (CHARSET_SKIPDIACRIT|CHARSET_MERGESPACE|CHARSET_SKIPHTML) : 0;
    data += 2; size -= 2;

    char *s = fuzz_cstr(data, size);
    free(charset_decode_mimeheader(s, flags));
    free(charset_parse_mimeheader(s, flags | CHARSET_MIME_UTF8));
    struct buf lang = BUF_INITIALIZER;
    free(charset_parse_mimexvalue(s, &lang));
    buf_free(&lang);
    free(charset_utf8_to_searchform(s, flags));
    free(charset_unfold(s, size, CHARSET_UNFOLD_SKIPWS));

    charset_t cs = charset_lookupname(csname);
    if (cs) {
        struct buf dst = BUF_INITIALIZER;
        charset_to_utf8(&dst, (const char *)data, size, cs, encoding);
        buf_free(&dst);
        charset_free(&cs);
    }
    struct buf dec = BUF_INITIALIZER;
    charset_decode(&dec, (const char *)data, size, encoding);
    buf_free(&dec);
    free(s);
    return 0;
}
