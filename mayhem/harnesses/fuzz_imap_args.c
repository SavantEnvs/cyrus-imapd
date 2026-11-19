/* IMAP command-argument parsing (imap/imapparse.c), as imapd reads client commands off
 * the wire: first byte 0x00-0x7f reads a stream of atoms/quoted strings/literals/numbers
 * with getword/getxstring/getint*; 0x80-0xff parses a SEARCH program
 * (get_search_program -> search_expr tree, normalised and serialised). */
#include <config.h>
#include <stdlib.h>
#include <string.h>

#include "imap/imapparse.h"
#include "imap/index.h"
#include "imap/mboxname.h"
#include "imap/search_expr.h"
#include "lib/charset.h"
#include "lib/prot.h"
#include "lib/util.h"

#include "fuzz_common.h"

static struct namespace ns;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc; (void)argv;
    fuzz_config_init(NULL);
    charset_lib_init();
    search_attr_init();
    if (mboxname_init_namespace(&ns, 0)) abort();
    return 0;
}

static const enum getxstring_flags kinds[] = {
    IMAP_ASTRING, IMAP_BIN_ASTRING, IMAP_NSTRING, IMAP_BIN_NSTRING, IMAP_QSTRING,
    IMAP_STRING, IMAP_NASTRING, MUPDATE_STRING,
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1) return -1;
    unsigned char mode = data[0];
    data++; size--;

    struct buf out = BUF_INITIALIZER;
    struct protstream *pin = prot_readmap((const char *)data, size);
    struct protstream *pout = prot_writebuf(&out);

    if (mode & 0x80) {
        struct searchargs *sa = new_searchargs("A1", 0, &ns, "fred", NULL, 0);
        int c = get_search_program(pin, pout, mode & 0x7f, sa);
        /* RFC 5182 "$": get_search_program leaves each result variable's uid
         * match value NULL; every caller (index_search, imap/index.c) fills it
         * with the saved search result before using the tree.  Do the same. */
        for (int v = 0; v < ptrarray_size(&sa->result_vars); v++) {
            search_expr_t *e = ptrarray_nth(&sa->result_vars, v);
            e->value.s = xstrdup("1:*");
        }
        if (c != EOF && sa->root) {
            char *s = search_expr_serialise(sa->root);
            search_expr_normalise(&sa->root);
            char *s2 = search_expr_serialise(sa->root);
            free(s);
            free(s2);
        }
        freesearchargs(sa);
    }
    else {
        struct buf arg = BUF_INITIALIZER;
        unsigned i = mode;
        for (int n = 0; n < 64; n++, i++) {
            int c;
            switch (i % 5) {
            case 0: c = getword(pin, &arg); break;
            case 1: { int v; c = getint32(pin, &v); break; }
            case 2: { uint64_t v; c = getuint64(pin, &v); break; }
            case 3: { modseq_t v; c = getmodseq(pin, &v); break; }
            default:
                c = getxstring(pin, pout, &arg, kinds[(i / 5) % (sizeof(kinds)/sizeof(kinds[0]))]);
                break;
            }
            if (c == EOF) break;
        }
        buf_free(&arg);
    }

    prot_flush(pout);
    prot_free(pin);
    prot_free(pout);
    buf_free(&out);
    return 0;
}
