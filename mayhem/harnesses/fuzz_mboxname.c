/* IMAP client mailbox names (imap/mboxname.c): every mailbox argument imapd receives goes
 * through mboxname_from_external()/mbname_from_extname() (modified UTF-7 decoding, hierarchy
 * separator and virtual-domain mapping, namespace prefixes), and CREATE/RENAME then apply
 * mboxname_policycheck(). The result is converted back with mboxname_to_external(), as
 * LIST/STATUS replies do.
 *
 * Byte 0 picks the namespace (user / admin / UTF-8 names), the authenticated userid and the
 * policy flags; the rest is the client's mailbox name. The namespaces are built once from a
 * fixed config (unixhierarchysep + altnamespace + virtdomains) and only read afterwards. */
#include <config.h>
#include <stdlib.h>
#include <string.h>

#include "imap/mboxname.h"
#include "lib/util.h"

#include "fuzz_common.h"

static struct namespace ns[3];
/* imapd always passes the authenticated user (imapd_userid); a NULL userid is for the admin
 * tools, and mboxlist_find_specialuse() asserts it is set. */
static const char *const userids[] = { "fred", "fred@example.com", "bob@example.org", "anonymous" };

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc; (void)argv;
    fuzz_config_init("unixhierarchysep: yes\naltnamespace: yes\nvirtdomains: userid\n"
                     "defaultdomain: example.org\n");
    if (mboxname_init_namespace(&ns[0], 0)) abort();
    if (mboxname_init_namespace(&ns[1], NAMESPACE_OPTION_ADMIN)) abort();
    if (mboxname_init_namespace(&ns[2], NAMESPACE_OPTION_UTF8)) abort();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1) return -1;
    unsigned char sel = data[0];
    const struct namespace *n = &ns[(sel & 3) % 3];
    const char *userid = userids[(sel >> 2) & 3];
    int flags = (sel >> 4) & (MBOXNAME_POLICY_SKIP_IDENTITY | MBOXNAME_POLICY_UNDER_DOMAIN);
    char *s = fuzz_cstr(data + 1, size - 1);

    char *intname = mboxname_from_external(s, n, userid);
    if (intname) {
        mboxname_policycheck(intname, flags);
        char *ext = mboxname_to_external(intname, n, userid);
        free(ext);

        mbname_t *mb = mbname_from_intname(intname);
        if (mb) {
            mbname_extname(mb, n, userid);
            mbname_free(&mb);
        }
        free(intname);
    }

    mbname_t *mb = mbname_from_extname(s, n, userid);
    if (mb) {
        const char *iname = mbname_intname(mb);
        if (iname) mboxname_policycheck(iname, flags);
        mbname_free(&mb);
    }

    free(s);
    return 0;
}
