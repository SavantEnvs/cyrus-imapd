/* RFC 5322 address-list parser (lib/parseaddr.c), applied to From/To/Cc headers,
 * LMTP/SMTP envelope addresses and Sieve address tests. */
#include <config.h>
#include <stdlib.h>

#include "lib/parseaddr.h"

#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *s = fuzz_cstr(data, size);
    struct address *list = NULL;
    parseaddr_list(s, &list);
    for (struct address *a = list; a; a = a->next) {
        free(address_get_all(a, 0));
        free(address_get_all(a, 1));
        free(address_get_localpart(a));
        free(address_get_domain(a, 1));
        free(address_get_user(a));
        free(address_get_detail(a));
    }
    parseaddr_free(list);
    free(address_canonicalise(s));
    free(s);
    return 0;
}
