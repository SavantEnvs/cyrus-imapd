/* Date/time parsers (lib/times.c): RFC 5322/822 Date headers, RFC 3501 IMAP date-time
 * arguments and ISO 8601 (JMAP/CalDAV), each formatted back on success. */
#include <config.h>
#include <stdlib.h>
#include <time.h>

#include "lib/times.h"

#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *s = fuzz_cstr(data, size);
    char out[128];
    time_t t;
    struct offsettime ot;

    if (time_from_rfc5322(s, &t, DATETIME_FULL) != -1) time_to_rfc5322(t, out, sizeof(out));
    if (time_from_rfc5322(s, &t, DATETIME_DATE_ONLY) != -1) time_to_rfc5322(t, out, sizeof(out));
    if (offsettime_from_rfc5322(s, &ot, DATETIME_FULL) != -1) offsettime_to_rfc5322(&ot, out, sizeof(out));
    if (time_from_rfc822(s, &t) != -1) time_to_rfc822(t, out, sizeof(out));
    if (time_from_rfc3501(s, &t) != -1) time_to_rfc3501(t, out, sizeof(out));
    if (time_from_iso8601(s, &t) != -1) time_to_iso8601(t, out, sizeof(out), 1);
    if (offsettime_from_iso8601(s, &ot) != -1) offsettime_to_iso8601(&ot, out, sizeof(out), 1);
    free(s);
    return 0;
}
