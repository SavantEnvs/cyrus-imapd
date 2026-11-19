/* VPATCH application (imap/ical_support.c icalcomponent_apply_vpatch), the CalDAV PATCH
 * path, mirroring imap/ical_apply_patch.c: the input is a VCALENDAR resource and a
 * VPATCH document separated by a NUL byte; both are parsed with libical. */
#include <config.h>
#include <stdlib.h>
#include <string.h>

#include <libical/ical.h>

#include "imap/ical_support.h"
#include "lib/util.h"

#include "fuzz_common.h"

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc; (void)argv;
    fuzz_config_init(NULL);
    ical_support_init();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    const uint8_t *sep = memchr(data, '\0', size);
    if (!sep) return -1;   /* the harness's own input framing: <resource> NUL <vpatch> */

    char *res_s = fuzz_cstr(data, sep - data);
    char *patch_s = fuzz_cstr(sep + 1, size - (sep + 1 - data));

    struct buf b = BUF_INITIALIZER;
    buf_init_ro_cstr(&b, res_s);
    icalcomponent *resource = ical_string_as_icalcomponent(&b);
    buf_init_ro_cstr(&b, patch_s);
    icalcomponent *patch = ical_string_as_icalcomponent(&b);
    if (resource && patch) {
        int num_changes = 0;
        const char *err = NULL;
        /* a PATCH body is a VCALENDAR wrapping the VPATCH; the VPATCH itself is applied
         * (cunit/ical_support.testc, imap/caldav_util.c) */
        icalcomponent *vpatch = patch;
        if (icalcomponent_isa(patch) == ICAL_VCALENDAR_COMPONENT)
            vpatch = icalcomponent_get_first_real_component(patch);
        if (vpatch) icalcomponent_apply_vpatch(resource, vpatch, &num_changes, &err);
        char *out = icalcomponent_as_ical_string_r(resource);
        free(out);
    }
    if (resource) icalcomponent_free(resource);
    if (patch) icalcomponent_free(patch);
    free(res_s);
    free(patch_s);
    return 0;
}
