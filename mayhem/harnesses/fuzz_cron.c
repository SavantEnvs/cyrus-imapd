/* cron spec parser (lib/cron-parse.y, lib/cron-lex.l): cyrus.conf EVENTS schedules. */
#include <config.h>
#include <stdlib.h>

#include "lib/cron.h"
#include "lib/util.h"

#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *s = fuzz_cstr(data, size);
    struct cron_spec spec;
    const char *err = NULL;
    if (!cron_parse_spec(s, &spec, &err)) {
        struct buf out = BUF_INITIALIZER;
        cron_spec_dump(&out, &spec);
        buf_free(&out);
    }
    free(s);
    return 0;
}
