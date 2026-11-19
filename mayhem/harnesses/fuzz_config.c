/* imapd.conf parser (lib/libconfig.c config_read), and the value parsers it applies
 * (config_parseduration / config_parsebytesize). The input is written to a scratch
 * file after a fixed configdirectory line (config_read requires one) and read back;
 * the config is reset after every input. */
#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "lib/libconfig.h"
#include "lib/util.h"

#include "fuzz_common.h"

static char conf_path[4096];
static char dir_line[4200];

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc; (void)argv;
    const char *dir = fuzz_tmpdir();
    snprintf(conf_path, sizeof(conf_path), "%s/imapd.conf", dir);
    snprintf(dir_line, sizeof(dir_line), "configdirectory: %s\n", dir);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FILE *f = fopen(conf_path, "w");
    if (!f) abort();
    fputs(dir_line, f);
    fwrite(data, 1, size, f);
    fclose(f);

    struct buf err = BUF_INITIALIZER;
    config_reset();
    config_read(conf_path, 0, &err);
    config_reset();
    buf_free(&err);

    char *s = fuzz_cstr(data, size);
    int32_t dur;
    int64_t bytes;
    config_parseduration(s, 's', &dur);
    config_parseduration(s, 'd', &dur);
    config_parsebytesize(s, 'K', &bytes);
    free(s);
    return 0;
}
