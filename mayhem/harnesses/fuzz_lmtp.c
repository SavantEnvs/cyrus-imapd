/* LMTP server session (imap/lmtpengine.c, lmtpmode()): the command loop lmtpd runs on every
 * connection. The input is the client's side of the conversation (LHLO, MAIL FROM with its
 * SIZE/BODY/AUTH/SMTPUTF8 parameters, RCPT TO with address and ORCPT/NOTIFY parsing, DATA with
 * dot-unstuffing, header parsing and spooling, RSET, AUTH, ...). Replies go to /dev/null.
 *
 * The callbacks stand in for lmtpd's (imap/lmtpd.c): every recipient is accepted, delivery
 * reads the parsed envelope and headers back and reports success per recipient, the spool is
 * a file in the private scratch directory, and shutdown exits like lmtpd's shut_down(). The
 * session is pre-authenticated, as lmtpd is on its UNIX socket.
 *
 * File-input (AFL) target: lmtpmode() ends the session through the shutdown callback (exit)
 * and fatal(..., EX_PROTOCOL) on protocol violations, as the daemon does. */
#include <config.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "imap/global.h"
#include "imap/lmtpengine.h"
#include "imap/mboxname.h"
#include "lib/prot.h"
#include "lib/util.h"

#include "fuzz_common.h"

int deliver_logfd = -1; /* used by lmtpengine.c; lmtpd defines it */

static struct namespace ns;

static int fz_deliver(message_data_t *m, char *authuser, const struct auth_state *authstate,
                      const struct namespace *n)
{
    (void)authuser; (void)authstate; (void)n;
    const char **h;
    if ((h = msg_getheader(m, "subject"))) (void)strlen(h[0]);
    if ((h = msg_getheader(m, "message-id"))) (void)strlen(h[0]);
    (void)msg_getsize(m);
    for (int i = 0; i < msg_getnumrcpt(m); i++) {
        const mbname_t *mb = msg_getrcpt(m, i);
        if (mb && mbname_intname(mb)) (void)strlen(mbname_intname(mb));
        const char *all = msg_getrcptall(m, i);
        if (all) (void)strlen(all);
        msg_setrcpt_status(m, i, 0, NULL);
    }
    return 0;
}

static int fz_verify_user(const mbname_t *mbname, quota_t qs, quota_t qm,
                          struct auth_state *authstate)
{
    (void)mbname; (void)qs; (void)qm; (void)authstate;
    return 0;
}

static void fz_shutdown(int code)
{
    exit(code);
}

static FILE *fz_spoolfile(message_data_t *m)
{
    (void)m;
    char path[4096];
    snprintf(path, sizeof(path), "%s/spool-XXXXXX", fuzz_tmpdir());
    int fd = mkstemp(path);
    if (fd < 0) return NULL;
    unlink(path);
    return fdopen(fd, "w+");
}

static void fz_removespool(message_data_t *m)
{
    (void)m;
}

static struct lmtp_func fz_lmtp = { &fz_deliver, &fz_verify_user, &fz_shutdown,
                                    &fz_spoolfile, &fz_removespool, &ns, NULL, 1, 1 };

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc; (void)argv;
    fuzz_config_init(NULL);
    if (mboxname_init_namespace(&ns, NAMESPACE_OPTION_ADMIN)) abort();
    global_sasl_init(1, 1, NULL);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char path[4096];
    snprintf(path, sizeof(path), "%s/session-XXXXXX", fuzz_tmpdir());
    int in = mkstemp(path);
    if (in < 0) abort();
    unlink(path);
    if (size && write(in, data, size) != (ssize_t)size) abort();
    lseek(in, 0, SEEK_SET);
    int out = open("/dev/null", O_WRONLY);
    if (out < 0) abort();

    struct protstream *pin = prot_new(in, 0);
    struct protstream *pout = prot_new(out, 1);
    prot_setflushonread(pin, pout);

    lmtpmode(&fz_lmtp, pin, pout, in);

    prot_free(pin);
    prot_free(pout);
    close(in);
    close(out);
    return 0;
}
