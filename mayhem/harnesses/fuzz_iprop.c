/*
 * fuzz_iprop.c - fuzzing harness for the replica side of incremental propagation.
 *
 * kpropd (iprop mode) receives a kdb_incr_result_t over XDR from the primary and ulog_replay()
 * converts each committed update into a database entry with ulog_conv_2dbentry(). This harness
 * decodes the input as that XDR message and runs the same conversion on every committed,
 * non-deletion update, against an open (empty) principal database. Entries are never stored, so
 * every input starts from the same state.
 */

#include "k5-int.h"
#include "kdb_log.h"
#include <gssrpc/rpc.h>
#include <ftw.h>

static krb5_context ctx;
static char tmpdir[PATH_MAX];

static int
remove_cb(const char *path, const struct stat *sb, int type, struct FTW *ftw)
{
    return remove(path);
}

static void
cleanup(void)
{
    if (ctx != NULL)
        krb5_db_fini(ctx);
    nftw(tmpdir, remove_cb, 16, FTW_DEPTH | FTW_PHYS);
}

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
    const char *base = getenv("TMPDIR");
    char conf[PATH_MAX];
    FILE *f;

    if (base == NULL || *base == '\0')
        base = "/tmp";
    snprintf(tmpdir, sizeof(tmpdir), "%s/fuzz_iprop.XXXXXX", base);
    if (mkdtemp(tmpdir) == NULL)
        abort();
    snprintf(conf, sizeof(conf), "%s/krb5.conf", tmpdir);
    f = fopen(conf, "w");
    if (f == NULL)
        abort();
    fprintf(f, "[libdefaults]\n\tdefault_realm = FUZZ.TEST\n"
            "[realms]\n\tFUZZ.TEST = {\n\t\tdatabase_name = %s/principal\n\t}\n"
            "[dbmodules]\n\tFUZZ.TEST = {\n\t\tdatabase_name = %s/principal\n\t}\n",
            tmpdir, tmpdir);
    fclose(f);
    setenv("KRB5_CONFIG", conf, 1);
    setenv("KRB5_KDC_PROFILE", conf, 1);

    atexit(cleanup);
    if (krb5_init_context(&ctx) != 0)
        abort();
    if (krb5_db_create(ctx, NULL) != 0)
        abort();
    return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    XDR xdrs;
    kdb_incr_result_t res;
    kdb_incr_update_t *upd;
    krb5_db_entry *ent;
    krb5_error_code ret = 0;
    unsigned int i;
    bool_t ok;

    memset(&res, 0, sizeof(res));
    xdrmem_create(&xdrs, (char *)data, size, XDR_DECODE);
    ok = xdr_kdb_incr_result_t(&xdrs, &res);
    xdr_destroy(&xdrs);
    if (!ok) {
        xdr_free((xdrproc_t)xdr_kdb_incr_result_t, (char *)&res);
        return -1;
    }

    for (i = 0; i < res.updates.kdb_ulog_t_len && ret == 0; i++) {
        upd = &res.updates.kdb_ulog_t_val[i];
        if (!upd->kdb_commit || upd->kdb_deleted)
            continue;
        ent = NULL;
        ret = ulog_conv_2dbentry(ctx, &ent, upd);
        krb5_db_free_principal(ctx, ent);
    }

    xdr_free((xdrproc_t)xdr_kdb_incr_result_t, (char *)&res);
    return 0;
}
