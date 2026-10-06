/* aggext.c -- the x_count aggregate the upstream regression test
 * (windowE.test 2.1) registers from TCL. The vulnerable build's
 * resolve path recurses on a WINDOW defined over this aggregate and
 * overflows the stack; the patched build returns a parse error. */
#include <sqlite3ext.h>
SQLITE_EXTENSION_INIT1
static void xc_step(sqlite3_context *c, int n, sqlite3_value **v) {
    int *p;
    (void)n; (void)v;
    p = sqlite3_aggregate_context(c, sizeof(int));
    if (p) (*p)++;
}
static void xc_final(sqlite3_context *c) {
    int *p = sqlite3_aggregate_context(c, sizeof(int));
    sqlite3_result_int(c, p ? *p : 0);
}
#ifdef _WIN32
__declspec(dllexport)
#endif
int sqlite3_aggext_init(sqlite3 *db, char **err,
                        const sqlite3_api_routines *api) {
    SQLITE_EXTENSION_INIT2(api);
    (void)err;
    return sqlite3_create_function(db, "x_count", 1, SQLITE_UTF8, 0,
                                   0, xc_step, xc_final);
}
