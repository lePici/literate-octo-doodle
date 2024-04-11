#define _GNU_SOURCE

#include <pthread.h>
#include <signal.h>

#include <libyang/libyang.h>
#include <sysrepo.h>

#include "rr_nc_rpc.h"
#include "rr_sessions.h"

volatile int exit_application = 0;

static void
sigint_handler(int signum)
{
    (void)signum;

    exit_application = 1;
}

int
main(void)
{
    sr_conn_ctx_t *connection = NULL;
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    int rc = SR_ERR_OK;

    /* turn logging on */
    sr_log_stderr(SR_LL_WRN);

    /* connect to sysrepo */
    rc = sr_connect(0, &connection);
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

    /* start session */
    rc = sr_session_start(connection, SR_DS_RUNNING, &session);
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

    /* session management initialization */
    rc = rr_sessions_init();
    if (rc != SR_ERR_OK) {
        //SRPLG_LOG_ERR("rr-rpc", "rr_sessions_init failed.");
        goto cleanup;
    }

#define SR_RPC_SUBSCR(xpath, cb, sub) \
    rc = sr_rpc_subscribe_tree(session, xpath, cb, NULL, 0, 0, sub); \
    if (rc != SR_ERR_OK) { \
        goto cleanup; \
    }

    SR_RPC_SUBSCR("/rr-ncl:get-config", rr_get_cb, &subscription);
    SR_RPC_SUBSCR("/rr-ncl:edit-config", rr_editconfig_cb, &subscription);
    SR_RPC_SUBSCR("/rr-ncl:copy-config", rr_copyconfig_cb, &subscription);
    SR_RPC_SUBSCR("/rr-ncl:delete-config", rr_deleteconfig_cb, &subscription);
    SR_RPC_SUBSCR("/rr-ncl:lock", rr_un_lock_cb, &subscription);
    SR_RPC_SUBSCR("/rr-ncl:unlock", rr_un_lock_cb, &subscription);
    SR_RPC_SUBSCR("/rr-ncl:get", rr_get_cb, &subscription);
    SR_RPC_SUBSCR("/rr-ncl:close-session", rr_close_cb, &subscription);
    SR_RPC_SUBSCR("/rr-ncl:discard-changes", rr_discard_cb, &subscription);
    SR_RPC_SUBSCR("/rr-ncl:validate", rr_validate_cb, &subscription);

    /* loop until ctrl-c is pressed / SIGINT is received */
    signal(SIGINT, sigint_handler);
    signal(SIGPIPE, SIG_IGN);
    while (!exit_application) {
        sleep(1000);
    }

cleanup:
    sr_disconnect(connection);
    rr_sessions_destroy();
    return rc ? EXIT_FAILURE : EXIT_SUCCESS;
}
