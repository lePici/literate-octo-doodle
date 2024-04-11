#define _GNU_SOURCE

#include <pthread.h>

#include <libyang/libyang.h>
#include <sysrepo.h>

static int
print_rpc_output(sr_data_t *output)
{
    int rc;
    struct ly_out *out = NULL;

    rc = ly_out_new_file(stdout, &out);
    if (rc != SR_ERR_OK) {
        return 1;
    }
    lyd_print_all(out, output->tree, LYD_XML, 0);
    ly_print_flush(out);

    /* cleanup */
    ly_out_free(out, NULL, 0);
    return 0;
}

static int
send_rpc(sr_session_ctx_t *ses, const char *str, int id, sr_data_t **output)
{
    int rc;
    struct lyd_node *input;
    struct ly_in *in = NULL;
    const struct ly_ctx *ctx;
    sr_data_t *output_temp = NULL;

    /* prepare data */
    ly_in_new_memory(str, &in);
    ctx = sr_session_acquire_context(ses);
    rc = lyd_parse_op(ctx, NULL, in, LYD_XML, LYD_TYPE_RPC_YANG, NULL, &input);
    if (rc) {
        fprintf(stderr, "parse data failed\n");
        goto cleanup;
    }

    /* prepare ID */
    rc = sr_session_set_orig_name(ses, "rr");
    if (rc) {
        fprintf(stderr, "set orig name\n");
        goto cleanup;
    }
    rc = sr_session_push_orig_data(ses, sizeof id, &id);
    if (rc) {
        fprintf(stderr, "push orig data\n");
        goto cleanup;
    }

    /* send the RPC */
    if (output) {
        rc = sr_rpc_send_tree(ses, input, 0, output);
    } else {
        rc = sr_rpc_send_tree(ses, input, 0, &output_temp);
        sr_release_data(output_temp);
    }
    if (rc != SR_ERR_OK) {
        fprintf(stderr, "<-- send rpc failed\n");
        goto cleanup;
    }

cleanup:
    sr_session_del_orig_data(ses);
    ly_in_free(in, 0);
    lyd_free_tree(input);
    fflush(stderr);

    return rc;
}

static void
get_config(sr_session_ctx_t *ses, const char *ds)
{
    char *str;
    sr_data_t *output;

    asprintf(&str,
            "<get-config xmlns=\"eu:racom:netconf-like\">"
            "  <source>"
            "    <%s/>"
            "  </source>"
            "</get-config>", ds);
    send_rpc(ses, str, getpid(), &output);
    print_rpc_output(output);

    /* cleanup */
    free(str);
    sr_release_data(output);
}

static void
edit_config(sr_session_ctx_t *ses, const char *msg)
{
    char *str;

    /* prepare data */
    asprintf(&str,
       "<edit-config xmlns=\"eu:racom:netconf-like\">"
       "  <target>"
       "    <candidate/>"
       "  </target>"
       "  <error-option>rollback-on-error</error-option>"
       "  <config>"
       "    <cont xmlns=\"urn:examples\">"
       "      <l>%s</l>"
       "    </cont>"
       "  </config>"
       "</edit-config>", msg);
    send_rpc(ses, str, getpid(), NULL);

    /* cleanup */
    free(str);
}

static void
lock_try(sr_session_ctx_t *ses)
{
    const char *str;

    fprintf(stderr, "--> lock\n");
    str =
       "<lock xmlns=\"eu:racom:netconf-like\">"
       "  <target>"
       "    <candidate/>"
       "  </target>"
       "</lock>";
    send_rpc(ses, str, getpid(), NULL);

    sleep(1);

    fprintf(stderr, "--> edit fail\n");
    str =
       "<edit-config xmlns=\"eu:racom:netconf-like\">"
       "  <target>"
       "    <candidate/>"
       "  </target>"
       "  <error-option>rollback-on-error</error-option>"
       "  <config>"
       "    <cont xmlns=\"urn:examples\">"
       "      <l>ciao</l>"
       "    </cont>"
       "  </config>"
       "</edit-config>";
    send_rpc(ses, str, getpid() + 1, NULL);

    fprintf(stderr, "--> edit success\n");
    str =
       "<edit-config xmlns=\"eu:racom:netconf-like\">"
       "  <target>"
       "    <candidate/>"
       "  </target>"
       "  <error-option>rollback-on-error</error-option>"
       "  <config>"
       "    <cont xmlns=\"urn:examples\">"
       "      <l>ciao</l>"
       "    </cont>"
       "  </config>"
       "</edit-config>";
    send_rpc(ses, str, getpid(), NULL);

    get_config(ses, "candidate");

    fprintf(stderr, "--> unlock\n");
    str =
       "<unlock xmlns=\"eu:racom:netconf-like\">"
       "  <target>"
       "    <candidate/>"
       "  </target>"
       "</unlock>";
    send_rpc(ses, str, getpid(), NULL);
}

static void
discard_changes(sr_session_ctx_t *session)
{
    const char *str;

    str = "<discard-changes xmlns=\"eu:racom:netconf-like\"/>";
    send_rpc(session, str, getpid(), NULL);
}

int
main(void)
{
    sr_conn_ctx_t *con = NULL;
    sr_session_ctx_t *ses = NULL;
    int rc = SR_ERR_OK;

    /* connect to sysrepo */
    rc = sr_connect(0, &con);
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

    /* start session */
    rc = sr_session_start(con, SR_DS_RUNNING, &ses);
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

    printf("TEST: edit-config of /examples:cont/l\n");
    edit_config(ses, "hello");
    get_config(ses, "candidate");
    edit_config(ses, "salut");
    get_config(ses, "candidate");
    discard_changes(ses);
    get_config(ses, "candidate");
    printf("\n");

    printf("TEST: lock, sleep, different ID try to edit -> failed, edit with right ID, unlock\n");
    lock_try(ses);
    printf("\n");

cleanup:
    sr_disconnect(con);
    return rc ? EXIT_FAILURE : EXIT_SUCCESS;
}
