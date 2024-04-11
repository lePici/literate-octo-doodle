#define _GNU_SOURCE

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <stdatomic.h>

#include <libyang/libyang.h>
#include <sysrepo.h>
#include <sysrepo/subscribed_notifications.h>
#include <sysrepo/netconf_acm.h>

#include "rr_sessions.h"
#include "rr_err.h"

#define RR_RPC_YANG "rr-ncl"

static int
op_filter_data_get(sr_session_ctx_t *session, uint32_t max_depth, sr_get_options_t get_opts, const char *xp_filter,
        sr_session_ctx_t *ev_sess, struct lyd_node **data)
{
    sr_data_t *sr_data = NULL;
    int rc;
    LY_ERR lyrc;

    /* get the selected data */
    rc = sr_get_data(session, xp_filter, max_depth, 0, get_opts, &sr_data);
    if (rc && (rc != SR_ERR_NOT_FOUND)) {
        //SRPLG_LOG_ERR("rr-rpc", "Getting data \"%s\" from sysrepo failed (%s)", xp_filter, sr_strerror(rc));
        rr_err_sr2nc_get(ev_sess, session);
        return rc;
    }

    if (sr_data) {
        /* merge */
        lyrc = lyd_merge_siblings(data, sr_data->tree, LYD_MERGE_DESTRUCT);
        sr_data->tree = NULL;
        sr_release_data(sr_data);
        if (lyrc) {
            return SR_ERR_LY;
        }
    }

    return SR_ERR_OK;
}

static struct lyd_node *
op_parse_config(struct lyd_node_any *config, uint32_t parse_options, int *rc, sr_session_ctx_t *ev_sess)
{
    const struct ly_ctx *ly_ctx;
    struct lyd_node *root = NULL;
    LY_ERR lyrc = 0;

    assert(config && config->schema && (config->schema->nodetype & LYD_NODE_ANY));

    if (!config->value.str) {
        /* nothing to do, no data */
        return NULL;
    }

    ly_ctx = LYD_CTX(config);

    switch (config->value_type) {
    case LYD_ANYDATA_STRING:
    case LYD_ANYDATA_XML:
        lyrc = lyd_parse_data_mem(ly_ctx, config->value.str, LYD_XML, parse_options, 0, &root);
        break;
    case LYD_ANYDATA_DATATREE:
        lyrc = lyd_dup_siblings(config->value.tree, NULL, LYD_DUP_RECURSIVE, &root);
        if (!lyrc && !(parse_options & (LYD_PARSE_ONLY | LYD_PARSE_OPAQ))) {
            /* separate validation if requested */
            lyrc = lyd_validate_all(&root, NULL, LYD_VALIDATE_NO_STATE, NULL);
        }
        break;
    case LYD_ANYDATA_LYB:
        lyrc = lyd_parse_data_mem(ly_ctx, config->value.mem, LYD_LYB, parse_options, 0, &root);
        break;
    case LYD_ANYDATA_JSON:
        *rc = SR_ERR_INTERNAL;
        return NULL;
    }
    if (lyrc) {
        *rc = SR_ERR_LY;
        sr_session_set_error(ev_sess, NULL, *rc, ly_err_last(ly_ctx)->msg);
    }

    return root;
}


int
rr_close_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *op_path, const struct lyd_node *input,
        sr_event_t event, uint32_t request_id, struct lyd_node *output, void *private_data)
{
    (void) sub_id;
    (void) op_path;
    (void) input;
    (void) event;
    (void) request_id;
    (void) output;
    (void) private_data;

    if (event == SR_EV_ABORT) {
        /* silent ignore */
        return SR_ERR_OK;
    }

    rr_session_close(session);

    return SR_ERR_OK;
}

static int
rr_get_rpc_data(sr_session_ctx_t *session, const char *xp_filter, sr_session_ctx_t *ev_sess,
        struct lyd_node **data)
{
    int rc = SR_ERR_OK;
    struct lyd_node *node, *base_data = NULL;
    struct ly_set *set = NULL;
    uint32_t i;

    *data = NULL;

    /* get base data from running */
    sr_session_switch_ds(session, SR_DS_RUNNING);
    if ((rc = op_filter_data_get(session, 0, SR_GET_NO_FILTER, xp_filter, ev_sess, &base_data))) {
        goto cleanup;
    }

    /* then append base operational data */
    sr_session_switch_ds(session, SR_DS_OPERATIONAL);
    if ((rc = op_filter_data_get(session, 0, SR_OPER_NO_CONFIG | SR_GET_NO_FILTER, xp_filter, ev_sess, &base_data))) {
        goto cleanup;
    }

    if (!strcmp(xp_filter, "/*")) {
        /* no filter, use all the data */
        *data = base_data;
        base_data = NULL;
        goto cleanup;
    }

    /* now filter only the requested data from the created running data + state data */
    if (lyd_find_xpath3(NULL, base_data, xp_filter, LY_VALUE_JSON, NULL, NULL, &set)) {
        rc = SR_ERR_LY;
        goto cleanup;
    }

    for (i = 0; i < set->count; ++i) {
        if (lyd_dup_single(set->dnodes[i], NULL, LYD_DUP_RECURSIVE | LYD_DUP_WITH_PARENTS | LYD_DUP_WITH_FLAGS, &node)) {
            rc = SR_ERR_LY;
            goto cleanup;
        }

        /* always find parent */
        while (node->parent) {
            node = lyd_parent(node);
        }

        /* merge */
        if (lyd_merge_tree(data, node, LYD_MERGE_DESTRUCT)) {
            lyd_free_tree(node);
            rc = SR_ERR_LY;
            goto cleanup;
        }
    }

cleanup:
    ly_set_free(set, NULL);
    lyd_free_siblings(base_data);
    return rc;
}

int
rr_get_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *op_path, const struct lyd_node *input,
        sr_event_t event, uint32_t request_id, struct lyd_node *output, void *private_data)
{
    (void)sub_id;
    (void)request_id;
    (void)private_data;

    int rc = SR_ERR_OK;
    struct lyd_node *node, *data_get = NULL;
    struct lyd_meta *meta;
    struct rr_session *user_sess = NULL;
    struct ly_set *nodeset = NULL;
    sr_datastore_t ds = 0;
    char *xp_filter = NULL;

    if (event == SR_EV_ABORT) {
        /* silent ignore */
        return SR_ERR_OK;
    }

    /* get the user session */
    if ((rc = rr_find_user_sess(session, &user_sess))) {
        goto cleanup;
    }

    /* get know which datastore is being affected for get-config */
    if (!strcmp(op_path, "/" RR_RPC_YANG ":get-config")) {
        lyd_find_xpath(input, "source/*", &nodeset);
        if (!strcmp(nodeset->dnodes[0]->schema->name, "running")) {
            ds = SR_DS_RUNNING;
        } else if (!strcmp(nodeset->dnodes[0]->schema->name, "startup")) {
            ds = SR_DS_STARTUP;
        } else {
            assert(!strcmp(nodeset->dnodes[0]->schema->name, "candidate"));
            ds = SR_DS_CANDIDATE;
        }

        ly_set_free(nodeset, NULL);
    }

    /* create filters */
    if (!lyd_find_path(input, "filter", 0, &node)) {
        /* learn filter type */
        meta = lyd_find_meta(node->meta, NULL, RR_RPC_YANG ":type");
        if (meta && !strcmp(lyd_get_meta_value(meta), "xpath")) {
            meta = lyd_find_meta(node->meta, NULL, RR_RPC_YANG ":select");
            if (!meta) {
                //SRPLG_LOG_ERR("rr-rpc", "RPC with an XPath filter without the \"select\" attribute.");
                rc = SR_ERR_INVAL_ARG;
                goto cleanup;
            }
        } else {
            meta = NULL;
        }

        if (!meta) {
            /* subtree */
            if (((struct lyd_node_any *)node)->value_type == LYD_ANYDATA_DATATREE) {
                if ((rc = srsn_filter_subtree2xpath(((struct lyd_node_any *)node)->value.tree, user_sess->sess, &xp_filter))) {
                    sr_session_dup_error(user_sess->sess, session);
                    goto cleanup;
                }
            }
        } else {
            /* xpath */
            xp_filter = strdup(lyd_get_meta_value(meta));
        }
    } else {
        xp_filter = strdup("/*");
    }

    /* we do not care here about with-defaults mode, it does not change anything */

    /* get filtered data */
    if (!strcmp(op_path, "/" RR_RPC_YANG ":get-config")) {
        /* update sysrepo session datastore */
        sr_session_switch_ds(user_sess->sess, ds);

        /* create the data tree for the data reply */
        if ((rc = op_filter_data_get(user_sess->sess, 0, 0, xp_filter, session, &data_get))) {
            goto cleanup;
        }
    } else {
        /* get properly merged data */
        if ((rc = rr_get_rpc_data(user_sess->sess, xp_filter, session, &data_get))) {
            goto cleanup;
        }
    }

    /* add output */
    if (lyd_new_any(output, NULL, "data", data_get, LYD_ANYDATA_DATATREE, LYD_NEW_ANY_USE_VALUE | LYD_NEW_VAL_OUTPUT, &node)) {
        rc = SR_ERR_LY;
        goto cleanup;
    }
    data_get = NULL;

cleanup:
    free(xp_filter);
    lyd_free_siblings(data_get);
    //rr_release_user_sess(user_sess);
    return rc;
}

int
rr_editconfig_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *op_path,
        const struct lyd_node *input, sr_event_t event, uint32_t request_id, struct lyd_node *output,
        void *private_data)
{
    (void)sub_id;
    (void)op_path;
    (void)request_id;
    (void)output;
    (void)private_data;

    sr_datastore_t ds = 0;
    struct ly_set *nodeset = NULL;
    struct lyd_node *node, *config = NULL;
    struct rr_session *user_sess = NULL;
    const char *defop = "merge", *testop = "test-then-set";
    int rc = SR_ERR_OK;

    if (event == SR_EV_ABORT) {
        /* silent ignore */
        return SR_ERR_OK;
    }

    /* get know which datastore is being affected */
    lyd_find_xpath(input, "target/*", &nodeset);
    if (!strcmp(nodeset->dnodes[0]->schema->name, "running")) {
        ds = SR_DS_RUNNING;
    } else {
        assert(!strcmp(nodeset->dnodes[0]->schema->name, "candidate"));
        ds = SR_DS_CANDIDATE;
    }
    ly_set_free(nodeset, NULL);

    /* default-operation */
    if (!lyd_find_path(input, "default-operation", 0, &node)) {
        defop = lyd_get_value(node);
    }

    /* test-option */
    if (!lyd_find_path(input, "test-option", 0, &node)) {
        testop = lyd_get_value(node);
        if (!strcmp(testop, "set")) {
            //SRPLG_LOG_DBG("rr-rpc", "edit-config test-option \"set\" not supported, validation will be performed.");
            testop = "test-then-set";
        }
    }

    /* error-option */
    if (!lyd_find_path(input, "error-option", 0, &node)) {
        if (strcmp(lyd_get_value(node), "rollback-on-error")) {
            //SRPLG_LOG_DBG("rr-rpc", "edit-config error-option \"%s\" not supported, rollback-on-error will be performed.", lyd_get_value(node));
        }
    }

    /* config */
    lyd_find_xpath(input, "config | url", &nodeset);
    if (!strcmp(nodeset->dnodes[0]->schema->name, "config")) {
        config = op_parse_config((struct lyd_node_any *)nodeset->dnodes[0], LYD_PARSE_ONLY | LYD_PARSE_OPAQ |
                LYD_PARSE_NO_STATE, &rc, session);
        if (rc) {
            ly_set_free(nodeset, NULL);
            goto cleanup;
        }
    } else {
        assert(!strcmp(nodeset->dnodes[0]->schema->name, "url"));
        ly_set_free(nodeset, NULL);
        rc = SR_ERR_UNSUPPORTED;
        sr_session_set_error(session, NULL, rc, "URL not supported.");
        goto cleanup;
    }
    ly_set_free(nodeset, NULL);

    /* get the user session */
    if ((rc = rr_find_user_sess(session, &user_sess))) {
        goto cleanup;
    }

    /* update sysrepo session datastore */
    sr_session_switch_ds(user_sess->sess, ds);

    /* sysrepo API */
    if (config) {
        rc = sr_edit_batch(user_sess->sess, config, defop);
        if (rc != SR_ERR_OK) {
            goto cleanup;
        }
    }

    if (!strcmp(testop, "test-then-set")) {
        if ((rc = sr_apply_changes(user_sess->sess, 0))) {
            /* specific edit-config error */
            rr_err_sr2nc_edit(session, user_sess->sess);
            goto cleanup;
        }
    } else {
        assert(!strcmp(testop, "test-only"));
        if ((rc = sr_validate(user_sess->sess, NULL, 0))) {
            sr_session_dup_error(user_sess->sess, session);
            goto cleanup;
        }
    }

cleanup:
    if (user_sess) {
        /* discard any changes that possibly failed to be applied */
        sr_discard_changes(user_sess->sess);
    }
    lyd_free_siblings(config);
    //rr_release_user_sess(user_sess);
    return rc;
}

int
rr_copyconfig_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *op_path,
        const struct lyd_node *input, sr_event_t event, uint32_t request_id, struct lyd_node *output,
        void *private_data)
{
    (void)sub_id;
    (void)op_path;
    (void)request_id;
    (void)output;
    (void)private_data;

    sr_datastore_t ds = SR_DS_OPERATIONAL, sds = SR_DS_OPERATIONAL;
    struct ly_set *nodeset = NULL;
    struct lyd_node *config = NULL;
    sr_data_t *sr_data;
    int rc = SR_ERR_OK, run_to_start = 0, source_is_config = 0;
    struct rr_session *user_sess = NULL;

    if (event == SR_EV_ABORT) {
        /* silent ignore */
        return SR_ERR_OK;
    }

    /* get know which datastores are affected */
    lyd_find_xpath(input, "target/*", &nodeset);
    if (!strcmp(nodeset->dnodes[0]->schema->name, "running")) {
        ds = SR_DS_RUNNING;
    } else if (!strcmp(nodeset->dnodes[0]->schema->name, "startup")) {
        ds = SR_DS_STARTUP;
    } else if (!strcmp(nodeset->dnodes[0]->schema->name, "candidate")) {
        ds = SR_DS_CANDIDATE;
    } else {
        assert(!strcmp(nodeset->dnodes[0]->schema->name, "url"));
        ly_set_free(nodeset, NULL);
        rc = SR_ERR_UNSUPPORTED;
        sr_session_set_error(session, NULL, rc, "URL not supported.");
        goto cleanup;
    }
    ly_set_free(nodeset, NULL);

    lyd_find_xpath(input, "source/*", &nodeset);
    if (!strcmp(nodeset->dnodes[0]->schema->name, "running")) {
        sds = SR_DS_RUNNING;
        if (ds == SR_DS_STARTUP) {
            /* special copy-config from running to startup that bypasses NACM */
            run_to_start = 1;
        }
    } else if (!strcmp(nodeset->dnodes[0]->schema->name, "startup")) {
        sds = SR_DS_STARTUP;
    } else if (!strcmp(nodeset->dnodes[0]->schema->name, "candidate")) {
        sds = SR_DS_CANDIDATE;
    } else if (!strcmp(nodeset->dnodes[0]->schema->name, "config")) {
        config = op_parse_config((struct lyd_node_any *)nodeset->dnodes[0],
                LYD_PARSE_STRICT | LYD_PARSE_NO_STATE | LYD_PARSE_ONLY, &rc, session);
        if (rc) {
            ly_set_free(nodeset, NULL);
            goto cleanup;
        }
        source_is_config = 1;
    } else {
        assert(!strcmp(nodeset->dnodes[0]->schema->name, "url"));
        ly_set_free(nodeset, NULL);
        rc = SR_ERR_UNSUPPORTED;
        sr_session_set_error(session, NULL, rc, "URL not supported.");
        goto cleanup;
    }
    ly_set_free(nodeset, NULL);

    /* if both are url it is a valid call */
    if (ds == sds)
    {
        rc = SR_ERR_INVAL_ARG;
        rr_err_sr2nc_same_ds(session, "Source and target datastores are the same.");
        goto cleanup;
    }

    if (!source_is_config && !run_to_start) {
        /* get source datastore data */
        sr_session_switch_ds(session, sds);
        if ((rc = sr_get_data(session, "/*", 0, 0, 0, &sr_data))) {
            goto cleanup;
        }
        config = sr_data->tree;
        sr_data->tree = NULL;
        sr_release_data(sr_data);
    }

    /* get the user session */
    if ((rc = rr_find_user_sess(session, &user_sess))) {
        goto cleanup;
    }

    /* update sysrepo session datastore */
    sr_session_switch_ds(user_sess->sess, ds);

    /* sysrepo API/URL handling */
    if (source_is_config) {
        /* config is spent */
        rc = sr_replace_config(user_sess->sess, NULL, config, 0);
        config = NULL;
        if (rc) {
            sr_session_dup_error(user_sess->sess, session);
            goto cleanup;
        }
    } else {
        if (run_to_start) {
            /* skip NACM check */
            //sr_nacm_set_user(user_sess->sess, NULL);
        }

        if ((rc = sr_copy_config(user_sess->sess, NULL, sds, 0))) {
            /* prevent the error info being overwritten */
            sr_session_dup_error(user_sess->sess, session);
        }

        /* set NACM username back */
        //sr_nacm_set_user(user_sess->sess, rr_session_get_username(nc_sess));

        if (rc) {
            goto cleanup;
        }
    }

cleanup:
    lyd_free_siblings(config);
    //rr_release_user_sess(user_sess);
    return rc;
}

int
rr_deleteconfig_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *op_path,
        const struct lyd_node *input, sr_event_t event, uint32_t request_id, struct lyd_node *output,
        void *private_data)
{
    (void)sub_id;
    (void)op_path;
    (void)request_id;
    (void)output;
    (void)private_data;

    sr_datastore_t ds = 0;
    struct ly_set *nodeset;
    int rc = SR_ERR_OK;
    struct rr_session *user_sess = NULL;

    if (event == SR_EV_ABORT) {
        /* silent ignore */
        return SR_ERR_OK;
    }

    /* get know which datastore is affected */
    lyd_find_xpath(input, "target/*", &nodeset);
    if (!strcmp(nodeset->dnodes[0]->schema->name, "startup")) {
        ds = SR_DS_STARTUP;
    } else {
        assert(!strcmp(nodeset->dnodes[0]->schema->name, "url"));
        ly_set_free(nodeset, NULL);
        rc = SR_ERR_UNSUPPORTED;
        sr_session_set_error(session, NULL, rc, "URL not supported.");
        goto cleanup;
    }
    ly_set_free(nodeset, NULL);

    /* get the user session */
    if ((rc = rr_find_user_sess(session, &user_sess))) {
        goto cleanup;
    }

    /* update sysrepo session datastore */
    sr_session_switch_ds(user_sess->sess, ds);

    /* sysrepo API/URL handling */
    rc = sr_replace_config(user_sess->sess, NULL, NULL, 0);
    if (rc) {
        sr_session_dup_error(user_sess->sess, session);
        goto cleanup;
    }

    /* success */

cleanup:
    //rr_release_user_sess(user_sess);
    return rc;
}

int
rr_un_lock_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *op_path,
        const struct lyd_node *input, sr_event_t event, uint32_t request_id, struct lyd_node *output,
        void *private_data)
{
    (void)sub_id;
    (void)op_path;
    (void)request_id;
    (void)output;
    (void)private_data;

    sr_datastore_t ds = 0;
    struct ly_set *nodeset = NULL;
    struct rr_session *user_sess = NULL;
    const sr_error_info_t *err_info;
    int rc = SR_ERR_OK;

    //SRPLG_LOG_DBG("rr-rpc", "enter into rr_un_lock_cb");
    if (event == SR_EV_ABORT) {
        /* silent ignore */
        return SR_ERR_OK;
    }
    //SRPLG_LOG_DBG("rr-rpc", "continue in rr_un_lock_cb");

    /* get know which datastore is being affected */
    lyd_find_xpath(input, "target/*", &nodeset);
    if (!strcmp(nodeset->dnodes[0]->schema->name, "running")) {
        ds = SR_DS_RUNNING;
    } else if (!strcmp(nodeset->dnodes[0]->schema->name, "startup")) {
        ds = SR_DS_STARTUP;
    } else {
        assert(!strcmp(nodeset->dnodes[0]->schema->name, "candidate"));
        ds = SR_DS_CANDIDATE;
    }
    ly_set_free(nodeset, NULL);

    /* get the user session */
    if ((rc = rr_find_user_sess(session, &user_sess))) {
        //SRPLG_LOG_DBG("rr-rpc", "%"PRIu32" not found", user_sess->id);
        goto cleanup;
    }
    //SRPLG_LOG_DBG("rr-rpc", "processing user_client: %"PRIu32"", user_sess->id);

    // TODO: vazba lock a confirmed-commit
    //if ((ds == SR_DS_RUNNING) && !strcmp(input->schema->name, "lock") && ncc_ongoing_confirmed_commit(&ncc_sess) &&
    //        (!ncc_sess || (ncc_sess != nc_sess))) {
    //    /* RFC 6241 sec. 7.5. */
    //    if (nc_sess) {
    //        np_err_lock_denied(session, "There is an ongoing confirmed commit.", nc_session_get_id(nc_sess));
    //    } else {
    //        np_err_lock_denied(session, "There is an ongoing persistent confirmed commit.", 0);
    //    }
    //    rc = SR_ERR_LOCKED;
    //    goto cleanup;
    //}

    /* update sysrepo session datastore */
    sr_session_switch_ds(user_sess->sess, ds);

    /* sysrepo API */
    if (!strcmp(input->schema->name, "lock")) {
        rc = sr_lock(user_sess->sess, NULL, 0);
    } else if (!strcmp(input->schema->name, "unlock")) {
        rc = sr_unlock(user_sess->sess, NULL);
    }
    if (rc == SR_ERR_LOCKED) {
        fprintf(stderr, "rr_un_lock_cb: datastore is already locked\n");
        /* NETCONF error */
        sr_session_get_error(user_sess->sess, &err_info);
        rr_err_sr2nc_lock_denied(session, err_info);
        goto cleanup;
    } else if (rc) {
        fprintf(stderr, "rr_un_lock_cb: generic error\n");
        /* generic error */
        sr_session_dup_error(user_sess->sess, session);
        goto cleanup;
    }
    fprintf(stderr, "rr_un_lock_cb: success un/lock\n");

cleanup:
    //rr_release_user_sess(user_sess);
    return rc;
}

int
rr_discard_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *op_path,
        const struct lyd_node *input, sr_event_t event, uint32_t request_id,
        struct lyd_node *output, void *private_data)
{
    (void)sub_id;
    (void)op_path;
    (void)request_id;
    (void)output;
    (void)private_data;
    (void)input;

    int rc = SR_ERR_OK;
    struct rr_session *user_sess = NULL;

    if (event == SR_EV_ABORT) {
        /* silent ignore */
        return SR_ERR_OK;
    }

    /* get the user session */
    if ((rc = rr_find_user_sess(session, &user_sess))) {
        goto cleanup;
    }

    /* update sysrepo session datastore */
    sr_session_switch_ds(user_sess->sess, SR_DS_CANDIDATE);

    /* sysrepo API */
    rc = sr_copy_config(user_sess->sess, NULL, SR_DS_RUNNING, 0);
    if (rc != SR_ERR_OK) {
        sr_session_dup_error(user_sess->sess, session);
        goto cleanup;
    }

cleanup:
    //rr_release_user_sess(user_sess);
    return rc;
}

int
rr_validate_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *op_path,
        const struct lyd_node *input, sr_event_t event, uint32_t request_id, struct lyd_node *output,
        void *private_data)
{
    (void)sub_id;
    (void)op_path;
    (void)request_id;
    (void)output;
    (void)private_data;
    (void)input;

    sr_datastore_t ds = 0;
    struct lyd_node *config = NULL;
    struct ly_set *nodeset = NULL;
    struct rr_session *user_sess = NULL;
    int rc = SR_ERR_OK;

    if (event == SR_EV_ABORT) {
        /* silent ignore */
        return SR_ERR_OK;
    }

    /* get know which datastore is affected */
    lyd_find_xpath(input, "source/*", &nodeset);
    if (!strcmp(nodeset->dnodes[0]->schema->name, "running")) {
        ds = SR_DS_RUNNING;
    } else if (!strcmp(nodeset->dnodes[0]->schema->name, "startup")) {
        ds = SR_DS_STARTUP;
    } else if (!strcmp(nodeset->dnodes[0]->schema->name, "candidate")) {
        ds = SR_DS_CANDIDATE;
    } else if (!strcmp(nodeset->dnodes[0]->schema->name, "config")) {
        config = op_parse_config((struct lyd_node_any *)nodeset->dnodes[0], LYD_PARSE_STRICT | LYD_PARSE_NO_STATE,
                &rc, session);
        if (rc) {
            ly_set_free(nodeset, NULL);
            goto cleanup;
        }
    } else {
        assert(!strcmp(nodeset->dnodes[0]->schema->name, "url"));
        ly_set_free(nodeset, NULL);
        rc = SR_ERR_UNSUPPORTED;
        sr_session_set_error(session, NULL, rc, "URL not supported.");
        goto cleanup;
    }
    ly_set_free(nodeset, NULL);

    if (!config) {
        /* get the user session */
        if ((rc = rr_find_user_sess(session, &user_sess))) {
            goto cleanup;
        }

        /* update sysrepo session datastore */
        sr_session_switch_ds(user_sess->sess, ds);

        /* sysrepo API */
        rc = sr_validate(user_sess->sess, NULL, 0);
        if (rc != SR_ERR_OK) {
            sr_session_dup_error(user_sess->sess, session);
            goto cleanup;
        }
    } /* else already validated */

cleanup:
    lyd_free_siblings(config);
    //rr_release_user_sess(user_sess);
    return rc;
}
