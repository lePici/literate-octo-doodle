#define _GNU_SOURCE

#include "rr_sysrepo.h"
#include "utils/subscribed_notifications.h"
#include "sysrepo_types.h"
#include "utils/netconf_acm.h"

static int
op_filter_data_get(sr_session_ctx_t *session, uint32_t max_depth, sr_get_options_t get_opts,
        const char *xp_filter, struct lyd_node **data)
{
    sr_data_t *sr_data = NULL;
    int rc;
    LY_ERR lyrc;

    /* get the selected data */
    rc = sr_get_data(session, xp_filter, max_depth, 0, get_opts, &sr_data);
    if (rc && (rc != SR_ERR_NOT_FOUND)) {
        /* "Getting data \"%s\" from sysrepo failed (%s).", xp_filter, sr_strerror(rc) */
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

sr_error_t
rrsr_get_config(sr_session_ctx_t *session, sr_datastore_t datastore, const char *xpath, struct lyd_node **data)
{
    const char *xp_filter;

    xp_filter = !xpath || (*xpath == '\0') ? "/*" : xpath;

    sr_session_switch_ds(session, datastore);
    return op_filter_data_get(session, 0, 0, xp_filter, data);
}

sr_error_t
rrsr_get_config2(sr_session_ctx_t *session, sr_datastore_t datastore, struct lyd_node *subtree, struct lyd_node **data)
{
    int rc;
    char *xpath;

    if ((rc = srsn_filter_subtree2xpath(subtree, session, &xpath))) {
        return rc;
    }

    rc = rrsr_get_config(session, datastore, xpath, data);
    free(xpath);

    return rc;
}

sr_error_t
rrsr_edit_config(sr_session_ctx_t *session, sr_datastore_t datastore,
        rrsr_ec_default_operation_t default_operation, rrsr_ec_test_option_t test_option, struct lyd_node *config)
{
    int rc;
    const char *defop;

    sr_session_switch_ds(session, datastore);

    switch (default_operation) {
    case RRSR_EC_MERGE:
        defop = "merge";
        break;
    case RRSR_EC_REPLACE:
        defop = "replace";
        break;
    case RRSR_EC_NONE:
        defop = "none";
        break;
    default:
        rc = SR_ERR_INVAL_ARG;
        goto cleanup;
    }
    rc = sr_edit_batch(session, config, defop);
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

    if (test_option == RRSR_EC_TEST_THEN_SET) {
        if ((rc = sr_apply_changes(session, 0))) {
            goto cleanup;
        }
    } else {
        assert(test_option == RRSR_EC_TEST_ONLY);
        if ((rc = sr_validate(session, NULL, 0))) {
            goto cleanup;
        }
    }

cleanup:
    /* discard any changes that possibly failed to be applied */
    sr_discard_changes(session);

    return rc;
}

sr_error_t
rrsr_copy_config(sr_session_ctx_t *session, sr_datastore_t dst_datastore, sr_datastore_t src_datastore)
{
    int rc;

    if (dst_datastore == src_datastore) {
        rc = SR_ERR_INVAL_ARG;
        goto cleanup;
    }

    sr_session_switch_ds(session, dst_datastore);
    rc = sr_copy_config(session, NULL, src_datastore, 0);

cleanup:
    return rc;
}

sr_error_t
rrsr_copy_config2(sr_session_ctx_t *session, sr_datastore_t dst_datastore, struct lyd_node *config)
{
    sr_session_switch_ds(session, dst_datastore);
    /* config is spent */
    return sr_replace_config(session, NULL, config, 0);
}

sr_error_t
rrsr_delete_config_startup(sr_session_ctx_t *session)
{
    sr_session_switch_ds(session, SR_DS_STARTUP);
    return sr_replace_config(session, NULL, NULL, 0);
}

sr_error_t
rrsr_lock(sr_session_ctx_t *session, sr_datastore_t datastore)
{
    sr_session_switch_ds(session, datastore);
    return sr_lock(session, NULL, 0);
}

sr_error_t
rrsr_unlock(sr_session_ctx_t *session, sr_datastore_t datastore)
{
    sr_session_switch_ds(session, datastore);
    return sr_unlock(session, NULL);
}

sr_error_t
rrsr_get(sr_session_ctx_t *session, const char *xpath, struct lyd_node **data)
{
    int rc;
    const char *xp_filter;
    struct lyd_node *node, *base_data = NULL;
    struct ly_set *set = NULL;
    uint32_t i;

    /* get filter */
    xp_filter = !xpath || (*xpath == '\0') ? "/*" : xpath;

    /* get base data from running */
    sr_session_switch_ds(session, SR_DS_RUNNING);
    if ((rc = op_filter_data_get(session, 0, SR_GET_NO_FILTER, xp_filter, &base_data))) {
        goto cleanup;
    }

    /* then append base operational data */
    sr_session_switch_ds(session, SR_DS_OPERATIONAL);
    if ((rc = op_filter_data_get(session, 0, SR_OPER_NO_CONFIG | SR_GET_NO_FILTER, xp_filter, &base_data))) {
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

sr_error_t
rrsr_get2(sr_session_ctx_t *session, struct lyd_node *subtree, struct lyd_node **data)
{
    int rc;
    char *xpath;

    if ((rc = srsn_filter_subtree2xpath(subtree, session, &xpath))) {
        return rc;
    }

    rc = rrsr_get(session, xpath, data);
    free(xpath);

    return rc;
}

sr_error_t
rrsr_discard_changes(sr_session_ctx_t *session)
{
    sr_session_switch_ds(session, SR_DS_CANDIDATE);
    return sr_copy_config(session, NULL, SR_DS_RUNNING, 0);
}

sr_error_t
rrsr_validate(sr_session_ctx_t *session, sr_datastore_t datastore)
{
    sr_session_switch_ds(session, datastore);
    return sr_validate(session, NULL, 0);
}
