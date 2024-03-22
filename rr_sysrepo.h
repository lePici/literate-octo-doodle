#define _GNU_SOURCE

#include <assert.h>

#include <libyang/libyang.h>
#include <sysrepo.h>

// ----
// rpc get-config
// ----
// sr_get_data
// sr_release_data

sr_error_t rrsr_get_config(sr_session_ctx_t *session, sr_datastore_t datastore, const char *xpath,
        struct lyd_node **data);

sr_error_t rrsr_get_config2(sr_session_ctx_t *session, sr_datastore_t datastore, struct lyd_node *subtree,
        struct lyd_node **data);
// srsn_filter_subtree2xpath

// ----
// rpc edit-config 
// ----
// sr_edit_batch
// sr_apply_changes -> test_then_set
// sr_validate -> test_only

typedef enum {
    RRSR_EC_MERGE,
    RRSR_EC_REPLACE,
    RRSR_EC_NONE
} rrsr_ec_default_operation_t;

typedef enum {
    RRSR_EC_TEST_THEN_SET,
    RRSR_EC_SET,
    RRSR_EC_TEST_ONLY
} rrsr_ec_test_option_t;

typedef enum {
    RRSR_EC_STOP_ON_ERROR,
    RRSR_EC_CONTINUE_ON_ERROR,
    RRSR_EC_ROLLBACK_ON_ERROR
} rrsr_ec_error_option_t;

sr_error_t rrsr_edit_config(sr_session_ctx_t *session, sr_datastore_t datastore,
        rrsr_ec_default_operation_t default_operation, rrsr_ec_test_option_t test_option, struct lyd_node *config);

sr_error_t rrsr_edit_config_url(sr_session_ctx_t *session, sr_datastore_t datastore,
        rrsr_ec_default_operation_t default_operation, rrsr_ec_test_option_t test_option, const char *url);

// ----
// rpc copy-config 
// ----
// sr_get_data
// sr_replace_config

sr_error_t rrsr_copy_config(sr_session_ctx_t *session, sr_datastore_t dst_datastore, sr_datastore_t src_datastore);

sr_error_t rrsr_copy_config2(sr_session_ctx_t *session, sr_datastore_t dst_datastore, const char *src_url);

sr_error_t rrsr_copy_config3(sr_session_ctx_t *session, sr_datastore_t dst_datastore, struct lyd_node *config);

sr_error_t rrsr_copy_config4(sr_session_ctx_t *session, const char *dst_url, sr_datastore_t src_datastore);

sr_error_t rrsr_copy_config5(sr_session_ctx_t *session, const char *dst_url, const char *src_url);

sr_error_t rrsr_copy_config6(sr_session_ctx_t *session, const char *dst_url, struct lyd_node *config);

// ----
// rpc delete-config 
// ----
// sr_replace_config

sr_error_t rrsr_delete_config_startup(sr_session_ctx_t *session);

sr_error_t rrsr_delete_config_url(sr_session_ctx_t *session, const char *url);

// ----
// rpc lock 
// ----
// sr_lock
// sr_unlock

sr_error_t rrsr_lock(sr_session_ctx_t *session, sr_datastore_t datastore);
sr_error_t rrsr_unlock(sr_session_ctx_t *session, sr_datastore_t datastore);

// ----
// rpc get
// ----
// sr_get_data
// sr_release_data

sr_error_t rrsr_get(sr_session_ctx_t *session, const char *xpath, struct lyd_node **data);

sr_error_t rrsr_get2(sr_session_ctx_t *session, struct lyd_node *subtree, struct lyd_node **data);

// ----
// rpc close-session
// ----
// sr_disconnect?

sr_error_t rrsr_close_session(sr_session_ctx_t *session);

// ----
// rpc kill-session -> skipped
// ----

// ----
// rpc commit -> skipped
// ----

// ----
// rpc discard-changes
// ----
// sr_copy_config

sr_error_t rrsr_discard_changes(sr_session_ctx_t *session);

// ----
// rpc validate 
// ----
// sr_validate

sr_error_t rrsr_validate(sr_session_ctx_t *session, sr_datastore_t datastore);

sr_error_t rrsr_validate2(sr_session_ctx_t *session, const char *url);

sr_error_t rrsr_validate3(sr_session_ctx_t *session, struct lyd_node *config);
