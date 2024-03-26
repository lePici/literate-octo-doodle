#ifndef _RR_SYSREPO_H
#define _RR_SYSREPO_H

#define _GNU_SOURCE

#include <assert.h>

#include <libyang/libyang.h>

#include "sysrepo.h"

/*
 * Missing rpc:
 * rpc close-session - use sr_session_stop() for session or sr_disconnect() for sysrepo connection.
 * rpc kill-session - use sr_get_lock() to find out which Sysrepo SID holds the lock. TODO: then what?
 * rpc commit - use just rrsr_copy_config(). This rpc is more useful if the confirmed-commit feature is enabled which is
 * implemented in netopeer2 but it's not trivial code.
 */

/**
 * @brief Retrieve all or part of a specified configuration.
 *
 * Implementation of get-config rpc. Details in RFC 6241, Section 7.1.
 *
 * @param[in] session Session to sysrepo.
 * @param[in] datastore Source datastore from which the configuration will be read.
 * @param[in] xpath XPath filter selecting root nodes of subtrees to be retrieved.
 * @param[out] data Data with connected top-level data trees of all the requested data.
 * @return SR_ERR_OK on success.
 */
sr_error_t rrsr_get_config(sr_session_ctx_t *session, sr_datastore_t datastore, const char *xpath,
        struct lyd_node **data);

/**
 * @brief Retrieve all or part of a specified configuration.
 *
 * Implementation of get-config rpc. Details in RFC 6241, Section 7.1.
 *
 * @param[in] session Session to sysrepo.
 * @param[in] datastore Source datastore from which the configuration will be read.
 * @param[in] subtree Subtree of the filter itself.
 * @param[out] data Data with connected top-level data trees of all the requested data.
 * @return SR_ERR_OK on success.
 */
sr_error_t rrsr_get_config2(sr_session_ctx_t *session, sr_datastore_t datastore, struct lyd_node *subtree,
        struct lyd_node **data);

/**
 * @brief Default operation for nodes for edit-config.
 *
 * Details in RFC 6241, Page 39.
 */
typedef enum {
    RRSR_EC_MERGE = 0,
    RRSR_EC_REPLACE,
    RRSR_EC_NONE
} rrsr_ec_default_operation_t;

/**
 * @brief Test options for edit-config.
 *
 * Details in RFC 6241, Page 39. Option 'set' is missing because it is not supported by libyang.
 */
typedef enum {
    RRSR_EC_TEST_THEN_SET = 0,  /**< Perform a validation test before attempting to set. */
    RRSR_EC_TEST_ONLY           /**< Perform only the validation test, without attempting to set. */
} rrsr_ec_test_option_t;

/**
 * @brief Loads all or part of a specified configuration to the datastore.
 *
 * Implementation of edit-config rpc. Details in RFC 6241, Section 7.2.
 * As for the error-option, only 'rollback on error' is supported.
 *
 * @param[in] session Session to sysrepo.
 * @param[in] datastore Target datastore to edit.
 * @param[in] default_operation Operation specification.
 * @param[in] test_option Option of test before applying edit.
 * @param[in] config Edit content.
 * @return SR_ERR_OK on success.
 */
sr_error_t rrsr_edit_config(sr_session_ctx_t *session, sr_datastore_t datastore,
        rrsr_ec_default_operation_t default_operation, rrsr_ec_test_option_t test_option, struct lyd_node *config);

/**
 * @brief Create or replace an entire datastore with the contents of another datastore.
 *
 * Implementation of copy-config rpc. Details in RFC 6241, Section 7.3.
 *
 * @param[in] session Session to sysrepo.
 * @param[in] dst_datastore Target datastore to copy to.
 * @param[in] src_datastore Source datastore to copy from.
 * @return SR_ERR_OK on success.
 */
sr_error_t rrsr_copy_config(sr_session_ctx_t *session, sr_datastore_t dst_datastore, sr_datastore_t src_datastore);

/**
 * @brief Create or replace an entire datastore with the data nodes.
 *
 * Implementation of copy-config rpc. Details in RFC 6241, Section 7.3.
 *
 * @param[in] session Session to sysrepo.
 * @param[in] dst_datastore Target datastore to copy to.
 * @param[in] config Source data to copy from. Is ALWAYS spent and cannot be further used by the application!
 * @return SR_ERR_OK on success.
 */
sr_error_t rrsr_copy_config2(sr_session_ctx_t *session, sr_datastore_t dst_datastore, struct lyd_node *config);

/**
 * @brief Delete a configuration datastore.
 *
 * Implementation of copy-config rpc. Details in RFC 6241, Section 7.4.
 *
 * @param[in] session Session to sysrepo.
 * @return SR_ERR_OK on success.
 */
sr_error_t rrsr_delete_config_startup(sr_session_ctx_t *session);

/**
 * @brief Lock configuration datastore.
 *
 * Implementation of lock rpc. Details in RFC 6241, Section 7.5.
 *
 * @param[in] session Session to sysrepo.
 * @param[in] datastore Datastore to lock.
 * @return SR_ERR_OK on success.
 */
sr_error_t rrsr_lock(sr_session_ctx_t *session, sr_datastore_t datastore);

/**
 * @brief Unlock configuration datastore.
 *
 * Implementation of unlock rpc. Details in RFC 6241, Section 7.6.
 *
 * @param[in] session Session to sysrepo.
 * @param[in] datastore Datastore to unlock.
 * @return SR_ERR_OK on success.
 */
sr_error_t rrsr_unlock(sr_session_ctx_t *session, sr_datastore_t datastore);


/**
 * @brief Retrieve running configuration and state (read-only) nodes.
 *
 * Implementation of get rpc. Details in RFC 6241, Section 7.7.
 *
 * @param[in] session Session to sysrepo.
 * @param[in] xpath XPath filter selecting root nodes of subtrees to be retrieved.
 * @param[out] data Data with connected top-level data trees of all the requested data.
 * @return SR_ERR_OK on success.
 */
sr_error_t rrsr_get(sr_session_ctx_t *session, const char *xpath, struct lyd_node **data);

/**
 * @brief Retrieve running configuration and state (read-only) nodes.
 *
 * Implementation of get rpc. Details in RFC 6241, Section 7.7.
 *
 * @param[in] session Session to sysrepo.
 * @param[in] subtree Subtree of the filter itself.
 * @param[out] data Data with connected top-level data trees of all the requested data.
 * @return SR_ERR_OK on success.
 */
sr_error_t rrsr_get2(sr_session_ctx_t *session, struct lyd_node *subtree, struct lyd_node **data);

/**
 * @brief Revert the candidate configuration to the current running configuration.
 *
 * Implementation of discard-changes rpc. Details in RFC 6241, Section 8.3.4.2.
 *
 * @param[in] session Session to sysrepo.
 * @return SR_ERR_OK on success.
 */
sr_error_t rrsr_discard_changes(sr_session_ctx_t *session);

/**
 * @brief Perform the validation a datastore and any changes made in the current session, but do not
 * apply nor discard them.
 *
 * Implementation of validate rpc. Details in RFC 6241, Section 8.6.
 * Provides only YANG validation, apply-changes **subscribers will not be notified** in this case.
 *
 * @param[in] session Session to sysrepo.
 * @param[in] datastore Datastore to validate.
 * @return SR_ERR_OK on success.
 */
sr_error_t rrsr_validate(sr_session_ctx_t *session, sr_datastore_t datastore);

#endif /* _RR_SYSREPO_H */
