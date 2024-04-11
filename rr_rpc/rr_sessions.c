#define _GNU_SOURCE

#include <pthread.h>

#include <libyang/libyang.h>
#include <sysrepo.h>

#include "rr_sessions.h"

#define RR_SESSION_COUNT 20

ly_bool lock_initialized = 0;
pthread_mutex_t rrs_lock;
struct rr_session rrs[RR_SESSION_COUNT] = {0};

int
rr_sessions_init(void)
{
    pthread_mutex_init(&rrs_lock, NULL);
    lock_initialized = 1;
    return 0;
}

int
rr_sessions_destroy(void)
{
    if (lock_initialized == 1) {
        pthread_mutex_destroy(&rrs_lock);
    }
    lock_initialized = 0;

    return 0;
}

int
rr_find_user_sess(sr_session_ctx_t *ev_sess, struct rr_session **user_sess)
{
    int rc = 0;
    uint32_t size;
    int *user_id, i;

    pthread_mutex_lock(&rrs_lock);

    rc = sr_session_get_orig_data(ev_sess, 0, &size, (const void **)&user_id);
    if (rc) {
        fprintf(stderr, "get_orig_data failed\n");
    }

    for (i = 0; i < RR_SESSION_COUNT; i++) {
        if (rrs[i].id == *user_id) {
            /* success, session was founded */
            *user_sess = &rrs[i];
            goto unlock;
        }
    }

    /* If not found, create new one */
    for (i = 0; i < RR_SESSION_COUNT; i++) {
        if (!rrs[i].sess) {
            rrs[i].id = *user_id;
            rc = sr_session_start(sr_session_get_connection(ev_sess), SR_DS_RUNNING, &rrs[i].sess);
            //if (rc != SR_ERR_OK) {
            //    SRPLG_LOG_ERR("rr-rpc", "create sysrepo session failed");
            //}
            *user_sess = &rrs[i];
            goto unlock;
        }
    }

unlock:
    pthread_mutex_unlock(&rrs_lock);

    return rc;
}

int
rr_get_sess_by_id(uint32_t sr_id, struct rr_session **user_sess)
{
    uint32_t i;
    int rc;

    pthread_mutex_lock(&rrs_lock);

    *user_sess = NULL;

    /* find the session */
    rc = 1;
    for (i = 0; i < RR_SESSION_COUNT; i++) {
        if (sr_session_get_id(rrs[i].sess) == sr_id) {
            *user_sess = &rrs[i];
            rc = 0;
            break;
        }
    }

    pthread_mutex_unlock(&rrs_lock);

    return rc;
}

int
rr_session_close(sr_session_ctx_t *session)
{
    uint32_t size;
    int *sid, i;

    sr_session_get_orig_data(session, 0, &size, (const void **)&sid);

    pthread_mutex_lock(&rrs_lock);

    for (i = 0; i < RR_SESSION_COUNT; i++) {
        if (rrs[i].id == *sid) {
            rrs[i].id = 0;
            sr_session_stop(rrs[i].sess);
            rrs[i].sess = NULL;
            break;
        }
    }

    //SRPLG_LOG_DBG("rr-rpc", "session %"PRIu32" end", sid);
    pthread_mutex_unlock(&rrs_lock);

    return 0;
}
