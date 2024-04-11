#ifndef _RR_SESSIONS_H
#define _RR_SESSIONS_H

#define _GNU_SOURCE

#include <stdatomic.h>

#include <libyang/libyang.h>

#include "sysrepo.h"

#define ATOMIC_T atomic_uint_fast32_t
#define ATOMIC_DEC_RELAXED(var) atomic_fetch_sub_explicit(&(var), 1, memory_order_relaxed)

struct rr_session {
    // pthread_mutex_t lock;
    // ATOMIC_T ref_count;

    sr_session_ctx_t *sess;
    int id;
};

int rr_sessions_init(void);
int rr_sessions_destroy(void);

int rr_find_user_sess(sr_session_ctx_t *ev_sess, struct rr_session **user_sess);
int rr_get_sess_by_id(uint32_t sr_id, struct rr_session **user_sess);
int rr_session_close(sr_session_ctx_t *session);

#endif /* _RR_SESSIONS_H */
