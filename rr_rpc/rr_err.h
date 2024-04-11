#ifndef _RR_ERR_H
#define _RR_ERR_H

#define _GNU_SOURCE

#include <sysrepo.h>

void rr_err_invalid_value(sr_session_ctx_t *ev_sess, const char *description, const char *bad_elem_name);

void rr_err_sr2nc_get(sr_session_ctx_t *ev_sess, const sr_session_ctx_t *err_sess);

void rr_err_sr2nc_edit(sr_session_ctx_t *ev_sess, const sr_session_ctx_t *err_sess);

void rr_err_sr2nc_same_ds(sr_session_ctx_t *ev_sess, const char *err_msg);

void rr_err_sr2nc_lock_denied(sr_session_ctx_t *ev_sess, const sr_error_info_t *err_info);

#endif /* _RR_ERR_H */
