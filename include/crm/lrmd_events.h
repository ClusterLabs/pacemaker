/*
 * Copyright 2012-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_LRMD_EVENTS__H
#define PCMK__CRM_LRMD_EVENTS__H

#include <sys/types.h>          // time_t

#include <glib.h>               // guint

#include <crm/common/results.h> // enum ocf_exitcode

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Resource agent executor events
 * \ingroup lrmd
 */

enum lrmd_callback_event {
    lrmd_event_register,
    lrmd_event_unregister,
    lrmd_event_exec_complete,
    lrmd_event_disconnect,
    lrmd_event_connect,
    lrmd_event_poke,
    lrmd_event_new_client,
};

/*!
 * \deprecated Use \c lrmd_event_data_t instead of
 *             <tt>struct lrmd_event_data_s</tt>.
 */
typedef struct lrmd_event_data_s {
    /*! Type of event, register, unregister, call_completed... */
    enum lrmd_callback_event type;

    /*! The resource this event occurred on. */
    const char *rsc_id;
    /*! The action performed, start, stop, monitor... */
    const char *op_type;
    /*! The user data passed by caller of exec() API function */
    const char *user_data;

    /*! The client api call id associated with this event */
    int call_id;

    /*! The operation's timeout period in ms. */
    int timeout;

    /*! The operation's recurring interval in ms. */
    guint interval_ms;

    /*! The operation's start delay value in ms. */
    int start_delay;

    /*! This operation that just completed is on a deleted rsc. */
    int rsc_deleted;

    /*! The executed ra return code mapped to OCF */
    enum ocf_exitcode rc;

    /*! The executor status returned for exec_complete events */
    int op_status;

    /*! stdout from resource agent operation */
    const char *output;

    /*! Timestamp of when op ran */
    time_t t_run;

    /*! Timestamp of last rc change */
    time_t t_rcchange;

    /*! Time in length op took to execute */
    unsigned int exec_time;

    /*! Time in length spent in queue */
    unsigned int queue_time;

    /*! int connection result. Used for connection and poke events */
    int connection_rc;

    /* This is a GHashTable containing the
     * parameters given to the operation */
    void *params;

    /*! client node name associated with this connection
     * (used to match actions to the proper client when there are multiple)
     */
    const char *remote_nodename;

    /*! exit failure reason string from resource agent operation */
    const char *exit_reason;
} lrmd_event_data_t;

lrmd_event_data_t *lrmd_new_event(const char *rsc_id, const char *task,
                                  guint interval_ms);
lrmd_event_data_t *lrmd_copy_event(lrmd_event_data_t *event);
void lrmd_free_event(lrmd_event_data_t *event);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_LRMD_EVENTS__H
