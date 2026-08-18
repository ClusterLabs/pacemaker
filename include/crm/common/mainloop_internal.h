/*
 * Copyright 2004-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__INCLUDED_CRM_COMMON_INTERNAL_H
#error "Include <crm/common/internal.h> instead of <mainloop_internal.h> directly"
#endif

#ifndef PCMK__CRM_COMMON_MAINLOOP_INTERNAL__H
#define PCMK__CRM_COMMON_MAINLOOP_INTERNAL__H

#include <stdbool.h>                // bool
#include <sys/types.h>              // pid_t

#include <crm/common/ipc.h>         // crm_ipc_t
#include <crm/common/mainloop.h>    // ipc_client_callbacks, mainloop_*

#ifdef __cplusplus
extern "C" {
#endif

/* Forward-declare because pcmk__main_loop_child_cb_t takes a
 * (pcmk__main_loop_child_t *) argument
 */
typedef struct mainloop_child_s pcmk__main_loop_child_t;

/*!
 * \internal
 * \brief Callback function called when a child process terminates
 */
typedef void (*pcmk__main_loop_child_cb_t)(pcmk__main_loop_child_t *child,
                                           int core, int signo, int exit_code);

/*!
 * \internal
 * \brief Info about a child process tracked by a main event loop
 */
struct mainloop_child_s {
    /* @COMPAT Drop "struct mainloop_child_s" when we drop it from
     * mainloop_compat.h
     */
    pid_t pid;              //!< Child PID
    char *desc;             //!< Description
    unsigned int timer_id;  //!< ID of timer for child timeout
    bool timed_out;         //!< Whether the child has timed out
    void *user_data;        //!< User data

    /*!
     * If \c true, kill the child's entire process group on timeout.
     * If \c false, kill only the child process.
     */
    bool kill_group;

    //! Callback function called when the child terminates
    pcmk__main_loop_child_cb_t callback;
};

/*!
 * \internal
 * \brief Main loop timer
 *
 * This is an abstraction for a \c GSource that's added using \c g_timeout_add()
 * or \c g_timeout_add_seconds().
 *
 * A given source has an unsigned ID. This ID identifies the source to the main
 * loop and allows it to be removed by \c g_source_remove().
 *
 * To stop a timeout using GLib primitives, we remove the source. At that point,
 * if we saved the source ID, it's no longer valid. If we want to start the
 * timeout again using the same interval, callback function, and user data, we
 * must pass all of those again to \c g_timeout_add() or similar.
 *
 * This structure facilitates timeout management and reuse. It encapsulates the
 * timeout interval, callback function, and user data; a timer name for logging
 * purposes; and the ID of the associated source if the timer is running. The ID
 * is set to 0 if the timer is not running, indicating that there's no
 * associated source.
 */
typedef struct {
    char *name;                 //!< Timer name (for logging only)
    unsigned int source_id;     //!< Source ID (0 indicates timer not running)
    unsigned int interval_ms;   //!< Interval in milliseconds
    GSourceFunc cb;             //!< Callback called every \c interval_ms
    void *user_data;            //!< User data passed to \c cb
} pcmk__main_loop_timer_t;

struct mainloop_io_s {
    char *name;
    void *userdata;

    int fd;
    unsigned int source;
    crm_ipc_t *ipc;
    GIOChannel *channel;

    int (*dispatch_fn_ipc)(const char *buffer, ssize_t length, void *user_data);
    int (*dispatch_fn_io)(void *user_data);
    void (*destroy_fn)(void *user_data);
};

void pcmk__main_loop_child_create(pid_t pid, const char *desc,
                                  unsigned int timeout_ms, void *user_data,
                                  bool kill_group,
                                  pcmk__main_loop_child_cb_t callback);
bool pcmk__main_loop_child_kill(pid_t pid);

int pcmk__add_mainloop_ipc(crm_ipc_t *ipc, int priority, void *userdata,
                           const struct ipc_client_callbacks *callbacks,
                           mainloop_io_t **source);

pcmk__main_loop_timer_t *pcmk__main_loop_timer_new(const char *name,
                                                   unsigned int interval_ms,
                                                   GSourceFunc callback,
                                                   void *user_data);
bool pcmk__main_loop_timer_running(const pcmk__main_loop_timer_t *timer);
void pcmk__main_loop_timer_stop(pcmk__main_loop_timer_t *timer);
void pcmk__main_loop_timer_start(pcmk__main_loop_timer_t *timer);
void pcmk__main_loop_timer_free(pcmk__main_loop_timer_t *timer);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_MAINLOOP_INTERNAL__H
