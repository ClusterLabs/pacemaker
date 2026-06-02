/*
 * Copyright 2009-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_MAINLOOP__H
#define PCMK__CRM_COMMON_MAINLOOP__H

#include <stdbool.h>    // bool
#include <signal.h>     // sighandler_t
#include <sys/types.h>  // pid_t, ssize_t

#include <glib.h>       // gpointer, gboolean, guint, GSourceFunc, GMainLoop
#include <qb/qbipcs.h>  // qb_ipcs_service_t, etc.

#include <crm/common/ipc.h>


#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Wrappers for and extensions to glib mainloop
 * \ingroup core
 */

enum mainloop_child_flags {
    /* don't kill pid group on timeout, only kill the pid */
    mainloop_leave_pid_group = 0x01,
};

// NOTE: sbd (as of at least 1.5.2) uses this
typedef struct trigger_s crm_trigger_t;

typedef struct mainloop_io_s mainloop_io_t;
typedef struct mainloop_child_s mainloop_child_t;

// NOTE: sbd (as of at least 1.5.2) uses this
typedef struct mainloop_timer_s mainloop_timer_t;

//! \deprecated This has been for internal use only since its creation.
typedef void (*pcmk__mainloop_child_exit_fn_t)(mainloop_child_t *p, int core,
                                               int signo, int exitcode);

void mainloop_cleanup(void);

// NOTE: sbd (as of at least 1.5.2) uses this
crm_trigger_t *mainloop_add_trigger(int priority, int (*dispatch) (gpointer user_data),
                                    gpointer userdata);

// NOTE: sbd (as of at least 1.5.2) uses this
void mainloop_set_trigger(crm_trigger_t * source);

void mainloop_trigger_complete(crm_trigger_t * trig);

gboolean mainloop_destroy_trigger(crm_trigger_t * source);

#ifndef HAVE_SIGHANDLER_T
typedef void (*sighandler_t)(int);
#endif

sighandler_t crm_signal_handler(int sig, sighandler_t dispatch);

// NOTE: sbd (as of at least 1.5.2) uses this
gboolean mainloop_add_signal(int sig, void (*dispatch) (int sig));

gboolean mainloop_destroy_signal(int sig);

bool mainloop_timer_running(mainloop_timer_t *t);

// NOTE: sbd (as of at least 1.5.2) uses this
void mainloop_timer_start(mainloop_timer_t *t);

// NOTE: sbd (as of at least 1.5.2) uses this
void mainloop_timer_stop(mainloop_timer_t *t);

guint mainloop_timer_set_period(mainloop_timer_t *t, guint period_ms);

// NOTE: sbd (as of at least 1.5.2) uses this
mainloop_timer_t *mainloop_timer_add(const char *name, guint period_ms, bool repeat, GSourceFunc cb, void *userdata);

void mainloop_timer_del(mainloop_timer_t *t);

struct ipc_client_callbacks {
    /*!
     * \brief Dispatch function for an IPC connection used as mainloop source
     *
     * \param[in] buffer    Message read from IPC connection
     * \param[in] length    Number of bytes in \p buffer
     * \param[in] userdata  User data passed when creating mainloop source
     *
     * \return Negative value to remove source, anything else to keep it
     */
    int (*dispatch) (const char *buffer, ssize_t length, gpointer userdata);

    /*!
     * \brief Destroy function for mainloop IPC connection client data
     *
     * \param[in,out] userdata  User data passed when creating mainloop source
     */
    void (*destroy) (gpointer userdata);
};

qb_ipcs_service_t *mainloop_add_ipc_server(const char *name, enum qb_ipc_type type,
                                           struct qb_ipcs_service_handlers *callbacks);

/*!
 * \brief Start server-side API end-point, hooked into the internal event loop
 *
 * \param[in] name    name of the IPC end-point ("address" for the client)
 * \param[in] type       Ignored
 * \param[in] callbacks  defines libqb's IPC service-level handlers
 * \param[in] priority  priority relative to other events handled in the
 *                      abstract handling loop, use #QB_LOOP_MED when unsure
 *
 * \return libqb's opaque handle to the created service abstraction
 *
 * \note For portability concerns, do not use this function if you keep
 *       \p priority as #QB_LOOP_MED, stick with #mainloop_add_ipc_server
 *       (with exactly such semantics) instead (once you link with this new
 *       symbol employed, you can't downgrade the library freely anymore).
 *
 * \note The intended effect will only get fully reflected when run-time
 *       linked to patched libqb: https://github.com/ClusterLabs/libqb/pull/352
 */
qb_ipcs_service_t *mainloop_add_ipc_server_with_prio(const char *name,
                                                    enum qb_ipc_type type,
                                                    struct qb_ipcs_service_handlers *callbacks,
                                                    enum qb_loop_priority prio);

void mainloop_del_ipc_server(qb_ipcs_service_t * server);

// @COMPAT max_size parameter is deprecated and unused since 3.0.1
mainloop_io_t *mainloop_add_ipc_client(const char *name, int priority, size_t max_size,
                                       void *userdata, struct ipc_client_callbacks *callbacks);

void mainloop_del_ipc_client(mainloop_io_t * client);

crm_ipc_t *mainloop_get_ipc_client(mainloop_io_t * client);

struct mainloop_fd_callbacks {
    /*!
     * \brief Dispatch function for mainloop file descriptor with data ready
     *
     * \param[in,out] userdata  User data passed when creating mainloop source
     *
     * \return Negative value to remove source, anything else to keep it
     */
    int (*dispatch) (gpointer userdata);

    /*!
     * \brief Destroy function for mainloop file descriptor client data
     *
     * \param[in,out] userdata  User data passed when creating mainloop source
     */
    void (*destroy) (gpointer userdata);
};

mainloop_io_t *mainloop_add_fd(const char *name, int priority, int fd, void *userdata,
                               struct mainloop_fd_callbacks *callbacks);

void mainloop_del_fd(mainloop_io_t * client);

/*
 * Create a new tracked process
 * To track a process group, use -pid
 */
void mainloop_child_add(pid_t pid, int timeout, const char *desc,
                        void *userdata,
                        pcmk__mainloop_child_exit_fn_t exit_fn);

void mainloop_child_add_with_flags(pid_t pid, int timeout, const char *desc,
                                   void *userdata, enum mainloop_child_flags,
                                   pcmk__mainloop_child_exit_fn_t exit_fn);

void *mainloop_child_userdata(mainloop_child_t * child);
int mainloop_child_timeout(mainloop_child_t * child);
const char *mainloop_child_name(mainloop_child_t * child);

pid_t mainloop_child_pid(mainloop_child_t * child);
void mainloop_clear_child_userdata(mainloop_child_t * child);
gboolean mainloop_child_kill(pid_t pid);

void pcmk_quit_main_loop(GMainLoop *mloop, unsigned int n);
void pcmk_drain_main_loop(GMainLoop *mloop, guint timer_ms,
                          bool (*check)(guint));

#define G_PRIORITY_MEDIUM (G_PRIORITY_HIGH/2)

#ifdef __cplusplus
}
#endif

#endif
