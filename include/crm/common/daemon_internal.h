/*
 * Copyright 2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__INCLUDED_CRM_COMMON_INTERNAL_H
#error "Include <crm/common/internal.h> instead of <daemon_internal.h> directly"
#endif

#ifndef PCMK__CRM_COMMON_DAEMON_INTERNAL__H
#define PCMK__CRM_COMMON_DAEMON_INTERNAL__H

#include <stdbool.h>                    // bool
#include <stdint.h>                     // int32_t
#include <sys/types.h>                  // gid_t, uid_t
#include <time.h>                       // time_t

#include <glib.h>                       // GMainLoop
#include <qb/qbipcs.h>                  // qb_ipcs_service_*
#include <qb/qbloop.h>                  // qb_loop_priority

#include <crm/common/ipc.h>             // pcmk_ipc_server
#include <crm/common/ipc_internal.h>    // pcmk__client_t
#include <crm/common/results.h>         // crm_exit_t

#ifdef __cplusplus
extern "C" {
#endif

typedef struct pcmk__daemon_s pcmk__daemon_t;

/*!
 * \internal
 * \brief Daemon-specific general operations
 */
typedef struct {
    /*!
     * \internal
     * \brief Perform daemon-specific quitting tasks
     *
     * This function should not perform any cleanup or memory freeing tasks.
     * It is meant to terminate anything that needs to happen before the
     * main loop quits, as well as to determine whether or not that happens
     * at all.
     *
     * \param[in,out] d The daemon object
     *
     * \return \c true if quitting should continue, and \c false if not
     */
    bool (*quit)(pcmk__daemon_t *);
} pcmk__daemon_fns_t;

/*!
 * \internal
 * \brief Daemon-specific IPC operations
 */
typedef struct {
    /*!
     * \internal
     * \brief Determine if an instance of an IPC server is already running
     *
     * \param[in,out] d The daemon object
     *
     * \return \c true if an instance of the daemon is already running, and
     *         \c false if not
     */
    bool (*already_running)(pcmk__daemon_t *);

    /*!
     * \internal
     * \brief Clean up IPC communication
     *
     * \param[in,out] d The daemon object
     */
    void (*cleanup)(pcmk__daemon_t *);

    /*!
     * \internal
     * \brief Close a client IPC connection
     *
     * \note This function is optional - it does not need to be defined if
     *       there's no daemon-specific action to take when closing a client's
     *       connection.
     *
     * \note If this function is defined for a daemon, that function must call
     *       pcmk__free_client on \p client.  If this function is not defined,
     *       pcmk__daemon_ipc_closed will call pcmk__free_client instead.
     *
     * \param[in,out] d      The daemon object
     * \param[in]     client The client to close
     */
    void (*closed)(pcmk__daemon_t *, pcmk__client_t *);

    /*!
     * \internal
     * \brief Initialize the IPC side of the server
     *
     * \param[in,out] d  The daemon object
     * \param[in,out] cb The IPC callback object
     *
     * \note The generic pcmk__daemon_ipc_init function should be assigned
     *       to this function pointer for most every server
     *
     * \return \c true if the IPC server was successfully initialized, and
     *         \c false if not
     */
    bool (*init)(pcmk__daemon_t *, struct qb_ipcs_service_handlers *);
} pcmk__daemon_ipc_fns_t;

/*!
 * \internal
 * \brief This structure describes and manages a single pacemaker daemon
 */
struct pcmk__daemon_s {
    //! Daemon type, indexed by the IPC enum
    enum pcmk_ipc_server type;

    //! Is the daemon currently shutting down?
    bool shutting_down;

    // NOTE: This is set by glib command line processing, hence gboolean
    //! Is the daemon running in stand alone mode?
    gboolean stand_alone;

    //! When did the daemon start running?
    time_t start_time;

    //! What is the exit code of the daemon?
    crm_exit_t ec;

    //! Main loop
    GMainLoop *mainloop;

    //! IPC server
    enum qb_loop_priority priority;
    qb_ipcs_service_t *ipcs;

    pcmk__daemon_fns_t *fns;

    pcmk__daemon_ipc_fns_t *ipc_fns;
};

// IPC functions

int32_t pcmk__daemon_ipc_accept(pcmk__daemon_t *d, qb_ipcs_connection_t *c,
                                uid_t uid, gid_t gid);
void pcmk__daemon_ipc_cleanup(pcmk__daemon_t *d);
int32_t pcmk__daemon_ipc_closed(pcmk__daemon_t *d, qb_ipcs_connection_t *c);
void pcmk__daemon_ipc_destroy(pcmk__daemon_t *d, qb_ipcs_connection_t *c);
bool pcmk__daemon_ipc_running(pcmk__daemon_t *d);
bool pcmk__daemon_ipc_init(pcmk__daemon_t *d,
                           struct qb_ipcs_service_handlers *cb);
bool pcmk__generic_ipc_running(pcmk__daemon_t *d);

// Mainloop management functions

int pcmk__daemon_init(pcmk__daemon_t *d);
void pcmk__daemon_quit(pcmk__daemon_t *d, crm_exit_t ec);
void pcmk__daemon_run(pcmk__daemon_t *d);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_DAEMON_INTERNAL__H
