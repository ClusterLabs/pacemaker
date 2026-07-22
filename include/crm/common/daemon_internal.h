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

#include <stdbool.h>            // bool

#include <glib.h>               // GMainLoop

#include <crm/common/ipc.h>     // pcmk_ipc_server
#include <crm/common/results.h> // crm_exit_t

#ifdef __cplusplus
extern "C" {
#endif

typedef struct pcmk__daemon_s pcmk__daemon_t;

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

    //! What is the exit code of the daemon?
    crm_exit_t ec;

    //! Main loop
    GMainLoop *mainloop;

    pcmk__daemon_ipc_fns_t *ipc_fns;
};

// IPC functions

bool pcmk__daemon_ipc_running(pcmk__daemon_t *d);

// Mainloop management functions

int pcmk__daemon_init(pcmk__daemon_t *d);
void pcmk__daemon_quit(pcmk__daemon_t *d, crm_exit_t ec);
void pcmk__daemon_run(pcmk__daemon_t *d);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_DAEMON_INTERNAL__H
