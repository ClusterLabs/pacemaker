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

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * \internal
 * \brief This structure describes and manages a single pacemaker daemon
 */
typedef struct {
    //! Daemon type, indexed by the IPC enum
    enum pcmk_ipc_server type;

    //! Is the daemon currently shutting down?
    bool shutting_down;

    //! Main loop
    GMainLoop *mainloop;
} pcmk__daemon_t;

// Mainloop management functions

int pcmk__daemon_init(pcmk__daemon_t *d);
void pcmk__daemon_quit(pcmk__daemon_t *d);
void pcmk__daemon_run(pcmk__daemon_t *d);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_DAEMON_INTERNAL__H
