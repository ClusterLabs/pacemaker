/*
 * Copyright 2015-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_MAINLOOP_INTERNAL__H
#define PCMK__CRM_COMMON_MAINLOOP_INTERNAL__H

#include <glib.h>                   // guint

#include <crm/common/ipc.h>         // crm_ipc_t
#include <crm/common/mainloop.h>    // ipc_client_callbacks, mainloop_*

#ifdef __cplusplus
extern "C" {
#endif

int pcmk__add_mainloop_ipc(crm_ipc_t *ipc, int priority, void *userdata,
                           const struct ipc_client_callbacks *callbacks,
                           mainloop_io_t **source);
guint pcmk__mainloop_timer_get_period(const mainloop_timer_t *timer);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_MAINLOOP_INTERNAL__H
