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

#include <sys/types.h>              // pid_t

#include <glib.h>                   // gboolean, guint

#include <crm/common/ipc.h>         // crm_ipc_t
#include <crm/common/mainloop.h>    // ipc_client_callbacks, mainloop_*

#ifdef __cplusplus
extern "C" {
#endif

struct mainloop_child_s {
    pid_t pid;
    char *desc;
    unsigned timerid;
    gboolean timeout;
    void *privatedata;

    enum mainloop_child_flags flags;

    /* Called when a process dies */
    pcmk__mainloop_child_exit_fn_t exit_fn;
};

struct mainloop_io_s {
    char *name;
    void *userdata;

    int fd;
    guint source;
    crm_ipc_t *ipc;
    GIOChannel *channel;

    int (*dispatch_fn_ipc)(const char *buffer, ssize_t length,
                           gpointer user_data);
    int (*dispatch_fn_io)(gpointer user_data);
    void (*destroy_fn)(gpointer user_data);
};

int pcmk__add_mainloop_ipc(crm_ipc_t *ipc, int priority, void *userdata,
                           const struct ipc_client_callbacks *callbacks,
                           mainloop_io_t **source);
guint pcmk__mainloop_timer_get_period(const mainloop_timer_t *timer);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_MAINLOOP_INTERNAL__H
