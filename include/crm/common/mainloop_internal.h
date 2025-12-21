/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_MAINLOOP_INTERNAL__H
#define PCMK__CRM_COMMON_MAINLOOP_INTERNAL__H

#include <sys/types.h>              // pid_t

#include <glib.h>                   // gboolean

#include <crm/common/mainloop.h>    // mainloop_*

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
    void (*callback)(mainloop_child_t *p, int core, int signo, int exitcode);
};

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_MAINLOOP_INTERNAL__H
