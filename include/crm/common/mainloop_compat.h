/*
 * Copyright 2009-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_MAINLOOP_COMPAT__H
#define PCMK__CRM_COMMON_MAINLOOP_COMPAT__H

#include <sys/types.h>              // pid_t

#include <glib.h>                   // gboolean

#include <crm/common/mainloop.h>    // mainloop_*

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Deprecated Pacemaker main event loop API
 * \ingroup core
 * \deprecated Do not include this header directly. The time APIs in this
 *             header, and the header itself, will be removed in a future
 *             release.
 */

//! \deprecated Do not use
typedef struct mainloop_child_s mainloop_child_t;

//! \deprecated Do not use
enum mainloop_child_flags {
    mainloop_leave_pid_group = 0x01,
};

//! \deprecated Do not use
void mainloop_child_add_with_flags(pid_t pid, int timeout_ms, const char *desc,
                                   void *user_data, enum mainloop_child_flags,
                                   void (*callback)(mainloop_child_t *child,
                                                    int core, int signo,
                                                    int exit_code));

//! \deprecated Do not use
void mainloop_child_add(pid_t pid, int timeout_ms, const char *desc,
                        void *user_data,
                        void (*callback)(mainloop_child_t *child, int core,
                                         int signo, int exit_code));

//! \deprecated Do not use
gboolean mainloop_child_kill(pid_t pid);

//! \deprecated Do not use
pid_t mainloop_child_pid(mainloop_child_t *child);

//! \deprecated Do not use
const char *mainloop_child_name(mainloop_child_t *child);

//! \deprecated Do not use
int mainloop_child_timeout(mainloop_child_t *child);

//! \deprecated Do not use
void *mainloop_child_userdata(mainloop_child_t *child);

//! \deprecated Do not use
void mainloop_clear_child_userdata(mainloop_child_t *child);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_MAINLOOP_COMPAT__H
