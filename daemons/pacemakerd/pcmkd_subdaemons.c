/*
 * Copyright 2010-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include "pacemakerd.h"

#include <errno.h>
#include <signal.h>
#include <sys/types.h>

static gboolean
stop_child(pcmk_child_t * child, int signal)
{
    if (signal == 0) {
        signal = SIGTERM;
    }

    /* why to skip PID of 1?
       - FreeBSD ~ how untrackable process behind IPC is masqueraded as
       - elsewhere: how "init" task is designated; in particular, in systemd
         arrangement of socket-based activation, this is pretty real */
    if (child->command == NULL || child->pid == PCMK__SPECIAL_PID) {
        crm_debug("Nothing to do for child \"%s\" (process %lld)",
                  child->name, (long long) PCMK__SPECIAL_PID_AS_0(child->pid));
        return TRUE;
    }

    if (child->pid <= 0) {
        crm_trace("Client %s not running", child->name);
        return TRUE;
    }

    errno = 0;
    if (kill(child->pid, signal) == 0) {
        crm_notice("Stopping %s "CRM_XS" sent signal %d to process %lld",
                   child->name, signal, (long long) child->pid);

    } else {
        crm_err("Could not stop %s (process %lld) with signal %d: %s",
                child->name, (long long) child->pid, signal, strerror(errno));
    }

    return TRUE;
}

