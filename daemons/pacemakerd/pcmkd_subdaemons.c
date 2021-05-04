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

#include <crm/msg_xml.h>

crm_trigger_t *shutdown_trigger = NULL;
crm_trigger_t *startup_trigger = NULL;

/* When contacted via pacemakerd-api by a client having sbd in
 * the name we assume it is sbd-daemon which wants to know
 * if pacemakerd shutdown gracefully.
 * Thus when everything is shutdown properly pacemakerd
 * waits till it has reported the graceful completion of
 * shutdown to sbd and just when sbd-client closes the
 * connection we can assume that the report has arrived
 * properly so that pacemakerd can finally exit.
 * Following two variables are used to track that handshake.
 */
unsigned int shutdown_complete_state_reported_to = 0;
gboolean shutdown_complete_state_reported_client_closed = FALSE;

/* state we report when asked via pacemakerd-api status-ping */
const char *pacemakerd_state = XML_PING_ATTR_PACEMAKERDSTATE_INIT;
gboolean running_with_sbd = FALSE; /* local copy */

GMainLoop *mainloop = NULL;

/*!
 * \internal
 * \brief Check the liveness of the child based on IPC name and PID if tracked
 *
 * \param[inout] child  Child tracked data
 *
 * \return Standard Pacemaker return code
 *
 * \note Return codes of particular interest include pcmk_rc_ipc_unresponsive
 *       indicating that no trace of IPC liveness was detected,
 *       pcmk_rc_ipc_unauthorized indicating that the IPC endpoint is blocked by
 *       an unauthorized process, and pcmk_rc_ipc_pid_only indicating that
 *       the child is up by PID but not IPC end-point (possibly starting).
 * \note This function doesn't modify any of \p child members but \c pid,
 *       and is not actively toying with processes as such but invoking
 *       \c stop_child in one particular case (there's for some reason
 *       a different authentic holder of the IPC end-point).
 */
static int
child_liveness(pcmk_child_t *child)
{
    uid_t cl_uid = 0;
    gid_t cl_gid = 0;
    const uid_t root_uid = 0;
    const gid_t root_gid = 0;
    const uid_t *ref_uid;
    const gid_t *ref_gid;
    int rc = pcmk_rc_ipc_unresponsive;
    pid_t ipc_pid = 0;

    if (child->endpoint == NULL
            && (child->pid <= 0 || child->pid == PCMK__SPECIAL_PID)) {
        crm_err("Cannot track child %s for missing both API end-point and PID",
                child->name);
        rc = EINVAL; // Misuse of function when child is not trackable

    } else if (child->endpoint != NULL) {
        int legacy_rc = pcmk_ok;

        if (child->uid == NULL) {
            ref_uid = &root_uid;
            ref_gid = &root_gid;
        } else {
            ref_uid = &cl_uid;
            ref_gid = &cl_gid;
            legacy_rc = pcmk_daemon_user(&cl_uid, &cl_gid);
        }

        if (legacy_rc < 0) {
            rc = pcmk_legacy2rc(legacy_rc);
            crm_err("Could not find user and group IDs for user %s: %s "
                    CRM_XS " rc=%d", CRM_DAEMON_USER, pcmk_rc_str(rc), rc);
        } else {
            rc = pcmk__ipc_is_authentic_process_active(child->endpoint,
                                                       *ref_uid, *ref_gid,
                                                       &ipc_pid);
            if ((rc == pcmk_rc_ok) || (rc == pcmk_rc_ipc_unresponsive)) {
                if (child->pid <= 0) {
                    /* If rc is pcmk_rc_ok, ipc_pid is nonzero and this
                     * initializes a new child. If rc is
                     * pcmk_rc_ipc_unresponsive, ipc_pid is zero, and we will
                     * investigate further.
                     */
                    child->pid = ipc_pid;
                } else if ((ipc_pid != 0) && (child->pid != ipc_pid)) {
                    /* An unexpected (but authorized) process is responding to
                     * IPC. Investigate further.
                     */
                    rc = pcmk_rc_ipc_unresponsive;
                }
            }
        }
    }

    if (rc == pcmk_rc_ipc_unresponsive) {
        /* If we get here, a child without IPC is being tracked, no IPC liveness
         * has been detected, or IPC liveness has been detected with an
         * unexpected (but authorized) process. This is safe on FreeBSD since
         * the only change possible from a proper child's PID into "special" PID
         * of 1 behind more loosely related process.
         */
        int ret = pcmk__pid_active(child->pid, child->name);

        if (ipc_pid && ((ret != pcmk_rc_ok)
                        || ipc_pid == PCMK__SPECIAL_PID
                        || (pcmk__pid_active(ipc_pid,
                                             child->name) == pcmk_rc_ok))) {
            /* An unexpected (but authorized) process was detected at the IPC
             * endpoint, and either it is active, or the child we're tracking is
             * not.
             */

            if (ret == pcmk_rc_ok) {
                /* The child we're tracking is active. Kill it, and adopt the
                 * detected process. This assumes that our children don't fork
                 * (thus getting a different PID owning the IPC), but rather the
                 * tracking got out of sync because of some means external to
                 * Pacemaker, and adopting the detected process is better than
                 * killing it and possibly having to spawn a new child.
                 */
                /* not possessing IPC, afterall (what about corosync CPG?) */
                stop_child(child, SIGKILL);
            }
            rc = pcmk_rc_ok;
            child->pid = ipc_pid;
        } else if (ret == pcmk_rc_ok) {
            // Our tracked child's PID was found active, but not its IPC
            rc = pcmk_rc_ipc_pid_only;
        } else if ((child->pid == 0) && (ret == EINVAL)) {
            // FreeBSD can return EINVAL
            rc = pcmk_rc_ipc_unresponsive;
        } else {
            switch (ret) {
                case EACCES:
                    rc = pcmk_rc_ipc_unauthorized;
                    break;
                case ESRCH:
                    rc = pcmk_rc_ipc_unresponsive;
                    break;
                default:
                    rc = ret;
                    break;
            }
        }
    }
    return rc;
}

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

