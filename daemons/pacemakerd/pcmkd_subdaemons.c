/*
 * Copyright 2010-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include "pacemakerd.h"

#if SUPPORT_COROSYNC
#include "pcmkd_corosync.h"
#endif

#include <errno.h>
#include <grp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <crm/cluster.h>
#include <crm/common/xml.h>

enum child_daemon_flags {
    child_none                  = 0,
    child_respawn               = 1 << 0,
    child_needs_cluster         = 1 << 1,
    child_needs_retry           = 1 << 2,
    child_active_before_startup = 1 << 3,
};

typedef struct pcmk_child_s {
    enum pcmk_ipc_server server;
    pid_t pid;
    int respawn_count;
    const char *uid;
    int check_count;
    uint32_t flags;
} pcmk_child_t;

#define PCMK_PROCESS_CHECK_INTERVAL 1000    /* 1s */
#define PCMK_PROCESS_CHECK_RETRIES  5
#define SHUTDOWN_ESCALATION_PERIOD  180000  /* 3m */

/* Index into the array below */
#define PCMK_CHILD_CONTROLD  5

static pcmk_child_t pcmk_children[] = {
    {
        pcmk_ipc_based, 0, 0, CRM_DAEMON_USER,
        0, child_respawn | child_needs_cluster
    },
    {
        pcmk_ipc_fenced, 0, 0, NULL,
        0, child_respawn | child_needs_cluster
    },
    {
        pcmk_ipc_execd, 0, 0, NULL,
        0, child_respawn
    },
    {
        pcmk_ipc_attrd, 0, 0, CRM_DAEMON_USER,
        0, child_respawn | child_needs_cluster
    },
    {
        pcmk_ipc_schedulerd, 0, 0, CRM_DAEMON_USER,
        0, child_respawn
    },
    {
        pcmk_ipc_controld, 0, 0, CRM_DAEMON_USER,
        0, child_respawn | child_needs_cluster
    },
};

static char *opts_default[] = { NULL, NULL };
static char *opts_vgrind[] = { NULL, NULL, NULL, NULL, NULL };

crm_trigger_t *shutdown_trigger = NULL;
crm_trigger_t *startup_trigger = NULL;
time_t subdaemon_check_progress = 0;

// Whether we need root group access to talk to cluster layer
static bool need_root_group = true;

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
const char *pacemakerd_state = PCMK__VALUE_INIT;
gboolean running_with_sbd = FALSE; /* local copy */

GMainLoop *mainloop = NULL;

static gboolean fatal_error = FALSE;

static int child_liveness(pcmk_child_t *child);
static gboolean escalate_shutdown(gpointer data);
static int start_child(pcmk_child_t * child);
static void pcmk_child_exit(mainloop_child_t * p, pid_t pid, int core, int signo, int exitcode);
static void pcmk_process_exit(pcmk_child_t * child);
static gboolean pcmk_shutdown_worker(gpointer user_data);
static gboolean stop_child(pcmk_child_t * child, int signal);

/*!
 * \internal
 * \brief Get path to subdaemon executable
 *
 * \param[in] subdaemon  Subdaemon to get path for
 *
 * \return Newly allocated string with path to subdaemon executable
 * \note It is the caller's responsibility to free() the return value
 */
static inline char *
subdaemon_path(pcmk_child_t *subdaemon)
{
    return crm_strdup_printf(CRM_DAEMON_DIR "/%s",
                             pcmk__server_name(subdaemon->server));
}

static bool
pcmkd_cluster_connected(void)
{
#if SUPPORT_COROSYNC
    return pcmkd_corosync_connected();
#else
    return true;
#endif
}

static gboolean
check_next_subdaemon(gpointer user_data)
{
    static int next_child = 0;

    pcmk_child_t *child = &(pcmk_children[next_child]);
    const char *name = pcmk__server_name(child->server);
    const long long pid = PCMK__SPECIAL_PID_AS_0(child->pid);
    int rc = child_liveness(child);

    crm_trace("Checked subdaemon %s[%lld]: %s (%d)",
              name, pid, pcmk_rc_str(rc), rc);

    switch (rc) {
        case pcmk_rc_ok:
            child->check_count = 0;
            subdaemon_check_progress = time(NULL);
            break;

        case pcmk_rc_ipc_pid_only: // Child was previously OK
            if (++(child->check_count) >= PCMK_PROCESS_CHECK_RETRIES) {
                // cts-lab looks for this message
                crm_crit("Subdaemon %s[%lld] is unresponsive to IPC "
                         "after %d attempt%s and will now be killed",
                         name, pid, child->check_count,
                         pcmk__plural_s(child->check_count));
                stop_child(child, SIGKILL);
                if (pcmk_is_set(child->flags, child_respawn)) {
                    // Respawn limit hasn't been reached, so retry another round
                    child->check_count = 0;
                }
            } else {
                crm_notice("Subdaemon %s[%lld] is unresponsive to IPC "
                           "after %d attempt%s (will recheck later)",
                           name, pid, child->check_count,
                           pcmk__plural_s(child->check_count));
                if (pcmk_is_set(child->flags, child_respawn)) {
                    /* as long as the respawn-limit isn't reached
                       and we haven't run out of connect retries
                       we account this as progress we are willing
                       to tell to sbd
                     */
                    subdaemon_check_progress = time(NULL);
                }
            }
            /* go to the next child and see if
               we can make progress there
             */
            break;
        case pcmk_rc_ipc_unresponsive:
            if (!pcmk_is_set(child->flags, child_respawn)) {
                /* if a subdaemon is down and we don't want it
                   to be restarted this is a success during
                   shutdown. if it isn't restarted anymore
                   due to MAX_RESPAWN it is
                   rather no success.
                 */
                if (child->respawn_count <= MAX_RESPAWN) {
                    subdaemon_check_progress = time(NULL);
                }
            }
            if (!pcmk_is_set(child->flags, child_active_before_startup)) {
                crm_trace("Subdaemon %s[%lld] terminated", name, pid);
                break;
            }
            if (pcmk_is_set(child->flags, child_respawn)) {
                // cts-lab looks for this message
                crm_err("Subdaemon %s[%lld] terminated", name, pid);
            } else {
                /* orderly shutdown */
                crm_notice("Subdaemon %s[%lld] terminated", name, pid);
            }
            pcmk_process_exit(child);
            break;
        default:
            crm_exit(CRM_EX_FATAL);
            break;  /* static analysis/noreturn */
    }

    if (++next_child >= PCMK__NELEM(pcmk_children)) {
        next_child = 0;
    }

    return G_SOURCE_CONTINUE;
}

static gboolean
escalate_shutdown(gpointer data)
{
    pcmk_child_t *child = data;

    if (child->pid == PCMK__SPECIAL_PID) {
        pcmk_process_exit(child);

    } else if (child->pid != 0) {
        /* Use SIGSEGV instead of SIGKILL to create a core so we can see what it was up to */
        crm_err("Subdaemon %s not terminating in a timely manner, forcing",
                pcmk__server_name(child->server));
        stop_child(child, SIGSEGV);
    }
    return FALSE;
}

static void
pcmk_child_exit(mainloop_child_t * p, pid_t pid, int core, int signo, int exitcode)
{
    pcmk_child_t *child = mainloop_child_userdata(p);
    const char *name = mainloop_child_name(p);

    if (signo) {
        // cts-lab looks for this message
        do_crm_log(((signo == SIGKILL)? LOG_WARNING : LOG_ERR),
                   "%s[%d] terminated with signal %d (%s)%s",
                   name, pid, signo, strsignal(signo),
                   (core? " and dumped core" : ""));

    } else {
        switch(exitcode) {
            case CRM_EX_OK:
                crm_info("%s[%d] exited with status %d (%s)",
                         name, pid, exitcode, crm_exit_str(exitcode));
                break;

            case CRM_EX_FATAL:
                crm_warn("Shutting cluster down because %s[%d] had fatal failure",
                         name, pid);
                child->flags &= ~child_respawn;
                fatal_error = TRUE;
                pcmk_shutdown(SIGTERM);
                break;

            case CRM_EX_PANIC:
                {
                    char *msg = NULL;

                    child->flags &= ~child_respawn;
                    fatal_error = TRUE;
                    msg = crm_strdup_printf("Subdaemon %s[%d] requested panic",
                                            name, pid);
                    pcmk__panic(msg);

                    // Should never get here
                    free(msg);
                    pcmk_shutdown(SIGTERM);
                }
                break;

            default:
                // cts-lab looks for this message
                crm_err("%s[%d] exited with status %d (%s)",
                        name, pid, exitcode, crm_exit_str(exitcode));
                break;
        }
    }

    pcmk_process_exit(child);
}

static void
pcmk_process_exit(pcmk_child_t * child)
{
    const char *name = pcmk__server_name(child->server);
    child->pid = 0;
    child->flags &= ~child_active_before_startup;
    child->check_count = 0;

    child->respawn_count += 1;
    if (child->respawn_count > MAX_RESPAWN) {
        crm_err("Subdaemon %s exceeded maximum respawn count", name);
        child->flags &= ~child_respawn;
    }

    if (shutdown_trigger) {
        /* resume step-wise shutdown (returned TRUE yields no parallelizing) */
        mainloop_set_trigger(shutdown_trigger);

    } else if (!pcmk_is_set(child->flags, child_respawn)) {
        /* nothing to do */

    } else if (pcmk__is_true(pcmk__env_option(PCMK__ENV_FAIL_FAST))) {
        pcmk__panic("Subdaemon failed");

    } else if (child_liveness(child) == pcmk_rc_ok) {
        crm_warn("Not respawning subdaemon %s because IPC endpoint %s is OK",
                 name, pcmk__server_ipc_name(child->server));

    } else if (pcmk_is_set(child->flags, child_needs_cluster) && !pcmkd_cluster_connected()) {
        crm_notice("Not respawning subdaemon %s until cluster returns", name);
        child->flags |= child_needs_retry;

    } else {
        // cts-lab looks for this message
        crm_notice("Respawning subdaemon %s after unexpected exit", name);
        start_child(child);
    }
}

static gboolean
pcmk_shutdown_worker(gpointer user_data)
{
    static int phase = PCMK__NELEM(pcmk_children) - 1;
    static time_t next_log = 0;

    if (phase == PCMK__NELEM(pcmk_children) - 1) {
        crm_notice("Shutting down Pacemaker");
        pacemakerd_state = PCMK__VALUE_SHUTTING_DOWN;
    }

    for (; phase >= 0; phase--) {
        pcmk_child_t *child = &(pcmk_children[phase]);
        const char *name = pcmk__server_name(child->server);

        if (child->pid != 0) {
            time_t now = time(NULL);

            if (pcmk_is_set(child->flags, child_respawn)) {
                if (child->pid == PCMK__SPECIAL_PID) {
                    crm_warn("Subdaemon %s cannot be terminated (shutdown "
                             "will be escalated after %ld seconds if it does "
                             "not terminate on its own; set PCMK_"
                             PCMK__ENV_FAIL_FAST "=1 to exit immediately "
                             "instead)",
                             name, (long) SHUTDOWN_ESCALATION_PERIOD);
                }
                next_log = now + 30;
                child->flags &= ~child_respawn;
                stop_child(child, SIGTERM);
                if (phase < PCMK_CHILD_CONTROLD) {
                    pcmk__create_timer(SHUTDOWN_ESCALATION_PERIOD,
                                       escalate_shutdown, child);
                }

            } else if (now >= next_log) {
                next_log = now + 30;
                crm_notice("Still waiting for subdaemon %s to terminate "
                           QB_XS " pid=%lld", name, (long long) child->pid);
            }
            return TRUE;
        }

        /* cleanup */
        crm_debug("Subdaemon %s confirmed stopped", name);
        child->pid = 0;
    }

    crm_notice("Shutdown complete");
    pacemakerd_state = PCMK__VALUE_SHUTDOWN_COMPLETE;
    if (!fatal_error && running_with_sbd &&
        pcmk__get_sbd_sync_resource_startup() &&
        !shutdown_complete_state_reported_client_closed) {
        crm_notice("Waiting for SBD to pick up shutdown-complete-state.");
        return TRUE;
    }

    g_main_loop_quit(mainloop);

    if (fatal_error) {
        crm_notice("Shutting down and staying down after fatal error");
#if SUPPORT_COROSYNC
        pcmkd_shutdown_corosync();
#endif
        crm_exit(CRM_EX_FATAL);
    }

    return TRUE;
}

/* TODO once libqb is taught to juggle with IPC end-points carried over as
        bare file descriptor (https://github.com/ClusterLabs/libqb/issues/325)
        it shall hand over these descriptors here if/once they are successfully
        pre-opened in (presumably) child_liveness(), to avoid any remaining
        room for races */
 // \return Standard Pacemaker return code
static int
start_child(pcmk_child_t * child)
{
    uid_t uid = 0;
    gid_t gid = 0;
    gboolean use_valgrind = FALSE;
    gboolean use_callgrind = FALSE;
    const char *name = pcmk__server_name(child->server);
    const char *env_valgrind = pcmk__env_option(PCMK__ENV_VALGRIND_ENABLED);
    const char *env_callgrind = pcmk__env_option(PCMK__ENV_CALLGRIND_ENABLED);

    child->flags &= ~child_active_before_startup;
    child->check_count = 0;

    if (pcmk__is_true(env_callgrind)) {
        use_callgrind = TRUE;
        use_valgrind = TRUE;

    } else if ((env_callgrind != NULL)
               && (strstr(env_callgrind, name) != NULL)) {
        use_callgrind = TRUE;
        use_valgrind = TRUE;

    } else if (pcmk__is_true(env_valgrind)) {
        use_valgrind = TRUE;

    } else if ((env_valgrind != NULL)
               && (strstr(env_valgrind, name) != NULL)) {
        use_valgrind = TRUE;
    }

    if (use_valgrind && strlen(PCMK__VALGRIND_EXEC) == 0) {
        crm_warn("Cannot enable valgrind for subdaemon %s: valgrind not found",
                 name);
        use_valgrind = FALSE;
    }

    if ((child->uid != NULL) && (crm_user_lookup(child->uid, &uid, &gid) < 0)) {
        crm_err("Invalid user (%s) for subdaemon %s: not found",
                child->uid, name);
        return EACCES;
    }

    child->pid = fork();
    pcmk__assert(child->pid != -1);

    if (child->pid > 0) {
        /* parent */
        mainloop_child_add(child->pid, 0, name, child, pcmk_child_exit);

	if (use_valgrind) {
	    crm_info("Forked process %lld using user %lu (%s) and group %lu "
		     "for subdaemon %s (valgrind enabled: %s)",
		     (long long) child->pid, (unsigned long) uid,
		     pcmk__s(child->uid, "root"), (unsigned long) gid, name,
		     PCMK__VALGRIND_EXEC);
	} else {
	    crm_info("Forked process %lld using user %lu (%s) and group %lu "
		     "for subdaemon %s",
		     (long long) child->pid, (unsigned long) uid,
		     pcmk__s(child->uid, "root"), (unsigned long) gid, name);
	}

        return pcmk_rc_ok;

    } else {
        /* Start a new session */
        (void)setsid();

        /* Setup the two alternate arg arrays */
        opts_vgrind[0] = pcmk__str_copy(PCMK__VALGRIND_EXEC);
        if (use_callgrind) {
            opts_vgrind[1] = pcmk__str_copy("--tool=callgrind");
            opts_vgrind[2] = pcmk__str_copy("--callgrind-out-file="
                                            CRM_STATE_DIR "/callgrind.out.%p");
            opts_vgrind[3] = subdaemon_path(child);
            opts_vgrind[4] = NULL;
        } else {
            opts_vgrind[1] = subdaemon_path(child);
            opts_vgrind[2] = NULL;
            opts_vgrind[3] = NULL;
            opts_vgrind[4] = NULL;
        }
        opts_default[0] = subdaemon_path(child);

        if(gid) {
            // Drop root group access if not needed
            if (!need_root_group && (setgid(gid) < 0)) {
                crm_warn("Could not set subdaemon %s group to %lu: %s",
                         name, (unsigned long) gid, strerror(errno));
            }

            /* Initialize supplementary groups to only those always granted to
             * the user, plus haclient (so we can access IPC).
             */
            if (initgroups(child->uid, gid) < 0) {
                crm_err("Cannot initialize system groups for subdaemon %s: %s "
                        QB_XS " errno=%d",
                        name, pcmk_rc_str(errno), errno);
            }
        }

        if (uid && setuid(uid) < 0) {
            crm_warn("Could not set subdaemon %s user to %s: %s "
                     QB_XS " uid=%lu errno=%d",
                     name, strerror(errno), child->uid, (unsigned long) uid,
                     errno);
        }

        pcmk__close_fds_in_child(true);

        pcmk__open_devnull(O_RDONLY);   // stdin (fd 0)
        pcmk__open_devnull(O_WRONLY);   // stdout (fd 1)
        pcmk__open_devnull(O_WRONLY);   // stderr (fd 2)

        if (use_valgrind) {
            (void)execvp(PCMK__VALGRIND_EXEC, opts_vgrind);
        } else {
            char *path = subdaemon_path(child);

            (void) execvp(path, opts_default);
            free(path);
        }
        crm_crit("Could not execute subdaemon %s: %s", name, strerror(errno));
        crm_exit(CRM_EX_FATAL);
    }
    return pcmk_rc_ok;          /* never reached */
}

/*!
 * \internal
 * \brief Check the liveness of the child based on IPC name and PID if tracked
 *
 * \param[in,out] child  Child tracked data
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
    const char *name = pcmk__server_name(child->server);
    int rc = pcmk_rc_ipc_unresponsive;
    int legacy_rc = pcmk_ok;
    pid_t ipc_pid = 0;

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
                QB_XS " rc=%d", CRM_DAEMON_USER, pcmk_rc_str(rc), rc);
    } else {
        const char *ipc_name = pcmk__server_ipc_name(child->server);

        rc = pcmk__ipc_is_authentic_process_active(ipc_name,
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

    if (rc == pcmk_rc_ipc_unresponsive) {
        /* If we get here, a child without IPC is being tracked, no IPC liveness
         * has been detected, or IPC liveness has been detected with an
         * unexpected (but authorized) process. This is safe on FreeBSD since
         * the only change possible from a proper child's PID into "special" PID
         * of 1 behind more loosely related process.
         */
        int ret = pcmk__pid_active(child->pid, name);

        if (ipc_pid && ((ret != pcmk_rc_ok)
                        || ipc_pid == PCMK__SPECIAL_PID
                        || (pcmk__pid_active(ipc_pid, name) == pcmk_rc_ok))) {
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

/*!
 * \internal
 * \brief Initial one-off check of the pre-existing "child" processes
 *
 * With "child" process, we mean the subdaemon that defines an API end-point
 * (all of them do as of the comment) -- the possible complement is skipped
 * as it is deemed it has no such shared resources to cause conflicts about,
 * hence it can presumably be started anew without hesitation.
 * If that won't hold true in the future, the concept of a shared resource
 * will have to be generalized beyond the API end-point.
 *
 * For boundary cases that the "child" is still starting (IPC end-point is yet
 * to be witnessed), or more rarely (practically FreeBSD only), when there's
 * a pre-existing "untrackable" authentic process, we give the situation some
 * time to possibly unfold in the right direction, meaning that said socket
 * will appear or the unattainable process will disappear per the observable
 * IPC, respectively.
 *
 * \return Standard Pacemaker return code
 *
 * \note Since this gets run at the very start, \c respawn_count fields
 *       for particular children get temporarily overloaded with "rounds
 *       of waiting" tracking, restored once we are about to finish with
 *       success (i.e. returning value >=0) and will remain unrestored
 *       otherwise.  One way to suppress liveness detection logic for
 *       particular child is to set the said value to a negative number.
 */
#define WAIT_TRIES 4  /* together with interleaved sleeps, worst case ~ 1s */
int
find_and_track_existing_processes(void)
{
    bool wait_in_progress;
    int rc;
    size_t i, rounds;

    for (rounds = 1; rounds <= WAIT_TRIES; rounds++) {
        wait_in_progress = false;
        for (i = 0; i < PCMK__NELEM(pcmk_children); i++) {
            const char *name = pcmk__server_name(pcmk_children[i].server);
            const char *ipc_name = NULL;

            if (pcmk_children[i].respawn_count < 0) {
                continue;
            }

            rc = child_liveness(&pcmk_children[i]);
            if (rc == pcmk_rc_ipc_unresponsive) {
                /* As a speculation, don't give up if there are more rounds to
                 * come for other reasons, but don't artificially wait just
                 * because of this, since we would preferably start ASAP.
                 */
                continue;
            }

            // @TODO Functionize more of this to reduce nesting
            ipc_name = pcmk__server_ipc_name(pcmk_children[i].server);
            pcmk_children[i].respawn_count = rounds;
            switch (rc) {
                case pcmk_rc_ok:
                    if (pcmk_children[i].pid == PCMK__SPECIAL_PID) {
                        const char *fail_fast =
                            pcmk__env_option(PCMK__ENV_FAIL_FAST);

                        if (pcmk__is_true(fail_fast)) {
                            crm_crit("Cannot reliably track pre-existing"
                                     " authentic process behind %s IPC on this"
                                     " platform and PCMK_" PCMK__ENV_FAIL_FAST
                                     " requested", ipc_name);
                            return EOPNOTSUPP;
                        } else if (pcmk_children[i].respawn_count == WAIT_TRIES) {
                            crm_notice("Assuming pre-existing authentic, though"
                                       " on this platform untrackable, process"
                                       " behind %s IPC is stable (was in %d"
                                       " previous samples) so rather than"
                                       " bailing out (PCMK_" PCMK__ENV_FAIL_FAST
                                       " not requested), we just switch to a"
                                       " less optimal IPC liveness monitoring"
                                       " (not very suitable for heavy load)",
                                       name, WAIT_TRIES - 1);
                            crm_warn("The process behind %s IPC cannot be"
                                     " terminated, so the overall shutdown"
                                     " will get delayed implicitly (%ld s),"
                                     " which serves as a graceful period for"
                                     " its native termination if it vitally"
                                     " depends on some other daemons going"
                                     " down in a controlled way already",
                                     name, (long) SHUTDOWN_ESCALATION_PERIOD);
                        } else {
                            wait_in_progress = true;
                            crm_warn("Cannot reliably track pre-existing"
                                     " authentic process behind %s IPC on this"
                                     " platform, can still disappear in %d"
                                     " attempt(s)", ipc_name,
                                     WAIT_TRIES - pcmk_children[i].respawn_count);
                            continue;
                        }
                    }
                    crm_notice("Tracking existing %s process (pid=%lld)",
                               name,
                               (long long) PCMK__SPECIAL_PID_AS_0(
                                               pcmk_children[i].pid));
                    pcmk_children[i].respawn_count = -1;  /* 0~keep watching */
                    pcmk_children[i].flags |= child_active_before_startup;
                    break;
                case pcmk_rc_ipc_pid_only:
                    if (pcmk_children[i].respawn_count == WAIT_TRIES) {
                        crm_crit("%s IPC endpoint for existing authentic"
                                 " process %lld did not (re)appear",
                                 ipc_name,
                                 (long long) PCMK__SPECIAL_PID_AS_0(
                                                 pcmk_children[i].pid));
                        return rc;
                    }
                    wait_in_progress = true;
                    crm_warn("Cannot find %s IPC endpoint for existing"
                             " authentic process %lld, can still (re)appear"
                             " in %d attempts (?)",
                             ipc_name,
                             (long long) PCMK__SPECIAL_PID_AS_0(
                                             pcmk_children[i].pid),
                             WAIT_TRIES - pcmk_children[i].respawn_count);
                    continue;
                default:
                    crm_crit("Checked liveness of %s: %s " QB_XS " rc=%d",
                             name, pcmk_rc_str(rc), rc);
                    return rc;
            }
        }
        if (!wait_in_progress) {
            break;
        }
        pcmk__sleep_ms(250); // Wait a bit for changes to possibly happen
    }
    for (i = 0; i < PCMK__NELEM(pcmk_children); i++) {
        pcmk_children[i].respawn_count = 0;  /* restore pristine state */
    }

    pcmk__create_timer(PCMK_PROCESS_CHECK_INTERVAL, check_next_subdaemon,
                       NULL);
    return pcmk_rc_ok;
}

gboolean
init_children_processes(void *user_data)
{
    if (pcmk_get_cluster_layer() == pcmk_cluster_layer_corosync) {
        /* Corosync clusters can drop root group access, because we set
         * uidgid.gid.${gid}=1 via CMAP, which allows these processes to connect
         * to corosync.
         */
        need_root_group = false;
    }

    /* start any children that have not been detected */
    for (int i = 0; i < PCMK__NELEM(pcmk_children); i++) {
        if (pcmk_children[i].pid != 0) {
            /* we are already tracking it */
            continue;
        }

        start_child(&(pcmk_children[i]));
    }

    /* From this point on, any daemons being started will be due to
     * respawning rather than node start.
     *
     * This may be useful for the daemons to know
     */
    pcmk__set_env_option(PCMK__ENV_RESPAWNED, PCMK_VALUE_TRUE, false);
    pacemakerd_state = PCMK__VALUE_RUNNING;
    return TRUE;
}

void
pcmk_shutdown(int nsig)
{
    if (shutdown_trigger == NULL) {
        shutdown_trigger = mainloop_add_trigger(G_PRIORITY_HIGH, pcmk_shutdown_worker, NULL);
    }
    mainloop_set_trigger(shutdown_trigger);
}

void
restart_cluster_subdaemons(void)
{
    for (int i = 0; i < PCMK__NELEM(pcmk_children); i++) {
        if (!pcmk_is_set(pcmk_children[i].flags, child_needs_retry) || pcmk_children[i].pid != 0) {
            continue;
        }

        crm_notice("Respawning cluster-based subdaemon %s",
                   pcmk__server_name(pcmk_children[i].server));
        if (start_child(&pcmk_children[i])) {
            pcmk_children[i].flags &= ~child_needs_retry;
        }
    }
}

static gboolean
stop_child(pcmk_child_t * child, int signal)
{
    const char *name = pcmk__server_name(child->server);

    if (signal == 0) {
        signal = SIGTERM;
    }

    /* why to skip PID of 1?
       - FreeBSD ~ how untrackable process behind IPC is masqueraded as
       - elsewhere: how "init" task is designated; in particular, in systemd
         arrangement of socket-based activation, this is pretty real */
    if (child->pid == PCMK__SPECIAL_PID) {
        crm_debug("Nothing to do to stop subdaemon %s[%lld]",
                  name, (long long) PCMK__SPECIAL_PID_AS_0(child->pid));
        return TRUE;
    }

    if (child->pid <= 0) {
        crm_trace("Nothing to do to stop subdaemon %s: Not running", name);
        return TRUE;
    }

    errno = 0;
    if (kill(child->pid, signal) == 0) {
        crm_notice("Stopping subdaemon %s "
                   QB_XS " via signal %d to process %lld",
                   name, signal, (long long) child->pid);
    } else {
        crm_err("Could not stop subdaemon %s[%lld] with signal %d: %s",
                name, (long long) child->pid, signal, strerror(errno));
    }

    return TRUE;
}
