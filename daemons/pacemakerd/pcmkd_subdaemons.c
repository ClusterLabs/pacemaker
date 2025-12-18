/*
 * Copyright 2010-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <errno.h>                      // errno, EAGAIN, EINVAL, EACCES
#include <grp.h>                        // initgroups
#include <signal.h>                     // SIGTERM, SIGKILL, kill, size_t
#include <stdbool.h>                    // true, bool, false
#include <stdint.h>                     // UINT32_C, uint32_t
#include <stdio.h>                      // NULL
#include <stdlib.h>                     // free
#include <string.h>                     // strerror, strsignal, strstr
#include <sys/types.h>                  // pid_t, gid_t, uid_t, time_t
#include <syslog.h>                     // LOG_ERR, LOG_WARNING
#include <time.h>                       // time, time_t
#include <unistd.h>                     // execlp, fork, setgid, setsid

#include <glib.h>                       // gboolean, G_SOURCE_CONTINUE
#include <qb/qblog.h>                   // QB_XS

#include <crm_config.h>                 // SUPPORT_COROSYNC, CRM_DAEMON_*
#include <crm/cluster.h>                // pcmk_get_cluster_layer, pcmk_cluster_layer
#include <crm/common/ipc.h>             // pcmk_ipc_server
#include <crm/common/mainloop.h>        // mainloop_set_trigger, crm_trigger_t
#include <crm/common/options.h>         // PCMK_VALUE_TRUE
#include <crm/common/results.h>         // pcmk_rc_*, pcmk_rc_str, crm_exit*

#include "pacemakerd.h"                 // MAX_RESPAWN
#if SUPPORT_COROSYNC
#include "pcmkd_corosync.h"             // pcmkd_corosync_connected
#endif

enum child_daemon_flags {
    child_none                  = 0,
    child_respawn               = (UINT32_C(1) << 0),
    child_needs_cluster         = (UINT32_C(1) << 1),
    child_needs_retry           = (UINT32_C(1) << 2),
    child_active_before_startup = (UINT32_C(1) << 3),
    child_shutting_down         = (UINT32_C(1) << 4),

    //! Child runs as \c root if set, or as \c CRM_DAEMON_USER otherwise
    child_as_root               = (UINT32_C(1) << 5),
};

typedef struct {
    enum pcmk_ipc_server server;
    uint32_t flags;
    pid_t pid;
    int respawn_count;
    int check_count;
} pcmkd_child_t;

#define PCMK_PROCESS_CHECK_INTERVAL 1000    /* 1s */
#define PCMK_PROCESS_CHECK_RETRIES  5
#define SHUTDOWN_ESCALATION_PERIOD  180000  /* 3m */

/* Index into the array below */
#define PCMK_CHILD_CONTROLD  5

static pcmkd_child_t pcmk_children[] = {
    { pcmk_ipc_based, child_respawn|child_needs_cluster },
    { pcmk_ipc_fenced, child_respawn|child_needs_cluster|child_as_root },
    { pcmk_ipc_execd, child_respawn|child_as_root },
    { pcmk_ipc_attrd, child_respawn|child_needs_cluster },
    { pcmk_ipc_schedulerd, child_respawn },
    { pcmk_ipc_controld, child_respawn|child_needs_cluster },
};

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
bool shutdown_complete_state_reported_client_closed = false;

/* state we report when asked via pacemakerd-api status-ping */
const char *pacemakerd_state = PCMK__VALUE_INIT;
bool running_with_sbd = false;

GMainLoop *mainloop = NULL;

static bool fatal_error = false;

static int child_liveness(pcmkd_child_t *child);
static gboolean escalate_shutdown(gpointer data);
static int start_child(pcmkd_child_t *child);
static void pcmk_child_exit(mainloop_child_t * p, pid_t pid, int core, int signo, int exitcode);
static void pcmk_process_exit(pcmkd_child_t *child);
static gboolean pcmk_shutdown_worker(gpointer user_data);
static void stop_child(pcmkd_child_t *child, int signal);

static void
for_each_child(void (*fn)(pcmkd_child_t *child))
{
    for (int i = 0; i < PCMK__NELEM(pcmk_children); i++) {
        fn(&pcmk_children[i]);
    }
}

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
subdaemon_path(pcmkd_child_t *subdaemon)
{
    return pcmk__assert_asprintf(CRM_DAEMON_DIR "/%s",
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

    pcmkd_child_t *child = &(pcmk_children[next_child]);
    const char *name = pcmk__server_name(child->server);
    const long long pid = PCMK__SPECIAL_PID_AS_0(child->pid);
    int rc = child_liveness(child);

    pcmk__trace("Checked subdaemon %s[%lld]: %s (%d)", name, pid,
                pcmk_rc_str(rc), rc);

    switch (rc) {
        case pcmk_rc_ok:
            child->check_count = 0;
            subdaemon_check_progress = time(NULL);
            break;

        case pcmk_rc_ipc_pid_only: // Child was previously OK
            if (pcmk__is_set(child->flags, child_shutting_down)) {
                pcmk__notice("Subdaemon %s[%lld] has stopped accepting IPC "
                             "connections during shutdown", name, pid);

            } else if (++(child->check_count) >= PCMK_PROCESS_CHECK_RETRIES) {
                // cts-lab looks for this message
                pcmk__crit("Subdaemon %s[%lld] is unresponsive to IPC "
                           "after %d attempt%s and will now be killed",
                           name, pid, child->check_count,
                           pcmk__plural_s(child->check_count));
                stop_child(child, SIGKILL);
                if (pcmk__is_set(child->flags, child_respawn)) {
                    // Respawn limit hasn't been reached, so retry another round
                    child->check_count = 0;
                }

            } else {
                pcmk__notice("Subdaemon %s[%lld] is unresponsive to IPC after "
                             "%d attempt%s (will recheck later)",
                             name, pid, child->check_count,
                             pcmk__plural_s(child->check_count));
                if (pcmk__is_set(child->flags, child_respawn)) {
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
            if (!pcmk__is_set(child->flags, child_respawn)) {
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
            if (!pcmk__is_set(child->flags, child_active_before_startup)) {
                pcmk__trace("Subdaemon %s[%lld] terminated", name, pid);
                break;
            }
            if (pcmk__is_set(child->flags, child_respawn)) {
                // cts-lab looks for this message
                pcmk__err("Subdaemon %s[%lld] terminated", name, pid);
            } else {
                /* orderly shutdown */
                pcmk__notice("Subdaemon %s[%lld] terminated", name, pid);
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
    pcmkd_child_t *child = data;

    if (child->pid == PCMK__SPECIAL_PID) {
        pcmk_process_exit(child);

    } else if (child->pid != 0) {
        /* Use SIGSEGV instead of SIGKILL to create a core so we can see what it was up to */
        pcmk__err("Subdaemon %s not terminating in a timely manner, forcing",
                  pcmk__server_name(child->server));
        stop_child(child, SIGSEGV);
    }

    return G_SOURCE_REMOVE;
}

static void
pcmk_child_exit(mainloop_child_t * p, pid_t pid, int core, int signo, int exitcode)
{
    pcmkd_child_t *child = mainloop_child_userdata(p);
    const char *name = mainloop_child_name(p);

    if (signo) {
        // cts-lab looks for this message
        do_crm_log(((signo == SIGKILL)? LOG_WARNING : LOG_ERR),
                   "%s[%d] terminated with signal %d (%s)%s",
                   name, pid, signo, strsignal(signo),
                   (core? " and dumped core" : ""));
        pcmk_process_exit(child);
        return;
    }

    switch(exitcode) {
        case CRM_EX_OK:
            pcmk__info("%s[%d] exited with status %d (%s)", name, pid, exitcode,
                       crm_exit_str(exitcode));
            break;

        case CRM_EX_FATAL:
            pcmk__warn("Shutting cluster down because %s[%d] had fatal failure",
                       name, pid);
            child->flags &= ~child_respawn;
            fatal_error = true;
            pcmk_shutdown(SIGTERM);
            break;

        case CRM_EX_PANIC:
            {
                char *msg = NULL;

                child->flags &= ~child_respawn;
                fatal_error = true;
                msg = pcmk__assert_asprintf("Subdaemon %s[%d] requested panic",
                                            name, pid);
                pcmk__panic(msg);

                // Should never get here
                free(msg);
                pcmk_shutdown(SIGTERM);
            }
            break;

        default:
            // cts-lab looks for this message
            pcmk__err("%s[%d] exited with status %d (%s)", name, pid, exitcode,
                      crm_exit_str(exitcode));
            break;
    }

    pcmk_process_exit(child);
}

static void
pcmk_process_exit(pcmkd_child_t * child)
{
    const char *name = pcmk__server_name(child->server);
    child->pid = 0;
    child->flags &= ~child_active_before_startup;
    child->check_count = 0;

    child->respawn_count += 1;
    if (child->respawn_count > MAX_RESPAWN) {
        pcmk__err("Subdaemon %s exceeded maximum respawn count", name);
        child->flags &= ~child_respawn;
    }

    if (shutdown_trigger) {
        /* resume step-wise shutdown (returned TRUE yields no parallelizing) */
        mainloop_set_trigger(shutdown_trigger);

    } else if (!pcmk__is_set(child->flags, child_respawn)) {
        /* nothing to do */

    } else if (pcmk__is_true(pcmk__env_option(PCMK__ENV_FAIL_FAST))) {
        pcmk__panic("Subdaemon failed");

    } else if (child_liveness(child) == pcmk_rc_ok) {
        pcmk__warn("Not respawning subdaemon %s because IPC endpoint %s is OK",
                   name, pcmk__server_ipc_name(child->server));

    } else if (pcmk__is_set(child->flags, child_needs_cluster)
               && !pcmkd_cluster_connected()) {
        pcmk__notice("Not respawning subdaemon %s until cluster returns", name);
        child->flags |= child_needs_retry;

    } else {
        // cts-lab looks for this message
        pcmk__notice("Respawning subdaemon %s after unexpected exit", name);
        start_child(child);
    }
}

static gboolean
pcmk_shutdown_worker(gpointer user_data)
{
    static int phase = PCMK__NELEM(pcmk_children) - 1;
    static time_t next_log = 0;

    if (phase == PCMK__NELEM(pcmk_children) - 1) {
        pcmk__notice("Shutting down Pacemaker");
        pacemakerd_state = PCMK__VALUE_SHUTTING_DOWN;
    }

    for (; phase >= 0; phase--) {
        pcmkd_child_t *child = &(pcmk_children[phase]);
        const char *name = pcmk__server_name(child->server);
        time_t now = 0;

        if (child->pid == 0) {
            /* cleanup */
            pcmk__debug("Subdaemon %s confirmed stopped", name);
            child->pid = 0;
            continue;
        }

        now = time(NULL);

        if (pcmk__is_set(child->flags, child_respawn)) {
            if (child->pid == PCMK__SPECIAL_PID) {
                pcmk__warn("Subdaemon %s cannot be terminated (shutdown "
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
            pcmk__notice("Still waiting for subdaemon %s to terminate "
                         QB_XS " pid=%lld", name, (long long) child->pid);
        }

        return G_SOURCE_CONTINUE;
    }

    pcmk__notice("Shutdown complete");
    pacemakerd_state = PCMK__VALUE_SHUTDOWN_COMPLETE;
    if (!fatal_error && running_with_sbd &&
        pcmk__get_sbd_sync_resource_startup() &&
        !shutdown_complete_state_reported_client_closed) {
        pcmk__notice("Waiting for SBD to pick up shutdown-complete-state");
        return G_SOURCE_CONTINUE;
    }

    g_main_loop_quit(mainloop);

    if (fatal_error) {
        pcmk__notice("Shutting down and staying down after fatal error");
#if SUPPORT_COROSYNC
        pcmkd_shutdown_corosync();
#endif
        crm_exit(CRM_EX_FATAL);
    }

    return G_SOURCE_CONTINUE;
}

/* TODO once libqb is taught to juggle with IPC end-points carried over as
        bare file descriptor (https://github.com/ClusterLabs/libqb/issues/325)
        it shall hand over these descriptors here if/once they are successfully
        pre-opened in (presumably) child_liveness(), to avoid any remaining
        room for races */
 // \return Standard Pacemaker return code
static int
start_child(pcmkd_child_t * child)
{
    const bool as_root = pcmk__is_set(child->flags, child_as_root);
    const char *user = as_root? "root" : CRM_DAEMON_USER;
    uid_t uid = 0;
    gid_t gid = 0;

    bool use_valgrind = false;
    bool use_callgrind = false;
    const char *name = pcmk__server_name(child->server);
    char *path = NULL;

    child->flags &= ~(child_active_before_startup | child_shutting_down);
    child->check_count = 0;

    if (pcmk__env_option_enabled(name, PCMK__ENV_CALLGRIND_ENABLED)) {
        use_callgrind = true;
        use_valgrind = true;

    } else if (pcmk__env_option_enabled(name, PCMK__ENV_VALGRIND_ENABLED)) {
        use_valgrind = true;
    }

    if (use_valgrind && strlen(PCMK__VALGRIND_EXEC) == 0) {
        pcmk__warn("Cannot enable valgrind for subdaemon %s: valgrind not "
                   "found", name);
        use_valgrind = false;
    }

    if (!as_root) {
        int rc = pcmk__daemon_user(&uid, &gid);

        if (rc != pcmk_rc_ok) {
            pcmk__err("User %s not found for subdaemon %s: %s", user, name,
                      pcmk_rc_str(rc));
            return rc;
        }
    }

    child->pid = fork();
    pcmk__assert(child->pid != -1);

    if (child->pid > 0) {
        // Parent
        const char *valgrind_s = "";

        if (use_valgrind) {
            valgrind_s = " (valgrind enabled: " PCMK__VALGRIND_EXEC ")";
        }

        mainloop_child_add(child->pid, 0, name, child, pcmk_child_exit);

        pcmk__info("Forked process %lld using user %lld (%s) and group %lld "
                   "for subdaemon %s%s",
                   (long long) child->pid, (long long) uid, user,
                   (long long) gid, name, valgrind_s);

        return pcmk_rc_ok;
    }

    // Child
    path = subdaemon_path(child);

    // Start a new session
    setsid();

    if (gid != 0) {
        // Drop root group access if not needed
        if (!need_root_group && (setgid(gid) < 0)) {
            pcmk__warn("Could not set subdaemon %s group to %lld: %s", name,
                       (long long) gid, strerror(errno));
        }

        /* Initialize supplementary groups to only those always granted to the
         * user, plus haclient (so we can access IPC).
         *
         * @TODO initgroups() is not portable (not part of any standard).
         */
        if (initgroups(user, gid) < 0) {
            pcmk__err("Cannot initialize system groups for subdaemon %s: %s "
                      QB_XS " errno=%d",
                      name, strerror(errno), errno);
        }
    }

    if ((uid != 0) && (setuid(uid) < 0)) {
        pcmk__warn("Could not set subdaemon %s user to %s: %s "
                   QB_XS " uid=%lld errno=%d",
                   name, strerror(errno), user, (long long) uid, errno);
    }

    pcmk__close_fds_in_child();
    pcmk__null_std_streams();

    if (use_callgrind) {
        char *out_file = pcmk__str_copy("--callgrind-out-file="
                                        CRM_STATE_DIR "/callgrind.opt.%p");
        execlp(PCMK__VALGRIND_EXEC, PCMK__VALGRIND_EXEC, "--tool=callgrind",
               out_file, path, (char *) NULL);
        free(out_file);

    } else if (use_valgrind) {
        execlp(PCMK__VALGRIND_EXEC, PCMK__VALGRIND_EXEC, path, (char *) NULL);

    } else {
        execlp(path, path, (char *) NULL);
    }

    free(path);
    pcmk__crit("Could not execute subdaemon %s: %s", name, strerror(errno));
    crm_exit(CRM_EX_FATAL);
    return pcmk_rc_ok;  // Never reached
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
child_liveness(pcmkd_child_t *child)
{
    // Initialize to root UID and GID
    uid_t uid = 0;
    gid_t gid = 0;

    const char *name = pcmk__server_name(child->server);
    const char *ipc_name = pcmk__server_ipc_name(child->server);
    int rc = pcmk_rc_ok;
    pid_t ipc_pid = 0;

    if (!pcmk__is_set(child->flags, child_as_root)) {
        rc = pcmk__daemon_user(&uid, &gid);
        if (rc != pcmk_rc_ok) {
            pcmk__err("Could not find user and group IDs for user "
                      CRM_DAEMON_USER ": %s " QB_XS " rc=%d",
                      pcmk_rc_str(rc), rc);
            return rc;
        }
    }

    rc = pcmk__ipc_is_authentic_process_active(ipc_name, uid, gid, &ipc_pid);
    if (rc == pcmk_rc_ok) {
        if (child->pid == 0) {
            // Initialize the child using the found PID
            child->pid = ipc_pid;
        }
        if (child->pid == ipc_pid) {
            // The found PID matches the expected one (if any)
            return pcmk_rc_ok;
        }

    } else if (rc != pcmk_rc_ipc_unresponsive) {
        return rc;
    }

    /* If we get here, either no IPC liveness has been detected, or IPC liveness
     * has been detected with an unexpected (but authorized) process. This is
     * safe on FreeBSD since the only change possible from a proper child's PID
     * into "special" PID of 1 behind more loosely related process.
     */
    rc = pcmk__pid_active(child->pid, name);

    if ((ipc_pid != 0)
        && ((rc != pcmk_rc_ok)
            || (ipc_pid == PCMK__SPECIAL_PID)
            || (pcmk__pid_active(ipc_pid, name) == pcmk_rc_ok))) {
        /* An unexpected (but authorized) process was detected at the IPC
         * endpoint, and either it is active, or the child we're tracking is
         * not.
         */

        if (rc == pcmk_rc_ok) {
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
        child->pid = ipc_pid;
        return pcmk_rc_ok;
    }

    switch (rc) {
        case pcmk_rc_ok:
            // Our tracked child's PID was found active, but not its IPC
            return pcmk_rc_ipc_pid_only;
        case EINVAL:
            // FreeBSD can return EINVAL
            return (child->pid == 0)? pcmk_rc_ipc_unresponsive : EINVAL;
        case EACCES:
            return pcmk_rc_ipc_unauthorized;
        case ESRCH:
            return pcmk_rc_ipc_unresponsive;
        default:
            return rc;
    }
}

static void
reset_respawn_count(pcmkd_child_t *child)
{
    /* Restore pristine state */
    child->respawn_count = 0;
}

#define WAIT_TRIES 4  /* together with interleaved sleeps, worst case ~ 1s */

static int
child_up_but_no_ipc(pcmkd_child_t *child)
{
    const char *ipc_name = pcmk__server_ipc_name(child->server);

    if (child->respawn_count == WAIT_TRIES) {
        pcmk__crit("%s IPC endpoint for existing process %lld did not "
                   "(re)appear",
                   ipc_name, (long long) PCMK__SPECIAL_PID_AS_0(child->pid));
        return pcmk_rc_ipc_pid_only;
    }

    pcmk__warn("Cannot find %s IPC endpoint for existing process %ld, could "
               "still reappear in %d attempts",
               ipc_name, (long long) PCMK__SPECIAL_PID_AS_0(child->pid),
               WAIT_TRIES - child->respawn_count);
    return EAGAIN;
}

static int
child_alive(pcmkd_child_t *child)
{
    const char *name = pcmk__server_name(child->server);

    if (child->pid == PCMK__SPECIAL_PID) {
        if (pcmk__is_true(pcmk__env_option(PCMK__ENV_FAIL_FAST))) {
            pcmk__crit("Cannot track pre-existing process for %s IPC on this "
                       "platform and PCMK_" PCMK__ENV_FAIL_FAST " requested",
                       name);
            return EOPNOTSUPP;

        } else if (child->respawn_count == WAIT_TRIES) {
            /* Because PCMK__ENV_FAIL_FAST wasn't requested, we can't bail
             * out.  Instead, switch to IPC liveness monitoring which is not
             * very suitable for heavy system load.
             */
            pcmk__notice("Cannot track pre-existing process for %s IPC on this "
                         "platform but assuming it is stable and using "
                         "liveness monitoring", name);
            pcmk__warn("The process for %s IPC cannot be terminated, so "
                       "shutdown will be delayed by %d s to allow time for it "
                       "to terminate on its own",
                       name, SHUTDOWN_ESCALATION_PERIOD);

        } else {
            pcmk__warn("Cannot track pre-existing process for %s IPC on this "
                       "platform; checking %d more times",
                       name, WAIT_TRIES - child->respawn_count);
            return EAGAIN;
        }
    }

    pcmk__notice("Tracking existing %s process (pid=%lld)", name,
                 (long long) PCMK__SPECIAL_PID_AS_0(child->pid));
    child->respawn_count = -1;  /* 0~keep watching */
    child->flags |= child_active_before_startup;
    return pcmk_rc_ok;
}

static int
find_and_track_child(pcmkd_child_t *child, int rounds, bool *wait_in_progress)
{
    int rc = pcmk_rc_ok;
    const char *name = pcmk__server_name(child->server);

    if (child->respawn_count < 0) {
        return EAGAIN;
    }

    rc = child_liveness(child);
    if (rc == pcmk_rc_ipc_unresponsive) {
        /* As a speculation, don't give up if there are more rounds to
         * come for other reasons, but don't artificially wait just
         * because of this, since we would preferably start ASAP.
         */
        return EAGAIN;
    }

    child->respawn_count = rounds;

    if (rc == pcmk_rc_ok) {
        rc = child_alive(child);

        if (rc == EAGAIN) {
            *wait_in_progress = true;
        }

    } else if (rc == pcmk_rc_ipc_pid_only) {
        rc = child_up_but_no_ipc(child);

        if (rc == EAGAIN) {
            *wait_in_progress = true;
        }

    } else {
        pcmk__crit("Checked liveness of %s: %s " QB_XS " rc=%d", name,
                   pcmk_rc_str(rc), rc);
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
int
find_and_track_existing_processes(void)
{
    bool wait_in_progress;
    size_t i, rounds;

    for (rounds = 1; rounds <= WAIT_TRIES; rounds++) {
        wait_in_progress = false;

        for (i = 0; i < PCMK__NELEM(pcmk_children); i++) {
            int rc = find_and_track_child(&pcmk_children[i], rounds,
                                          &wait_in_progress);

            if (rc == pcmk_rc_ok) {
                break;
            } else if (rc != EAGAIN) {
                return rc;
            }
        }

        if (!wait_in_progress) {
            break;
        }

        pcmk__sleep_ms(250); // Wait a bit for changes to possibly happen
    }

    for_each_child(reset_respawn_count);
    pcmk__create_timer(PCMK_PROCESS_CHECK_INTERVAL, check_next_subdaemon,
                       NULL);
    return pcmk_rc_ok;
}

static void
start_subdaemon(pcmkd_child_t *child)
{
    if (child->pid != 0) {
        /* We are already tracking this process */
        return;
    }

    start_child(child);
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
    for_each_child(start_subdaemon);

    /* From this point on, any daemons being started will be due to
     * respawning rather than node start.
     *
     * This may be useful for the daemons to know
     */
    pcmk__set_env_option(PCMK__ENV_RESPAWNED, PCMK_VALUE_TRUE, false);
    pacemakerd_state = PCMK__VALUE_RUNNING;
    return G_SOURCE_CONTINUE;
}

void
pcmk_shutdown(int nsig)
{
    if (shutdown_trigger == NULL) {
        shutdown_trigger = mainloop_add_trigger(G_PRIORITY_HIGH, pcmk_shutdown_worker, NULL);
    }
    mainloop_set_trigger(shutdown_trigger);
}

static void
restart_subdaemon(pcmkd_child_t *child)
{
    if (!pcmk__is_set(child->flags, child_needs_retry) || child->pid != 0) {
        return;
    }

    pcmk__notice("Respawning cluster-based subdaemon %s",
                 pcmk__server_name(child->server));

    if (start_child(child)) {
        child->flags &= ~child_needs_retry;
    }
}

void
restart_cluster_subdaemons(void)
{
    for_each_child(restart_subdaemon);
}

static void
stop_child(pcmkd_child_t *child, int signal)
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
        pcmk__debug("Nothing to do to stop subdaemon %s[%lld]", name,
                    (long long) PCMK__SPECIAL_PID_AS_0(child->pid));
        return;
    }

    if (child->pid <= 0) {
        pcmk__trace("Nothing to do to stop subdaemon %s: Not running", name);
        return;
    }

    errno = 0;
    if (kill(child->pid, signal) == 0) {
        pcmk__notice("Stopping subdaemon %s "
                     QB_XS " via signal %d to process %lld",
                     name, signal, (long long) child->pid);
        child->flags |= child_shutting_down;

    } else {
        pcmk__err("Could not stop subdaemon %s[%lld] with signal %d: %s",
                  name, (long long) child->pid, signal, strerror(errno));
    }
}
