/*
 * Copyright 2013-2020 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <sched.h>
#include <sys/ioctl.h>
#include <sys/reboot.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ctype.h>
#include <dirent.h>
#include <signal.h>

#ifdef _POSIX_MEMLOCK
#  include <sys/mman.h>
#endif

static pid_t sbd_pid = 0;

static void
sysrq_trigger(char t)
{
#if HAVE_PROCFS
    FILE *procf;

    // Root can always write here, regardless of kernel.sysrq value
    procf = fopen("/proc/sysrq-trigger", "a");
    if (!procf) {
        crm_perror(LOG_WARNING, "Opening sysrq-trigger failed");
        return;
    }
    crm_info("sysrq-trigger: %c", t);
    fprintf(procf, "%c\n", t);
    fclose(procf);
#endif // HAVE_PROCFS
    return;
}


/*!
 * \internal
 * \brief Panic the local host (if root) or tell pacemakerd to do so
 */
static void
panic_local(void)
{
    int rc = pcmk_ok;
    uid_t uid = geteuid();
    pid_t ppid = getppid();

    if(uid != 0 && ppid > 1) {
        /* We're a non-root pacemaker daemon (pacemaker-based,
         * pacemaker-controld, pacemaker-schedulerd, pacemaker-attrd, etc.) with
         * the original pacemakerd parent.
         *
         * Of these, only the controller is likely to be initiating resets.
         */
        crm_emerg("Signaling parent %lld to panic", (long long) ppid);
        crm_exit(CRM_EX_PANIC);
        return;

    } else if (uid != 0) {
#if HAVE_PROCFS
        /*
         * No permissions, and no pacemakerd parent to escalate to.
         * Track down the new pacemakerd process and send a signal instead.
         */
        union sigval signal_value;

        memset(&signal_value, 0, sizeof(signal_value));
        ppid = pcmk__procfs_pid_of("pacemakerd");
        crm_emerg("Signaling pacemakerd[%lld] to panic", (long long) ppid);

        if(ppid > 1 && sigqueue(ppid, SIGQUIT, signal_value) < 0) {
            crm_perror(LOG_EMERG, "Cannot signal pacemakerd[%lld] to panic",
                       (long long) ppid);
        }
#endif // HAVE_PROCFS

        /* The best we can do now is die */
        crm_exit(CRM_EX_PANIC);
        return;
    }

    /* We're either pacemakerd, or a pacemaker daemon running as root */

    if (pcmk__str_eq("crash", getenv("PCMK_panic_action"), pcmk__str_casei)) {
        sysrq_trigger('c');
    } else if (pcmk__str_eq("sync-crash", getenv("PCMK_panic_action"), pcmk__str_casei)) {
        sync();
        sysrq_trigger('c');
    } else {
        if (pcmk__str_eq("sync-reboot", getenv("PCMK_panic_action"), pcmk__str_casei)) {
            sync();
        }
        sysrq_trigger('b');
    }
    /* reboot(RB_HALT_SYSTEM); rc = errno; */
    reboot(RB_AUTOBOOT);
    rc = errno;

    crm_emerg("Reboot failed, escalating to parent %lld: %s " CRM_XS " rc=%d",
              (long long) ppid, pcmk_rc_str(rc), rc);

    if(ppid > 1) {
        /* child daemon */
        exit(CRM_EX_PANIC);
    } else {
        /* pacemakerd or orphan child */
        exit(CRM_EX_FATAL);
    }
}

/*!
 * \internal
 * \brief Tell sbd to kill the local host, then exit
 */
static void
panic_sbd(void)
{
    union sigval signal_value;
    pid_t ppid = getppid();

    crm_emerg("Signaling sbd[%lld] to panic", (long long) sbd_pid);

    memset(&signal_value, 0, sizeof(signal_value));
    /* TODO: Arrange for a slightly less brutal option? */
    if(sigqueue(sbd_pid, SIGKILL, signal_value) < 0) {
        crm_perror(LOG_EMERG, "Cannot signal sbd[%lld] to terminate",
                   (long long) sbd_pid);
        panic_local();
    }

    if(ppid > 1) {
        /* child daemon */
        exit(CRM_EX_PANIC);
    } else {
        /* pacemakerd or orphan child */
        exit(CRM_EX_FATAL);
    }
}

/*!
 * \internal
 * \brief Panic the local host
 *
 * Panic the local host either by sbd (if running), directly, or by asking
 * pacemakerd. If trace logging this function, exit instead.
 *
 * \param[in] origin   Function caller (for logging only)
 */
void
pcmk__panic(const char *origin)
{
    static struct qb_log_callsite *panic_cs = NULL;

    if (panic_cs == NULL) {
        panic_cs = qb_log_callsite_get(__func__, __FILE__, "panic-delay",
                                       LOG_TRACE, __LINE__, crm_trace_nonlog);
    }

    /* Ensure sbd_pid is set */
    (void) pcmk__locate_sbd();

    if (panic_cs && panic_cs->targets) {
        /* getppid() == 1 means our original parent no longer exists */
        crm_emerg("Shutting down instead of panicking the node "
                  CRM_XS " origin=%s sbd=%lld parent=%d",
                  origin, (long long) sbd_pid, getppid());
        crm_exit(CRM_EX_FATAL);
        return;
    }

    if(sbd_pid > 1) {
        crm_emerg("Signaling sbd[%lld] to panic the system: %s",
                  (long long) sbd_pid, origin);
        panic_sbd();

    } else {
        crm_emerg("Panicking the system directly: %s", origin);
        panic_local();
    }
}

/*!
 * \internal
 * \brief Return the process ID of sbd (or 0 if it is not running)
 */
pid_t
pcmk__locate_sbd(void)
{
    char *pidfile = NULL;
    char *sbd_path = NULL;
    int rc;

    if(sbd_pid > 1) {
        return sbd_pid;
    }

    /* Look for the pid file */
    pidfile = crm_strdup_printf(PCMK_RUN_DIR "/sbd.pid");
    sbd_path = crm_strdup_printf("%s/sbd", SBIN_DIR);

    /* Read the pid file */
    rc = pcmk__pidfile_matches(pidfile, 0, sbd_path, &sbd_pid);
    if (rc == pcmk_rc_ok) {
        crm_trace("SBD detected at pid %lld (via PID file %s)",
                  (long long) sbd_pid, pidfile);

#if HAVE_PROCFS
    } else {
        /* Fall back to /proc for systems that support it */
        sbd_pid = pcmk__procfs_pid_of("sbd");
        crm_trace("SBD detected at pid %lld (via procfs)",
                  (long long) sbd_pid);
#endif // HAVE_PROCFS
    }

    if(sbd_pid < 0) {
        sbd_pid = 0;
        crm_trace("SBD not detected");
    }

    free(pidfile);
    free(sbd_path);

    return sbd_pid;
}

long
pcmk__get_sbd_timeout(void)
{
    static long sbd_timeout = -2;

    if (sbd_timeout == -2) {
        sbd_timeout = crm_get_msec(getenv("SBD_WATCHDOG_TIMEOUT"));
    }
    return sbd_timeout;
}

bool
pcmk__get_sbd_sync_resource_startup(void)
{
    static int sync_resource_startup = PCMK__SBD_SYNC_DEFAULT;
    static bool checked_sync_resource_startup = false;

    if (!checked_sync_resource_startup) {
        const char *sync_env = getenv("SBD_SYNC_RESOURCE_STARTUP");

        if (sync_env == NULL) {
            crm_trace("Defaulting to %sstart-up synchronization with sbd",
                      (PCMK__SBD_SYNC_DEFAULT? "" : "no "));

        } else if (crm_str_to_boolean(sync_env, &sync_resource_startup) < 0) {
            crm_warn("Defaulting to %sstart-up synchronization with sbd "
                     "because environment value '%s' is invalid",
                     (PCMK__SBD_SYNC_DEFAULT? "" : "no "), sync_env);
        }
        checked_sync_resource_startup = true;
    }
    return sync_resource_startup != 0;
}

long
pcmk__auto_watchdog_timeout(void)
{
    long sbd_timeout = pcmk__get_sbd_timeout();

    return (sbd_timeout <= 0)? 0 : (2 * sbd_timeout);
}

bool
pcmk__valid_sbd_timeout(const char *value)
{
    long st_timeout = value? crm_get_msec(value) : 0;

    if (st_timeout < 0) {
        st_timeout = pcmk__auto_watchdog_timeout();
        crm_debug("Using calculated value %ld for stonith-watchdog-timeout (%s)",
                  st_timeout, value);
    }

    if (st_timeout == 0) {
        crm_debug("Watchdog may be enabled but stonith-watchdog-timeout is disabled (%s)",
                  value? value : "default");

    } else if (pcmk__locate_sbd() == 0) {
        crm_emerg("Shutting down: stonith-watchdog-timeout configured (%s) "
                  "but SBD not active", (value? value : "auto"));
        crm_exit(CRM_EX_FATAL);
        return false;

    } else {
        long sbd_timeout = pcmk__get_sbd_timeout();

        if (st_timeout < sbd_timeout) {
            crm_emerg("Shutting down: stonith-watchdog-timeout (%s) too short "
                      "(must be >%ldms)", value, sbd_timeout);
            crm_exit(CRM_EX_FATAL);
            return false;
        }
        crm_info("Watchdog configured with stonith-watchdog-timeout %s and SBD timeout %ldms",
                 value, sbd_timeout);
    }
    return true;
}
