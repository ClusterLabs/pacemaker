/*
 * Copyright 2013-2025 the Pacemaker project contributors
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

#include <qb/qbdefs.h>      // QB_MIN(), QB_MAX()

static pid_t sbd_pid = 0;

/*!
 * \internal
 * \brief Tell pacemakerd to panic the local host
 *
 * \param[in] ppid  Process ID of parent process
 */
static void
panic_local_nonroot(pid_t ppid)
{
    if (ppid > 1) { // pacemakerd is still our parent
        crm_emerg("Escalating panic to " PCMK__SERVER_PACEMAKERD "[%lld]",
                  (long long) ppid);
    } else { // Signal (non-parent) pacemakerd if possible
        ppid = pcmk__procfs_pid_of(PCMK__SERVER_PACEMAKERD);
        if (ppid > 0) {
            union sigval signal_value;

            crm_emerg("Signaling " PCMK__SERVER_PACEMAKERD "[%lld] to panic",
                      (long long) ppid);
            memset(&signal_value, 0, sizeof(signal_value));
            if (sigqueue(ppid, SIGQUIT, signal_value) < 0) {
                crm_emerg("Exiting after signal failure: %s", strerror(errno));
            }
        } else {
            crm_emerg("Exiting with no known " PCMK__SERVER_PACEMAKERD
                      "process");
        }
    }
    crm_exit(CRM_EX_PANIC);
}

/*!
 * \internal
 * \brief Panic the local host (if root) or tell pacemakerd to do so
 */
static void
panic_local(void)
{
    const char *full_panic_action = pcmk__env_option(PCMK__ENV_PANIC_ACTION);
    const char *panic_action = full_panic_action;
    int reboot_cmd = RB_AUTOBOOT; // Default panic action is reboot

    if (geteuid() != 0) { // Non-root caller such as the controller
        panic_local_nonroot(getppid());
        return;
    }

    if (pcmk__starts_with(full_panic_action, "sync-")) {
        panic_action += sizeof("sync-") - 1;
        sync();
    }

    if (pcmk__str_empty(full_panic_action)
        || pcmk__str_eq(panic_action, PCMK_VALUE_REBOOT, pcmk__str_none)) {
        pcmk__sysrq_trigger('b');

    } else if (pcmk__str_eq(panic_action, PCMK_VALUE_CRASH, pcmk__str_none)) {
        pcmk__sysrq_trigger('c');

    } else if (pcmk__str_eq(panic_action, PCMK_VALUE_OFF, pcmk__str_none)) {
        pcmk__sysrq_trigger('o');
#ifdef RB_POWER_OFF
        reboot_cmd = RB_POWER_OFF;
#elif defined(RB_POWEROFF)
        reboot_cmd = RB_POWEROFF;
#endif
    } else {
        crm_warn("Using default '" PCMK_VALUE_REBOOT "' for local option PCMK_"
                 PCMK__ENV_PANIC_ACTION " because '%s' is not a valid value",
                 full_panic_action);
        pcmk__sysrq_trigger('b');
    }

    // sysrq failed or is not supported on this platform, so fall back to reboot
    reboot(reboot_cmd);

    // Even reboot failed, nothing left to do but exit
    crm_emerg("Exiting after reboot failed: %s", strerror(errno));
    if (getppid() > 1) { // pacemakerd is parent process
        crm_exit(CRM_EX_PANIC);
    } else { // This is pacemakerd, or an orphaned subdaemon
        crm_exit(CRM_EX_FATAL);
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

    memset(&signal_value, 0, sizeof(signal_value));
    /* TODO: Arrange for a slightly less brutal option? */
    if(sigqueue(sbd_pid, SIGKILL, signal_value) < 0) {
        crm_emerg("Panicking directly because couldn't signal sbd");
        panic_local();
    }

    if(ppid > 1) {
        /* child daemon */
        crm_exit(CRM_EX_PANIC);
    } else {
        /* pacemakerd or orphan child */
        crm_exit(CRM_EX_FATAL);
    }
}

/*!
 * \internal
 * \brief Panic the local host
 *
 * Panic the local host either by sbd (if running), directly, or by asking
 * pacemakerd. If trace logging this function, exit instead.
 *
 * \param[in] reason  Why panic is needed (for logging only)
 */
void
pcmk__panic(const char *reason)
{
    if (pcmk__locate_sbd() > 1) {
        crm_emerg("Signaling sbd[%lld] to panic the system: %s",
                  (long long) sbd_pid, reason);
        panic_sbd();

    } else {
        crm_emerg("Panicking the system directly: %s", reason);
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
    const char *pidfile = PCMK__RUN_DIR "/sbd.pid";
    int rc;

    if(sbd_pid > 1) {
        return sbd_pid;
    }

    /* Read the pid file */
    rc = pcmk__pidfile_matches(pidfile, 0, SBIN_DIR "/sbd", &sbd_pid);
    if (rc == pcmk_rc_ok) {
        crm_trace("SBD detected at pid %lld (via PID file %s)",
                  (long long) sbd_pid, pidfile);
    } else {
        /* Fall back to /proc for systems that support it */
        sbd_pid = pcmk__procfs_pid_of("sbd");

        if (sbd_pid != 0) {
            crm_trace("SBD detected at pid %lld (via procfs)",
                      (long long) sbd_pid);
        }
    }

    if(sbd_pid < 0) {
        sbd_pid = 0;
        crm_trace("SBD not detected");
    }

    return sbd_pid;
}

// 0 <= return value <= LONG_MAX
long
pcmk__get_sbd_watchdog_timeout(void)
{
    static long sbd_timeout = -2;

    if (sbd_timeout == -2) {
        long long timeout = crm_get_msec(getenv("SBD_WATCHDOG_TIMEOUT"));

        timeout = QB_MAX(timeout, 0);
        sbd_timeout = (long) QB_MIN(timeout, LONG_MAX);
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

// 0 <= return value <= min(LONG_MAX, (2 * SBD timeout))
long
pcmk__auto_stonith_watchdog_timeout(void)
{
    long sbd_timeout = pcmk__get_sbd_watchdog_timeout();
    long long st_timeout = 2 * (long long) sbd_timeout;

    return (long) QB_MIN(st_timeout, LONG_MAX);
}

bool
pcmk__valid_stonith_watchdog_timeout(const char *value)
{
    /* @COMPAT At a compatibility break, accept either negative values or a
     * specific string like "auto" (but not both) to mean "auto-calculate the
     * timeout." Reject other values that aren't parsable as timeouts.
     */
    long long st_timeout = 0;

    if (value != NULL) {
        st_timeout = crm_get_msec(value);
        st_timeout = QB_MIN(st_timeout, LONG_MAX);
    }

    if (st_timeout < 0) {
        st_timeout = pcmk__auto_stonith_watchdog_timeout();

        // At this point, 0 <= sbd_timeout <= st_timeout
        crm_debug("Using calculated value %lld for "
                  PCMK_OPT_STONITH_WATCHDOG_TIMEOUT " (%s)",
                  st_timeout, value);
    }

    if (st_timeout == 0) {
        crm_debug("Watchdog may be enabled but "
                  PCMK_OPT_STONITH_WATCHDOG_TIMEOUT " is disabled (%s)",
                  value? value : "default");

    } else if (pcmk__locate_sbd() == 0) {
        crm_emerg("Shutting down: " PCMK_OPT_STONITH_WATCHDOG_TIMEOUT
                  " configured (%s) but SBD not active",
                  pcmk__s(value, "auto"));
        crm_exit(CRM_EX_FATAL);
        return false;

    } else {
        long sbd_timeout = pcmk__get_sbd_watchdog_timeout();

        if (st_timeout < sbd_timeout) {
            /* Passed-in value for PCMK_OPT_STONITH_WATCHDOG_TIMEOUT was
             * parsable, positive, and less than the SBD_WATCHDOG_TIMEOUT
             */
            crm_emerg("Shutting down: " PCMK_OPT_STONITH_WATCHDOG_TIMEOUT
                      " (%s) too short (must be >%ldms)",
                      value, sbd_timeout);
            crm_exit(CRM_EX_FATAL);
            return false;
        }
        crm_info("Watchdog configured with " PCMK_OPT_STONITH_WATCHDOG_TIMEOUT
                 " %s and SBD timeout %ldms",
                 value, sbd_timeout);
    }
    return true;
}
