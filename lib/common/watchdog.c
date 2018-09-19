/*
 * Copyright 2013 Lars Marowsky-Bree <lmb@suse.com>
 *           2014-2018 Andrew Beekhof <andrew@beekhof.net>
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

static int sbd_pid = 0;

enum pcmk_panic_flags
{
    pcmk_panic_none     = 0x00,
    pcmk_panic_delay    = 0x01,
    pcmk_panic_kdump    = 0x02,
    pcmk_panic_shutdown = 0x04,
};

#define SYSRQ  "/proc/sys/kernel/sysrq"
/* 8 for debugging dumps of processes, 128 for reboot/poweroff */
#define SYSRQ_CONTROLS_MASK  (8 | 128)

void
sysrq_init(void)
{
#if SUPPORT_PROCFS
    static bool need_init = true;
    FILE* procf;
    unsigned controls;

    if(need_init) {
        need_init = false;
    } else {
        return;
    }

    procf = fopen(SYSRQ, "r");
    if (!procf) {
        crm_perror(LOG_WARNING, "Cannot open "SYSRQ" for read");
        return;
    }
    if (fscanf(procf, "%u", &controls) != 1) {
        crm_perror(LOG_ERR, "Parsing "SYSRQ" failed");
        controls = 0;
    }
    fclose(procf);
    if (controls == 1
            || (controls & SYSRQ_CONTROLS_MASK) == SYSRQ_CONTROLS_MASK) {
        return;
    }

    controls |= SYSRQ_CONTROLS_MASK;
    procf = fopen(SYSRQ, "w");
    if (!procf) {
        crm_perror(LOG_ERR, "Cannot write to "SYSRQ);
        return;
    }
    fprintf(procf, "%u", controls);
    fclose(procf);
#endif // SUPPORT_PROCFS
    return;
}

static void
sysrq_trigger(char t)
{
#if SUPPORT_PROCFS
    FILE *procf;

    sysrq_init();

    procf = fopen("/proc/sysrq-trigger", "a");
    if (!procf) {
        crm_perror(LOG_WARNING, "Opening sysrq-trigger failed");
        return;
    }
    crm_info("sysrq-trigger: %c", t);
    fprintf(procf, "%c\n", t);
    fclose(procf);
#endif // SUPPORT_PROCFS
    return;
}


static void
pcmk_panic_local(void) 
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
        do_crm_log_always(LOG_EMERG, "Signaling parent %d to panic", ppid);
        crm_exit(CRM_EX_PANIC);
        return;

    } else if (uid != 0) {
#if SUPPORT_PROCFS
        /*
         * No permissions, and no pacemakerd parent to escalate to.
         * Track down the new pacemakerd process and send a signal instead.
         */
        union sigval signal_value;

        memset(&signal_value, 0, sizeof(signal_value));
        ppid = crm_procfs_pid_of("pacemakerd");
        do_crm_log_always(LOG_EMERG, "Signaling pacemakerd(%d) to panic", ppid);

        if(ppid > 1 && sigqueue(ppid, SIGQUIT, signal_value) < 0) {
            crm_perror(LOG_EMERG, "Cannot signal pacemakerd(%d) to panic", ppid);
        }
#endif // SUPPORT_PROCFS

        /* The best we can do now is die */
        crm_exit(CRM_EX_PANIC);
        return;
    }

    /* We're either pacemakerd, or a pacemaker daemon running as root */

    if (safe_str_eq("crash", getenv("PCMK_panic_action"))) {
        sysrq_trigger('c');
    } else {
        sysrq_trigger('b');
    }
    /* reboot(RB_HALT_SYSTEM); rc = errno; */
    reboot(RB_AUTOBOOT);
    rc = errno;

    do_crm_log_always(LOG_EMERG, "Reboot failed, escalating to %d: %s (%d)", ppid, pcmk_strerror(rc), rc);

    if(ppid > 1) {
        /* child daemon */
        exit(CRM_EX_PANIC);
    } else {
        /* pacemakerd or orphan child */
        exit(CRM_EX_FATAL);
    }
}

static void
pcmk_panic_sbd(void) 
{
    union sigval signal_value;
    pid_t ppid = getppid();

    do_crm_log_always(LOG_EMERG, "Signaling sbd(%d) to panic", sbd_pid);

    memset(&signal_value, 0, sizeof(signal_value));
    /* TODO: Arrange for a slightly less brutal option? */
    if(sigqueue(sbd_pid, SIGKILL, signal_value) < 0) {
        crm_perror(LOG_EMERG, "Cannot signal SBD(%d) to terminate", sbd_pid);
        pcmk_panic_local();
    }

    if(ppid > 1) {
        /* child daemon */
        exit(CRM_EX_PANIC);
    } else {
        /* pacemakerd or orphan child */
        exit(CRM_EX_FATAL);
    }
}

void
pcmk_panic(const char *origin) 
{
    static struct qb_log_callsite *panic_cs = NULL;

    if (panic_cs == NULL) {
        panic_cs = qb_log_callsite_get(__func__, __FILE__, "panic-delay", LOG_TRACE, __LINE__, crm_trace_nonlog);
    }

    /* Ensure sbd_pid is set */
    (void)pcmk_locate_sbd();

    if (panic_cs && panic_cs->targets) {
        /* getppid() == 1 means our original parent no longer exists */
        do_crm_log_always(LOG_EMERG,
                          "Shutting down instead of panicking the node: origin=%s, sbd=%d, parent=%d",
                          origin, sbd_pid, getppid());
        crm_exit(CRM_EX_FATAL);
        return;
    }

    if(sbd_pid > 1) {
        do_crm_log_always(LOG_EMERG, "Signaling sbd(%d) to panic the system: %s", sbd_pid, origin);
        pcmk_panic_sbd();

    } else {
        do_crm_log_always(LOG_EMERG, "Panicking the system directly: %s", origin);
        pcmk_panic_local();
    }
}

pid_t
pcmk_locate_sbd(void)
{
    char *pidfile = NULL;
    char *sbd_path = NULL;

    if(sbd_pid > 1) {
        return sbd_pid;
    }

    /* Look for the pid file */
    pidfile = crm_strdup_printf("%s/sbd.pid", HA_STATE_DIR);
    sbd_path = crm_strdup_printf("%s/sbd", SBIN_DIR);

    /* Read the pid file */
    CRM_ASSERT(pidfile);

    sbd_pid = crm_pidfile_inuse(pidfile, 0, sbd_path);
    if(sbd_pid > 0) {
        crm_trace("SBD detected at pid=%d (file)", sbd_pid);

#if SUPPORT_PROCFS
    } else {
        /* Fall back to /proc for systems that support it */
        sbd_pid = crm_procfs_pid_of("sbd");
        crm_trace("SBD detected at pid=%d (proc)", sbd_pid);
#endif // SUPPORT_PROCFS
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
crm_get_sbd_timeout(void)
{
    static long sbd_timeout = -2;

    if (sbd_timeout == -2) {
        sbd_timeout = crm_get_msec(getenv("SBD_WATCHDOG_TIMEOUT"));
    }
    return sbd_timeout;
}

long
crm_auto_watchdog_timeout()
{
    long sbd_timeout = crm_get_sbd_timeout();

    return (sbd_timeout <= 0)? 0 : (2 * sbd_timeout);
}

gboolean
check_sbd_timeout(const char *value)
{
    long st_timeout = value? crm_get_msec(value) : 0;

    if (st_timeout < 0) {
        st_timeout = crm_auto_watchdog_timeout();
        crm_debug("Using calculated value %ld for stonith-watchdog-timeout (%s)",
                  st_timeout, value);
    }

    if (st_timeout == 0) {
        crm_debug("Watchdog may be enabled but stonith-watchdog-timeout is disabled (%s)",
                  value? value : "default");

    } else if (pcmk_locate_sbd() == 0) {
        do_crm_log_always(LOG_EMERG,
                          "Shutting down: stonith-watchdog-timeout configured (%s) but SBD not active",
                          (value? value : "auto"));
        crm_exit(CRM_EX_FATAL);
        return FALSE;

    } else {
        long sbd_timeout = crm_get_sbd_timeout();

        if (st_timeout < sbd_timeout) {
            do_crm_log_always(LOG_EMERG,
                              "Shutting down: stonith-watchdog-timeout (%s) too short (must be >%ldms)",
                              value, sbd_timeout);
            crm_exit(CRM_EX_FATAL);
            return FALSE;
        }
        crm_info("Watchdog configured with stonith-watchdog-timeout %s and SBD timeout %ldms",
                 value, sbd_timeout);
    }
    return TRUE;
}
