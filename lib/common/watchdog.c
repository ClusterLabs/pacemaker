/*
 * Copyright (C) 2013 Lars Marowsky-Bree <lmb@suse.com>
 *               2014 Andrew Beekhof <andrew@beekhof.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <crm_internal.h>

#include <sched.h>
#include <syscall.h>
#include <sys/ioctl.h>
#include <sys/reboot.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ctype.h>
#include <dirent.h>

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

#define SYSRQ "/proc/sys/kernel/sysrq"

void
sysrq_init(void)
{
    static bool need_init = true;
    FILE* procf;
    int c;

    if(need_init) {
        need_init = false;
    } else {
        return;
    }

    procf = fopen(SYSRQ, "r");
    if (!procf) {
        crm_perror(LOG_ERR, "Cannot open "SYSRQ" for read");
        return;
    }
    if (fscanf(procf, "%d", &c) != 1) {
        crm_perror(LOG_ERR, "Parsing "SYSRQ" failed");
        c = 0;
    }
    fclose(procf);
    if (c == 1)
        return;

    /* 8 for debugging dumps of processes, 128 for reboot/poweroff */
    c |= 136;
    procf = fopen(SYSRQ, "w");
    if (!procf) {
        crm_perror(LOG_ERR, "Cannot write to "SYSRQ);
        return;
    }
    fprintf(procf, "%d", c);
    fclose(procf);
    return;
}

static void
sysrq_trigger(char t)
{
    FILE *procf;

    sysrq_init();

    procf = fopen("/proc/sysrq-trigger", "a");
    if (!procf) {
        crm_perror(LOG_ERR, "Opening sysrq-trigger failed");
        return;
    }
    crm_info("sysrq-trigger: %c\n", t);
    fprintf(procf, "%c\n", t);
    fclose(procf);
    return;
}


static pid_t
pcmk_locate_proc_entry(const char *name) 
{
    DIR *dp;
    struct dirent *entry;
    struct stat statbuf;

    dp = opendir("/proc");
    if (!dp) {
        /* no proc directory to search through */
        crm_notice("Can not read /proc directory to track existing components");
        return 0;
    }

    while ((entry = readdir(dp)) != NULL) {
        char procpath[128];
        char value[64];
        char key[16];
        FILE *file;
        int pid;

        strcpy(procpath, "/proc/");
        /* strlen("/proc/") + strlen("/status") + 1 = 14
         * 128 - 14 = 114 */
        strncat(procpath, entry->d_name, 114);

        if (lstat(procpath, &statbuf)) {
            continue;
        }
        if (!S_ISDIR(statbuf.st_mode) || !isdigit(entry->d_name[0])) {
            continue;
        }

        strcat(procpath, "/status");

        file = fopen(procpath, "r");
        if (!file) {
            continue;
        }
        if (fscanf(file, "%15s%63s", key, value) != 2) {
            fclose(file);
            continue;
        }
        fclose(file);

        pid = atoi(entry->d_name);
        if (pid <= 0) {
            continue;
        }

        if (safe_str_eq(name, value) && crm_pid_active(pid) == 1) {
            crm_notice("Found %s at process %d", value, pid);
            closedir(dp);
            return pid;
        }
    }

    closedir(dp);
    return 0;
}

static void
pcmk_panic_local(void) 
{
    int rc = pcmk_ok;
    uid_t uid = geteuid();
    pid_t ppid = getppid();

    if(uid != 0 && ppid > 1) {
        /* We're a non-root pacemaker daemon (cib, crmd, pengine,
         * attrd, etc) with the original pacemakerd parent
         *
         * Of these, only crmd is likely to be initiating resets
         */
        do_crm_log_always(LOG_EMERG, "Signaling parent %d to panic", ppid);
        crm_exit(pcmk_err_panic);
        return;

    } else if (uid != 0) {
        /*
         * No permissions and no pacemakerd parent to escalate to
         * Track down the new pacakerd process and send a signal instead
         */
        union sigval signal_value;

        memset(&signal_value, 0, sizeof(signal_value));
        ppid = pcmk_locate_proc_entry("pacemakerd");
        do_crm_log_always(LOG_EMERG, "Signaling pacemakerd(%d) to panic", ppid);

        if(ppid > 1 && sigqueue(ppid, SIGQUIT, signal_value) < 0) {
            crm_perror(LOG_EMERG, "Cannot signal pacemakerd(%d) to panic", ppid);
        }
        /* The best we can do now is die */
        crm_exit(pcmk_err_panic);
        return;
    }

    /* We're either pacemakerd, or a pacemaker daemon running as root */

    sysrq_trigger('b');
    /* reboot(RB_HALT_SYSTEM); rc = errno; */
    reboot(RB_AUTOBOOT);
    rc = errno;

    do_crm_log_always(LOG_EMERG, "Reboot failed, escalating to %d: %s (%d)", ppid, pcmk_strerror(rc), rc);

    if(ppid > 1) {
        /* child daemon */
        exit(pcmk_err_panic);
    } else {
        /* pacemakerd or orphan child */
        exit(DAEMON_RESPAWN_STOP);
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
        exit(pcmk_err_panic);
    } else {
        /* pacemakerd or orphan child */
        exit(DAEMON_RESPAWN_STOP);
    }
}

void
pcmk_panic(const char *origin) 
{
    static struct qb_log_callsite *panic_cs = NULL;

    if (panic_cs == NULL) {
        panic_cs = qb_log_callsite_get(__func__, __FILE__, "panic-delay", LOG_TRACE, __LINE__, crm_trace_nonlog);
    }

    pcmk_locate_sbd();

    if (panic_cs && panic_cs->targets) {
        /* getppid() == 1 means our original parent no longer exists */
        do_crm_log_always(LOG_EMERG,
                          "Shutting down instead of panicing the node: origin=%s, sbd=%d, parent=%d",
                          origin, sbd_pid, getppid());
        crm_exit(DAEMON_RESPAWN_STOP);
        return;
    }

    if(sbd_pid > 1) {
        do_crm_log_always(LOG_EMERG, "Signaling sbd(%d) to panic the system: %s", sbd_pid, origin);
        pcmk_panic_sbd();

    } else {
        do_crm_log_always(LOG_EMERG, "Panicing the system directly: %s", origin);
        pcmk_panic_local();
    }
}

pid_t
pcmk_locate_sbd(void)
{
    char *pidfile = NULL;

    if(sbd_pid > 1) {
        return sbd_pid;
    }

    /* Look for the pid file */
    pidfile = g_strdup_printf("%s/sbd.pid", HA_STATE_DIR);

    /* Read the pid file */
    if(pidfile) {
        int rc = crm_pidfile_inuse(pidfile, 1);
        if(rc < pcmk_ok && rc != -ENOENT) {
            sbd_pid = crm_read_pidfile(pidfile);
            crm_trace("SBD detected at pid=%d (file)");
        }
    }

    if(sbd_pid < 0) {
        /* Fall back to /proc for systems that support it */
        sbd_pid = pcmk_locate_proc_entry("sbd");
        crm_trace("SBD detected at pid=%d (proc)");
    }

    if(sbd_pid < 0) {
        sbd_pid = 0;
    }

    free(pidfile);
    return sbd_pid;
}
