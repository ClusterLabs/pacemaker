/*
 * Copyright 2004-2019 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include <crm/crm.h>

int
crm_pid_active(long pid, const char *daemon)
{
    static int last_asked_pid = 0;  /* log spam prevention */
#if SUPPORT_PROCFS
    static int have_proc_pid = 0;
#else
    static int have_proc_pid = -1;
#endif
    int rc = 0;

    if (have_proc_pid == 0) {
        /* evaluation of /proc/PID/exe applicability via self-introspection */
        char proc_path[PATH_MAX], exe_path[PATH_MAX];
        snprintf(proc_path, sizeof(proc_path), "/proc/%lu/exe",
                 (long unsigned int) getpid());
        have_proc_pid = 1;
        if (readlink(proc_path, exe_path, sizeof(exe_path) - 1) < 0) {
            have_proc_pid = -1;
        }
    }

    if (pid <= 0) {
        return -1;

    } else if ((rc = kill(pid, 0)) < 0 && errno == ESRCH) {
        return 0;  /* no such PID detected */

    } else if (rc < 0 && have_proc_pid == -1) {
        if (last_asked_pid != pid) {
            crm_info("Cannot examine PID %ld: %s", pid, strerror(errno));
            last_asked_pid = pid;
        }
        return -2;  /* errno != ESRCH */

    } else if (rc == 0 && (daemon == NULL || have_proc_pid == -1)) {
        return 1;  /* kill as the only indicator, cannot double check */

    } else {
        /* make sure PID hasn't been reused by another process
           XXX: might still be just a zombie, which could confuse decisions */
        bool checked_through_kill = (rc == 0);
        char proc_path[PATH_MAX], exe_path[PATH_MAX], myexe_path[PATH_MAX];
        snprintf(proc_path, sizeof(proc_path), "/proc/%ld/exe", pid);

        rc = readlink(proc_path, exe_path, sizeof(exe_path) - 1);
        if ((rc < 0) && (errno == EACCES)) {
            if (last_asked_pid != pid) {
                crm_info("Could not read from %s: %s", proc_path,
                         strerror(errno));
                last_asked_pid = pid;
            }
            return checked_through_kill ? 1 : -2;
        } else if (rc < 0) {
            if (last_asked_pid != pid) {
                crm_err("Could not read from %s: %s (%d)", proc_path,
                        strerror(errno), errno);
                last_asked_pid = pid;
            }
            return 0;  /* most likely errno == ENOENT */
        }
        exe_path[rc] = '\0';

        if (daemon[0] != '/') {
            rc = snprintf(myexe_path, sizeof(myexe_path), CRM_DAEMON_DIR"/%s",
                          daemon);
        } else {
            rc = snprintf(myexe_path, sizeof(myexe_path), "%s", daemon);
        }

        if (rc > 0 && rc < sizeof(myexe_path) && !strcmp(exe_path, myexe_path)) {
            return 1;
        }
    }

    return 0;
}

#define	LOCKSTRLEN	11

long
crm_read_pidfile(const char *filename)
{
    int fd;
    struct stat sbuf;
    long pid = -ENOENT;
    char buf[LOCKSTRLEN + 1];

    fd = open(filename, O_RDONLY);
    if (fd < 0) {
        goto bail;
    }

    if ((fstat(fd, &sbuf) >= 0) && (sbuf.st_size < LOCKSTRLEN)) {
        sleep(2);           /* if someone was about to create one,
                             * give'm a sec to do so
                             */
    }

    if (read(fd, buf, sizeof(buf)) < 1) {
        goto bail;
    }

    if (sscanf(buf, "%ld", &pid) > 0) {
        if (pid <= 0) {
            pid = -ESRCH;
        } else {
            crm_trace("Got pid %lu from %s\n", pid, filename);
        }
    }

  bail:
    if (fd >= 0) {
        close(fd);
    }
    return pid;
}

long
crm_pidfile_inuse(const char *filename, long mypid, const char *daemon)
{
    long pid = crm_read_pidfile(filename);

    if (pid < 2) {
        // Invalid pid
        pid = -ENOENT;
        unlink(filename);

    } else if (mypid && (pid == mypid)) {
        // In use by us
        pid = pcmk_ok;

    } else if (crm_pid_active(pid, daemon) == FALSE) {
        // Contains a stale value
        unlink(filename);
        pid = -ENOENT;

    } else if (mypid && (pid != mypid)) {
        // Locked by existing process
        pid = -EEXIST;
    }

    return pid;
}

int
crm_lock_pidfile(const char *filename, const char *name)
{
    long mypid = 0;
    int fd = 0;
    int rc = 0;
    char buf[LOCKSTRLEN + 2];

    mypid = (unsigned long) getpid();

    rc = crm_pidfile_inuse(filename, 0, name);
    if (rc == -ENOENT) {
        // Exists, but the process is not active

    } else if (rc != pcmk_ok) {
        // Locked by existing process
        return rc;
    }

    fd = open(filename, O_CREAT | O_WRONLY | O_EXCL, 0644);
    if (fd < 0) {
        return -errno;
    }

    snprintf(buf, sizeof(buf), "%*ld\n", LOCKSTRLEN - 1, mypid);
    rc = write(fd, buf, LOCKSTRLEN);
    close(fd);

    if (rc != LOCKSTRLEN) {
        crm_perror(LOG_ERR, "Incomplete write to %s", filename);
        return -errno;
    }

    return crm_pidfile_inuse(filename, mypid, name);
}
