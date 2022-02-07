/*
 * Copyright 2004-2020 the Pacemaker project contributors
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
pcmk__pid_active(pid_t pid, const char *daemon)
{
    static pid_t last_asked_pid = 0;  /* log spam prevention */
#if SUPPORT_PROCFS
    static int have_proc_pid = 0;
#else
    static int have_proc_pid = -1;
#endif
    int rc = 0;
    bool no_name_check = ((daemon == NULL) || (have_proc_pid == -1));

    if (have_proc_pid == 0) {
        /* evaluation of /proc/PID/exe applicability via self-introspection */
        char proc_path[PATH_MAX], exe_path[PATH_MAX];
        snprintf(proc_path, sizeof(proc_path), "/proc/%lld/exe",
                 (long long) getpid());
        have_proc_pid = 1;
        if (readlink(proc_path, exe_path, sizeof(exe_path) - 1) < 0) {
            have_proc_pid = -1;
        }
    }

    if (pid <= 0) {
        return EINVAL;
    }

    rc = kill(pid, 0);
    if ((rc < 0) && (errno == ESRCH)) {
        return ESRCH;  /* no such PID detected */

    } else if ((rc < 0) && no_name_check) {
        rc = errno;
        if (last_asked_pid != pid) {
            crm_info("Cannot examine PID %lld: %s",
                     (long long) pid, strerror(errno));
            last_asked_pid = pid;
        }
        return rc; /* errno != ESRCH */

    } else if ((rc == 0) && no_name_check) {
        return pcmk_rc_ok; /* kill as the only indicator, cannot double check */

    } else if (daemon != NULL) {
        /* make sure PID hasn't been reused by another process
           XXX: might still be just a zombie, which could confuse decisions */
        bool checked_through_kill = (rc == 0);
        char proc_path[PATH_MAX], exe_path[PATH_MAX], myexe_path[PATH_MAX];
        snprintf(proc_path, sizeof(proc_path), "/proc/%lld/exe",
                 (long long) pid);

        rc = readlink(proc_path, exe_path, sizeof(exe_path) - 1);
        if (rc < 0) {
            int rdlnk_errno = errno;

            if (rdlnk_errno != EACCES) {
                int rc = kill(pid,0); /* check once again - filter out races */

                if ((rc < 0) && (errno == ESRCH)) {
                    return ESRCH;
                }
            }
            if (last_asked_pid != pid) {
                if (rdlnk_errno == EACCES) {
                    crm_info("Could not read from %s: %s " CRM_XS " errno=%d",
                             proc_path, strerror(rdlnk_errno), rdlnk_errno);
                } else {
                    crm_err("Could not read from %s: %s " CRM_XS " errno=%d",
                            proc_path, strerror(rdlnk_errno), rdlnk_errno);
                }
                last_asked_pid = pid;
            }
            if ((rdlnk_errno == EACCES) && checked_through_kill) {
                // Trust kill result, can't double-check via path
                return pcmk_rc_ok;
            } else if (rdlnk_errno == EACCES) {
                return EACCES;
            } else {
                return ESRCH;  /* most likely errno == ENOENT */
            }
        }
        exe_path[rc] = '\0';

        if (daemon[0] != '/') {
            rc = snprintf(myexe_path, sizeof(myexe_path), CRM_DAEMON_DIR"/%s",
                          daemon);
        } else {
            rc = snprintf(myexe_path, sizeof(myexe_path), "%s", daemon);
        }

        if (rc > 0 && rc < sizeof(myexe_path) && !strcmp(exe_path, myexe_path)) {
            return pcmk_rc_ok;
        }
    }

    return ESRCH;
}

#define	LOCKSTRLEN	11

/*!
 * \internal
 * \brief Read a process ID from a file
 *
 * \param[in]  filename  Process ID file to read
 * \param[out] pid       Where to put PID that was read
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__read_pidfile(const char *filename, pid_t *pid)
{
    int fd;
    struct stat sbuf;
    int rc = pcmk_rc_unknown_format;
    long long pid_read = 0;
    char buf[LOCKSTRLEN + 1];

    CRM_CHECK((filename != NULL) && (pid != NULL), return EINVAL);

    fd = open(filename, O_RDONLY);
    if (fd < 0) {
        return errno;
    }

    if ((fstat(fd, &sbuf) >= 0) && (sbuf.st_size < LOCKSTRLEN)) {
        sleep(2);           /* if someone was about to create one,
                             * give'm a sec to do so
                             */
    }

    if (read(fd, buf, sizeof(buf)) < 1) {
        rc = errno;
        goto bail;
    }

    if (sscanf(buf, "%lld", &pid_read) > 0) {
        if (pid_read <= 0) {
            rc = ESRCH;
        } else {
            rc = pcmk_rc_ok;
            *pid = (pid_t) pid_read;
            crm_trace("Read pid %lld from %s", pid_read, filename);
        }
    }

  bail:
    close(fd);
    return rc;
}

/*!
 * \internal
 * \brief Check whether a process from a PID file matches expected values
 *
 * \param[in]  filename       Path of PID file
 * \param[in]  expected_pid   If positive, compare to this PID
 * \param[in]  expected_name  If not NULL, the PID from the PID file is valid
 *                            only if it is active as a process with this name
 * \param[out] pid            If not NULL, store PID found in PID file here
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__pidfile_matches(const char *filename, pid_t expected_pid,
                      const char *expected_name, pid_t *pid)
{
    pid_t pidfile_pid = 0;
    int rc = pcmk__read_pidfile(filename, &pidfile_pid);

    if (pid) {
        *pid = pidfile_pid;
    }

    if (rc != pcmk_rc_ok) {
        // Error reading PID file or invalid contents
        unlink(filename);
        rc = ENOENT;

    } else if ((expected_pid > 0) && (pidfile_pid == expected_pid)) {
        // PID in file matches what was expected
        rc = pcmk_rc_ok;

    } else if (pcmk__pid_active(pidfile_pid, expected_name) == ESRCH) {
        // Contains a stale value
        unlink(filename);
        rc = ENOENT;

    } else if ((expected_pid > 0) && (pidfile_pid != expected_pid)) {
        // Locked by existing process
        rc = EEXIST;
    }

    return rc;
}

/*!
 * \internal
 * \brief Create a PID file for the current process (if not already existent)
 *
 * \param[in] filename   Name of PID file to create
 * \param[in] name       Name of current process
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__lock_pidfile(const char *filename, const char *name)
{
    pid_t mypid = getpid();
    int fd = 0;
    int rc = 0;
    char buf[LOCKSTRLEN + 2];

    rc = pcmk__pidfile_matches(filename, 0, name, NULL);
    if ((rc != pcmk_rc_ok) && (rc != ENOENT)) {
        // Locked by existing process
        return rc;
    }

    fd = open(filename, O_CREAT | O_WRONLY | O_EXCL, 0644);
    if (fd < 0) {
        return errno;
    }

    snprintf(buf, sizeof(buf), "%*lld\n", LOCKSTRLEN - 1, (long long) mypid);
    rc = write(fd, buf, LOCKSTRLEN);
    close(fd);

    if (rc != LOCKSTRLEN) {
        crm_perror(LOG_ERR, "Incomplete write to %s", filename);
        return errno;
    }

    rc = pcmk__pidfile_matches(filename, mypid, name, NULL);
    if (rc != pcmk_rc_ok) {
        // Something is really wrong -- maybe I/O error on read back?
        unlink(filename);
    }
    return rc;
}
