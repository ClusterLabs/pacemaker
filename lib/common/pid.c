/*
 * Copyright 2004-2022 the Pacemaker project contributors
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

    if (have_proc_pid == 0) {
        /* evaluation of /proc/PID/exe applicability via self-introspection */
        char path[PATH_MAX];

        if (pcmk__procfs_pid2path(getpid(), path, sizeof(path)) == pcmk_rc_ok) {
            have_proc_pid = 1;
        } else {
            have_proc_pid = -1;
        }
    }

    if (pid <= 0) {
        return EINVAL;
    }

    rc = kill(pid, 0);
    if ((rc < 0) && (errno == ESRCH)) {
        return ESRCH;  /* no such PID detected */

    } else if ((daemon == NULL) || (have_proc_pid == -1)) {
        // The kill result is all we have, we can't check the name

        if (rc == 0) {
            return pcmk_rc_ok;
        }
        rc = errno;
        if (last_asked_pid != pid) {
            crm_info("Cannot examine PID %lld: %s",
                     (long long) pid, pcmk_rc_str(rc));
            last_asked_pid = pid;
        }
        return rc; /* errno != ESRCH */

    } else {
        /* make sure PID hasn't been reused by another process
           XXX: might still be just a zombie, which could confuse decisions */
        bool checked_through_kill = (rc == 0);
        char exe_path[PATH_MAX], myexe_path[PATH_MAX];

        rc = pcmk__procfs_pid2path(pid, exe_path, sizeof(exe_path));
        if (rc != pcmk_rc_ok) {
            if (rc != EACCES) {
                // Check again to filter out races
                if ((kill(pid, 0) < 0) && (errno == ESRCH)) {
                    return ESRCH;
                }
            }
            if (last_asked_pid != pid) {
                if (rc == EACCES) {
                    crm_info("Could not get executable for PID %lld: %s "
                             CRM_XS " rc=%d",
                             (long long) pid, pcmk_rc_str(rc), rc);
                } else {
                    crm_err("Could not get executable for PID %lld: %s "
                            CRM_XS " rc=%d",
                            (long long) pid, pcmk_rc_str(rc), rc);
                }
                last_asked_pid = pid;
            }
            if (rc == EACCES) {
                // Trust kill if it was OK (we can't double-check via path)
                return checked_through_kill? pcmk_rc_ok : EACCES;
            } else {
                return ESRCH;  /* most likely errno == ENOENT */
            }
        }

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
