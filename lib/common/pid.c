/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>

#include <crm/crm.h>

int
pcmk__pid_active(pid_t pid, const char *daemon)
{
    static pid_t last_asked_pid = 0;  /* log spam prevention */
    int rc = 0;

    if (pid <= 0) {
        return EINVAL;
    }

    rc = kill(pid, 0);
    if ((rc < 0) && (errno == ESRCH)) {
        return ESRCH;  /* no such PID detected */

    } else if ((daemon == NULL) || !pcmk__procfs_has_pids()) {
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
        bool paths_equal = false;
        char *exe_path = NULL;
        char *myexe_path = NULL;

        rc = pcmk__procfs_pid2path(pid, &exe_path);
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
                             QB_XS " rc=%d",
                             (long long) pid, pcmk_rc_str(rc), rc);
                } else {
                    crm_err("Could not get executable for PID %lld: %s "
                            QB_XS " rc=%d",
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
            myexe_path = pcmk__assert_asprintf(CRM_DAEMON_DIR "/%s", daemon);
        } else {
            myexe_path = pcmk__str_copy(daemon);
        }

        paths_equal = pcmk__str_eq(exe_path, myexe_path, pcmk__str_none);
        free(exe_path);
        free(myexe_path);
        if (paths_equal) {
            return pcmk_rc_ok;
        }
    }

    return ESRCH;
}
