/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include <glib.h>
#include <libxml/tree.h>

#include <crm/crm.h>

#include <crm/cib.h>
#include <crm/common/util.h>
#include <crm/common/xml.h>
#include <crm/cib/internal.h>
#include <crm/cluster.h>

#include <pacemaker-based.h>

crm_trigger_t *cib_writer = NULL;

int write_cib_contents(gpointer p);

static void
cib_rename(const char *old)
{
    int new_fd;
    char *new = pcmk__assert_asprintf("%s/cib.auto.XXXXXX", cib_root);

    umask(S_IWGRP | S_IWOTH | S_IROTH);
    new_fd = mkstemp(new);

    if ((new_fd < 0) || (rename(old, new) < 0)) {
        pcmk__err("Couldn't archive unusable file %s (disabling disk writes "
                  "and continuing)",
                  old);
        cib_writes_enabled = FALSE;
    } else {
        pcmk__err("Archived unusable file %s as %s", old, new);
    }

    if (new_fd > 0) {
        close(new_fd);
    }
    free(new);
}

/*
 * It is the callers responsibility to free the output of this function
 */

static xmlNode *
retrieveCib(const char *filename, const char *sigfile)
{
    xmlNode *root = NULL;
    int rc = cib_file_read_and_verify(filename, sigfile, &root);

    if (rc == pcmk_ok) {
        pcmk__info("Loaded CIB from %s (with digest %s)", filename, sigfile);
    } else {
        pcmk__warn("Continuing but NOT using CIB from %s (with digest %s): %s",
                   filename, sigfile, pcmk_strerror(rc));
        if (rc == -pcmk_err_cib_modified) {
            // Archive the original files so the contents are not lost
            cib_rename(filename);
            cib_rename(sigfile);
        }
    }
    return root;
}

static int cib_archive_filter(const struct dirent * a)
{
    int rc = 0;
    // Looking for regular files starting with "cib-" and not ending in .sig
    struct stat s;
    char *a_path = pcmk__assert_asprintf("%s/%s", cib_root, a->d_name);

    if(stat(a_path, &s) != 0) {
        rc = errno;
        pcmk__trace("%s - stat failed: %s (%d)", a->d_name, pcmk_rc_str(rc),
                    rc);
        rc = 0;

    } else if (!S_ISREG(s.st_mode)) {
        pcmk__trace("%s - wrong type (%#o)", a->d_name,
                    (unsigned int) (s.st_mode & S_IFMT));

    } else if (!g_str_has_prefix(a->d_name, "cib-")) {
        pcmk__trace("%s - wrong prefix", a->d_name);

    } else if (g_str_has_suffix(a->d_name, ".sig")) {
        pcmk__trace("%s - wrong suffix", a->d_name);

    } else {
        pcmk__debug("%s - candidate", a->d_name);
        rc = 1;
    }

    free(a_path);
    return rc;
}

static int cib_archive_sort(const struct dirent ** a, const struct dirent **b)
{
    /* Order by creation date - most recently created file first */
    int rc = 0;
    struct stat buf;

    time_t a_age = 0;
    time_t b_age = 0;

    char *a_path = pcmk__assert_asprintf("%s/%s", cib_root, a[0]->d_name);
    char *b_path = pcmk__assert_asprintf("%s/%s", cib_root, b[0]->d_name);

    if(stat(a_path, &buf) == 0) {
        a_age = buf.st_ctime;
    }
    if(stat(b_path, &buf) == 0) {
        b_age = buf.st_ctime;
    }

    free(a_path);
    free(b_path);

    if(a_age > b_age) {
        rc = 1;
    } else if(a_age < b_age) {
        rc = -1;
    }

    pcmk__trace("%s (%lu) vs. %s (%lu) : %d",
	a[0]->d_name, (unsigned long)a_age,
	b[0]->d_name, (unsigned long)b_age, rc);
    return rc;
}

xmlNode *
readCibXmlFile(const char *dir, const char *file, bool discard_status)
{
    struct dirent **namelist = NULL;

    int lpc = 0;
    char *sigfile = NULL;
    char *sigfilepath = NULL;
    char *filename = NULL;
    const char *name = NULL;
    const char *value = NULL;

    xmlNode *root = NULL;
    xmlNode *status = NULL;

    sigfile = pcmk__assert_asprintf("%s.sig", file);
    if (pcmk__daemon_can_write(dir, file) == FALSE
            || pcmk__daemon_can_write(dir, sigfile) == FALSE) {
        cib_status = EACCES;
        return NULL;
    }

    filename = pcmk__assert_asprintf("%s/%s", dir, file);
    sigfilepath = pcmk__assert_asprintf("%s/%s", dir, sigfile);
    free(sigfile);

    cib_status = pcmk_rc_ok;
    root = retrieveCib(filename, sigfilepath);
    free(filename);
    free(sigfilepath);

    if (root == NULL) {
        lpc = scandir(cib_root, &namelist, cib_archive_filter, cib_archive_sort);
        if (lpc < 0) {
            pcmk__err("Could not check for CIB backups in %s: %s", cib_root,
                      pcmk_rc_str(errno));
        }
    }

    while (root == NULL && lpc > 1) {
        int rc = pcmk_ok;

        lpc--;

        filename = pcmk__assert_asprintf("%s/%s", cib_root,
                                         namelist[lpc]->d_name);
        sigfile = pcmk__assert_asprintf("%s.sig", filename);

        rc = cib_file_read_and_verify(filename, sigfile, &root);
        if (rc == pcmk_ok) {
            pcmk__notice("Loaded CIB from last valid backup %s (with digest "
                         "%s)",
                         filename, sigfile);
        } else {
            pcmk__warn("Not using next most recent CIB backup from %s (with "
                       "digest %s): %s",
                       filename, sigfile, pcmk_strerror(rc));
        }

        free(namelist[lpc]);
        free(filename);
        free(sigfile);
    }
    free(namelist);

    if (root == NULL) {
        root = createEmptyCib(0);
        pcmk__warn("Continuing with an empty configuration");
    }

    if (cib_writes_enabled
        && pcmk__env_option_enabled(PCMK__SERVER_BASED,
                                    PCMK__ENV_VALGRIND_ENABLED)) {

        cib_writes_enabled = FALSE;
        pcmk__err("*** Disabling disk writes to avoid confusing Valgrind ***");
    }

    status = pcmk__xe_first_child(root, PCMK_XE_STATUS, NULL, NULL);
    if (discard_status && status != NULL) {
        // Strip out the PCMK_XE_STATUS section if there is one
        pcmk__xml_free(status);
        status = NULL;
    }
    if (status == NULL) {
        pcmk__xe_create(root, PCMK_XE_STATUS);
    }

    /* Do this before schema validation happens */

    /* fill in some defaults */
    value = pcmk__xe_get(root, PCMK_XA_ADMIN_EPOCH);
    if (value == NULL) { // Not possible with schema validation enabled
        pcmk__warn("Defaulting missing " PCMK_XA_ADMIN_EPOCH " to 0, but "
                   "cluster may get confused about which node's configuration "
                   "is most recent");
        pcmk__xe_set_int(root, PCMK_XA_ADMIN_EPOCH, 0);
    }

    name = PCMK_XA_EPOCH;
    value = pcmk__xe_get(root, name);
    if (value == NULL) {
        pcmk__xe_set_int(root, name, 0);
    }

    name = PCMK_XA_NUM_UPDATES;
    value = pcmk__xe_get(root, name);
    if (value == NULL) {
        pcmk__xe_set_int(root, name, 0);
    }

    // Unset (DC should set appropriate value)
    pcmk__xe_remove_attr(root, PCMK_XA_DC_UUID);

    if (discard_status) {
        crm_log_xml_trace(root, "[on-disk]");
    }

    if (!pcmk__configured_schema_validates(root)) {
        cib_status = pcmk_rc_schema_validation;
    }
    return root;
}

void
uninitializeCib(void)
{
    xmlNode *tmp_cib = the_cib;

    if (tmp_cib == NULL) {
        return;
    }

    the_cib = NULL;
    pcmk__xml_free(tmp_cib);
}

/*
 * This method will free the old CIB pointer on success and the new one
 * on failure.
 */
int
activateCibXml(xmlNode *new_cib, bool to_disk, const char *op)
{
    if (new_cib) {
        xmlNode *saved_cib = the_cib;

        pcmk__assert(new_cib != saved_cib);
        the_cib = new_cib;
        pcmk__xml_free(saved_cib);
        if (cib_writes_enabled && cib_status == pcmk_rc_ok && to_disk) {
            pcmk__debug("Triggering CIB write for %s op", op);
            mainloop_set_trigger(cib_writer);
        }
        return pcmk_ok;
    }

    pcmk__err("Ignoring invalid CIB");
    if (the_cib) {
        pcmk__warn("Reverting to last known CIB");
    } else {
        pcmk__crit("Could not write out new CIB and no saved version to revert "
                   "to");
    }
    return -ENODATA;
}

static void
cib_diskwrite_complete(mainloop_child_t * p, pid_t pid, int core, int signo, int exitcode)
{
    const char *errmsg = "Could not write CIB to disk";

    if ((exitcode != 0) && cib_writes_enabled) {
        cib_writes_enabled = FALSE;
        errmsg = "Disabling CIB disk writes after failure";
    }

    if ((signo == 0) && (exitcode == 0)) {
        pcmk__trace("Disk write [%d] succeeded", (int) pid);

    } else if (signo == 0) {
        pcmk__err("%s: process %d exited %d", errmsg, (int) pid, exitcode);

    } else {
        pcmk__err("%s: process %d terminated with signal %d (%s)%s",
                  errmsg, (int) pid, signo, strsignal(signo),
                  ((core != 0)? " and dumped core" : ""));
    }

    mainloop_trigger_complete(cib_writer);
}

int
write_cib_contents(gpointer p)
{
    int exit_rc = pcmk_ok;
    xmlNode *cib_local = NULL;

    /* Make a copy of the CIB to write (possibly in a forked child) */
    if (p) {
        /* Synchronous write out */
        cib_local = pcmk__xml_copy(NULL, p);

    } else {
        int pid = 0;
        int bb_state = qb_log_ctl(QB_LOG_BLACKBOX, QB_LOG_CONF_STATE_GET, 0);

        /* Turn it off before the fork() to avoid:
         * - 2 processes writing to the same shared mem
         * - the child needing to disable it
         *   (which would close it from underneath the parent)
         * This way, the shared mem files are already closed
         */
        qb_log_ctl(QB_LOG_BLACKBOX, QB_LOG_CONF_ENABLED, QB_FALSE);

        pid = fork();
        if (pid < 0) {
            pcmk__err("Disabling disk writes after fork failure: %s",
                      pcmk_rc_str(errno));
            cib_writes_enabled = FALSE;
            return FALSE;
        }

        if (pid) {
            /* Parent */
            mainloop_child_add(pid, 0, "disk-writer", NULL, cib_diskwrite_complete);
            if (bb_state == QB_LOG_STATE_ENABLED) {
                /* Re-enable now that it it safe */
                qb_log_ctl(QB_LOG_BLACKBOX, QB_LOG_CONF_ENABLED, QB_TRUE);
            }

            return -1;          /* -1 means 'still work to do' */
        }

        /* Asynchronous write-out after a fork() */

        /* In theory, we can scribble on the_cib here and not affect the parent,
         * but let's be safe anyway.
         */
        cib_local = pcmk__xml_copy(NULL, the_cib);
    }

    /* Write the CIB */
    exit_rc = cib_file_write_with_digest(cib_local, cib_root, "cib.xml");

    /* A nonzero exit code will cause further writes to be disabled */
    pcmk__xml_free(cib_local);
    if (p == NULL) {
        crm_exit_t exit_code = CRM_EX_OK;

        switch (exit_rc) {
            case pcmk_ok:
                exit_code = CRM_EX_OK;
                break;
            case pcmk_err_cib_modified:
                exit_code = CRM_EX_DIGEST; // Existing CIB doesn't match digest
                break;
            case pcmk_err_cib_backup: // Existing CIB couldn't be backed up
            case pcmk_err_cib_save:   // New CIB couldn't be saved
                exit_code = CRM_EX_CANTCREAT;
                break;
            default:
                exit_code = CRM_EX_ERROR;
                break;
        }

        /* Use _exit() because exit() could affect the parent adversely */
        pcmk_common_cleanup();
        _exit(exit_code);
    }
    return exit_rc;
}
