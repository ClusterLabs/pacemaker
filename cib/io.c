/*
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <crm_internal.h>

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

#include <crm/crm.h>

#include <cibio.h>
#include <crm/cib.h>
#include <crm/common/util.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/util.h>
#include <crm/cluster.h>

#define CIB_SERIES "cib"
#define CIB_SERIES_MAX 100
#define CIB_SERIES_BZIP FALSE /* Must be false due to the way archived
                               * copies are created - ie. with calls to
                               * link()
                               */

extern const char *cib_root;

crm_trigger_t *cib_writer = NULL;
gboolean initialized = FALSE;

extern int cib_status;

int write_cib_contents(gpointer p);

static gboolean
validate_cib_digest(xmlNode *local_cib, const char *sigfile)
{
    gboolean passed = FALSE;
    char *expected = crm_read_contents(sigfile);

    if (expected == NULL) {
        switch (errno) {
            case 0:
                crm_err("On-disk digest is empty");
                return FALSE;
            case ENOENT:
                crm_warn("No on-disk digest present");
                return TRUE;
            default:
                crm_perror(LOG_ERR, "Could not read on-disk digest from %s", sigfile);
                return FALSE;
        }
    }
    passed = crm_digest_verify(local_cib, expected);
    free(expected);
    return passed;
}

static gboolean
validate_on_disk_cib(const char *filename)
{
    int s_res = -1;
    struct stat buf;
    gboolean passed = TRUE;
    char *sigfile = NULL;
    xmlNode *root = NULL;

    CRM_ASSERT(filename != NULL);

    s_res = stat(filename, &buf);
    if (s_res < 0) {
        crm_perror(LOG_WARNING, "Could not validate cluster configuration file %s", filename);
    } else if (buf.st_size == 0) {
        crm_warn("Cluster configuration file %s is corrupt: size is zero", filename);
        return FALSE;
    } else {
        crm_trace("Reading cluster configuration from: %s", filename);
        root = filename2xml(filename);
        sigfile = crm_concat(filename, "sig", '.');
        if (validate_cib_digest(root, sigfile) == FALSE) {
            passed = FALSE;
        }
        free(sigfile);
        free_xml(root);
    }
    return passed;
}

static int
cib_rename(const char *old, const char *new)
{
    int rc = 0;
    int automatic_fd = 0;
    char *automatic = NULL;

    if (new == NULL) {
        umask(S_IWGRP | S_IWOTH | S_IROTH);

        automatic = g_strdup_printf("%s/cib.auto.XXXXXX", cib_root);
        automatic_fd = mkstemp(automatic);
        new = automatic;

        crm_err("Archiving corrupt or unusable file %s as %s", old, automatic);
    }

    rc = rename(old, new);
    if (rc < 0) {
        crm_perror(LOG_ERR, "Couldn't rename %s as %s - Disabling disk writes and continuing", old,
                   new);
        cib_writes_enabled = FALSE;
    }
    if (automatic_fd > 0) {
        close(automatic_fd);
    }
    free(automatic);
    return rc;
}

/*
 * It is the callers responsibility to free the output of this function
 */

static xmlNode *
retrieveCib(const char *filename, const char *sigfile, gboolean archive_invalid)
{
    struct stat buf;
    xmlNode *root = NULL;

    crm_info("Reading cluster configuration from: %s (digest: %s)", filename, sigfile);

    if (stat(filename, &buf) != 0) {
        crm_warn("Cluster configuration not found: %s", filename);
        return NULL;
    }

    root = filename2xml(filename);
    if (root == NULL) {
        crm_err("%s exists but does NOT contain valid XML. ", filename);
        crm_warn("Continuing but %s will NOT used.", filename);

    } else if (validate_cib_digest(root, sigfile) == FALSE) {
        crm_err("Checksum of %s failed!  Configuration contents ignored!", filename);
        crm_err("Usually this is caused by manual changes, "
                "please refer to http://clusterlabs.org/wiki/FAQ#cib_changes_detected");
        crm_warn("Continuing but %s will NOT used.", filename);
        free_xml(root);
        root = NULL;

        if (archive_invalid) {
            /* Archive the original files so the contents are not lost */
            cib_rename(filename, NULL);
            cib_rename(sigfile, NULL);
        }
    }
    return root;
}

/*
 * for OSs without support for direntry->d_type, like Solaris
 */
#ifndef DT_UNKNOWN
# define DT_UNKNOWN     0
# define DT_FIFO        1
# define DT_CHR         2
# define DT_DIR         4
# define DT_BLK         6
# define DT_REG         8
# define DT_LNK         10
# define DT_SOCK        12
# define DT_WHT         14
#endif /*DT_UNKNOWN*/

static int cib_archive_filter(const struct dirent * a)
{
    int rc = 0;
    /* Looking for regular files (d_type = 8) starting with 'cib-' and not ending in .sig */
    struct stat s;
    char *a_path = g_strdup_printf("%s/%s", cib_root, a->d_name);

    if(stat(a_path, &s) != 0) {
        rc = errno;
        crm_trace("%s - stat failed: %s (%d)", a->d_name, pcmk_strerror(rc), rc);
        rc = 0;

    } else if ((s.st_mode & S_IFREG) != S_IFREG) {
        unsigned char dtype;
#ifdef HAVE_STRUCT_DIRENT_D_TYPE
        dtype = a->d_type;
#else
        switch (s.st_mode & S_IFMT) {
            case S_IFREG:  dtype = DT_REG;      break;
            case S_IFDIR:  dtype = DT_DIR;      break;
            case S_IFCHR:  dtype = DT_CHR;      break;
            case S_IFBLK:  dtype = DT_BLK;      break;
            case S_IFLNK:  dtype = DT_LNK;      break;
            case S_IFIFO:  dtype = DT_FIFO;     break;
            case S_IFSOCK: dtype = DT_SOCK;     break;
            default:       dtype = DT_UNKNOWN;  break;
        }
#endif
         crm_trace("%s - wrong type (%d)", a->d_name, dtype);

    } else if(strstr(a->d_name, "cib-") != a->d_name) {
        crm_trace("%s - wrong prefix", a->d_name);

    } else if(strstr(a->d_name, ".sig") != NULL) {
        crm_trace("%s - wrong suffix", a->d_name);

    } else {
        crm_debug("%s - candidate", a->d_name);
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

    char *a_path = g_strdup_printf("%s/%s", cib_root, a[0]->d_name);
    char *b_path = g_strdup_printf("%s/%s", cib_root, b[0]->d_name);

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

    crm_trace("%s (%u) vs. %s (%u) : %d", a[0]->d_name, a_age, b[0]->d_name, b_age, rc);
    return rc;
}

xmlNode *
readCibXmlFile(const char *dir, const char *file, gboolean discard_status)
{
    struct dirent **namelist = NULL;

    int lpc = 0;
    char *sigfile = NULL;
    char *filename = NULL;
    const char *name = NULL;
    const char *value = NULL;
    const char *validation = NULL;
    const char *use_valgrind = getenv("PCMK_valgrind_enabled");

    xmlNode *root = NULL;
    xmlNode *status = NULL;

    if (!crm_is_writable(dir, file, CRM_DAEMON_USER, NULL, FALSE)) {
        cib_status = -EACCES;
        return NULL;
    }

    filename = crm_concat(dir, file, '/');
    sigfile = crm_concat(filename, "sig", '.');

    cib_status = pcmk_ok;
    root = retrieveCib(filename, sigfile, TRUE);
    free(filename);
    free(sigfile);

    if (root == NULL) {
        crm_warn("Primary configuration corrupt or unusable, trying backups in %s", cib_root);
        lpc = scandir(cib_root, &namelist, cib_archive_filter, cib_archive_sort);
        if (lpc < 0) {
            crm_perror(LOG_NOTICE, "scandir(%s) failed", cib_root);
        }
    }

    while (root == NULL && lpc > 1) {
        crm_debug("Testing %d candidates", lpc);

        lpc--;

        filename = g_strdup_printf("%s/%s", cib_root, namelist[lpc]->d_name);
        sigfile = crm_concat(filename, "sig", '.');

        root = retrieveCib(filename, sigfile, FALSE);
        if(root) {
            crm_notice("Continuing with last valid configuration archive: %s", filename);
        }

        free(namelist[lpc]);
        free(filename);
        free(sigfile);
    }
    free(namelist);

    if (root == NULL) {
        root = createEmptyCib(0);
        crm_warn("Continuing with an empty configuration.");
    }

    if (cib_writes_enabled && use_valgrind) {
        if (crm_is_true(use_valgrind) || strstr(use_valgrind, "cib")) {
            cib_writes_enabled = FALSE;
            crm_err("*********************************************************");
            crm_err("*** Disabling disk writes to avoid confusing Valgrind ***");
            crm_err("*********************************************************");
        }
    }

    status = find_xml_node(root, XML_CIB_TAG_STATUS, FALSE);
    if (discard_status && status != NULL) {
        /* strip out the status section if there is one */
        free_xml(status);
        status = NULL;
    }
    if (status == NULL) {
        create_xml_node(root, XML_CIB_TAG_STATUS);
    }

    /* Do this before DTD validation happens */

    /* fill in some defaults */
    name = XML_ATTR_GENERATION_ADMIN;
    value = crm_element_value(root, name);
    if (value == NULL) {
        crm_warn("No value for %s was specified in the configuration.", name);
        crm_warn("The reccomended course of action is to shutdown,"
                 " run crm_verify and fix any errors it reports.");
        crm_warn("We will default to zero and continue but may get"
                 " confused about which configuration to use if"
                 " multiple nodes are powered up at the same time.");
        crm_xml_add_int(root, name, 0);
    }

    name = XML_ATTR_GENERATION;
    value = crm_element_value(root, name);
    if (value == NULL) {
        crm_xml_add_int(root, name, 0);
    }

    name = XML_ATTR_NUMUPDATES;
    value = crm_element_value(root, name);
    if (value == NULL) {
        crm_xml_add_int(root, name, 0);
    }

    /* unset these and require the DC/CCM to update as needed */
    xml_remove_prop(root, XML_ATTR_DC_UUID);

    if (discard_status) {
        crm_log_xml_trace(root, "[on-disk]");
    }

    validation = crm_element_value(root, XML_ATTR_VALIDATION);
    if (validate_xml(root, NULL, TRUE) == FALSE) {
        crm_err("CIB does not validate with %s", crm_str(validation));
        cib_status = -pcmk_err_schema_validation;

    } else if (validation == NULL) {
        int version = 0;

        update_validation(&root, &version, 0, FALSE, FALSE);
        if (version > 0) {
            crm_notice("Enabling %s validation on"
                       " the existing (sane) configuration", get_schema_name(version));
        } else {
            crm_err("CIB does not validate with any known DTD or schema");
            cib_status = -pcmk_err_schema_validation;
        }
    }

    return root;
}

/*
 * The caller should never free the return value
 */
xmlNode *
get_the_CIB(void)
{
    return the_cib;
}

gboolean
uninitializeCib(void)
{
    xmlNode *tmp_cib = the_cib;

    if (tmp_cib == NULL) {
        crm_debug("The CIB has already been deallocated.");
        return FALSE;
    }

    initialized = FALSE;
    the_cib = NULL;

    crm_debug("Deallocating the CIB.");

    free_xml(tmp_cib);

    crm_debug("The CIB has been deallocated.");

    return TRUE;
}

/*
 * This method will not free the old CIB pointer or the new one.
 * We rely on the caller to have saved a pointer to the old CIB
 *   and to free the old/bad one depending on what is appropriate.
 */
gboolean
initializeCib(xmlNode * new_cib)
{
    if (new_cib == NULL) {
        return FALSE;
    }

    the_cib = new_cib;
    initialized = TRUE;
    return TRUE;
}

/*
 * This method will free the old CIB pointer on success and the new one
 * on failure.
 */
int
activateCibXml(xmlNode * new_cib, gboolean to_disk, const char *op)
{
    xmlNode *saved_cib = the_cib;

    CRM_ASSERT(new_cib != saved_cib);
    if (initializeCib(new_cib) == FALSE) {
        free_xml(new_cib);
        crm_err("Ignoring invalid or NULL CIB");

        if (saved_cib != NULL) {
            crm_warn("Reverting to last known CIB");
            if (initializeCib(saved_cib) == FALSE) {
                /* oh we are so dead  */
                crm_crit("Couldn't re-initialize the old CIB!");
                exit(1);
            }

        } else {
            crm_crit("Could not write out new CIB and no saved" " version to revert to");
        }
        return -ENODATA;
    }

    free_xml(saved_cib);
    if (cib_writes_enabled && cib_status == pcmk_ok && to_disk) {
        crm_debug("Triggering CIB write for %s op", op);
        mainloop_set_trigger(cib_writer);
    }

    return pcmk_ok;
}

static void
cib_diskwrite_complete(mainloop_child_t * p, pid_t pid, int core, int signo, int exitcode)
{
    if (signo) {
        crm_notice("Disk write process terminated with signal %d (pid=%d, core=%d)", signo, pid,
                   core);

    } else  {
        do_crm_log(exitcode == 0 ? LOG_TRACE : LOG_ERR, "Disk write process exited (pid=%d, rc=%d)",
                   pid, exitcode);
    }

    if (exitcode != 0 && cib_writes_enabled) {
        crm_err("Disabling disk writes after write failure");
        cib_writes_enabled = FALSE;
    }

    mainloop_trigger_complete(cib_writer);
}

int
write_cib_contents(gpointer p)
{
    int exit_rc = pcmk_ok;
    char *digest = NULL;
    xmlNode *cib_status_root = NULL;

    xmlNode *cib_local = NULL;
    xmlNode *cib_tmp = NULL;

    int tmp_cib_fd = 0;
    int tmp_digest_fd = 0;
    char *tmp_cib = NULL;
    char *tmp_digest = NULL;

    char *digest_file = NULL;
    char *primary_file = NULL;

    char *backup_file = NULL;
    char *backup_digest = NULL;

    const char *epoch = NULL;
    const char *admin_epoch = NULL;

    if (p) {
        /* Synchronous write out */
        cib_local = copy_xml(p);

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
            crm_perror(LOG_ERR, "Disabling disk writes after fork failure");
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

        /* A-synchronous write out after a fork() */

        /* In theory we can scribble on "the_cib" here and not affect the parent
         * But lets be safe anyway
         */
        cib_local = copy_xml(the_cib);
    }

    epoch = crm_element_value(cib_local, XML_ATTR_GENERATION);
    admin_epoch = crm_element_value(cib_local, XML_ATTR_GENERATION_ADMIN);

    primary_file = crm_concat(cib_root, "cib.xml", '/');
    digest_file = crm_concat(primary_file, "sig", '.');

    /* Always write out with num_updates=0 */
    crm_xml_add(cib_local, XML_ATTR_NUMUPDATES, "0");

    /* check the admin didn't modify it underneath us */
    if (validate_on_disk_cib(primary_file) == FALSE) {
        crm_err("%s was manually modified while the cluster was active!", primary_file);
        exit_rc = pcmk_err_cib_modified;
        goto cleanup;

    } else {
        int rc = 0;
        int seq = get_last_sequence(cib_root, CIB_SERIES);

        backup_file = generate_series_filename(cib_root, CIB_SERIES, seq, CIB_SERIES_BZIP);
        backup_digest = crm_concat(backup_file, "sig", '.');

        unlink(backup_file);
        unlink(backup_digest);

        rc = link(primary_file, backup_file);
        if (rc < 0) {
            rc = errno;
            switch(rc) {
                case ENOENT:
                    /* No file to back up */
                    goto writeout;
                    break;
                default:
                    exit_rc = pcmk_err_cib_backup;
                    crm_err("Cannot link %s to %s: %s (%d)", primary_file, backup_file, pcmk_strerror(rc), rc);
            }
            goto cleanup;
        }

        rc = link(digest_file, backup_digest);
        if (rc < 0 && errno != ENOENT) {
            exit_rc = pcmk_err_cib_backup;
            crm_perror(LOG_ERR, "Cannot link %s to %s", digest_file, backup_digest);
            goto cleanup;
        }
        write_last_sequence(cib_root, CIB_SERIES, seq + 1, CIB_SERIES_MAX);
        crm_sync_directory(cib_root);

        crm_info("Archived previous version as %s", backup_file);
    }

  writeout:
    /* Given that we discard the status section on startup
     *   there is no point writing it out in the first place
     *   since users just get confused by it
     *
     * So delete the status section before we write it out
     */
    crm_debug("Writing CIB to disk");
    if (p == NULL) {
        cib_status_root = find_xml_node(cib_local, XML_CIB_TAG_STATUS, TRUE);
        CRM_LOG_ASSERT(cib_status_root != NULL);

        if (cib_status_root != NULL) {
            free_xml(cib_status_root);
        }
    }

    tmp_cib = g_strdup_printf("%s/cib.XXXXXX", cib_root);
    tmp_digest = g_strdup_printf("%s/cib.XXXXXX", cib_root);

    umask(S_IWGRP | S_IWOTH | S_IROTH);

    tmp_cib_fd = mkstemp(tmp_cib);
    if (tmp_cib_fd < 0) {
        crm_perror(LOG_ERR, "Couldn't open temporary file %s for writing CIB", tmp_cib);
        exit_rc = pcmk_err_cib_save;
        goto cleanup;
    }

    fchmod(tmp_cib_fd, S_IRUSR | S_IWUSR); /* establish the correct permissions */
    crm_xml_add_last_written(cib_local);
    if (write_xml_fd(cib_local, tmp_cib, tmp_cib_fd, FALSE) <= 0) {
        crm_err("Changes couldn't be written to %s", tmp_cib);
        exit_rc = pcmk_err_cib_save;
        goto cleanup;
    }

    /* Calculate the digest after writing, because we updated the last-written field */
    digest = calculate_on_disk_digest(cib_local);
    CRM_ASSERT(digest != NULL);
    crm_info("Wrote version %s.%s.0 of the CIB to disk (digest: %s)",
             admin_epoch ? admin_epoch : "0", epoch ? epoch : "0", digest);

    tmp_digest_fd = mkstemp(tmp_digest);
    if ((tmp_digest_fd < 0) || (crm_write_sync(tmp_digest_fd, digest) < 0)) {
        crm_perror(LOG_ERR, "Could not write digest to file %s", tmp_digest);
        exit_rc = pcmk_err_cib_save;
        goto cleanup;
    }
    crm_debug("Wrote digest %s to disk", digest);
    cib_tmp = retrieveCib(tmp_cib, tmp_digest, FALSE);
    CRM_ASSERT(cib_tmp != NULL);
    crm_sync_directory(cib_root);

    crm_debug("Activating %s", tmp_cib);
    cib_rename(tmp_cib, primary_file);
    cib_rename(tmp_digest, digest_file);
    crm_sync_directory(cib_root);

  cleanup:
    free(backup_digest);
    free(primary_file);
    free(backup_file);
    free(digest_file);
    free(digest);
    free(tmp_digest);
    free(tmp_cib);

    free_xml(cib_tmp);
    free_xml(cib_local);

    if (p == NULL) {
        /* exit() could potentially affect the parent by closing things it shouldn't
         * Use _exit instead
         */
        _exit(exit_rc);
    }
    return exit_rc;
}
