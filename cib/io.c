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
#include <crm/cib/internal.h>
#include <crm/cluster.h>

extern const char *cib_root;

crm_trigger_t *cib_writer = NULL;
gboolean initialized = FALSE;

extern int cib_status;

int write_cib_contents(gpointer p);

static void
cib_rename(const char *old)
{
    int new_fd;
    char *new = g_strdup_printf("%s/cib.auto.XXXXXX", cib_root);

    crm_err("Archiving unusable file %s as %s", old, new);
    umask(S_IWGRP | S_IWOTH | S_IROTH);
    if ((new_fd = mkstemp(new) < 0) || (rename(old, new) < 0)) {
        crm_perror(LOG_ERR, "Couldn't rename %s as %s", old, new);
        crm_err("Disabling disk writes and continuing");
        cib_writes_enabled = FALSE;
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

    switch (cib_file_read_and_verify(filename, sigfile, &root)) {
        case -pcmk_err_cib_corrupt:
            crm_warn("Continuing but %s will NOT be used.", filename);
            break;

        case -pcmk_err_cib_modified:
            /* Archive the original files so the contents are not lost */
            crm_warn("Continuing but %s will NOT be used.", filename);
            cib_rename(filename);
            cib_rename(sigfile);
            break;
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
    root = retrieveCib(filename, sigfile);
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

        if (cib_file_read_and_verify(filename, sigfile, &root) < 0) {
            crm_warn("Continuing but %s will NOT be used.", filename);
        } else {
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
    xmlNode *cib_local = NULL;

    /* Make a copy of the CIB to write (possibly in a forked child) */
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

    /* Write the CIB */
    exit_rc = cib_file_write_with_digest(cib_local, cib_root, "cib.xml");

    /* A nonzero exit code will cause further writes to be disabled */
    free_xml(cib_local);
    if (p == NULL) {
        /* Use _exit() because exit() could affect the parent adversely */
        _exit(exit_rc);
    }
    return exit_rc;
}
