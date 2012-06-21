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

#include <sys/param.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>

#include <crm/crm.h>

#include <cibio.h>
#include <crm/cib.h>
#include <crm/common/util.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/util.h>
#include <crm/cluster.h>

#define CIB_SERIES "cib"

extern const char *cib_root;
static int cib_wrap = 100;

#define CIB_WRITE_PARANOIA	0

const char *local_resource_path[] = {
    XML_CIB_TAG_STATUS,
};

const char *resource_path[] = {
    XML_CIB_TAG_RESOURCES,
};

const char *node_path[] = {
    XML_CIB_TAG_NODES,
};

const char *constraint_path[] = {
    XML_CIB_TAG_CONSTRAINTS,
};

crm_trigger_t *cib_writer = NULL;
gboolean initialized = FALSE;
xmlNode *node_search = NULL;
xmlNode *resource_search = NULL;
xmlNode *constraint_search = NULL;
xmlNode *status_search = NULL;

extern enum cib_errors cib_status;

int set_connected_peers(xmlNode * xml_obj);
void GHFunc_count_peers(gpointer key, gpointer value, gpointer user_data);
int write_cib_contents(gpointer p);
extern void cib_cleanup(void);

static gboolean
validate_cib_digest(xmlNode * local_cib, const char *sigfile)
{
    int s_res = -1;
    struct stat buf;
    char *digest = NULL;
    char *expected = NULL;
    gboolean passed = FALSE;
    FILE *expected_strm = NULL;
    int start = 0, length = 0, read_len = 0;

    CRM_ASSERT(sigfile != NULL);
    s_res = stat(sigfile, &buf);

    if (s_res != 0) {
        crm_warn("No on-disk digest present");
        return TRUE;
    }

    if (local_cib != NULL) {
        digest = calculate_on_disk_digest(local_cib);
    }

    expected_strm = fopen(sigfile, "r");
    if (expected_strm == NULL) {
        crm_perror(LOG_ERR, "Could not open signature file %s for reading", sigfile);
        goto bail;
    }

    start = ftell(expected_strm);
    fseek(expected_strm, 0L, SEEK_END);
    length = ftell(expected_strm);
    fseek(expected_strm, 0L, start);

    CRM_ASSERT(length >= 0);
    CRM_ASSERT(start == ftell(expected_strm));

    if (length > 0) {
        crm_trace("Reading %d bytes from file", length);
        expected = calloc(1, (length + 1));
        read_len = fread(expected, 1, length, expected_strm);   /* Coverity: False positive */
        CRM_ASSERT(read_len == length);
    }
    fclose(expected_strm);

  bail:
    if (expected == NULL) {
        crm_err("On-disk digest is empty");

    } else if (safe_str_eq(expected, digest)) {
        crm_trace("Digest comparision passed: %s", digest);
        passed = TRUE;

    } else {
        crm_err("Digest comparision failed: expected %s (%s), calculated %s",
                expected, sigfile, digest);
    }

    free(digest);
    free(expected);
    return passed;
}

static int
write_cib_digest(xmlNode * local_cib, const char *digest_file, char *digest)
{
    int rc = 0;
    char *local_digest = NULL;
    FILE *digest_strm = fopen(digest_file, "w");

    if (digest_strm == NULL) {
        crm_perror(LOG_ERR, "Cannot open signature file %s for writing", digest_file);
        return -1;
    }

    if (digest == NULL) {
        local_digest = calculate_on_disk_digest(local_cib);
        CRM_ASSERT(digest != NULL);
        digest = local_digest;
    }

    rc = fprintf(digest_strm, "%s", digest);
    if (rc < 0) {
        crm_perror(LOG_ERR, "Cannot write to signature file %s", digest_file);
    }

    CRM_ASSERT(digest_strm != NULL);
    if (fflush(digest_strm) != 0) {
        crm_perror(LOG_ERR, "Couldnt flush the contents of %s", digest_file);
        rc = -1;
    }

    if (fsync(fileno(digest_strm)) < 0) {
        crm_perror(LOG_ERR, "Couldnt sync the contents of %s", digest_file);
        rc = -1;
    }

    fclose(digest_strm);
    free(local_digest);
    return rc;
}

static gboolean
validate_on_disk_cib(const char *filename, xmlNode ** on_disk_cib)
{
    int s_res = -1;
    struct stat buf;
    gboolean passed = TRUE;
    xmlNode *root = NULL;

    CRM_ASSERT(filename != NULL);

    s_res = stat(filename, &buf);
    if (s_res == 0) {
        char *sigfile = NULL;
        size_t fnsize;

        crm_trace("Reading cluster configuration from: %s", filename);
        root = filename2xml(filename);

        fnsize = strlen(filename) + 5;
        sigfile = calloc(1, fnsize);
        snprintf(sigfile, fnsize, "%s.sig", filename);
        if (validate_cib_digest(root, sigfile) == FALSE) {
            passed = FALSE;
        }
        free(sigfile);
    }

    if (on_disk_cib != NULL) {
        *on_disk_cib = root;
    } else {
        free_xml(root);
    }

    return passed;
}

static int
cib_rename(const char *old, const char *new)
{
    int rc = 0;
    char *automatic = NULL;

    if (new == NULL) {
        automatic = crm_concat(cib_root, "cib.auto.XXXXXX", '/');
        automatic = mktemp(automatic);
        new = automatic;

        crm_err("Archiving corrupt or unusable file %s as %s", old, automatic);
    }

    rc = rename(old, new);
    if (rc < 0) {
        crm_perror(LOG_ERR, "Couldn't rename %s as %s - Disabling disk writes and continuing", old,
                   new);
        cib_writes_enabled = FALSE;
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

xmlNode *
readCibXmlFile(const char *dir, const char *file, gboolean discard_status)
{
    int seq = 0;
    char *backup_file = NULL;
    char *filename = NULL, *sigfile = NULL;
    const char *name = NULL;
    const char *value = NULL;
    const char *validation = NULL;
    const char *use_valgrind = getenv("HA_VALGRIND_ENABLED");

    xmlNode *root = NULL;
    xmlNode *status = NULL;

    if (!crm_is_writable(dir, file, CRM_DAEMON_USER, NULL, FALSE)) {
        cib_status = cib_bad_permissions;
        return NULL;
    }

    filename = crm_concat(dir, file, '/');
    sigfile = crm_concat(filename, "sig", '.');

    cib_status = cib_ok;
    root = retrieveCib(filename, sigfile, TRUE);

    if (root == NULL) {
        crm_warn("Primary configuration corrupt or unusable, trying backup...");
        seq = get_last_sequence(cib_root, CIB_SERIES);
    }

    while (root == NULL) {
        struct stat buf;

        free(sigfile);

        if (seq == 0) {
            seq += cib_wrap;    /* unwrap */
        }

        backup_file = generate_series_filename(cib_root, CIB_SERIES, seq - 1, FALSE);
        sigfile = crm_concat(filename, "sig", '.');

        if (stat(backup_file, &buf) != 0) {
            crm_debug("Backup file %s not found", backup_file);
            break;
        }
        crm_warn("Attempting to load: %s", backup_file);
        root = retrieveCib(backup_file, sigfile, FALSE);
        seq--;
    }
    free(backup_file);

    if (root == NULL) {
        root = createEmptyCib();
        crm_xml_add(root, XML_ATTR_GENERATION, "0");
        crm_xml_add(root, XML_ATTR_NUMUPDATES, "0");
        crm_xml_add(root, XML_ATTR_GENERATION_ADMIN, "0");
        crm_xml_add(root, XML_ATTR_VALIDATION, LATEST_SCHEMA_VERSION);
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
        free_xml_from_parent(root, status);
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
        cib_status = cib_dtd_validation;

    } else if (validation == NULL) {
        int version = 0;

        update_validation(&root, &version, FALSE, FALSE);
        if (version > 0) {
            crm_notice("Enabling %s validation on"
                       " the existing (sane) configuration", get_schema_name(version));
        } else {
            crm_err("CIB does not validate with any known DTD or schema");
            cib_status = cib_dtd_validation;
        }
    }

    free(filename);
    free(sigfile);
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
    node_search = NULL;
    resource_search = NULL;
    constraint_search = NULL;
    status_search = NULL;

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

static void
sync_directory(const char *name)
{
    int fd = 0;
    DIR *directory = NULL;

    directory = opendir(name);
    if (directory == NULL) {
        crm_perror(LOG_ERR, "Could not open %s for syncing", name);
        return;
    }

    fd = dirfd(directory);
    if (fd < 0) {
        crm_perror(LOG_ERR, "Could not obtain file descriptor for %s", name);

    } else if (fsync(fd) < 0) {
        crm_perror(LOG_ERR, "Could not sync %s", name);
    }

    if (closedir(directory) < 0) {
        crm_perror(LOG_ERR, "Could not close %s after fsync", name);
    }
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
                cl_flush_logs();
                exit(1);
            }

        } else {
            crm_crit("Could not write out new CIB and no saved" " version to revert to");
        }
        return cib_ACTIVATION;
    }

    free_xml(saved_cib);
    if (cib_writes_enabled && cib_status == cib_ok && to_disk) {
        crm_debug("Triggering CIB write for %s op", op);
        mainloop_set_trigger(cib_writer);
    }

    return cib_ok;
}

static void cib_diskwrite_complete(GPid pid, gint status, gpointer user_data) 
{
    int exitcode = -1;

    if(WIFSIGNALED(status)) {
        int signo = WTERMSIG(status);
        int core = WCOREDUMP(status);
        crm_notice("Disk write process terminated with signal %d (pid=%d, core=%d)", signo, pid, core);

    } else if(WIFEXITED(status)) {
        exitcode = WEXITSTATUS(status);
        do_crm_log(exitcode == 0 ? LOG_TRACE : LOG_ERR, "Disk write process exited (pid=%d, rc=%d)", pid, exitcode);
    }

    if(exitcode != 0 && cib_writes_enabled) {
        crm_err("Disabling disk writes after write failure");
        cib_writes_enabled = FALSE;
    }

    mainloop_trigger_complete(cib_writer);
}

int
write_cib_contents(gpointer p)
{
    int exit_rc = EX_OK;
    gboolean need_archive = FALSE;
    struct stat buf;
    char *digest = NULL;
    xmlNode *cib_status_root = NULL;

    xmlNode *local_cib = NULL;
    xmlNode *tmp_cib = NULL;

    char *tmp1 = NULL;
    char *tmp2 = NULL;
    char *digest_file = NULL;
    char *primary_file = NULL;

    char *backup_file = NULL;
    char *backup_digest = NULL;

    const char *epoch = NULL;
    const char *admin_epoch = NULL;

    if (p) {
        /* Synchronous write out */
        local_cib = copy_xml(p);

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
            g_child_watch_add(pid, cib_diskwrite_complete, NULL);
            if(bb_state == QB_LOG_STATE_ENABLED) {
                /* Re-enable now that it it safe */
                qb_log_ctl(QB_LOG_BLACKBOX, QB_LOG_CONF_ENABLED, QB_TRUE);
            }

            return -1; /* -1 means 'still work to do' */
        }
        
        /* A-synchronous write out after a fork() */

        /* Don't log anything unless strictly necessary */
        set_crm_log_level(LOG_ERR);

        /* In theory we can scribble on "the_cib" here and not affect the parent
         * But lets be safe anyway
         */
        local_cib = copy_xml(the_cib);
    }

    epoch = crm_element_value(local_cib, XML_ATTR_GENERATION);
    admin_epoch = crm_element_value(local_cib, XML_ATTR_GENERATION_ADMIN);

    tmp1 = crm_concat(cib_root, "cib.XXXXXX", '/');
    tmp2 = crm_concat(cib_root, "cib.XXXXXX", '/');

    primary_file = crm_concat(cib_root, "cib.xml", '/');
    digest_file = crm_concat(primary_file, "sig", '.');

    /* Always write out with num_updates=0 */
    crm_xml_add(local_cib, XML_ATTR_NUMUPDATES, "0");

    need_archive = (stat(primary_file, &buf) == 0);
    if (need_archive) {
        int rc = 0;
        int seq = get_last_sequence(cib_root, CIB_SERIES);

        /* check the admin didnt modify it underneath us */
        if (validate_on_disk_cib(primary_file, NULL) == FALSE) {
            crm_err("%s was manually modified while the cluster was active!", primary_file);
            exit_rc = 1;
            goto cleanup;
        }

        backup_file = generate_series_filename(cib_root, CIB_SERIES, seq, FALSE);
        backup_digest = crm_concat(backup_file, "sig", '.');

        unlink(backup_file);
        unlink(backup_digest);
        rc = link(primary_file, backup_file);
        if(rc < 0) {
            exit_rc = 4;
            crm_perror(LOG_ERR, "Cannot link %s to %s", primary_file, backup_file);
            goto cleanup;
        }

        rc = stat(digest_file, &buf);
        if (rc == 0) {
            rc = link(digest_file, backup_digest);
            if(rc < 0) {
                exit_rc = 5;
                crm_perror(LOG_ERR, "Cannot link %s to %s", digest_file, backup_digest);
                goto cleanup;
            }
        }
        write_last_sequence(cib_root, CIB_SERIES, seq + 1, cib_wrap);
        sync_directory(cib_root);

        crm_info("Archived previous version as %s", backup_file);
    }

    /* Given that we discard the status section on startup
     *   there is no point writing it out in the first place
     *   since users just get confused by it
     *
     * So delete the status section before we write it out
     */
    crm_debug("Writing CIB to disk");
    if (p == NULL) {
        cib_status_root = find_xml_node(local_cib, XML_CIB_TAG_STATUS, TRUE);
        CRM_LOG_ASSERT(cib_status_root != NULL);

        if (cib_status_root != NULL) {
            free_xml_from_parent(local_cib, cib_status_root);
        }
    }

    tmp1 = mktemp(tmp1);        /* cib    */
    tmp2 = mktemp(tmp2);        /* digest */

    if (write_xml_file(local_cib, tmp1, FALSE) <= 0) {
        crm_err("Changes couldn't be written to %s", tmp1);
        exit_rc = 2;
        goto cleanup;
    }

    /* Must calculate the digest after writing as write_xml_file() updates the last-written field */
    digest = calculate_on_disk_digest(local_cib);
    crm_info("Wrote version %s.%s.0 of the CIB to disk (digest: %s)",
             admin_epoch ? admin_epoch : "0", epoch ? epoch : "0", digest);

    if (write_cib_digest(local_cib, tmp2, digest) <= 0) {
        crm_err("Digest couldn't be written to %s", tmp2);
        exit_rc = 3;
        goto cleanup;
    }
    crm_debug("Wrote digest %s to disk", digest);
    tmp_cib = retrieveCib(tmp1, tmp2, FALSE);
    CRM_ASSERT(tmp_cib != NULL);
    sync_directory(cib_root);

    crm_debug("Activating %s", tmp1);
    cib_rename(tmp1, primary_file);
    cib_rename(tmp2, digest_file);
    sync_directory(cib_root);

  cleanup:
    free(backup_digest);
    free(primary_file);
    free(backup_file);
    free(digest_file);
    free(digest);
    free(tmp2);
    free(tmp1);

    free_xml(tmp_cib);
    free_xml(local_cib);

    if (p == NULL) {
        /* exit() could potentially affect the parent by closing things it shouldn't
         * Use _exit instead
         */
        _exit(exit_rc);
    }
    return exit_rc;
}

void
GHFunc_count_peers(gpointer key, gpointer value, gpointer user_data)
{
    int *active = user_data;

    if (safe_str_eq(value, ONLINESTATUS)) {
        (*active)++;

    } else if (safe_str_eq(value, JOINSTATUS)) {
        (*active)++;
    }
}
