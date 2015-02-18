/*
 * Copyright (c) 2004 International Business Machines
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */
#include <crm_internal.h>
#include <unistd.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <pwd.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <glib.h>

#include <crm/crm.h>
#include <crm/cib/internal.h>
#include <crm/msg_xml.h>
#include <crm/common/ipc.h>
#include <crm/common/xml.h>

#define cib_flag_dirty 0x00001
#define cib_flag_live  0x00002

typedef struct cib_file_opaque_s {
    int flags;
    char *filename;

} cib_file_opaque_t;

int cib_file_perform_op(cib_t * cib, const char *op, const char *host, const char *section,
                        xmlNode * data, xmlNode ** output_data, int call_options);

int cib_file_perform_op_delegate(cib_t * cib, const char *op, const char *host, const char *section,
                                 xmlNode * data, xmlNode ** output_data, int call_options,
                                 const char *user_name);

int cib_file_signon(cib_t * cib, const char *name, enum cib_conn_type type);
int cib_file_signoff(cib_t * cib);
int cib_file_free(cib_t * cib);

static int
cib_file_inputfd(cib_t * cib)
{
    return -EPROTONOSUPPORT;
}

static int
cib_file_set_connection_dnotify(cib_t * cib, void (*dnotify) (gpointer user_data))
{
    return -EPROTONOSUPPORT;
}

static int
cib_file_register_notification(cib_t * cib, const char *callback, int enabled)
{
    return -EPROTONOSUPPORT;
}

/*!
 * \internal
 * \brief Compare the calculated digest of an XML tree against a signature file
 *
 * \param[in] root Root of XML tree to compare
 * \param[in] sigfile Name of signature file containing digest to compare
 *
 * \return TRUE if digests match or signature file does not exist, else FALSE
 */
static gboolean
cib_file_verify_digest(xmlNode *root, const char *sigfile)
{
    gboolean passed = FALSE;
    char *expected = crm_read_contents(sigfile);

    if (expected == NULL) {
        switch (errno) {
            case 0:
                crm_err("On-disk digest at %s is empty", sigfile);
                return FALSE;
            case ENOENT:
                crm_warn("No on-disk digest present at %s", sigfile);
                return TRUE;
            default:
                crm_perror(LOG_ERR, "Could not read on-disk digest from %s", sigfile);
                return FALSE;
        }
    }
    passed = crm_digest_verify(root, expected);
    free(expected);
    return passed;
}

/*!
 * \internal
 * \brief Read an XML tree from a file and verify its digest
 *
 * \param[in] filename Name of XML file to read
 * \param[in] sigfile Name of signature file containing digest to compare
 * \param[in] root If non-NULL, will be set to pointer to parsed XML tree
 *
 * \return 0 if file was successfully read, parsed and verified, otherwise:
 *         -errno on stat() failure,
 *         -pcmk_err_cib_corrupt if file size is 0 or XML is not parseable, or
 *         -pcmk_err_cib_modified if digests do not match
 * \note If root is non-NULL, it is the caller's responsibility to free *root on
 *       successful return.
 */
int
cib_file_read_and_verify(const char *filename, const char *sigfile, xmlNode **root)
{
    int s_res;
    struct stat buf;
    char *local_sigfile = NULL;
    xmlNode *local_root = NULL;

    CRM_ASSERT(filename != NULL);
    if (root) {
        *root = NULL;
    }

    /* Verify that file exists and its size is nonzero */
    s_res = stat(filename, &buf);
    if (s_res < 0) {
        crm_perror(LOG_WARNING, "Could not verify cluster configuration file %s", filename);
        return -errno;
    } else if (buf.st_size == 0) {
        crm_warn("Cluster configuration file %s is corrupt (size is zero)", filename);
        return -pcmk_err_cib_corrupt;
    }

    /* Parse XML */
    crm_info("Reading cluster configuration file %s", filename);
    local_root = filename2xml(filename);
    if (local_root == NULL) {
        crm_warn("Cluster configuration file %s is corrupt (unparseable as XML)", filename);
        return -pcmk_err_cib_corrupt;
    }

    /* If sigfile is not specified, use original file name plus .sig */
    if (sigfile == NULL) {
        sigfile = local_sigfile = crm_concat(filename, "sig", '.');
    }

    /* Verify that digests match */
    crm_info("Verifying cluster configuration signature from %s", sigfile);
    if (cib_file_verify_digest(local_root, sigfile) == FALSE) {
        free(local_sigfile);
        free_xml(local_root);
        return -pcmk_err_cib_modified;
    }

    free(local_sigfile);
    if (root) {
        *root = local_root;
    } else {
        free_xml(local_root);
    }
    return pcmk_ok;
}

#define CIB_SERIES "cib"
#define CIB_SERIES_MAX 100
#define CIB_SERIES_BZIP FALSE /* Must be false because archived copies are
                                 created with hard links
                               */

#define CIB_LIVE_NAME CIB_SERIES ".xml"

/*!
 * \internal
 * \brief Check whether a file is the live CIB
 *
 * \param[in] filename Name of file to check
 *
 * \return TRUE if file exists and has one of the possible live CIB filenames
 */
static gboolean
cib_file_is_live(const char *filename)
{
    if (filename != NULL) {
        /* Canonicalize all file names for true comparison */
        char *real_filename = crm_compat_realpath(filename);

        if (real_filename != NULL) {
            const char *livenames[] = {
                CRM_CONFIG_DIR "/" CIB_LIVE_NAME,
                CRM_LEGACY_CONFIG_DIR "/" CIB_LIVE_NAME
            };
            char *real_livename;
            int i;

            /* Compare against each possible live CIB name */
            for (i = 0; i < sizeof(livenames)/sizeof(const char*); ++i) {
                real_livename = crm_compat_realpath(livenames[i]);
                if (real_livename && !strcmp(real_filename, real_livename)) {
                    free(real_livename);
                    return TRUE;
                }
                free(real_livename);
            }
            free(real_filename);
        }
    }
    return FALSE;
}

/* cib_file_backup() and cib_file_write_with_digest() need to chown the
 * written files only in limited circumstances, so these variables allow
 * that to be indicated without affecting external callers
 */
static uid_t cib_file_owner = 0;
static uid_t cib_file_group = 0;
static gboolean cib_do_chown = FALSE;

/*!
 * \internal
 * \brief Back up a CIB
 *
 * \param[in] cib_dirname Directory containing CIB file and backups
 * \param[in] cib_filename Name (relative to cib_dirname) of CIB file to back up
 *
 * \return 0 on success, -1 on error
 */
static int
cib_file_backup(const char *cib_dirname, const char *cib_filename)
{
    int rc = 0;
    char *cib_path = crm_concat(cib_dirname, cib_filename, '/');
    char *cib_digest = crm_concat(cib_path, "sig", '.');

    /* Figure out what backup file sequence number to use */
    int seq = get_last_sequence(cib_dirname, CIB_SERIES);
    char *backup_path = generate_series_filename(cib_dirname, CIB_SERIES, seq,
                                                 CIB_SERIES_BZIP);
    char *backup_digest = crm_concat(backup_path, "sig", '.');

    CRM_ASSERT((cib_path != NULL) && (cib_digest != NULL)
               && (backup_path != NULL) && (backup_digest != NULL));

    /* Remove the old backups if they exist */
    unlink(backup_path);
    unlink(backup_digest);

    /* Back up the CIB, by hard-linking it to the backup name */
    if ((link(cib_path, backup_path) < 0) && (errno != ENOENT)) {
        crm_perror(LOG_ERR, "Could not archive %s by linking to %s",
                   cib_path, backup_path);
        rc = -1;

    /* Back up the CIB signature similarly */
    } else if ((link(cib_digest, backup_digest) < 0) && (errno != ENOENT)) {
        crm_perror(LOG_ERR, "Could not archive %s by linking to %s",
                   cib_digest, backup_digest);
        rc = -1;

    /* Update the last counter and ensure everything is sync'd to media */
    } else {
        write_last_sequence(cib_dirname, CIB_SERIES, seq + 1, CIB_SERIES_MAX);
        if (cib_do_chown) {
            if ((chown(backup_path, cib_file_owner, cib_file_group) < 0)
                    && (errno != ENOENT)) {
                crm_perror(LOG_ERR, "Could not set owner of %s", backup_path);
                rc = -1;
            }
            if ((chown(backup_digest, cib_file_owner, cib_file_group) < 0)
                    && (errno != ENOENT)) {
                crm_perror(LOG_ERR, "Could not set owner of %s", backup_digest);
                rc = -1;
            }
            if (crm_chown_last_sequence(cib_dirname, CIB_SERIES, cib_file_owner,
                                        cib_file_group) < 0) {
                crm_perror(LOG_ERR,
                           "Could not set owner of %s last sequence file",
                           cib_dirname);
                rc = -1;
            }
        }
        crm_sync_directory(cib_dirname);
        crm_info("Archived previous version as %s", backup_path);
    }

    free(cib_path);
    free(cib_digest);
    free(backup_path);
    free(backup_digest);
    return rc;
}

/*!
 * \internal
 * \brief Prepare CIB XML to be written to disk
 *
 * Set num_updates to 0, set cib-last-written to the current timestamp,
 * and strip out the status section.
 *
 * \param[in] root Root of CIB XML tree
 *
 * \return void
 */
static void
cib_file_prepare_xml(xmlNode *root)
{
    xmlNode *cib_status_root = NULL;

    /* Always write out with num_updates=0 and current last-written timestamp */
    crm_xml_add(root, XML_ATTR_NUMUPDATES, "0");
    crm_xml_add_last_written(root);

    /* Delete status section before writing to file, because
     * we discard it on startup anyway, and users get confused by it */
    cib_status_root = find_xml_node(root, XML_CIB_TAG_STATUS, TRUE);
    CRM_LOG_ASSERT(cib_status_root != NULL);
    if (cib_status_root != NULL) {
        free_xml(cib_status_root);
    }
}

/*!
 * \internal
 * \brief Write CIB to disk, along with a signature file containing its digest
 *
 * \param[in] cib_root Root of XML tree to write
 * \param[in] cib_dirname Directory containing CIB and signature files
 * \param[in] cib_filename Name (relative to cib_dirname) of file to write
 *
 * \return pcmk_ok on success,
 *         pcmk_err_cib_modified if existing cib_filename doesn't match digest,
 *         pcmk_err_cib_backup if existing cib_filename couldn't be backed up,
 *         or pcmk_err_cib_save if new cib_filename couldn't be saved
 */
int
cib_file_write_with_digest(xmlNode *cib_root, const char *cib_dirname,
                           const char *cib_filename)
{
    int exit_rc = pcmk_ok;
    int rc, fd;
    char *digest = NULL;

    /* Detect CIB version for diagnostic purposes */
    const char *epoch = crm_element_value(cib_root, XML_ATTR_GENERATION);
    const char *admin_epoch = crm_element_value(cib_root,
                                                XML_ATTR_GENERATION_ADMIN);

    /* Determine full CIB and signature pathnames */
    char *cib_path = crm_concat(cib_dirname, cib_filename, '/');
    char *digest_path = crm_concat(cib_path, "sig", '.');

    /* Create temporary file name patterns for writing out CIB and signature */
    char *tmp_cib = g_strdup_printf("%s/cib.XXXXXX", cib_dirname);
    char *tmp_digest = g_strdup_printf("%s/cib.XXXXXX", cib_dirname);

    CRM_ASSERT((cib_path != NULL) && (digest_path != NULL)
               && (tmp_cib != NULL) && (tmp_digest != NULL));

    /* Ensure the admin didn't modify the existing CIB underneath us */
    rc = cib_file_read_and_verify(cib_path, NULL, NULL);
    if ((rc != pcmk_ok) && (rc != -ENOENT)) {
        crm_err("%s was manually modified while the cluster was active!",
                cib_path);
        exit_rc = pcmk_err_cib_modified;
        goto cleanup;
    }

    /* Back up the existing CIB */
    if (cib_file_backup(cib_dirname, cib_filename) < 0) {
        exit_rc = pcmk_err_cib_backup;
        goto cleanup;
    }

    crm_debug("Writing CIB to disk");
    umask(S_IWGRP | S_IWOTH | S_IROTH);
    cib_file_prepare_xml(cib_root);

    /* Write the CIB to a temporary file, so we can deploy (near) atomically */
    fd = mkstemp(tmp_cib);
    if (fd < 0) {
        crm_perror(LOG_ERR, "Couldn't open temporary file %s for writing CIB",
                   tmp_cib);
        exit_rc = pcmk_err_cib_save;
        goto cleanup;
    }

    /* Protect the temporary file */
    if (fchmod(fd, S_IRUSR | S_IWUSR) < 0) {
        crm_perror(LOG_ERR, "Couldn't protect temporary file %s for writing CIB",
                   tmp_cib);
        exit_rc = pcmk_err_cib_save;
        goto cleanup;
    }
    if (cib_do_chown && (fchown(fd, cib_file_owner, cib_file_group) < 0)) {
        crm_perror(LOG_ERR, "Couldn't protect temporary file %s for writing CIB",
                   tmp_cib);
        exit_rc = pcmk_err_cib_save;
        goto cleanup;
    }

    /* Write out the CIB */
    if (write_xml_fd(cib_root, tmp_cib, fd, FALSE) <= 0) {
        crm_err("Changes couldn't be written to %s", tmp_cib);
        exit_rc = pcmk_err_cib_save;
        goto cleanup;
    }

    /* Calculate CIB digest */
    digest = calculate_on_disk_digest(cib_root);
    CRM_ASSERT(digest != NULL);
    crm_info("Wrote version %s.%s.0 of the CIB to disk (digest: %s)",
             (admin_epoch ? admin_epoch : "0"), (epoch ? epoch : "0"), digest);

    /* Write the CIB digest to a temporary file */
    fd = mkstemp(tmp_digest);
    if (cib_do_chown && (fchown(fd, cib_file_owner, cib_file_group) < 0)) {
        crm_perror(LOG_ERR, "Couldn't protect temporary file %s for writing CIB",
                   tmp_cib);
        exit_rc = pcmk_err_cib_save;
        goto cleanup;
    }
    if ((fd < 0) || (crm_write_sync(fd, digest) < 0)) {
        crm_perror(LOG_ERR, "Could not write digest to file %s", tmp_digest);
        exit_rc = pcmk_err_cib_save;
        goto cleanup;
    }
    crm_debug("Wrote digest %s to disk", digest);

    /* Verify that what we wrote is sane */
    rc = cib_file_read_and_verify(tmp_cib, tmp_digest, NULL);
    CRM_ASSERT(rc == 0);

    /* Rename temporary files to live, and sync directory changes to media */
    crm_debug("Activating %s", tmp_cib);
    if (rename(tmp_cib, cib_path) < 0) {
        crm_perror(LOG_ERR, "Couldn't rename %s as %s", tmp_cib, cib_path);
        exit_rc = pcmk_err_cib_save;
    }
    if (rename(tmp_digest, digest_path) < 0) {
        crm_perror(LOG_ERR, "Couldn't rename %s as %s", tmp_digest,
                   digest_path);
        exit_rc = pcmk_err_cib_save;
    }
    crm_sync_directory(cib_dirname);

  cleanup:
    free(cib_path);
    free(digest_path);
    free(digest);
    free(tmp_digest);
    free(tmp_cib);
    return exit_rc;
}

cib_t *
cib_file_new(const char *cib_location)
{
    cib_file_opaque_t *private = NULL;
    cib_t *cib = cib_new_variant();

    private = calloc(1, sizeof(cib_file_opaque_t));
    CRM_ASSERT((cib != NULL) && (private != NULL));

    cib->variant = cib_file;
    cib->variant_opaque = private;

    if (cib_location == NULL) {
        cib_location = getenv("CIB_file");
    }
    private->flags = 0;
    if (cib_file_is_live(cib_location)) {
        set_bit(private->flags, cib_flag_live);
        crm_trace("File %s detected as live CIB", cib_location);
    }
    private->filename = strdup(cib_location);

    /* assign variant specific ops */
    cib->delegate_fn = cib_file_perform_op_delegate;
    cib->cmds->signon = cib_file_signon;
    cib->cmds->signoff = cib_file_signoff;
    cib->cmds->free = cib_file_free;
    cib->cmds->inputfd = cib_file_inputfd;

    cib->cmds->register_notification = cib_file_register_notification;
    cib->cmds->set_connection_dnotify = cib_file_set_connection_dnotify;

    return cib;
}

static xmlNode *in_mem_cib = NULL;

/*!
 * \internal
 * \brief Read CIB from disk and validate it against XML DTD
 *
 * \param[in] filename Name of file to read CIB from
 *
 * \return pcmk_ok on success,
 *         -ENXIO if file does not exist (or stat() otherwise fails), or
 *         -pcmk_err_schema_validation if XML doesn't parse or validate
 * \note If filename is the live CIB, this will *not* verify its digest,
 *       though that functionality would be trivial to add here.
 *       Also, this will *not* verify that the file is writeable,
 *       because some callers might not need to write.
 */
static int
load_file_cib(const char *filename)
{
    struct stat buf;
    xmlNode *root = NULL;
    const char *ignore_dtd = NULL;

    /* Ensure file is readable */
    if (stat(filename, &buf) < 0) {
        return -ENXIO;
    }

    /* Parse XML from file */
    root = filename2xml(filename);
    if (root == NULL) {
        return -pcmk_err_schema_validation;
    }

    /* Add a status section if not already present */
    if (find_xml_node(root, XML_CIB_TAG_STATUS, FALSE) == NULL) {
        create_xml_node(root, XML_CIB_TAG_STATUS);
    }

    /* Validate XML against its specified DTD */
    ignore_dtd = crm_element_value(root, XML_ATTR_VALIDATION);
    if (validate_xml(root, NULL, TRUE) == FALSE) {
        crm_err("CIB does not validate against %s", ignore_dtd);
        free_xml(root);
        return -pcmk_err_schema_validation;
    }

    /* Remember the parsed XML for later use */
    in_mem_cib = root;
    return pcmk_ok;
}

int
cib_file_signon(cib_t * cib, const char *name, enum cib_conn_type type)
{
    int rc = pcmk_ok;
    cib_file_opaque_t *private = cib->variant_opaque;

    if (private->filename == NULL) {
        rc = -EINVAL;
    } else {
        rc = load_file_cib(private->filename);
    }

    if (rc == pcmk_ok) {
        crm_debug("%s: Opened connection to local file '%s'", name, private->filename);
        cib->state = cib_connected_command;
        cib->type = cib_command;

    } else {
        fprintf(stderr, "%s: Connection to local file '%s' failed: %s\n",
                name, private->filename, pcmk_strerror(rc));
    }

    return rc;
}

/*!
 * \internal
 * \brief Write out the in-memory CIB to a live CIB file
 *
 * param[in] path Full path to file to write
 *
 * \return 0 on success, -1 on failure
 */
static int
cib_file_write_live(char *path)
{
    uid_t uid = geteuid();
    struct passwd *daemon_pwent;
    char *sep = strrchr(path, '/');
    const char *cib_dirname, *cib_filename;
    int rc = 0;

    /* Get the desired uid/gid */
    errno = 0;
    daemon_pwent = getpwnam(CRM_DAEMON_USER);
    if (daemon_pwent == NULL) {
        crm_perror(LOG_ERR, "Could not find %s user", CRM_DAEMON_USER);
        return -1;
    }

    /* If we're root, we can change the ownership;
     * if we're daemon, anything we create will be OK;
     * otherwise, block access so we don't create wrong owner
     */
    if ((uid != 0) && (uid == daemon_pwent->pw_uid)) {
        crm_perror(LOG_ERR, "Must be root or %s to modify live CIB",
                   CRM_DAEMON_USER);
        return 0;
    }

    /* fancy footwork to separate dirname from filename
     * (we know the canonical name maps to the live CIB,
     * but the given name might be relative, or symlinked)
     */
    if (sep == NULL) { /* no directory component specified */
        cib_dirname = "./";
        cib_filename = path;
    } else if (sep == path) { /* given name is in / */
        cib_dirname = "/";
        cib_filename = path + 1;
    } else { /* typical case; split given name into parts */
        *sep = '\0';
        cib_dirname = path;
        cib_filename = sep + 1;
    }

    /* if we're root, we want to update the file ownership */
    if (uid == 0) {
        cib_file_owner = daemon_pwent->pw_uid;
        cib_file_group = daemon_pwent->pw_gid;
        cib_do_chown = TRUE;
    }

    /* write the file */
    if (cib_file_write_with_digest(in_mem_cib, cib_dirname,
                                   cib_filename) != pcmk_ok) {
        rc = -1;
    }

    /* turn off file ownership changes, for other callers */
    if (uid == 0) {
        cib_do_chown = FALSE;
    }

    /* undo fancy stuff */
    if ((sep != NULL) && (*sep = '\0')) {
        *sep = '/';
    }

    return rc;
}

/*!
 * \internal
 * \brief Sign-off method for CIB file variants
 *
 * This will write the file to disk if needed, and free the in-memory CIB. If
 * the file is the live CIB, it will compute and write a signature as well.
 *
 * \param[in] cib CIB object to sign off
 *
 * \return pcmk_ok on success, pcmk_err_generic on failure
 * \todo This method should refuse to write the live CIB if the CIB daemon is
 *       running.
 */
int
cib_file_signoff(cib_t * cib)
{
    int rc = pcmk_ok;
    cib_file_opaque_t *private = cib->variant_opaque;

    crm_debug("Signing out of the CIB Service");
    cib->state = cib_disconnected;
    cib->type = cib_no_connection;

    /* If the in-memory CIB has been changed, write it to disk */
    if (is_set(private->flags, cib_flag_dirty)) {

        /* If this is the live CIB, write it out with a digest */
        if (is_set(private->flags, cib_flag_live)) {
            if (cib_file_write_live(private->filename) < 0) {
                rc = pcmk_err_generic;
            }

        /* Otherwise, it's a simple write */
        } else {
            gboolean do_bzip = (strstr(private->filename, ".bz2") != NULL);

            if (write_xml_file(in_mem_cib, private->filename, do_bzip) <= 0) {
                rc = pcmk_err_generic;
            }
        }

        if (rc == pcmk_ok) {
            crm_info("Wrote CIB to %s", private->filename);
            clear_bit(private->flags, cib_flag_dirty);
        } else {
            crm_err("Could not write CIB to %s", private->filename);
        }
    }

    /* Free the in-memory CIB */
    free_xml(in_mem_cib);
    in_mem_cib = NULL;
    return rc;
}

int
cib_file_free(cib_t * cib)
{
    int rc = pcmk_ok;

    if (cib->state != cib_disconnected) {
        rc = cib_file_signoff(cib);
    }

    if (rc == pcmk_ok) {
        cib_file_opaque_t *private = cib->variant_opaque;

        free(private->filename);
        free(cib->cmds);
        free(private);
        free(cib);

    } else {
        fprintf(stderr, "Couldn't sign off: %d\n", rc);
    }

    return rc;
}

struct cib_func_entry {
    const char *op;
    gboolean read_only;
    cib_op_t fn;
};

/* *INDENT-OFF* */
static struct cib_func_entry cib_file_ops[] = {
    {CIB_OP_QUERY,      TRUE,  cib_process_query},
    {CIB_OP_MODIFY,     FALSE, cib_process_modify},
    {CIB_OP_APPLY_DIFF, FALSE, cib_process_diff},
    {CIB_OP_BUMP,       FALSE, cib_process_bump},
    {CIB_OP_REPLACE,    FALSE, cib_process_replace},
    {CIB_OP_CREATE,     FALSE, cib_process_create},
    {CIB_OP_DELETE,     FALSE, cib_process_delete},
    {CIB_OP_ERASE,      FALSE, cib_process_erase},
    {CIB_OP_UPGRADE,    FALSE, cib_process_upgrade},
};
/* *INDENT-ON* */

int
cib_file_perform_op(cib_t * cib, const char *op, const char *host, const char *section,
                    xmlNode * data, xmlNode ** output_data, int call_options)
{
    return cib_file_perform_op_delegate(cib, op, host, section, data, output_data, call_options,
                                        NULL);
}

int
cib_file_perform_op_delegate(cib_t * cib, const char *op, const char *host, const char *section,
                             xmlNode * data, xmlNode ** output_data, int call_options,
                             const char *user_name)
{
    int rc = pcmk_ok;
    char *effective_user = NULL;
    gboolean query = FALSE;
    gboolean changed = FALSE;
    xmlNode *request = NULL;
    xmlNode *output = NULL;
    xmlNode *cib_diff = NULL;
    xmlNode *result_cib = NULL;
    cib_op_t *fn = NULL;
    int lpc = 0;
    static int max_msg_types = DIMOF(cib_file_ops);
    cib_file_opaque_t *private = cib->variant_opaque;

    crm_info("%s on %s", op, section);
    call_options |= (cib_no_mtime | cib_inhibit_bcast | cib_scope_local);

    if (cib->state == cib_disconnected) {
        return -ENOTCONN;
    }

    if (output_data != NULL) {
        *output_data = NULL;
    }

    if (op == NULL) {
        return -EINVAL;
    }

    for (lpc = 0; lpc < max_msg_types; lpc++) {
        if (safe_str_eq(op, cib_file_ops[lpc].op)) {
            fn = &(cib_file_ops[lpc].fn);
            query = cib_file_ops[lpc].read_only;
            break;
        }
    }

    if (fn == NULL) {
        return -EPROTONOSUPPORT;
    }

    cib->call_id++;
    request = cib_create_op(cib->call_id, "dummy-token", op, host, section, data, call_options, user_name);
#if ENABLE_ACL
    if(user_name) {
        crm_xml_add(request, XML_ACL_TAG_USER, user_name);
    }
    crm_trace("Performing %s operation as %s", op, user_name);
#endif

    /* Mirror the logic in cib_prepare_common() */
    if (section != NULL && data != NULL && crm_str_eq(crm_element_name(data), XML_TAG_CIB, TRUE)) {
        data = get_object_root(section, data);
    }

    rc = cib_perform_op(op, call_options, fn, query,
                        section, request, data, TRUE, &changed, in_mem_cib, &result_cib, &cib_diff,
                        &output);

    free_xml(request);
    if (rc == -pcmk_err_schema_validation) {
        validate_xml_verbose(result_cib);
    }

    if (rc != pcmk_ok) {
        free_xml(result_cib);

    } else if (query == FALSE) {
        xml_log_patchset(LOG_DEBUG, "cib:diff", cib_diff);
        free_xml(in_mem_cib);
        in_mem_cib = result_cib;
        set_bit(private->flags, cib_flag_dirty);
    }

    free_xml(cib_diff);

    if (cib->op_callback != NULL) {
        cib->op_callback(NULL, cib->call_id, rc, output);
    }

    if (output_data && output) {
        if(output == in_mem_cib) {
            *output_data = copy_xml(output);
        } else {
            *output_data = output;
        }

    } else if(output != in_mem_cib) {
        free_xml(output);
    }

    free(effective_user);
    return rc;
}
