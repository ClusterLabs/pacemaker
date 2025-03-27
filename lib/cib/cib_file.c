/*
 * Original copyright 2004 International Business Machines
 * Later changes copyright 2008-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <unistd.h>
#include <limits.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <pwd.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <glib.h>

#include <crm/crm.h>
#include <crm/cib/internal.h>
#include <crm/common/ipc.h>
#include <crm/common/xml.h>
#include <crm/common/xml_internal.h>

#define CIB_SERIES "cib"
#define CIB_SERIES_MAX 100
#define CIB_SERIES_BZIP FALSE /* Must be false because archived copies are
                                 created with hard links
                               */

#define CIB_LIVE_NAME CIB_SERIES ".xml"

// key: client ID (const char *) -> value: client (cib_t *)
static GHashTable *client_table = NULL;

enum cib_file_flags {
    cib_file_flag_dirty = (1 << 0),
    cib_file_flag_live  = (1 << 1),
};

typedef struct cib_file_opaque_s {
    char *id;
    char *filename;
    uint32_t flags; // Group of enum cib_file_flags
    xmlNode *cib_xml;
} cib_file_opaque_t;

static int cib_file_process_commit_transaction(const char *op, int options,
                                               const char *section,
                                               xmlNode *req, xmlNode *input,
                                               xmlNode *existing_cib,
                                               xmlNode **result_cib,
                                               xmlNode **answer);

/*!
 * \internal
 * \brief Add a CIB file client to client table
 *
 * \param[in] cib  CIB client
 */
static void
register_client(const cib_t *cib)
{
    cib_file_opaque_t *private = cib->variant_opaque;

    if (client_table == NULL) {
        client_table = pcmk__strkey_table(NULL, NULL);
    }
    g_hash_table_insert(client_table, private->id, (gpointer) cib);
}

/*!
 * \internal
 * \brief Remove a CIB file client from client table
 *
 * \param[in] cib  CIB client
 */
static void
unregister_client(const cib_t *cib)
{
    cib_file_opaque_t *private = cib->variant_opaque;

    if (client_table == NULL) {
        return;
    }

    g_hash_table_remove(client_table, private->id);

    /* @COMPAT: Add to crm_exit() when libcib and libcrmcommon are merged,
     * instead of destroying the client table when there are no more clients.
     */
    if (g_hash_table_size(client_table) == 0) {
        g_hash_table_destroy(client_table);
        client_table = NULL;
    }
}

/*!
 * \internal
 * \brief Look up a CIB file client by its ID
 *
 * \param[in] client_id  CIB client ID
 *
 * \return CIB client with matching ID if found, or \p NULL otherwise
 */
static cib_t *
get_client(const char *client_id)
{
    if (client_table == NULL) {
        return NULL;
    }
    return g_hash_table_lookup(client_table, (gpointer) client_id);
}

static const cib__op_fn_t cib_op_functions[] = {
    [cib__op_apply_patch]      = cib_process_diff,
    [cib__op_bump]             = cib_process_bump,
    [cib__op_commit_transact]  = cib_file_process_commit_transaction,
    [cib__op_create]           = cib_process_create,
    [cib__op_delete]           = cib_process_delete,
    [cib__op_erase]            = cib_process_erase,
    [cib__op_modify]           = cib_process_modify,
    [cib__op_query]            = cib_process_query,
    [cib__op_replace]          = cib_process_replace,
    [cib__op_upgrade]          = cib_process_upgrade,
};

/* cib_file_backup() and cib_file_write_with_digest() need to chown the
 * written files only in limited circumstances, so these variables allow
 * that to be indicated without affecting external callers
 */
static uid_t cib_file_owner = 0;
static uid_t cib_file_group = 0;
static gboolean cib_do_chown = FALSE;

#define cib_set_file_flags(cibfile, flags_to_set) do {                  \
        (cibfile)->flags = pcmk__set_flags_as(__func__, __LINE__,       \
                                              LOG_TRACE, "CIB file",    \
                                              cibfile->filename,        \
                                              (cibfile)->flags,         \
                                              (flags_to_set),           \
                                              #flags_to_set);           \
    } while (0)

#define cib_clear_file_flags(cibfile, flags_to_clear) do {              \
        (cibfile)->flags = pcmk__clear_flags_as(__func__, __LINE__,     \
                                                LOG_TRACE, "CIB file",  \
                                                cibfile->filename,      \
                                                (cibfile)->flags,       \
                                                (flags_to_clear),       \
                                                #flags_to_clear);       \
    } while (0)

/*!
 * \internal
 * \brief Get the function that performs a given CIB file operation
 *
 * \param[in] operation  Operation whose function to look up
 *
 * \return Function that performs \p operation for a CIB file client
 */
static cib__op_fn_t
file_get_op_function(const cib__operation_t *operation)
{
    enum cib__op_type type = operation->type;

    pcmk__assert(type >= 0);

    if (type >= PCMK__NELEM(cib_op_functions)) {
        return NULL;
    }
    return cib_op_functions[type];
}

/*!
 * \internal
 * \brief Check whether a file is the live CIB
 *
 * \param[in] filename Name of file to check
 *
 * \return TRUE if file exists and its real path is same as live CIB's
 */
static gboolean
cib_file_is_live(const char *filename)
{
    gboolean same = FALSE;

    if (filename != NULL) {
        // Canonicalize file names for true comparison
        char *real_filename = NULL;

        if (pcmk__real_path(filename, &real_filename) == pcmk_rc_ok) {
            char *real_livename = NULL;

            if (pcmk__real_path(CRM_CONFIG_DIR "/" CIB_LIVE_NAME,
                                &real_livename) == pcmk_rc_ok) {
                same = !strcmp(real_filename, real_livename);
                free(real_livename);
            }
            free(real_filename);
        }
    }
    return same;
}

static int
cib_file_process_request(cib_t *cib, xmlNode *request, xmlNode **output)
{
    int rc = pcmk_ok;
    const cib__operation_t *operation = NULL;
    cib__op_fn_t op_function = NULL;

    int call_id = 0;
    uint32_t call_options = cib_none;
    const char *op = pcmk__xe_get(request, PCMK__XA_CIB_OP);
    const char *section = pcmk__xe_get(request, PCMK__XA_CIB_SECTION);
    xmlNode *wrapper = pcmk__xe_first_child(request, PCMK__XE_CIB_CALLDATA,
                                            NULL, NULL);
    xmlNode *data = pcmk__xe_first_child(wrapper, NULL, NULL, NULL);

    bool changed = false;
    bool read_only = false;
    xmlNode *result_cib = NULL;
    xmlNode *cib_diff = NULL;

    cib_file_opaque_t *private = cib->variant_opaque;

    // We error checked these in callers
    cib__get_operation(op, &operation);
    op_function = file_get_op_function(operation);

    pcmk__xe_get_int(request, PCMK__XA_CIB_CALLID, &call_id);
    rc = pcmk__xe_get_flags(request, PCMK__XA_CIB_CALLOPT, &call_options,
                            cib_none);
    if (rc != pcmk_rc_ok) {
        crm_warn("Couldn't parse options from request: %s", pcmk_rc_str(rc));
    }

    read_only = !pcmk_is_set(operation->flags, cib__op_attr_modifies);

    // Mirror the logic in prepare_input() in the CIB manager
    if ((section != NULL) && pcmk__xe_is(data, PCMK_XE_CIB)) {

        data = pcmk_find_cib_element(data, section);
    }

    rc = cib_perform_op(cib, op, call_options, op_function, read_only, section,
                        request, data, true, &changed, &private->cib_xml,
                        &result_cib, &cib_diff, output);

    if (pcmk_is_set(call_options, cib_transaction)) {
        /* The rest of the logic applies only to the transaction as a whole, not
         * to individual requests.
         */
        goto done;
    }

    if (rc == -pcmk_err_schema_validation) {
        // Show validation errors to stderr
        pcmk__validate_xml(result_cib, NULL, NULL, NULL);

    } else if ((rc == pcmk_ok) && !read_only) {
        pcmk__log_xml_patchset(LOG_DEBUG, cib_diff);

        if (result_cib != private->cib_xml) {
            pcmk__xml_free(private->cib_xml);
            private->cib_xml = result_cib;
        }
        cib_set_file_flags(private, cib_file_flag_dirty);
    }

done:
    if ((result_cib != private->cib_xml) && (result_cib != *output)) {
        pcmk__xml_free(result_cib);
    }
    pcmk__xml_free(cib_diff);
    return rc;
}

static int
cib_file_perform_op_delegate(cib_t *cib, const char *op, const char *host,
                             const char *section, xmlNode *data,
                             xmlNode **output_data, int call_options,
                             const char *user_name)
{
    int rc = pcmk_ok;
    xmlNode *request = NULL;
    xmlNode *output = NULL;
    cib_file_opaque_t *private = cib->variant_opaque;

    const cib__operation_t *operation = NULL;

    crm_info("Handling %s operation for %s as %s",
             pcmk__s(op, "invalid"), pcmk__s(section, "entire CIB"),
             pcmk__s(user_name, "default user"));

    if (output_data != NULL) {
        *output_data = NULL;
    }

    if (cib->state == cib_disconnected) {
        return -ENOTCONN;
    }

    rc = cib__get_operation(op, &operation);
    rc = pcmk_rc2legacy(rc);
    if (rc != pcmk_ok) {
        // @COMPAT: At compatibility break, use rc directly
        return -EPROTONOSUPPORT;
    }

    if (file_get_op_function(operation) == NULL) {
        // @COMPAT: At compatibility break, use EOPNOTSUPP
        crm_err("Operation %s is not supported by CIB file clients", op);
        return -EPROTONOSUPPORT;
    }

    cib__set_call_options(call_options, "file operation", cib_no_mtime);

    rc = cib__create_op(cib, op, host, section, data, call_options, user_name,
                        NULL, &request);
    if (rc != pcmk_ok) {
        return rc;
    }
    pcmk__xe_set(request, PCMK__XA_ACL_TARGET, user_name);
    pcmk__xe_set(request, PCMK__XA_CIB_CLIENTID, private->id);

    if (pcmk_is_set(call_options, cib_transaction)) {
        rc = cib__extend_transaction(cib, request);
        goto done;
    }

    rc = cib_file_process_request(cib, request, &output);

    if ((output_data != NULL) && (output != NULL)) {
        if (output->doc == private->cib_xml->doc) {
            *output_data = pcmk__xml_copy(NULL, output);
        } else {
            *output_data = output;
        }
    }

done:
    if ((output != NULL)
        && (output->doc != private->cib_xml->doc)
        && ((output_data == NULL) || (output != *output_data))) {

        pcmk__xml_free(output);
    }
    pcmk__xml_free(request);
    return rc;
}

/*!
 * \internal
 * \brief Read CIB from disk and validate it against XML schema
 *
 * \param[in]   filename  Name of file to read CIB from
 * \param[out]  output    Where to store the read CIB XML
 *
 * \return pcmk_ok on success,
 *         -ENXIO if file does not exist (or stat() otherwise fails), or
 *         -pcmk_err_schema_validation if XML doesn't parse or validate
 * \note If filename is the live CIB, this will *not* verify its digest,
 *       though that functionality would be trivial to add here.
 *       Also, this will *not* verify that the file is writable,
 *       because some callers might not need to write.
 */
static int
load_file_cib(const char *filename, xmlNode **output)
{
    struct stat buf;
    xmlNode *root = NULL;

    /* Ensure file is readable */
    if (strcmp(filename, "-") && (stat(filename, &buf) < 0)) {
        return -ENXIO;
    }

    /* Parse XML from file */
    root = pcmk__xml_read(filename);
    if (root == NULL) {
        return -pcmk_err_schema_validation;
    }

    /* Add a status section if not already present */
    if (pcmk__xe_first_child(root, PCMK_XE_STATUS, NULL, NULL) == NULL) {
        pcmk__xe_create(root, PCMK_XE_STATUS);
    }

    /* Validate XML against its specified schema */
    if (!pcmk__configured_schema_validates(root)) {
        pcmk__xml_free(root);
        return -pcmk_err_schema_validation;
    }

    /* Remember the parsed XML for later use */
    *output = root;
    return pcmk_ok;
}

static int
cib_file_signon(cib_t *cib, const char *name, enum cib_conn_type type)
{
    int rc = pcmk_ok;
    cib_file_opaque_t *private = cib->variant_opaque;

    if (private->filename == NULL) {
        rc = -EINVAL;
    } else {
        rc = load_file_cib(private->filename, &private->cib_xml);
    }

    if (rc == pcmk_ok) {
        crm_debug("Opened connection to local file '%s' for %s",
                  private->filename, pcmk__s(name, "client"));
        cib->state = cib_connected_command;
        cib->type = cib_command;
        register_client(cib);

    } else {
        crm_info("Connection to local file '%s' for %s (client %s) failed: %s",
                 private->filename, pcmk__s(name, "client"), private->id,
                 pcmk_strerror(rc));
    }
    return rc;
}

/*!
 * \internal
 * \brief Write out the in-memory CIB to a live CIB file
 *
 * \param[in]     cib_root  Root of XML tree to write
 * \param[in,out] path      Full path to file to write
 *
 * \return 0 on success, -1 on failure
 */
static int
cib_file_write_live(xmlNode *cib_root, char *path)
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
    if ((uid != 0) && (uid != daemon_pwent->pw_uid)) {
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
    if (cib_file_write_with_digest(cib_root, cib_dirname,
                                   cib_filename) != pcmk_ok) {
        rc = -1;
    }

    /* turn off file ownership changes, for other callers */
    if (uid == 0) {
        cib_do_chown = FALSE;
    }

    /* undo fancy stuff */
    if ((sep != NULL) && (*sep == '\0')) {
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
 * \param[in,out] cib  CIB object to sign off
 *
 * \return pcmk_ok on success, pcmk_err_generic on failure
 * \todo This method should refuse to write the live CIB if the CIB manager is
 *       running.
 */
static int
cib_file_signoff(cib_t *cib)
{
    int rc = pcmk_ok;
    cib_file_opaque_t *private = cib->variant_opaque;

    crm_debug("Disconnecting from the CIB manager");
    cib->state = cib_disconnected;
    cib->type = cib_no_connection;
    unregister_client(cib);
    cib->cmds->end_transaction(cib, false, cib_none);

    /* If the in-memory CIB has been changed, write it to disk */
    if (pcmk_is_set(private->flags, cib_file_flag_dirty)) {

        /* If this is the live CIB, write it out with a digest */
        if (pcmk_is_set(private->flags, cib_file_flag_live)) {
            if (cib_file_write_live(private->cib_xml, private->filename) < 0) {
                rc = pcmk_err_generic;
            }

        /* Otherwise, it's a simple write */
        } else {
            bool compress = pcmk__ends_with_ext(private->filename, ".bz2");

            if (pcmk__xml_write_file(private->cib_xml, private->filename,
                                     compress) != pcmk_rc_ok) {
                rc = pcmk_err_generic;
            }
        }

        if (rc == pcmk_ok) {
            crm_info("Wrote CIB to %s", private->filename);
            cib_clear_file_flags(private, cib_file_flag_dirty);
        } else {
            crm_err("Could not write CIB to %s", private->filename);
        }
    }

    /* Free the in-memory CIB */
    pcmk__xml_free(private->cib_xml);
    private->cib_xml = NULL;
    return rc;
}

static int
cib_file_free(cib_t *cib)
{
    int rc = pcmk_ok;

    if (cib->state != cib_disconnected) {
        rc = cib_file_signoff(cib);
    }

    if (rc == pcmk_ok) {
        cib_file_opaque_t *private = cib->variant_opaque;

        free(private->id);
        free(private->filename);
        free(private);
        free(cib->cmds);
        free(cib->user);
        free(cib);

    } else {
        fprintf(stderr, "Couldn't sign off: %d\n", rc);
    }

    return rc;
}

static int
cib_file_register_notification(cib_t *cib, const char *callback, int enabled)
{
    return -EPROTONOSUPPORT;
}

static int
cib_file_set_connection_dnotify(cib_t *cib,
                                void (*dnotify) (gpointer user_data))
{
    return -EPROTONOSUPPORT;
}

/*!
 * \internal
 * \brief Get the given CIB connection's unique client identifier
 *
 * \param[in]  cib       CIB connection
 * \param[out] async_id  If not \p NULL, where to store asynchronous client ID
 * \param[out] sync_id   If not \p NULL, where to store synchronous client ID
 *
 * \return Legacy Pacemaker return code
 *
 * \note This is the \p cib_file variant implementation of
 *       \p cib_api_operations_t:client_id().
 */
static int
cib_file_client_id(const cib_t *cib, const char **async_id,
                   const char **sync_id)
{
    cib_file_opaque_t *private = cib->variant_opaque;

    if (async_id != NULL) {
        *async_id = private->id;
    }
    if (sync_id != NULL) {
        *sync_id = private->id;
    }
    return pcmk_ok;
}

cib_t *
cib_file_new(const char *cib_location)
{
    cib_t *cib = NULL;
    cib_file_opaque_t *private = NULL;
    char *filename = NULL;

    if (cib_location == NULL) {
        cib_location = getenv("CIB_file");
        if (cib_location == NULL) {
            return NULL; // Shouldn't be possible if we were called internally
        }
    }

    cib = cib_new_variant();
    if (cib == NULL) {
        return NULL;
    }

    filename = strdup(cib_location);
    if (filename == NULL) {
        free(cib);
        return NULL;
    }

    private = calloc(1, sizeof(cib_file_opaque_t));
    if (private == NULL) {
        free(cib);
        free(filename);
        return NULL;
    }

    private->id = crm_generate_uuid();
    private->filename = filename;

    cib->variant = cib_file;
    cib->variant_opaque = private;

    private->flags = 0;
    if (cib_file_is_live(cib_location)) {
        cib_set_file_flags(private, cib_file_flag_live);
        crm_trace("File %s detected as live CIB", cib_location);
    }

    /* assign variant specific ops */
    cib->delegate_fn = cib_file_perform_op_delegate;
    cib->cmds->signon = cib_file_signon;
    cib->cmds->signoff = cib_file_signoff;
    cib->cmds->free = cib_file_free;
    cib->cmds->register_notification = cib_file_register_notification;
    cib->cmds->set_connection_dnotify = cib_file_set_connection_dnotify;

    cib->cmds->client_id = cib_file_client_id;

    return cib;
}

/*!
 * \internal
 * \brief Compare the calculated digest of an XML tree against a signature file
 *
 * \param[in] root     Root of XML tree to compare
 * \param[in] sigfile  Name of signature file containing digest to compare
 *
 * \return TRUE if digests match or signature file does not exist, else FALSE
 */
static gboolean
cib_file_verify_digest(xmlNode *root, const char *sigfile)
{
    gboolean passed = FALSE;
    char *expected;
    int rc = pcmk__file_contents(sigfile, &expected);

    switch (rc) {
        case pcmk_rc_ok:
            if (expected == NULL) {
                crm_err("On-disk digest at %s is empty", sigfile);
                return FALSE;
            }
            break;
        case ENOENT:
            crm_warn("No on-disk digest present at %s", sigfile);
            return TRUE;
        default:
            crm_err("Could not read on-disk digest from %s: %s",
                    sigfile, pcmk_rc_str(rc));
            return FALSE;
    }
    passed = pcmk__verify_digest(root, expected);
    free(expected);
    return passed;
}

/*!
 * \internal
 * \brief Read an XML tree from a file and verify its digest
 *
 * \param[in]  filename  Name of XML file to read
 * \param[in]  sigfile   Name of signature file containing digest to compare
 * \param[out] root      If non-NULL, will be set to pointer to parsed XML tree
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

    pcmk__assert(filename != NULL);
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
    local_root = pcmk__xml_read(filename);
    if (local_root == NULL) {
        crm_warn("Cluster configuration file %s is corrupt (unparseable as XML)", filename);
        return -pcmk_err_cib_corrupt;
    }

    /* If sigfile is not specified, use original file name plus .sig */
    if (sigfile == NULL) {
        sigfile = local_sigfile = crm_strdup_printf("%s.sig", filename);
    }

    /* Verify that digests match */
    if (cib_file_verify_digest(local_root, sigfile) == FALSE) {
        free(local_sigfile);
        pcmk__xml_free(local_root);
        return -pcmk_err_cib_modified;
    }

    free(local_sigfile);
    if (root) {
        *root = local_root;
    } else {
        pcmk__xml_free(local_root);
    }
    return pcmk_ok;
}

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
    unsigned int seq = 0U;
    char *cib_path = crm_strdup_printf("%s/%s", cib_dirname, cib_filename);
    char *cib_digest = crm_strdup_printf("%s.sig", cib_path);
    char *backup_path;
    char *backup_digest;

    // Determine backup and digest file names
    if (pcmk__read_series_sequence(cib_dirname, CIB_SERIES,
                                   &seq) != pcmk_rc_ok) {
        // @TODO maybe handle errors better ...
        seq = 0U;
    }
    backup_path = pcmk__series_filename(cib_dirname, CIB_SERIES, seq,
                                        CIB_SERIES_BZIP);
    backup_digest = crm_strdup_printf("%s.sig", backup_path);

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
        pcmk__write_series_sequence(cib_dirname, CIB_SERIES, ++seq,
                                    CIB_SERIES_MAX);
        if (cib_do_chown) {
            int rc2;

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
            rc2 = pcmk__chown_series_sequence(cib_dirname, CIB_SERIES,
                                              cib_file_owner, cib_file_group);
            if (rc2 != pcmk_rc_ok) {
                crm_err("Could not set owner of sequence file in %s: %s",
                        cib_dirname, pcmk_rc_str(rc2));
                rc = -1;
            }
        }
        pcmk__sync_directory(cib_dirname);
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
 * Set \c PCMK_XA_NUM_UPDATES to 0, set \c PCMK_XA_CIB_LAST_WRITTEN to the
 * current timestamp, and strip out the status section.
 *
 * \param[in,out] root  Root of CIB XML tree
 *
 * \return void
 */
static void
cib_file_prepare_xml(xmlNode *root)
{
    xmlNode *cib_status_root = NULL;

    /* Always write out with num_updates=0 and current last-written timestamp */
    pcmk__xe_set(root, PCMK_XA_NUM_UPDATES, "0");
    pcmk__xe_add_last_written(root);

    /* Delete status section before writing to file, because
     * we discard it on startup anyway, and users get confused by it */
    cib_status_root = pcmk__xe_first_child(root, PCMK_XE_STATUS, NULL, NULL);
    CRM_CHECK(cib_status_root != NULL, return);
    pcmk__xml_free(cib_status_root);
}

/*!
 * \internal
 * \brief Write CIB to disk, along with a signature file containing its digest
 *
 * \param[in,out] cib_root      Root of XML tree to write
 * \param[in]     cib_dirname   Directory containing CIB and signature files
 * \param[in]     cib_filename  Name (relative to cib_dirname) of file to write
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
    const char *epoch = pcmk__xe_get(cib_root, PCMK_XA_EPOCH);
    const char *admin_epoch = pcmk__xe_get(cib_root, PCMK_XA_ADMIN_EPOCH);

    /* Determine full CIB and signature pathnames */
    char *cib_path = crm_strdup_printf("%s/%s", cib_dirname, cib_filename);
    char *digest_path = crm_strdup_printf("%s.sig", cib_path);

    /* Create temporary file name patterns for writing out CIB and signature */
    char *tmp_cib = crm_strdup_printf("%s/cib.XXXXXX", cib_dirname);
    char *tmp_digest = crm_strdup_printf("%s/cib.XXXXXX", cib_dirname);

    /* Ensure the admin didn't modify the existing CIB underneath us */
    crm_trace("Reading cluster configuration file %s", cib_path);
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
    if (pcmk__xml_write_fd(cib_root, tmp_cib, fd) != pcmk_rc_ok) {
        crm_err("Changes couldn't be written to %s", tmp_cib);
        exit_rc = pcmk_err_cib_save;
        goto cleanup;
    }

    /* Calculate CIB digest */
    digest = pcmk__digest_on_disk_cib(cib_root);
    pcmk__assert(digest != NULL);
    crm_info("Wrote version %s.%s.0 of the CIB to disk (digest: %s)",
             (admin_epoch ? admin_epoch : "0"), (epoch ? epoch : "0"), digest);

    /* Write the CIB digest to a temporary file */
    fd = mkstemp(tmp_digest);
    if (fd < 0) {
        crm_perror(LOG_ERR, "Could not create temporary file for CIB digest");
        exit_rc = pcmk_err_cib_save;
        goto cleanup;
    }
    if (cib_do_chown && (fchown(fd, cib_file_owner, cib_file_group) < 0)) {
        crm_perror(LOG_ERR, "Couldn't protect temporary file %s for writing CIB",
                   tmp_cib);
        exit_rc = pcmk_err_cib_save;
        close(fd);
        goto cleanup;
    }
    rc = pcmk__write_sync(fd, digest);
    if (rc != pcmk_rc_ok) {
        crm_err("Could not write digest to %s: %s",
                tmp_digest, pcmk_rc_str(rc));
        exit_rc = pcmk_err_cib_save;
        close(fd);
        goto cleanup;
    }
    close(fd);
    crm_debug("Wrote digest %s to disk", digest);

    /* Verify that what we wrote is sane */
    crm_info("Reading cluster configuration file %s (digest: %s)",
             tmp_cib, tmp_digest);
    rc = cib_file_read_and_verify(tmp_cib, tmp_digest, NULL);
    pcmk__assert(rc == 0);

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
    pcmk__sync_directory(cib_dirname);

  cleanup:
    free(cib_path);
    free(digest_path);
    free(digest);
    free(tmp_digest);
    free(tmp_cib);
    return exit_rc;
}

/*!
 * \internal
 * \brief Process requests in a CIB transaction
 *
 * Stop when a request fails or when all requests have been processed.
 *
 * \param[in,out] cib          CIB client
 * \param[in,out] transaction  CIB transaction
 *
 * \return Standard Pacemaker return code
 */
static int
cib_file_process_transaction_requests(cib_t *cib, xmlNode *transaction)
{
    cib_file_opaque_t *private = cib->variant_opaque;

    for (xmlNode *request = pcmk__xe_first_child(transaction,
                                                 PCMK__XE_CIB_COMMAND, NULL,
                                                 NULL);
         request != NULL;
         request = pcmk__xe_next(request, PCMK__XE_CIB_COMMAND)) {

        xmlNode *output = NULL;
        const char *op = pcmk__xe_get(request, PCMK__XA_CIB_OP);

        int rc = cib_file_process_request(cib, request, &output);

        rc = pcmk_legacy2rc(rc);
        if (rc != pcmk_rc_ok) {
            crm_err("Aborting transaction for CIB file client (%s) on file "
                    "'%s' due to failed %s request: %s",
                    private->id, private->filename, op, pcmk_rc_str(rc));
            crm_log_xml_info(request, "Failed request");
            return rc;
        }

        crm_trace("Applied %s request to transaction working CIB for CIB file "
                  "client (%s) on file '%s'",
                  op, private->id, private->filename);
        crm_log_xml_trace(request, "Successful request");
    }

    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Commit a given CIB file client's transaction to a working CIB copy
 *
 * \param[in,out] cib          CIB file client
 * \param[in]     transaction  CIB transaction
 * \param[in,out] result_cib   Where to store result CIB
 *
 * \return Standard Pacemaker return code
 *
 * \note The caller is responsible for replacing the \p cib argument's
 *       \p private->cib_xml with \p result_cib on success, and for freeing
 *       \p result_cib using \p pcmk__xml_free() on failure.
 */
static int
cib_file_commit_transaction(cib_t *cib, xmlNode *transaction,
                            xmlNode **result_cib)
{
    int rc = pcmk_rc_ok;
    cib_file_opaque_t *private = cib->variant_opaque;
    xmlNode *saved_cib = private->cib_xml;

    CRM_CHECK(pcmk__xe_is(transaction, PCMK__XE_CIB_TRANSACTION),
              return pcmk_rc_no_transaction);

    /* *result_cib should be a copy of private->cib_xml (created by
     * cib_perform_op()). If not, make a copy now. Change tracking isn't
     * strictly required here because:
     * * Each request in the transaction will have changes tracked and ACLs
     *   checked if appropriate.
     * * cib_perform_op() will infer changes for the commit request at the end.
     */
    CRM_CHECK((*result_cib != NULL) && (*result_cib != private->cib_xml),
              *result_cib = pcmk__xml_copy(NULL, private->cib_xml));

    crm_trace("Committing transaction for CIB file client (%s) on file '%s' to "
              "working CIB",
              private->id, private->filename);

    // Apply all changes to a working copy of the CIB
    private->cib_xml = *result_cib;

    rc = cib_file_process_transaction_requests(cib, transaction);

    crm_trace("Transaction commit %s for CIB file client (%s) on file '%s'",
              ((rc == pcmk_rc_ok)? "succeeded" : "failed"),
              private->id, private->filename);

    /* Some request types (for example, erase) may have freed private->cib_xml
     * (the working copy) and pointed it at a new XML object. In that case, it
     * follows that *result_cib (the working copy) was freed.
     *
     * Point *result_cib at the updated working copy stored in private->cib_xml.
     */
    *result_cib = private->cib_xml;

    // Point private->cib_xml back to the unchanged original copy
    private->cib_xml = saved_cib;

    return rc;
}

static int
cib_file_process_commit_transaction(const char *op, int options,
                                    const char *section, xmlNode *req,
                                    xmlNode *input, xmlNode *existing_cib,
                                    xmlNode **result_cib, xmlNode **answer)
{
    int rc = pcmk_rc_ok;
    const char *client_id = pcmk__xe_get(req, PCMK__XA_CIB_CLIENTID);
    cib_t *cib = NULL;

    CRM_CHECK(client_id != NULL, return -EINVAL);

    cib = get_client(client_id);
    CRM_CHECK(cib != NULL, return -EINVAL);

    rc = cib_file_commit_transaction(cib, input, result_cib);
    if (rc != pcmk_rc_ok) {
        cib_file_opaque_t *private = cib->variant_opaque;

        crm_err("Could not commit transaction for CIB file client (%s) on "
                "file '%s': %s",
                private->id, private->filename, pcmk_rc_str(rc));
    }
    return pcmk_rc2legacy(rc);
}
