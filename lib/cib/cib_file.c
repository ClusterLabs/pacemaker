/*
 * Original copyright 2004 International Business Machines
 * Later changes copyright 2008-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <unistd.h>
#include <limits.h>
#include <stdbool.h>
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

#define CIB_SERIES "cib"
#define CIB_SERIES_MAX 100
#define CIB_LIVE_NAME CIB_SERIES ".xml"

// key: client ID (const char *) -> value: client (cib_t *)
static GHashTable *client_table = NULL;

enum file_flags {
    file_flag_dirty = (UINT32_C(1) << 0),
    file_flag_live  = (UINT32_C(1) << 1),
};

typedef struct {
    char *id;
    char *filename;
    uint32_t flags; // Group of enum file_flags
    xmlNode *cib_xml;
} file_opaque_t;

/* backup_cib_file() and cib_file_write_with_digest() need to chown the
 * written files only in limited circumstances, so these variables allow
 * that to be indicated without affecting external callers
 */
static uid_t file_owner = 0;
static uid_t file_group = 0;
static bool do_chown = false;

static cib__op_fn_t get_op_function(const cib__operation_t *operation);

#define set_file_flags(cibfile, flags_to_set) do {                      \
        (cibfile)->flags = pcmk__set_flags_as(__func__, __LINE__,       \
                                              LOG_TRACE, "CIB file",    \
                                              cibfile->filename,        \
                                              (cibfile)->flags,         \
                                              (flags_to_set),           \
                                              #flags_to_set);           \
    } while (0)

#define clear_file_flags(cibfile, flags_to_clear) do {                  \
        (cibfile)->flags = pcmk__clear_flags_as(__func__, __LINE__,     \
                                                LOG_TRACE, "CIB file",  \
                                                cibfile->filename,      \
                                                (cibfile)->flags,       \
                                                (flags_to_clear),       \
                                                #flags_to_clear);       \
    } while (0)

/*!
 * \internal
 * \brief Add a CIB file client to client table
 *
 * \param[in] cib  CIB client
 */
static void
register_client(const cib_t *cib)
{
    file_opaque_t *private = cib->variant_opaque;

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
    file_opaque_t *private = cib->variant_opaque;

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

static int
process_request(cib_t *cib, xmlNode *request, xmlNode **output)
{
    int rc = pcmk_rc_ok;
    const cib__operation_t *operation = NULL;
    cib__op_fn_t op_function = NULL;

    uint32_t call_options = cib_none;
    const char *op = pcmk__xe_get(request, PCMK__XA_CIB_OP);

    bool changed = false;
    bool read_only = false;
    xmlNode *result_cib = NULL;
    xmlNode *cib_diff = NULL;

    file_opaque_t *private = cib->variant_opaque;

    // We error checked these in callers
    cib__get_operation(op, &operation);
    op_function = get_op_function(operation);

    rc = pcmk__xe_get_flags(request, PCMK__XA_CIB_CALLOPT, &call_options,
                            cib_none);
    if (rc != pcmk_rc_ok) {
        pcmk__warn("Couldn't parse options from request: %s", pcmk_rc_str(rc));
    }

    read_only = !pcmk__is_set(operation->flags, cib__op_attr_modifies);

    if (read_only) {
        rc = cib__perform_query(op_function, request, &private->cib_xml,
                                output);
    } else {
        result_cib = private->cib_xml;
        rc = cib_perform_op(cib_file, op_function, request, &changed,
                            &result_cib, &cib_diff, output);
    }

    if (pcmk__is_set(call_options, cib_transaction)) {
        /* The rest of the logic applies only to the transaction as a whole, not
         * to individual requests.
         */
        goto done;
    }

    if (rc == pcmk_rc_schema_validation) {
        // Show validation errors to stderr
        pcmk__validate_xml(result_cib, NULL, NULL);

    } else if ((rc == pcmk_rc_ok) && !read_only) {
        if (result_cib != private->cib_xml) {
            pcmk__xml_free(private->cib_xml);
            private->cib_xml = result_cib;
        }
        set_file_flags(private, file_flag_dirty);
    }

done:
    if ((result_cib != private->cib_xml) && (result_cib != *output)) {
        pcmk__xml_free(result_cib);
    }
    pcmk__xml_free(cib_diff);
    return rc;
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
process_transaction_requests(cib_t *cib, xmlNode *transaction)
{
    file_opaque_t *private = cib->variant_opaque;

    for (xmlNode *request = pcmk__xe_first_child(transaction,
                                                 PCMK__XE_CIB_COMMAND, NULL,
                                                 NULL);
         request != NULL;
         request = pcmk__xe_next(request, PCMK__XE_CIB_COMMAND)) {

        xmlNode *output = NULL;
        const char *op = pcmk__xe_get(request, PCMK__XA_CIB_OP);

        int rc = process_request(cib, request, &output);

        if (rc != pcmk_rc_ok) {
            pcmk__err("Aborting transaction for CIB file client (%s) on file "
                      "'%s' due to failed %s request: %s",
                      private->id, private->filename, op, pcmk_rc_str(rc));
            pcmk__log_xml_info(request, "Failed request");
            return rc;
        }

        pcmk__trace("Applied %s request to transaction working CIB for CIB "
                    "file client (%s) on file '%s'",
                    op, private->id, private->filename);
        pcmk__log_xml_trace(request, "Successful request");
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
commit_transaction(cib_t *cib, xmlNode *transaction, xmlNode **result_cib)
{
    int rc = pcmk_rc_ok;
    file_opaque_t *private = cib->variant_opaque;
    xmlNode *saved_cib = private->cib_xml;

    CRM_CHECK(pcmk__xe_is(transaction, PCMK__XE_CIB_TRANSACTION),
              return pcmk_rc_no_transaction);

    /* *result_cib should be a copy of private->cib_xml (created by
     * cib_perform_op()). If not, make a copy now. Change tracking isn't
     * strictly required here because each request in the transaction will have
     * changes tracked and ACLs checked if appropriate.
     */
    CRM_CHECK((*result_cib != NULL) && (*result_cib != private->cib_xml),
              *result_cib = pcmk__xml_copy(NULL, private->cib_xml));

    pcmk__trace("Committing transaction for CIB file client (%s) on file '%s' "
                "to working CIB",
                private->id, private->filename);

    // Apply all changes to a working copy of the CIB
    private->cib_xml = *result_cib;

    rc = process_transaction_requests(cib, transaction);

    pcmk__trace("Transaction commit %s for CIB file client (%s) on file '%s'",
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
process_commit_transact(const char *section, xmlNode *req, xmlNode *input,
                        xmlNode **cib_xml, xmlNode **answer)
{
    int rc = pcmk_rc_ok;
    const char *client_id = pcmk__xe_get(req, PCMK__XA_CIB_CLIENTID);
    cib_t *cib = NULL;

    CRM_CHECK(client_id != NULL, return -EINVAL);

    cib = get_client(client_id);
    CRM_CHECK(cib != NULL, return -EINVAL);

    rc = commit_transaction(cib, input, cib_xml);
    if (rc != pcmk_rc_ok) {
        file_opaque_t *private = cib->variant_opaque;

        pcmk__err("Could not commit transaction for CIB file client (%s) on "
                  "file '%s': %s",
                  private->id, private->filename, pcmk_rc_str(rc));
    }
    return pcmk_rc2legacy(rc);
}

static const cib__op_fn_t op_functions[] = {
    [cib__op_apply_patch]      = cib__process_apply_patch,
    [cib__op_bump]             = cib__process_bump,
    [cib__op_commit_transact]  = process_commit_transact,
    [cib__op_create]           = cib__process_create,
    [cib__op_delete]           = cib__process_delete,
    [cib__op_erase]            = cib__process_erase,
    [cib__op_modify]           = cib__process_modify,
    [cib__op_query]            = cib__process_query,
    [cib__op_replace]          = cib__process_replace,
    [cib__op_upgrade]          = cib__process_upgrade,
};

/*!
 * \internal
 * \brief Get the function that performs a given CIB file operation
 *
 * \param[in] operation  Operation whose function to look up
 *
 * \return Function that performs \p operation for a CIB file client
 */
static cib__op_fn_t
get_op_function(const cib__operation_t *operation)
{
    enum cib__op_type type = operation->type;

    pcmk__assert(type >= 0);

    if (type >= PCMK__NELEM(op_functions)) {
        return NULL;
    }
    return op_functions[type];
}

/*!
 * \internal
 * \brief Check whether a file is the live CIB
 *
 * \param[in] filename Name of file to check
 *
 * \return \c true if file exists and its real path is same as the live CIB's,
 *         or \c false otherwise
 */
static bool
is_live(const char *filename)
{
    bool same = false;

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
file_perform_op_delegate(cib_t *cib, const char *op, const char *host,
                         const char *section, xmlNode *data,
                         xmlNode **output_data, int call_options,
                         const char *user_name)
{
    int rc = pcmk_ok;
    xmlNode *request = NULL;
    xmlNode *output = NULL;
    file_opaque_t *private = cib->variant_opaque;

    const cib__operation_t *operation = NULL;

    pcmk__info("Handling %s operation for %s as %s",
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

    if (get_op_function(operation) == NULL) {
        // @COMPAT: At compatibility break, use EOPNOTSUPP
        pcmk__err("Operation %s is not supported by CIB file clients", op);
        return -EPROTONOSUPPORT;
    }

    cib__set_call_options(call_options, "file operation", cib_no_mtime);

    rc = cib__create_op(cib, op, host, section, data, call_options, user_name,
                        NULL, &request);
    rc = pcmk_rc2legacy(rc);
    if (rc != pcmk_ok) {
        return rc;
    }

    pcmk__xe_set(request, PCMK__XA_ACL_TARGET, user_name);
    pcmk__xe_set(request, PCMK__XA_CIB_CLIENTID, private->id);

    if (pcmk__is_set(call_options, cib_transaction)) {
        rc = cib__extend_transaction(cib, request);
        rc = pcmk_rc2legacy(rc);
        goto done;
    }

    rc = process_request(cib, request, &output);
    rc = pcmk_rc2legacy(rc);

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
file_signon(cib_t *cib, const char *name, enum cib_conn_type type)
{
    int rc = pcmk_ok;
    file_opaque_t *private = cib->variant_opaque;

    if (private->filename == NULL) {
        rc = -EINVAL;
    } else {
        rc = load_file_cib(private->filename, &private->cib_xml);
    }

    if (rc == pcmk_ok) {
        pcmk__debug("Opened connection to local file '%s' for %s",
                    private->filename, pcmk__s(name, "client"));
        cib->state = cib_connected_command;
        cib->type = cib_command;
        register_client(cib);

    } else {
        pcmk__info("Connection to local file '%s' for %s (client %s) failed: "
                   "%s",
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
 * \return Standard Pacemaker return code
 */
static int
write_live(xmlNode *cib_root, char *path)
{
    uid_t euid = geteuid();
    uid_t daemon_uid = 0;
    gid_t daemon_gid = 0;
    char *sep = strrchr(path, '/');
    const char *cib_dirname, *cib_filename;
    int rc = pcmk_rc_ok;

    /* Get the desired uid/gid */
    rc = pcmk__daemon_user(&daemon_uid, &daemon_gid);
    if (rc != pcmk_rc_ok) {
        pcmk__err("Could not find user " CRM_DAEMON_USER ": %s",
                  pcmk_rc_str(rc));
        return rc;
    }

    /* If we're root, we can change the ownership;
     * if we're daemon, anything we create will be OK;
     * otherwise, block access so we don't create wrong owner
     */
    if ((euid != 0) && (euid != daemon_uid)) {
        pcmk__err("Must be root or " CRM_DAEMON_USER " to modify live CIB");

        // @TODO Should this return an error instead?
        return pcmk_rc_ok;
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
    if (euid == 0) {
        file_owner = daemon_uid;
        file_group = daemon_gid;
        do_chown = true;
    }

    /* write the file */
    rc = cib_file_write_with_digest(cib_root, cib_dirname, cib_filename);
    rc = pcmk_legacy2rc(rc);

    /* turn off file ownership changes, for other callers */
    if (euid == 0) {
        do_chown = false;
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
file_signoff(cib_t *cib)
{
    int rc = pcmk_ok;
    file_opaque_t *private = cib->variant_opaque;

    pcmk__debug("Disconnecting from the CIB manager");
    cib->state = cib_disconnected;
    cib->type = cib_no_connection;
    unregister_client(cib);
    cib->cmds->end_transaction(cib, false, cib_none);

    /* If the in-memory CIB has been changed, write it to disk */
    if (pcmk__is_set(private->flags, file_flag_dirty)) {

        /* If this is the live CIB, write it out with a digest */
        if (pcmk__is_set(private->flags, file_flag_live)) {
            rc = write_live(private->cib_xml, private->filename);
            rc = pcmk_rc2legacy(rc);

        /* Otherwise, it's a simple write */
        } else {
            bool compress = g_str_has_suffix(private->filename, ".bz2");

            if (pcmk__xml_write_file(private->cib_xml, private->filename,
                                     compress) != pcmk_rc_ok) {
                rc = pcmk_err_generic;
            }
        }

        if (rc == pcmk_ok) {
            pcmk__info("Wrote CIB to %s", private->filename);
            clear_file_flags(private, file_flag_dirty);
        } else {
            pcmk__err("Could not write CIB to %s", private->filename);
        }
    }

    /* Free the in-memory CIB */
    pcmk__xml_free(private->cib_xml);
    private->cib_xml = NULL;
    return rc;
}

static int
file_free(cib_t *cib)
{
    int rc = pcmk_ok;

    if (cib->state != cib_disconnected) {
        rc = file_signoff(cib);
    }

    if (rc == pcmk_ok) {
        file_opaque_t *private = cib->variant_opaque;

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
file_register_notification(cib_t *cib, const char *callback, int enabled)
{
    return -EPROTONOSUPPORT;
}

static int
file_set_connection_dnotify(cib_t *cib, void (*dnotify)(gpointer user_data))
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
file_client_id(const cib_t *cib, const char **async_id, const char **sync_id)
{
    file_opaque_t *private = cib->variant_opaque;

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
    file_opaque_t *private = NULL;
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

    private = calloc(1, sizeof(file_opaque_t));
    if (private == NULL) {
        free(cib);
        free(filename);
        return NULL;
    }

    private->id = pcmk__generate_uuid();
    private->filename = filename;

    cib->variant = cib_file;
    cib->variant_opaque = private;

    private->flags = 0;
    if (is_live(cib_location)) {
        set_file_flags(private, file_flag_live);
        pcmk__trace("File %s detected as live CIB", cib_location);
    }

    /* assign variant specific ops */
    cib->delegate_fn = file_perform_op_delegate;
    cib->cmds->signon = file_signon;
    cib->cmds->signoff = file_signoff;
    cib->cmds->free = file_free;
    cib->cmds->register_notification = file_register_notification;
    cib->cmds->set_connection_dnotify = file_set_connection_dnotify;

    cib->cmds->client_id = file_client_id;

    return cib;
}

/*!
 * \internal
 * \brief Compare the calculated digest of an XML tree against a signature file
 *
 * \param[in] root     Root of XML tree to compare
 * \param[in] sigfile  Name of signature file containing digest to compare
 *
 * \return \c true if digests match or signature file does not exist, or
 *         \c false otherwise
 */
static bool
verify_digest(xmlNode *root, const char *sigfile)
{
    bool passed = false;
    char *expected;
    int rc = pcmk__file_contents(sigfile, &expected);

    switch (rc) {
        case pcmk_rc_ok:
            if (expected == NULL) {
                pcmk__err("On-disk digest at %s is empty", sigfile);
                return false;
            }
            break;
        case ENOENT:
            pcmk__warn("No on-disk digest present at %s", sigfile);
            return true;
        default:
            pcmk__err("Could not read on-disk digest from %s: %s", sigfile,
                      pcmk_rc_str(rc));
            return false;
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
        pcmk__warn("Could not verify cluster configuration file %s: "
                   "stat() failed: %s",
                   filename, strerror(errno));
        return -errno;
    } else if (buf.st_size == 0) {
        pcmk__warn("Cluster configuration file %s is corrupt (size is zero)",
                   filename);
        return -pcmk_err_cib_corrupt;
    }

    /* Parse XML */
    local_root = pcmk__xml_read(filename);
    if (local_root == NULL) {
        pcmk__warn("Cluster configuration file %s is corrupt (unparseable as "
                   "XML)",
                   filename);
        return -pcmk_err_cib_corrupt;
    }

    /* If sigfile is not specified, use original file name plus .sig */
    if (sigfile == NULL) {
        sigfile = local_sigfile = pcmk__assert_asprintf("%s.sig", filename);
    }

    /* Verify that digests match */
    if (!verify_digest(local_root, sigfile)) {
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
backup_cib_file(const char *cib_dirname, const char *cib_filename)
{
    int rc = 0;
    unsigned int seq = 0U;
    char *cib_path = pcmk__assert_asprintf("%s/%s", cib_dirname, cib_filename);
    char *cib_digest = pcmk__assert_asprintf("%s.sig", cib_path);
    char *backup_path;
    char *backup_digest;

    // Determine backup and digest file names
    if (pcmk__read_series_sequence(cib_dirname, CIB_SERIES,
                                   &seq) != pcmk_rc_ok) {
        // @TODO maybe handle errors better ...
        seq = 0U;
    }

    // Must pass false because archived copies are created with hard links
    backup_path = pcmk__series_filename(cib_dirname, CIB_SERIES, seq, false);
    backup_digest = pcmk__assert_asprintf("%s.sig", backup_path);

    /* Remove the old backups if they exist */
    unlink(backup_path);
    unlink(backup_digest);

    /* Back up the CIB, by hard-linking it to the backup name */
    if ((link(cib_path, backup_path) < 0) && (errno != ENOENT)) {
        pcmk__err("Could not archive %s by linking to %s: %s", cib_path,
                  backup_path, strerror(errno));
        rc = -1;

    /* Back up the CIB signature similarly */
    } else if ((link(cib_digest, backup_digest) < 0) && (errno != ENOENT)) {
        pcmk__err("Could not archive %s by linking to %s: %s", cib_digest,
                  backup_digest, strerror(errno));
        rc = -1;

    /* Update the last counter and ensure everything is sync'd to media */
    } else {
        pcmk__write_series_sequence(cib_dirname, CIB_SERIES, ++seq,
                                    CIB_SERIES_MAX);
        if (do_chown) {
            int rc2;

            if ((chown(backup_path, file_owner, file_group) < 0)
                && (errno != ENOENT)) {

                pcmk__err("Could not set owner of %s: %s", backup_path,
                          strerror(errno));
                rc = -1;
            }
            if ((chown(backup_digest, file_owner, file_group) < 0)
                && (errno != ENOENT)) {

                pcmk__err("Could not set owner of %s: %s", backup_digest,
                          strerror(errno));
                rc = -1;
            }
            rc2 = pcmk__chown_series_sequence(cib_dirname, CIB_SERIES,
                                              file_owner, file_group);
            if (rc2 != pcmk_rc_ok) {
                pcmk__err("Could not set owner of sequence file in %s: %s",
                          cib_dirname, pcmk_rc_str(rc2));
                rc = -1;
            }
        }
        pcmk__sync_directory(cib_dirname);
        pcmk__info("Archived previous version as %s", backup_path);
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
prepare_xml(xmlNode *root)
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
    char *cib_path = pcmk__assert_asprintf("%s/%s", cib_dirname, cib_filename);
    char *digest_path = pcmk__assert_asprintf("%s.sig", cib_path);

    /* Create temporary file name patterns for writing out CIB and signature */
    char *tmp_cib = pcmk__assert_asprintf("%s/cib.XXXXXX", cib_dirname);
    char *tmp_digest = pcmk__assert_asprintf("%s/cib.XXXXXX", cib_dirname);

    /* Ensure the admin didn't modify the existing CIB underneath us */
    pcmk__trace("Reading cluster configuration file %s", cib_path);
    rc = cib_file_read_and_verify(cib_path, NULL, NULL);
    if ((rc != pcmk_ok) && (rc != -ENOENT)) {
        pcmk__err("%s was manually modified while the cluster was active!",
                  cib_path);
        exit_rc = pcmk_err_cib_modified;
        goto cleanup;
    }

    /* Back up the existing CIB */
    if (backup_cib_file(cib_dirname, cib_filename) < 0) {
        exit_rc = pcmk_err_cib_backup;
        goto cleanup;
    }

    pcmk__debug("Writing CIB to disk");
    umask(S_IWGRP | S_IWOTH | S_IROTH);
    prepare_xml(cib_root);

    /* Write the CIB to a temporary file, so we can deploy (near) atomically */
    fd = mkstemp(tmp_cib);
    if (fd < 0) {
        pcmk__err("Couldn't open temporary file %s for writing CIB: %s",
                  tmp_cib, strerror(errno));
        exit_rc = pcmk_err_cib_save;
        goto cleanup;
    }

    /* Protect the temporary file */
    if (fchmod(fd, S_IRUSR | S_IWUSR) < 0) {
        pcmk__err("Couldn't protect temporary file %s for writing CIB: %s",
                  tmp_cib, strerror(errno));
        exit_rc = pcmk_err_cib_save;
        goto cleanup;
    }
    if (do_chown && (fchown(fd, file_owner, file_group) < 0)) {
        pcmk__err("Couldn't protect temporary file %s for writing CIB: %s",
                  tmp_cib, strerror(errno));
        exit_rc = pcmk_err_cib_save;
        goto cleanup;
    }

    /* Write out the CIB */
    if (pcmk__xml_write_fd(cib_root, tmp_cib, fd) != pcmk_rc_ok) {
        pcmk__err("Changes couldn't be written to %s", tmp_cib);
        exit_rc = pcmk_err_cib_save;
        goto cleanup;
    }

    /* Calculate CIB digest */
    digest = pcmk__digest_on_disk_cib(cib_root);
    pcmk__assert(digest != NULL);
    pcmk__info("Wrote version %s.%s.0 of the CIB to disk (digest: %s)",
               pcmk__s(admin_epoch, "0"), pcmk__s(epoch, "0"), digest);

    /* Write the CIB digest to a temporary file */
    fd = mkstemp(tmp_digest);
    if (fd < 0) {
        pcmk__err("Could not create temporary file %s for CIB digest: %s",
                  tmp_digest, strerror(errno));
        exit_rc = pcmk_err_cib_save;
        goto cleanup;
    }
    if (do_chown && (fchown(fd, file_owner, file_group) < 0)) {
        pcmk__err("Couldn't protect temporary file %s for writing CIB: %s",
                  tmp_cib, strerror(errno));
        exit_rc = pcmk_err_cib_save;
        close(fd);
        goto cleanup;
    }
    rc = pcmk__write_sync(fd, digest);
    if (rc != pcmk_rc_ok) {
        pcmk__err("Could not write digest to %s: %s", tmp_digest,
                  pcmk_rc_str(rc));
        exit_rc = pcmk_err_cib_save;
        close(fd);
        goto cleanup;
    }
    close(fd);
    pcmk__debug("Wrote digest %s to disk", digest);

    /* Verify that what we wrote is sane */
    pcmk__info("Reading cluster configuration file %s (digest: %s)", tmp_cib,
               tmp_digest);
    rc = cib_file_read_and_verify(tmp_cib, tmp_digest, NULL);
    pcmk__assert(rc == 0);

    /* Rename temporary files to live, and sync directory changes to media */
    pcmk__debug("Activating %s", tmp_cib);
    if (rename(tmp_cib, cib_path) < 0) {
        pcmk__err("Couldn't rename %s as %s: %s", tmp_cib, cib_path,
                  strerror(errno));
        exit_rc = pcmk_err_cib_save;
    }
    if (rename(tmp_digest, digest_path) < 0) {
        pcmk__err("Couldn't rename %s as %s: %s", tmp_digest, digest_path,
                  strerror(errno));
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
