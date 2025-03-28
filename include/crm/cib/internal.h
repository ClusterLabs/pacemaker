/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_CIB_INTERNAL__H
#define PCMK__CRM_CIB_INTERNAL__H

#include <crm/cib.h>
#include <crm/common/ipc_internal.h>
#include <crm/common/logging_internal.h>    // PCMK__LOG_TRACE
#include <crm/common/output_internal.h>
#include <crm/common/servers_internal.h>
#include <crm/common/strings_internal.h>

#ifdef __cplusplus
extern "C" {
#endif

// Request types for CIB manager IPC/CPG
#define PCMK__CIB_REQUEST_SECONDARY     "cib_slave"
#define PCMK__CIB_REQUEST_PRIMARY       "cib_master"
#define PCMK__CIB_REQUEST_SYNC_TO_ALL   "cib_sync"
#define PCMK__CIB_REQUEST_SYNC_TO_ONE   "cib_sync_one"
#define PCMK__CIB_REQUEST_IS_PRIMARY    "cib_ismaster"
#define PCMK__CIB_REQUEST_BUMP          "cib_bump"
#define PCMK__CIB_REQUEST_QUERY         "cib_query"
#define PCMK__CIB_REQUEST_CREATE        "cib_create"
#define PCMK__CIB_REQUEST_MODIFY        "cib_modify"
#define PCMK__CIB_REQUEST_DELETE        "cib_delete"
#define PCMK__CIB_REQUEST_ERASE         "cib_erase"
#define PCMK__CIB_REQUEST_REPLACE       "cib_replace"
#define PCMK__CIB_REQUEST_APPLY_PATCH   "cib_apply_diff"
#define PCMK__CIB_REQUEST_UPGRADE       "cib_upgrade"
#define PCMK__CIB_REQUEST_ABS_DELETE    "cib_delete_alt"
#define PCMK__CIB_REQUEST_NOOP          "noop"
#define PCMK__CIB_REQUEST_SHUTDOWN      "cib_shutdown_req"
#define PCMK__CIB_REQUEST_COMMIT_TRANSACT   "cib_commit_transact"
#define PCMK__CIB_REQUEST_SCHEMAS       "cib_schemas"

/*!
 * \internal
 * \brief Flags for CIB operation attributes
 */
enum cib__op_attr {
    cib__op_attr_none           = 0,        //!< No special attributes
    cib__op_attr_modifies       = (1 << 1), //!< Modifies CIB
    cib__op_attr_privileged     = (1 << 2), //!< Requires privileges
    cib__op_attr_local          = (1 << 3), //!< Must only be processed locally
    cib__op_attr_replaces       = (1 << 4), //!< Replaces CIB
    cib__op_attr_writes_through = (1 << 5), //!< Writes to disk on success
    cib__op_attr_transaction    = (1 << 6), //!< Supported in a transaction
};

/*!
 * \internal
 * \brief Types of CIB operations
 */
enum cib__op_type {
    cib__op_abs_delete,
    cib__op_apply_patch,
    cib__op_bump,
    cib__op_commit_transact,
    cib__op_create,
    cib__op_delete,
    cib__op_erase,
    cib__op_is_primary,
    cib__op_modify,
    cib__op_noop,
    cib__op_ping,
    cib__op_primary,
    cib__op_query,
    cib__op_replace,
    cib__op_secondary,
    cib__op_shutdown,
    cib__op_sync_all,
    cib__op_sync_one,
    cib__op_upgrade,
    cib__op_schemas,
};

gboolean cib_diff_version_details(xmlNode * diff, int *admin_epoch, int *epoch, int *updates,
                                  int *_admin_epoch, int *_epoch, int *_updates);

gboolean cib_read_config(GHashTable * options, xmlNode * current_cib);

typedef int (*cib__op_fn_t)(const char *, int, const char *, xmlNode *,
                            xmlNode *, xmlNode *, xmlNode **, xmlNode **);

typedef struct cib__operation_s {
    const char *name;
    enum cib__op_type type;
    uint32_t flags; //!< Group of <tt>enum cib__op_attr</tt> flags
} cib__operation_t;

typedef struct cib_notify_client_s {
    const char *event;
    const char *obj_id;         /* implement one day */
    const char *obj_type;       /* implement one day */
    void (*callback) (const char *event, xmlNode * msg);

} cib_notify_client_t;

typedef struct cib_callback_client_s {
    void (*callback) (xmlNode *, int, int, xmlNode *, void *);
    const char *id;
    void *user_data;
    gboolean only_success;
    struct timer_rec_s *timer;
    void (*free_func)(void *);
} cib_callback_client_t;

struct timer_rec_s {
    int call_id;
    int timeout;
    guint ref;
    cib_t *cib;
};

#define cib__set_call_options(cib_call_opts, call_for, flags_to_set) do {   \
        cib_call_opts = pcmk__set_flags_as(__func__, __LINE__,              \
                                           PCMK__LOG_TRACE, "CIB call",     \
                                           (call_for), (cib_call_opts),     \
                                           (flags_to_set), #flags_to_set);  \
    } while (0)

#define cib__clear_call_options(cib_call_opts, call_for, flags_to_clear) do {  \
        cib_call_opts = pcmk__clear_flags_as(__func__, __LINE__,               \
                                             PCMK__LOG_TRACE, "CIB call",      \
                                             (call_for), (cib_call_opts),      \
                                             (flags_to_clear),                 \
                                             #flags_to_clear);                 \
    } while (0)

cib_t *cib_new_variant(void);

/*!
 * \internal
 * \brief Check whether a given CIB client's update should trigger a refresh
 *
 * Here, "refresh" means that Pacemaker daemons write out their current state.
 *
 * If a Pacemaker daemon or one of certain Pacemaker CLI tools modifies the CIB,
 * we can assume that the CIB hasn't diverged from the true cluster state. A
 * "safe" CLI tool requests that all relevant daemons update their state before
 * the tool requests any CIB modifications directly.
 *
 * In contrast, other "unsafe" tools (for example, \c cibadmin and external
 * tools) may request arbitrary CIB changes.
 *
 * A Pacemaker daemon can write out its current state to the CIB when it's
 * notified of an update from an unsafe client, to ensure the CIB still contains
 * the daemon's correct state.
 *
 * \param[in] name  CIB client name
 *
 * \return \c true if the CIB client should trigger a refresh, or \c false
 *         otherwise
 */
static inline bool
cib__client_triggers_refresh(const char *name)
{
    return (pcmk__parse_server(name) == pcmk_ipc_unknown)
           && !pcmk__str_any_of(name,
                                "attrd_updater",
                                "crm_attribute",
                                "crm_node",
                                "crm_resource",
                                "crm_ticket",
                                NULL);
}

int cib__get_notify_patchset(const xmlNode *msg, const xmlNode **patchset);

int cib_perform_op(cib_t *cib, const char *op, uint32_t call_options,
                   cib__op_fn_t fn, bool is_query, const char *section,
                   xmlNode *req, xmlNode *input, bool manage_counters,
                   bool *config_changed, xmlNode **current_cib,
                   xmlNode **result_cib, xmlNode **diff, xmlNode **output);

int cib__create_op(cib_t *cib, const char *op, const char *host,
                   const char *section, xmlNode *data, int call_options,
                   const char *user_name, const char *client_name,
                   xmlNode **op_msg);

int cib__extend_transaction(cib_t *cib, xmlNode *request);

void cib_native_callback(cib_t * cib, xmlNode * msg, int call_id, int rc);
void cib_native_notify(gpointer data, gpointer user_data);

int cib__get_operation(const char *op, const cib__operation_t **operation);

int cib_process_query(const char *op, int options, const char *section, xmlNode * req,
                      xmlNode * input, xmlNode * existing_cib, xmlNode ** result_cib,
                      xmlNode ** answer);

int cib_process_erase(const char *op, int options, const char *section, xmlNode * req,
                      xmlNode * input, xmlNode * existing_cib, xmlNode ** result_cib,
                      xmlNode ** answer);

int cib_process_bump(const char *op, int options, const char *section, xmlNode * req,
                     xmlNode * input, xmlNode * existing_cib, xmlNode ** result_cib,
                     xmlNode ** answer);

int cib_process_replace(const char *op, int options, const char *section, xmlNode * req,
                        xmlNode * input, xmlNode * existing_cib, xmlNode ** result_cib,
                        xmlNode ** answer);

int cib_process_create(const char *op, int options, const char *section, xmlNode * req,
                       xmlNode * input, xmlNode * existing_cib, xmlNode ** result_cib,
                       xmlNode ** answer);

int cib_process_modify(const char *op, int options, const char *section, xmlNode * req,
                       xmlNode * input, xmlNode * existing_cib, xmlNode ** result_cib,
                       xmlNode ** answer);

int cib_process_delete(const char *op, int options, const char *section, xmlNode * req,
                       xmlNode * input, xmlNode * existing_cib, xmlNode ** result_cib,
                       xmlNode ** answer);

int cib_process_diff(const char *op, int options, const char *section, xmlNode * req,
                     xmlNode * input, xmlNode * existing_cib, xmlNode ** result_cib,
                     xmlNode ** answer);

int cib_process_upgrade(const char *op, int options, const char *section, xmlNode * req,
                        xmlNode * input, xmlNode * existing_cib, xmlNode ** result_cib,
                        xmlNode ** answer);

/*!
 * \internal
 * \brief Query or modify a CIB
 *
 * \param[in]     op            PCMK__CIB_REQUEST_* operation to be performed
 * \param[in]     options       Flag set of \c cib_call_options
 * \param[in]     section       XPath to query or modify
 * \param[in]     req           unused
 * \param[in]     input         Portion of CIB to modify (used with
 *                              PCMK__CIB_REQUEST_CREATE,
 *                              PCMK__CIB_REQUEST_MODIFY, and
 *                              PCMK__CIB_REQUEST_REPLACE)
 * \param[in,out] existing_cib  Input CIB (used with PCMK__CIB_REQUEST_QUERY)
 * \param[in,out] result_cib    CIB copy to make changes in (used with
 *                              PCMK__CIB_REQUEST_CREATE,
 *                              PCMK__CIB_REQUEST_MODIFY,
 *                              PCMK__CIB_REQUEST_DELETE, and
 *                              PCMK__CIB_REQUEST_REPLACE)
 * \param[out]    answer        Query result (used with PCMK__CIB_REQUEST_QUERY)
 *
 * \return Legacy Pacemaker return code
 */
int cib_process_xpath(const char *op, int options, const char *section,
                      const xmlNode *req, xmlNode *input, xmlNode *existing_cib,
                      xmlNode **result_cib, xmlNode ** answer);

int cib_internal_op(cib_t * cib, const char *op, const char *host,
                    const char *section, xmlNode * data,
                    xmlNode ** output_data, int call_options, const char *user_name);


int cib_file_read_and_verify(const char *filename, const char *sigfile,
                             xmlNode **root);
int cib_file_write_with_digest(xmlNode *cib_root, const char *cib_dirname,
                               const char *cib_filename);

void cib__set_output(cib_t *cib, pcmk__output_t *out);

cib_callback_client_t* cib__lookup_id (int call_id);

/*!
 * \internal
 * \brief Connect to, query, and optionally disconnect from the CIB
 *
 * Open a read-write connection to the CIB manager if an already connected
 * client is not passed in. Then query the CIB and store the resulting XML.
 * Finally, disconnect if the CIB connection isn't being returned to the caller.
 *
 * \param[in,out] out         Output object (may be \p NULL)
 * \param[in,out] cib         If not \p NULL, where to store CIB connection
 * \param[out]    cib_object  Where to store query result
 *
 * \return Standard Pacemaker return code
 *
 * \note If \p cib is not \p NULL, the caller is responsible for freeing \p *cib
 *       using \p cib_delete().
 * \note If \p *cib points to an existing \p cib_t object, this function will
 *       reuse it instead of creating a new one. If the existing client is
 *       already connected, the connection will be reused, even if it's
 *       read-only.
 */
int cib__signon_query(pcmk__output_t *out, cib_t **cib, xmlNode **cib_object);

int cib__signon_attempts(cib_t *cib, enum cib_conn_type type, int attempts);

int cib__clean_up_connection(cib_t **cib);

int cib__update_node_attr(pcmk__output_t *out, cib_t *cib, int call_options,
                          const char *section, const char *node_uuid, const char *set_type,
                          const char *set_name, const char *attr_id, const char *attr_name,
                          const char *attr_value, const char *user_name,
                          const char *node_type);

int cib__get_node_attrs(pcmk__output_t *out, cib_t *cib, const char *section,
                        const char *node_uuid, const char *set_type, const char *set_name,
                        const char *attr_id, const char *attr_name, const char *user_name,
                        xmlNode **result);

int cib__delete_node_attr(pcmk__output_t *out, cib_t *cib, int options,
                          const char *section, const char *node_uuid, const char *set_type,
                          const char *set_name, const char *attr_id, const char *attr_name,
                          const char *attr_value, const char *user_name);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_CIB_INTERNAL__H
