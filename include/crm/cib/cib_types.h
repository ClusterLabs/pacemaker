/*
 * Copyright 2004-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_CIB_CIB_TYPES__H
#define PCMK__CRM_CIB_CIB_TYPES__H

#include <stdbool.h>
#include <stdint.h>             // UINT32_C

#include <glib.h>               // gboolean, GList
#include <libxml/tree.h>        // xmlNode

#include <crm/common/ipc.h>
#include <crm/common/xml.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Data types for Cluster Information Base access
 * \ingroup cib
 */

enum cib_variant {
    cib_undefined = 0,
    cib_native    = 1,
    cib_file      = 2,
    cib_remote    = 3,
};

enum cib_state {
    // NOTE: sbd (as of at least 1.5.2) uses this value
    cib_connected_command,

    // NOTE: sbd (as of at least 1.5.2) uses this value
    cib_connected_query,

    cib_disconnected
};

enum cib_conn_type {
    cib_command,

    // NOTE: sbd (as of at least 1.5.2) uses this value
    cib_query,

    cib_no_connection,
    cib_command_nonblocking,
};

enum cib_call_options {
    cib_none            = 0,
    cib_verbose         = (UINT32_C(1) << 0),  //!< Prefer stderr to logs
    cib_xpath           = (UINT32_C(1) << 1),
    cib_multiple        = (UINT32_C(1) << 2),
    cib_can_create      = (UINT32_C(1) << 3),
    cib_discard_reply   = (UINT32_C(1) << 4),
    cib_no_children     = (UINT32_C(1) << 5),

    //! \deprecated This value will be removed in a future release
    cib_xpath_address   = (UINT32_C(1) << 6),

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
    // NOTE: sbd (as of at least 1.5.2) uses this value
    //! \deprecated This value will be removed in a future release
    cib_scope_local     = (UINT32_C(1) << 8),
#endif // !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)

    cib_dryrun          = (UINT32_C(1) << 9),

    /*!
     * \brief Process request when the client commits the active transaction
     *
     * Add the request to the client's active transaction instead of processing
     * it immediately. If the client has no active transaction, or if the
     * request is not supported in transactions, the call will fail.
     *
     * The request is added to the transaction synchronously, and the return
     * value indicates whether it was added successfully.
     *
     * Refer to \p cib_api_operations_t:init_transaction() and
     * \p cib_api_operations_t:end_transaction() for more details on CIB
     * transactions.
     */
    cib_transaction     = (UINT32_C(1) << 10),

    /*!
     * \brief Treat new attribute values as atomic score updates where possible
     *
     * This option takes effect when updating XML attributes. For an attribute
     * named \c "name", if the new value is \c "name++" or \c "name+=X" for some
     * score \c X, the new value is set as follows:
     * * If attribute \c "name" is not already set to some value in the element
     *   being updated, the new value is set as a literal string.
     * * If the new value is \c "name++", then the attribute is set to its
     *   existing value (parsed as a score) plus 1.
     * * If the new value is \c "name+=X" for some score \c X, then the
     *   attribute is set to its existing value plus \c X, where the existing
     *   value and \c X are parsed and added as scores.
     *
     * Scores are integer values capped at \c INFINITY and \c -INFINITY. Refer
     * to Pacemaker Explained and to the \c pcmk_parse_score() function for more
     * details on scores, including how they're parsed and added.
     *
     * Note: This is implemented only for modify operations.
     */
    cib_score_update    = (UINT32_C(1) << 11),

    // NOTE: sbd (as of at least 1.5.2) uses this value
    cib_sync_call       = (UINT32_C(1) << 12),

    cib_no_mtime        = (UINT32_C(1) << 13),

    //! \deprecated This value will be removed in a future release
    cib_inhibit_notify  = (UINT32_C(1) << 16),

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
    //! \deprecated This value will be removed in a future release
    cib_force_diff      = (UINT32_C(1) << 28),
#endif // !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
};

typedef struct cib_s cib_t;

/*!
 * \deprecated Use \c cib_api_operations_t instead of
 *             <tt>struct cib_api_operations_s</tt>.
 */
typedef struct cib_api_operations_s {
    // NOTE: sbd (as of at least 1.5.2) uses this
    // @COMPAT At compatibility break, drop name (always use crm_system_name)
    int (*signon) (cib_t *cib, const char *name, enum cib_conn_type type);

    // NOTE: sbd (as of at least 1.5.2) uses this
    int (*signoff) (cib_t *cib);

    int (*free) (cib_t *cib);

    // NOTE: sbd (as of at least 1.5.2) uses this
    int (*add_notify_callback) (cib_t *cib, const char *event,
                                void (*callback) (const char *event,
                                                  xmlNode *msg));

    // NOTE: sbd (as of at least 1.5.2) uses this
    int (*del_notify_callback) (cib_t *cib, const char *event,
                                void (*callback) (const char *event,
                                                  xmlNode *msg));
    // NOTE: sbd (as of at least 1.5.2) uses this
    int (*set_connection_dnotify) (cib_t *cib,
                                   void (*dnotify) (gpointer user_data));

    // NOTE: sbd (as of at least 1.5.2) uses this
    //! \deprecated This method will be removed and should not be used
    int (*noop) (cib_t *cib, int call_options);

    int (*ping) (cib_t *cib, xmlNode **output_data, int call_options);

    // NOTE: sbd (as of at least 1.5.2) uses this
    int (*query) (cib_t *cib, const char *section, xmlNode **output_data,
                  int call_options);

    int (*query_from) (cib_t *cib, const char *host, const char *section,
                       xmlNode **output_data, int call_options);

    int (*sync) (cib_t *cib, const char *section, int call_options);
    int (*sync_from) (cib_t *cib, const char *host, const char *section,
                      int call_options);
    int (*upgrade) (cib_t *cib, int call_options);
    int (*bump_epoch) (cib_t *cib, int call_options);

    /*!
     * The \c <failed> element in the reply to a failed creation call is
     * deprecated since 2.1.8.
     */
    int (*create) (cib_t *cib, const char *section, xmlNode *data,
                   int call_options);
    int (*modify) (cib_t *cib, const char *section, xmlNode *data,
                   int call_options);

    int (*replace) (cib_t *cib, const char *section, xmlNode *data,
                    int call_options);
    int (*remove) (cib_t *cib, const char *section, xmlNode *data,
                   int call_options);
    int (*erase) (cib_t *cib, xmlNode **output_data, int call_options);

    int (*register_notification) (cib_t *cib, const char *callback,
                                  int enabled);
    gboolean (*register_callback) (cib_t *cib, int call_id, int timeout,
                                   gboolean only_success, void *user_data,
                                   const char *callback_name,
                                   void (*callback) (xmlNode*, int, int,
                                                     xmlNode*, void *));
    gboolean (*register_callback_full)(cib_t *cib, int call_id, int timeout,
                                       gboolean only_success, void *user_data,
                                       const char *callback_name,
                                       void (*callback)(xmlNode *, int, int,
                                                        xmlNode *, void *),
                                       void (*free_func)(void *));

    /*!
     * \brief Set the local CIB manager as the cluster's primary instance
     *
     * \param[in,out] cib           CIB connection
     * \param[in]     call_options  Group of enum cib_call_options flags
     *
     * \return Legacy Pacemaker return code (in particular, pcmk_ok on success)
     */
    int (*set_primary)(cib_t *cib, int call_options);

    /*!
     * \brief Set the local CIB manager as a secondary instance
     *
     * \param[in,out] cib           CIB connection
     * \param[in]     call_options  Group of enum cib_call_options flags
     *
     * \return Legacy Pacemaker return code (in particular, pcmk_ok on success)
     */
    int (*set_secondary)(cib_t *cib, int call_options);

    /*!
     * \brief Get the given CIB connection's unique client identifier(s)
     *
     * These can be used to check whether this client requested the action that
     * triggered a CIB notification.
     *
     * \param[in]  cib       CIB connection
     * \param[out] async_id  If not \p NULL, where to store asynchronous client
     *                       ID
     * \param[out] sync_id   If not \p NULL, where to store synchronous client
     *                       ID
     *
     * \return Legacy Pacemaker return code
     *
     * \note Some variants may have only one client for both asynchronous and
     *       synchronous requests.
     */
    int (*client_id)(const cib_t *cib, const char **async_id,
                     const char **sync_id);

    /*!
     * \brief Initiate an atomic CIB transaction for this client
     *
     * If the client has initiated a transaction and a new request's call
     * options contain \p cib_transaction, the new request is appended to the
     * transaction for later processing.
     *
     * Supported requests are those that meet the following conditions:
     * * can be processed synchronously (with any changes applied to a working
     *   CIB copy)
     * * are not queries
     * * do not involve other nodes
     * * do not affect the state of the CIB manager itself
     *
     * Currently supported CIB API functions include:
     * * \p bump_epoch()
     * * \p create()
     * * \p erase()
     * * \p modify()
     * * \p remove()
     * * \p replace()
     * * \p upgrade()
     *
     * Because the transaction is atomic, individual requests do not trigger
     * callbacks or notifications when they are processed, and they do not
     * receive output XML. The commit request itself can trigger callbacks and
     * notifications if any are registered.
     *
     * An \c init_transaction() call is always synchronous.
     *
     * \param[in,out] cib           CIB connection
     *
     * \return Legacy Pacemaker return code
     */
    int (*init_transaction)(cib_t *cib);

    /*!
     * \brief End and optionally commit this client's CIB transaction
     *
     * When a client commits a transaction, all requests in the transaction are
     * processed in a FIFO manner until either a request fails or all requests
     * have been processed. Changes are applied to a working copy of the CIB.
     * If a request fails, the transaction and working CIB copy are discarded,
     * and an error is returned. If all requests succeed, the working CIB copy
     * replaces the initial CIB copy.
     *
     * Callbacks and notifications can be triggered by the commit request itself
     * but not by the individual requests in a transaction.
     *
     * An \c end_transaction() call with \p commit set to \c false is always
     * synchronous.
     *
     * \param[in,out] cib           CIB connection
     * \param[in]     commit        If \p true, commit transaction; otherwise,
     *                              discard it
     * \param[in]     call_options  Group of <tt>enum cib_call_options</tt>
     *                              flags
     *
     * \return Legacy Pacemaker return code
     */
    int (*end_transaction)(cib_t *cib, bool commit, int call_options);

    /*!
     * \brief Set the user as whom all CIB requests via methods will be executed
     *
     * By default, the value of the \c CIB_user environment variable is used if
     * set. Otherwise, the current effective user is used.
     *
     * \param[in,out] cib   CIB connection
     * \param[in]     user  Name of user whose permissions to use when
     *                      processing requests
     */
    void (*set_user)(cib_t *cib, const char *user);

    int (*fetch_schemas)(cib_t *cib, xmlNode **output_data, const char *after_ver,
                         int call_options);
} cib_api_operations_t;

//! \deprecated Use \c cib_t instead of <tt>struct cib_s</tt>.
struct cib_s {
    // NOTE: sbd (as of at least 1.5.2) uses this
    enum cib_state state;

    enum cib_conn_type type;
    enum cib_variant variant;

    int call_id;
    int call_timeout;
    void *variant_opaque;
    void *delegate_fn;

    GList *notify_list;

    // NOTE: sbd (as of at least 1.5.2) uses this
    cib_api_operations_t *cmds;

    xmlNode *transaction;

    char *user;
};

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_CIB_CIB_TYPES__H
