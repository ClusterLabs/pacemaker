/*
 * Copyright 2004-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_CIB_CIB_TYPES__H
#  define PCMK__CRM_CIB_CIB_TYPES__H

#  include <glib.h>             // gboolean, GList
#  include <libxml/tree.h>      // xmlNode
#  include <crm/common/ipc.h>
#  include <crm/common/xml.h>

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

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
    //! \deprecated This value will be removed in a future release
    cib_database  = 4,
#endif // !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
};

enum cib_state {
    cib_connected_command,
    cib_connected_query,
    cib_disconnected
};

enum cib_conn_type {
    cib_command,
    cib_query,
    cib_no_connection,
    cib_command_nonblocking,
};

enum cib_call_options {
    cib_none            = 0,
    cib_verbose         = (1 << 0),  //!< Prefer stderr to logs
    cib_xpath           = (1 << 1),
    cib_multiple        = (1 << 2),
    cib_can_create      = (1 << 3),
    cib_discard_reply   = (1 << 4),
    cib_no_children     = (1 << 5),
    cib_xpath_address   = (1 << 6),
    cib_mixed_update    = (1 << 7),

    /* @COMPAT: cib_scope_local is processed only in the legacy function
     * parse_local_options_v1().
     *
     * If (host == NULL):
     * * In legacy mode, the CIB manager forwards a request to the primary
     *   instance unless cib_scope_local is set or the local node is primary.
     * * Outside of legacy mode:
     *   * If a request modifies the CIB, the CIB manager forwards it to all
     *     nodes.
     *   * Otherwise, the CIB manager processes the request locally.
     *
     * There is no current use case for this implementing this flag in
     * non-legacy mode.
     */

    //! \deprecated This value will be removed in a future release
    cib_scope_local     = (1 << 8),

    cib_dryrun          = (1 << 9),

    //! Add request to the client's CIB transaction instead of processing
    cib_transaction     = (1 << 10),

    cib_sync_call       = (1 << 12),
    cib_no_mtime        = (1 << 13),

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
    //! \deprecated This value will be removed in a future release
    cib_zero_copy       = (1 << 14),
#endif // !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)

    cib_inhibit_notify  = (1 << 16),

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
    //! \deprecated This value will be removed in a future release
    cib_quorum_override = (1 << 20),
#endif // !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)

    //! \deprecated This value will be removed in a future release
    cib_inhibit_bcast   = (1 << 24),

    cib_force_diff      = (1 << 28),
};

typedef struct cib_s cib_t;

typedef struct cib_api_operations_s {
    int (*signon) (cib_t *cib, const char *name, enum cib_conn_type type);
    int (*signon_raw) (cib_t *cib, const char *name, enum cib_conn_type type,
                       int *event_fd);
    int (*signoff) (cib_t *cib);
    int (*free) (cib_t *cib);

    //! \deprecated This method will be removed and should not be used
    int (*set_op_callback) (cib_t *cib, void (*callback) (const xmlNode *msg,
                                                          int callid, int rc,
                                                          xmlNode *output));

    int (*add_notify_callback) (cib_t *cib, const char *event,
                                void (*callback) (const char *event,
                                                  xmlNode *msg));
    int (*del_notify_callback) (cib_t *cib, const char *event,
                                void (*callback) (const char *event,
                                                  xmlNode *msg));
    int (*set_connection_dnotify) (cib_t *cib,
                                   void (*dnotify) (gpointer user_data));

    //! \deprecated This method will be removed and should not be used
    int (*inputfd) (cib_t *cib);

    //! \deprecated This method will be removed and should not be used
    int (*noop) (cib_t *cib, int call_options);

    int (*ping) (cib_t *cib, xmlNode **output_data, int call_options);
    int (*query) (cib_t *cib, const char *section, xmlNode **output_data,
                  int call_options);
    int (*query_from) (cib_t *cib, const char *host, const char *section,
                       xmlNode **output_data, int call_options);

    //! \deprecated This method will be removed and should not be used
    int (*is_master) (cib_t *cib);

    //! \deprecated Use the set_primary() method instead
    int (*set_master) (cib_t *cib, int call_options);

    //! \deprecated Use the set_secondary() method instead
    int (*set_slave) (cib_t *cib, int call_options);

    //! \deprecated This method will be removed and should not be used
    int (*set_slave_all) (cib_t *cib, int call_options);

    int (*sync) (cib_t *cib, const char *section, int call_options);
    int (*sync_from) (cib_t *cib, const char *host, const char *section,
                      int call_options);
    int (*upgrade) (cib_t *cib, int call_options);
    int (*bump_epoch) (cib_t *cib, int call_options);
    int (*create) (cib_t *cib, const char *section, xmlNode *data,
                   int call_options);
    int (*modify) (cib_t *cib, const char *section, xmlNode *data,
                   int call_options);

    //! \deprecated Use the \p modify() method instead
    int (*update) (cib_t *cib, const char *section, xmlNode *data,
                   int call_options);

    int (*replace) (cib_t *cib, const char *section, xmlNode *data,
                    int call_options);
    int (*remove) (cib_t *cib, const char *section, xmlNode *data,
                   int call_options);
    int (*erase) (cib_t *cib, xmlNode **output_data, int call_options);

    //! \deprecated This method does nothing and should not be called
    int (*delete_absolute) (cib_t *cib, const char *section, xmlNode *data,
                            int call_options);

    //! \deprecated This method is not implemented and should not be used
    int (*quit) (cib_t *cib, int call_options);

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
} cib_api_operations_t;

struct cib_s {
    enum cib_state state;
    enum cib_conn_type type;
    enum cib_variant variant;

    int call_id;
    int call_timeout;
    void *variant_opaque;
    void *delegate_fn;

    GList *notify_list;

    //! \deprecated This method will be removed in a future release
    void (*op_callback) (const xmlNode *msg, int call_id, int rc,
                         xmlNode *output);

    cib_api_operations_t *cmds;
};

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_CIB_CIB_TYPES__H
