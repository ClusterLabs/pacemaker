/*
 * Copyright 2004-2019 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef CIB_TYPES__H
#  define CIB_TYPES__H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Data types for Cluster Information Base access
 * \ingroup cib
 */

#  include <glib.h>             // gboolean, GList
#  include <libxml/tree.h>      // xmlNode
#  include <crm/common/ipc.h>
#  include <crm/common/xml.h>

enum cib_variant {
    cib_undefined,
    cib_native,
    cib_file,
    cib_remote,
    cib_database,
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
    cib_none            = 0x00000000,
    cib_verbose         = 0x00000001,  //!< Prefer stderr to logs
    cib_xpath           = 0x00000002,
    cib_multiple        = 0x00000004,
    cib_can_create      = 0x00000008,
    cib_discard_reply   = 0x00000010,
    cib_no_children     = 0x00000020,
    cib_xpath_address   = 0x00000040,
    cib_mixed_update    = 0x00000080,
    cib_scope_local     = 0x00000100,
    cib_dryrun          = 0x00000200,
    cib_sync_call       = 0x00001000,
    cib_no_mtime        = 0x00002000,
    cib_zero_copy       = 0x00004000,
    cib_inhibit_notify  = 0x00010000,
    cib_quorum_override = 0x00100000,
    cib_inhibit_bcast   = 0x01000000, //!< \deprecated Will be removed in future
    cib_force_diff      = 0x10000000
};

enum cib_change_section_info {
    cib_change_section_none     = 0x00000000,
    cib_change_section_nodes    = 0x00000001,
    cib_change_section_alerts   = 0x00000002,
    cib_change_section_status   = 0x00000004
};

typedef struct cib_s cib_t;

typedef struct cib_api_operations_s {
    int (*signon) (cib_t *cib, const char *name, enum cib_conn_type type);
    int (*signon_raw) (cib_t *cib, const char *name, enum cib_conn_type type,
                       int *event_fd);
    int (*signoff) (cib_t *cib);
    int (*free) (cib_t *cib);
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
    int (*inputfd) (cib_t *cib);
    int (*noop) (cib_t *cib, int call_options);
    int (*ping) (cib_t *cib, xmlNode **output_data, int call_options);
    int (*query) (cib_t *cib, const char *section, xmlNode **output_data,
                  int call_options);
    int (*query_from) (cib_t *cib, const char *host, const char *section,
                       xmlNode **output_data, int call_options);
    int (*is_master) (cib_t *cib);
    int (*set_master) (cib_t *cib, int call_options);
    int (*set_slave) (cib_t *cib, int call_options);
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
    int (*update) (cib_t *cib, const char *section, xmlNode *data,
                   int call_options);
    int (*replace) (cib_t *cib, const char *section, xmlNode *data,
                    int call_options);
    int (*remove) (cib_t *cib, const char *section, xmlNode *data,
                   int call_options);
    int (*erase) (cib_t *cib, xmlNode **output_data, int call_options);
    int (*delete_absolute) (cib_t *cib, const char *section, xmlNode *data,
                            int call_options);
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
    void (*op_callback) (const xmlNode *msg, int call_id, int rc,
                         xmlNode *output);
    cib_api_operations_t *cmds;
};

#ifdef __cplusplus
}
#endif

#endif // CIB_TYPES__H
