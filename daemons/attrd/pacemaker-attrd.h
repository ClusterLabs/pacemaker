/*
 * Copyright 2013-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#ifndef PACEMAKER_ATTRD__H
#  define PACEMAKER_ATTRD__H

#include <regex.h>
#include <stdbool.h>
#include <stdint.h>

#include <glib.h>

#include <crm/crm.h>
#include <crm/cluster.h>
#include <crm/cluster/election_internal.h>
#include <crm/common/internal.h>
#include <crm/cib/cib_types.h>

/*
 * Legacy attrd (all pre-1.1.11 Pacemaker versions, plus all versions when used
 * with the no-longer-supported CMAN or corosync-plugin stacks) is unversioned.
 *
 * With atomic attrd, each attrd will send ATTRD_PROTOCOL_VERSION with every
 * peer request and reply. As of Pacemaker 2.0.0, at start-up each attrd will
 * also set a private attribute for itself with its version, so any attrd can
 * determine the minimum version supported by all peers.
 *
 * Protocol  Pacemaker  Significant changes
 * --------  ---------  -------------------
 *     1       1.1.11   PCMK__ATTRD_CMD_UPDATE (PCMK__XA_ATTR_NAME only),
 *                      PCMK__ATTRD_CMD_PEER_REMOVE, PCMK__ATTRD_CMD_REFRESH,
 *                      "flush", PCMK__ATTRD_CMD_SYNC_RESPONSE
 *     1       1.1.13   PCMK__ATTRD_CMD_UPDATE (with PCMK__XA_ATTR_REGEX),
 *                      PCMK__ATTRD_CMD_QUERY
 *     1       1.1.15   PCMK__ATTRD_CMD_UPDATE_BOTH,
 *                      PCMK__ATTRD_CMD_UPDATE_DELAY
 *     2       1.1.17   PCMK__ATTRD_CMD_CLEAR_FAILURE
 *     3       2.1.1    PCMK__ATTRD_CMD_SYNC_RESPONSE indicates remote nodes
 *     4       2.1.5    Multiple attributes can be updated in a single IPC
 *                      message
 *     5       2.1.5    Peers can request confirmation of a sent message
 *     6       2.1.7    PCMK__ATTRD_CMD_PEER_REMOVE supports PCMK__XA_REAP
 *     7       3.0.0    "flush" support dropped
 */
#define ATTRD_PROTOCOL_VERSION "7"

#define ATTRD_SUPPORTS_MULTI_MESSAGE(x) ((x) >= 4)
#define ATTRD_SUPPORTS_CONFIRMATION(x)  ((x) >= 5)

#define attrd_send_ack(client, id, flags)                               \
    pcmk__ipc_send_ack((client), (id), (flags), ATTRD_PROTOCOL_VERSION, \
                       CRM_EX_INDETERMINATE)

void attrd_init_mainloop(void);
void attrd_run_mainloop(void);

void attrd_free_waitlist(void);
bool attrd_shutting_down(void);
void attrd_shutdown(int nsig);
void attrd_ipc_init(void);
void attrd_ipc_cleanup(void);

int attrd_cib_connect(int max_retry);
void attrd_cib_disconnect(void);
void attrd_cib_init(void);
void attrd_cib_erase_transient_attrs(const char *node);

bool attrd_value_needs_expansion(const char *value);
int attrd_expand_value(const char *value, const char *old_value);

/* regular expression to clear failures of all resources */
#define ATTRD_RE_CLEAR_ALL \
    "^(" PCMK__FAIL_COUNT_PREFIX "|" PCMK__LAST_FAILURE_PREFIX ")-"

/* regular expression to clear failure of all operations for one resource
 * (format takes resource name)
 */
#define ATTRD_RE_CLEAR_ONE ATTRD_RE_CLEAR_ALL "%s#.+_[0-9]+$"

/* regular expression to clear failure of one operation for one resource
 * (format takes resource name, operation name, and interval)
 */
#define ATTRD_RE_CLEAR_OP ATTRD_RE_CLEAR_ALL "%s#%s_%u$"

int attrd_failure_regex(regex_t *regex, const char *rsc, const char *op,
                        guint interval_ms);

extern cib_t *the_cib;
extern crm_exit_t attrd_exit_status;

/* Alerts */

extern lrmd_t *the_lrmd;
extern crm_trigger_t *attrd_config_read;

void attrd_lrmd_disconnect(void);
gboolean attrd_read_options(gpointer user_data);
int attrd_send_attribute_alert(const char *node, const char *node_xml_id,
                               const char *attr, const char *value);

// Elections
void attrd_election_init(void);
void attrd_start_election_if_needed(void);
bool attrd_election_won(void);
void attrd_handle_election_op(const pcmk__node_status_t *peer, xmlNode *xml);
bool attrd_check_for_new_writer(const pcmk__node_status_t *peer,
                                const xmlNode *xml);
void attrd_declare_winner(void);
void attrd_remove_voter(const pcmk__node_status_t *peer);
void attrd_xml_add_writer(xmlNode *xml);

enum attrd_attr_flags {
    attrd_attr_none         = 0,

    // At least one of attribute's values has changed since last write
    attrd_attr_changed      = (UINT32_C(1) << 0),

    // At least one of attribute's values has an unknown node XML ID
    attrd_attr_node_unknown = (UINT32_C(1) << 1),

    // This attribute should never be written to the CIB
    attrd_attr_is_private   = (UINT32_C(1) << 2),

    // Ignore any configured delay for next write of this attribute
    attrd_attr_force_write  = (UINT32_C(1) << 3),
};

typedef struct {
    char *id;       // Attribute name
    char *set_type; // PCMK_XE_INSTANCE_ATTRIBUTES or PCMK_XE_UTILIZATION
    char *set_id;   // Set's XML ID to use when writing
    char *user;     // ACL user to use for CIB writes
    int update;     // Call ID of pending write
    int timeout_ms; // How long to wait for more changes before writing
    uint32_t flags; // Group of enum attrd_attr_flags
    GHashTable *values;         // Key: node name, value: attribute_value_t
    mainloop_timer_t *timer;    // Timer to use for timeout_ms
} attribute_t;

#define attrd_set_attr_flags(attr, flags_to_set) do {               \
        (attr)->flags = pcmk__set_flags_as(__func__, __LINE__,      \
            LOG_TRACE, "Value for attribute", (attr)->id,           \
            (attr)->flags, (flags_to_set), #flags_to_set);          \
    } while (0)

#define attrd_clear_attr_flags(attr, flags_to_clear) do {           \
        (attr)->flags = pcmk__clear_flags_as(__func__, __LINE__,    \
            LOG_TRACE, "Value for attribute", (attr)->id,           \
            (attr)->flags, (flags_to_clear), #flags_to_clear);      \
    } while (0)

enum attrd_value_flags {
    attrd_value_none        = 0,

    //! Value is for Pacemaker Remote node
    attrd_value_remote      = (UINT32_C(1) << 0),

    //! Value is from peer sync response
    attrd_value_from_peer   = (UINT32_C(1) << 1),
};

typedef struct {
    char *nodename;     // Node that this value is for
    char *current;      // Attribute value
    char *requested;    // Value specified in pending CIB write, if any
    uint32_t flags;     // Group of attrd_value_flags
} attribute_value_t;

#define attrd_set_value_flags(attr_value, flags_to_set) do {            \
        (attr_value)->flags = pcmk__set_flags_as(__func__, __LINE__,    \
            LOG_TRACE, "Value for node", (attr_value)->nodename,        \
            (attr_value)->flags, (flags_to_set), #flags_to_set);        \
    } while (0)

#define attrd_clear_value_flags(attr_value, flags_to_clear) do {        \
        (attr_value)->flags = pcmk__clear_flags_as(__func__, __LINE__,  \
            LOG_TRACE, "Value for node", (attr_value)->nodename,        \
            (attr_value)->flags, (flags_to_clear), #flags_to_clear);    \
    } while (0)

extern pcmk_cluster_t *attrd_cluster;
extern GHashTable *attributes;
extern GHashTable *peer_protocol_vers;

#define CIB_OP_TIMEOUT_S 120

void attrd_free_removed_peers(void);
void attrd_erase_removed_peer_attributes(void);

int attrd_cluster_connect(void);
void attrd_cluster_disconnect(void);
void attrd_broadcast_value(const attribute_t *a, const attribute_value_t *v);
void attrd_peer_update(const pcmk__node_status_t *peer, xmlNode *xml,
                       const char *host, bool filter);
void attrd_peer_sync(pcmk__node_status_t *peer);
void attrd_peer_remove(const char *host, bool uncache, const char *source);
void attrd_peer_clear_failure(pcmk__request_t *request);
void attrd_peer_sync_response(const pcmk__node_status_t *peer, bool peer_won,
                              xmlNode *xml);

void attrd_send_protocol(const pcmk__node_status_t *peer);
void attrd_client_peer_remove(pcmk__request_t *request);
void attrd_client_clear_failure(pcmk__request_t *request);
void attrd_client_update(pcmk__request_t *request);
void attrd_client_refresh(pcmk__request_t *request);
xmlNode *attrd_client_query(pcmk__request_t *request);
gboolean attrd_send_message(const pcmk__node_status_t *node, xmlNode *data,
                            bool confirm);

xmlNode *attrd_add_value_xml(xmlNode *parent, const attribute_t *a,
                             const attribute_value_t *v, bool force_write);
void attrd_clear_value_seen(void);
void attrd_free_attribute(gpointer data);
void attrd_free_attribute_value(gpointer data);
attribute_t *attrd_populate_attribute(xmlNode *xml, const char *attr);
char *attrd_set_id(const attribute_t *attr, const char *node_state_id);
char *attrd_nvpair_id(const attribute_t *attr, const char *node_state_id);

enum attrd_write_options {
    attrd_write_changed         = 0,
    attrd_write_all             = (UINT32_C(1) << 0),
    attrd_write_no_delay        = (UINT32_C(1) << 1),
};

void attrd_write_attributes(uint32_t options);
void attrd_write_or_elect_attribute(attribute_t *a);

extern int minimum_protocol_version;
void attrd_remove_peer_protocol_ver(const char *host);
void attrd_update_minimum_protocol_ver(const char *host, const char *value);

mainloop_timer_t *attrd_add_timer(const char *id, int timeout_ms, attribute_t *attr);

void attrd_unregister_handlers(void);
void attrd_handle_request(pcmk__request_t *request);

enum attrd_sync_point {
    attrd_sync_point_local,
    attrd_sync_point_cluster,
};

typedef int (*attrd_confirmation_action_fn)(xmlNode *);

void attrd_add_client_to_waitlist(pcmk__request_t *request);
void attrd_ack_waitlist_clients(enum attrd_sync_point sync_point, const xmlNode *xml);
int attrd_cluster_sync_point_update(xmlNode *xml);
void attrd_do_not_expect_from_peer(const char *host);
void attrd_do_not_wait_for_client(pcmk__client_t *client);
void attrd_expect_confirmations(pcmk__request_t *request, attrd_confirmation_action_fn fn);
void attrd_free_confirmations(void);
void attrd_handle_confirmation(int callid, const char *host);
void attrd_remove_client_from_waitlist(pcmk__client_t *client);
const char *attrd_request_sync_point(xmlNode *xml);
bool attrd_request_has_sync_point(xmlNode *xml);

extern gboolean stand_alone;

// Node utilities (from attrd_nodes.c)
const char *attrd_get_node_xml_id(const char *node_name);
void attrd_set_node_xml_id(const char *node_name, const char *node_xml_id);
void attrd_forget_node_xml_id(const char *node_name);
void attrd_cleanup_xml_ids(void);

#endif /* PACEMAKER_ATTRD__H */
