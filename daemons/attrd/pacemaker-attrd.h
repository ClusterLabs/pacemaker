/*
 * Copyright 2013-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#ifndef PACEMAKER_ATTRD__H
#  define PACEMAKER_ATTRD__H

#include <regex.h>
#include <glib.h>
#include <crm/crm.h>
#include <crm/cluster.h>
#include <crm/cluster/election_internal.h>
#include <crm/common/messages_internal.h>
#include <crm/cib/internal.h>

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
 *                      PCMK__ATTRD_CMD_FLUSH, PCMK__ATTRD_CMD_SYNC,
 *                      PCMK__ATTRD_CMD_SYNC_RESPONSE
 *     1       1.1.13   PCMK__ATTRD_CMD_UPDATE (with PCMK__XA_ATTR_PATTERN),
 *                      PCMK__ATTRD_CMD_QUERY
 *     1       1.1.15   PCMK__ATTRD_CMD_UPDATE_BOTH,
 *                      PCMK__ATTRD_CMD_UPDATE_DELAY
 *     2       1.1.17   PCMK__ATTRD_CMD_CLEAR_FAILURE
 *     3       2.1.1    PCMK__ATTRD_CMD_SYNC_RESPONSE indicates remote nodes
 *     4       2.1.5    Multiple attributes can be updated in a single IPC
 *                      message
 *     5       2.1.5    Peers can request confirmation of a sent message
 */
#define ATTRD_PROTOCOL_VERSION "5"

#define ATTRD_SUPPORTS_MULTI_MESSAGE(x) ((x) >= 4)
#define ATTRD_SUPPORTS_CONFIRMATION(x)  ((x) >= 5)

#define attrd_send_ack(client, id, flags) \
    pcmk__ipc_send_ack((client), (id), (flags), "ack", ATTRD_PROTOCOL_VERSION, CRM_EX_INDETERMINATE)

void attrd_init_mainloop(void);
void attrd_run_mainloop(void);

void attrd_set_requesting_shutdown(void);
void attrd_clear_requesting_shutdown(void);
void attrd_free_waitlist(void);
bool attrd_requesting_shutdown(void);
bool attrd_shutting_down(void);
void attrd_shutdown(int nsig);
void attrd_init_ipc(void);
void attrd_ipc_fini(void);

void attrd_cib_disconnect(void);

bool attrd_value_needs_expansion(const char *value);
int attrd_expand_value(const char *value, const char *old_value);

/* regular expression to clear failures of all resources */
#define ATTRD_RE_CLEAR_ALL \
    "^(" PCMK__FAIL_COUNT_PREFIX "|" PCMK__LAST_FAILURE_PREFIX ")-"

/* regular expression to clear failure of all operations for one resource
 * (format takes resource name)
 *
 * @COMPAT attributes set < 1.1.17:
 * also match older attributes that do not have the operation part
 */
#define ATTRD_RE_CLEAR_ONE ATTRD_RE_CLEAR_ALL "%s(#.+_[0-9]+)?$"

/* regular expression to clear failure of one operation for one resource
 * (format takes resource name, operation name, and interval)
 *
 * @COMPAT attributes set < 1.1.17:
 * also match older attributes that do not have the operation part
 */
#define ATTRD_RE_CLEAR_OP ATTRD_RE_CLEAR_ALL "%s(#%s_%u)?$"

int attrd_failure_regex(regex_t *regex, const char *rsc, const char *op,
                        guint interval_ms);

extern cib_t *the_cib;

/* Alerts */

extern lrmd_t *the_lrmd;
extern crm_trigger_t *attrd_config_read;

void attrd_lrmd_disconnect(void);
gboolean attrd_read_options(gpointer user_data);
void attrd_cib_replaced_cb(const char *event, xmlNode * msg);
void attrd_cib_updated_cb(const char *event, xmlNode *msg);
int attrd_send_attribute_alert(const char *node, int nodeid,
                               const char *attr, const char *value);

// Elections
void attrd_election_init(void);
void attrd_election_fini(void);
void attrd_start_election_if_needed(void);
bool attrd_election_won(void);
void attrd_handle_election_op(const crm_node_t *peer, xmlNode *xml);
bool attrd_check_for_new_writer(const crm_node_t *peer, const xmlNode *xml);
void attrd_declare_winner(void);
void attrd_remove_voter(const crm_node_t *peer);
void attrd_xml_add_writer(xmlNode *xml);

typedef struct attribute_s {
    char *uuid; /* TODO: Remove if at all possible */
    char *id;
    char *set_id;
    char *set_type;
    GHashTable *values;
    int update;
    int timeout_ms;

    /* TODO: refactor these three as a bitmask */
    bool changed; /* whether attribute value has changed since last write */
    bool unknown_peer_uuids; /* whether we know we're missing a peer uuid */
    gboolean is_private; /* whether to keep this attribute out of the CIB */

    mainloop_timer_t *timer;

    char *user;

    gboolean force_write; /* Flag for updating attribute by ignoring delay */

} attribute_t;

typedef struct attribute_value_s {
        uint32_t nodeid;
        gboolean is_remote;
        char *nodename;
        char *current;
        char *requested;
        gboolean seen;
} attribute_value_t;

extern crm_cluster_t *attrd_cluster;
extern GHashTable *attributes;
extern GHashTable *peer_protocol_vers;

#define CIB_OP_TIMEOUT_S 120

int attrd_cluster_connect(void);
void attrd_peer_update(const crm_node_t *peer, xmlNode *xml, const char *host,
                       bool filter);
void attrd_peer_sync(crm_node_t *peer, xmlNode *xml);
void attrd_peer_remove(const char *host, bool uncache, const char *source);
void attrd_peer_clear_failure(pcmk__request_t *request);
void attrd_peer_sync_response(const crm_node_t *peer, bool peer_won,
                              xmlNode *xml);

void attrd_broadcast_protocol(void);
xmlNode *attrd_client_peer_remove(pcmk__request_t *request);
xmlNode *attrd_client_clear_failure(pcmk__request_t *request);
xmlNode *attrd_client_update(pcmk__request_t *request);
xmlNode *attrd_client_refresh(pcmk__request_t *request);
xmlNode *attrd_client_query(pcmk__request_t *request);
gboolean attrd_send_message(crm_node_t *node, xmlNode *data, bool confirm);

xmlNode *attrd_add_value_xml(xmlNode *parent, const attribute_t *a,
                             const attribute_value_t *v, bool force_write);
void attrd_clear_value_seen(void);
void attrd_free_attribute(gpointer data);
void attrd_free_attribute_value(gpointer data);
attribute_t *attrd_populate_attribute(xmlNode *xml, const char *attr);

void attrd_write_attribute(attribute_t *a, bool ignore_delay);
void attrd_write_attributes(bool all, bool ignore_delay);
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

void attrd_copy_xml_attributes(xmlNode *src, xmlNode *dest);

extern gboolean stand_alone;

#endif /* PACEMAKER_ATTRD__H */
