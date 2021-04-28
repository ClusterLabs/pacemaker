/*
 * Copyright 2013-2021 the Pacemaker project contributors
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
#include <crm/cib/internal.h>

void attrd_init_mainloop(void);
void attrd_run_mainloop(void);

void attrd_set_requesting_shutdown(void);
void attrd_clear_requesting_shutdown(void);
gboolean attrd_requesting_shutdown(void);
gboolean attrd_shutting_down(void);
void attrd_shutdown(int nsig);
void attrd_init_ipc(qb_ipcs_service_t **ipcs,
                    qb_ipcs_msg_process_fn dispatch_fn);
void attrd_ipc_fini(void);

void attrd_cib_disconnect(void);

gboolean attrd_value_needs_expansion(const char *value);
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
    char *set;
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

#define attrd_send_ack(client, id, flags) \
    pcmk__ipc_send_ack((client), (id), (flags), "ack", CRM_EX_INDETERMINATE)

#define CIB_OP_TIMEOUT_S 120

void write_attributes(bool all, bool ignore_delay);
void attrd_broadcast_protocol(void);
void attrd_peer_message(crm_node_t *client, xmlNode *msg);
void attrd_client_peer_remove(pcmk__client_t *client, xmlNode *xml);
void attrd_client_clear_failure(xmlNode *xml);
void attrd_client_update(xmlNode *xml);
void attrd_client_refresh(void);
void attrd_client_query(pcmk__client_t *client, uint32_t id, uint32_t flags,
                        xmlNode *query);

void free_attribute(gpointer data);

gboolean attrd_election_cb(gpointer user_data);
void attrd_peer_change_cb(enum crm_status_type type, crm_node_t *peer, const void *data);

#endif /* PACEMAKER_ATTRD__H */
