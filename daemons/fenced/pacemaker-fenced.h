/*
 * Copyright 2009-2021 the Pacemaker project contributors
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <stdint.h>                 // uint32_t, uint64_t
#include <crm/common/mainloop.h>

/*!
 * \internal
 * \brief Check whether target has already been fenced recently
 *
 * \param[in] tolerance  Number of seconds to look back in time
 * \param[in] target     Name of node to search for
 * \param[in] action     Action we want to match
 *
 * \return TRUE if an equivalent fencing operation took place in the last
 *         \p tolerance seconds, FALSE otherwise
 */
gboolean stonith_check_fence_tolerance(int tolerance, const char *target, const char *action);

typedef struct stonith_device_s {
    char *id;
    char *agent;
    char *namespace;

    /*! list of actions that must execute on the target node. Used for unfencing */
    char *on_target_actions;
    GList *targets;
    time_t targets_age;
    gboolean has_attr_map;
    /* should nodeid parameter for victim be included in agent arguments */
    gboolean include_nodeid;
    /* whether the cluster should automatically unfence nodes with the device */
    gboolean automatic_unfencing;
    guint priority;

    uint32_t flags; // Group of enum st_device_flags

    GHashTable *params;
    GHashTable *aliases;
    GList *pending_ops;
    mainloop_timer_t *timer;
    crm_trigger_t *work;
    xmlNode *agent_metadata;

    /*! A verified device is one that has contacted the
     * agent successfully to perform a monitor operation */
    gboolean verified;

    gboolean cib_registered;
    gboolean api_registered;
    gboolean dirty;
} stonith_device_t;

/* These values are used to index certain arrays by "phase". Usually an
 * operation has only one "phase", so phase is always zero. However, some
 * reboots are remapped to "off" then "on", in which case "reboot" will be
 * phase 0, "off" will be phase 1 and "on" will be phase 2.
 */
enum st_remap_phase {
    st_phase_requested = 0,
    st_phase_off = 1,
    st_phase_on = 2,
    st_phase_max = 3
};

typedef struct remote_fencing_op_s {
    /* The unique id associated with this operation */
    char *id;
    /*! The node this operation will fence */
    char *target;
    /*! The fencing action to perform on the target. (reboot, on, off) */
    char *action;

    /*! When was the fencing action recorded (seconds since epoch) */
    time_t created;

    /*! Marks if the final notifications have been sent to local stonith clients. */
    gboolean notify_sent;
    /*! The number of query replies received */
    guint replies;
    /*! The number of query replies expected */
    guint replies_expected;
    /*! Does this node own control of this operation */
    gboolean owner;
    /*! After query is complete, This the high level timer that expires the entire operation */
    guint op_timer_total;
    /*! This timer expires the current fencing request. Many fencing
     * requests may exist in a single operation */
    guint op_timer_one;
    /*! This timer expires the query request sent out to determine
     * what nodes are contain what devices, and who those devices can fence */
    guint query_timer;
    /*! This is the default timeout to use for each fencing device if no
     * custom timeout is received in the query. */
    gint base_timeout;
    /*! This is the calculated total timeout an operation can take before
     * expiring. This is calculated by adding together all the timeout
     * values associated with the devices this fencing operation may call */
    gint total_timeout;

    /*! Requested fencing delay.
     * Value -1 means disable any static/random fencing delays. */
    int delay;

    /*! Delegate is the node being asked to perform a fencing action
     * on behalf of the node that owns the remote operation. Some operations
     * will involve multiple delegates. This value represents the final delegate
     * that is used. */
    char *delegate;
    /*! The point at which the remote operation completed */
    time_t completed;
    //! Group of enum stonith_call_options associated with this operation
    uint32_t call_options;

    /*! The current state of the remote operation. This indicates
     * what stage the op is in, query, exec, done, duplicate, failed. */
    enum op_state state;
    /*! The node that owns the remote operation */
    char *originator;
    /*! The local client id that initiated the fencing request */
    char *client_id;
    /*! The client's call_id that initiated the fencing request */
    int client_callid;
    /*! The name of client that initiated the fencing request */
    char *client_name;
    /*! List of the received query results for all the nodes in the cpg group */
    GList *query_results;
    /*! The original request that initiated the remote stonith operation */
    xmlNode *request;

    /*! The current topology level being executed */
    guint level;
    /*! The current operation phase being executed */
    enum st_remap_phase phase;

    /*! Devices with automatic unfencing (always run if "on" requested, never if remapped) */
    GList *automatic_list;
    /*! List of all devices at the currently executing topology level */
    GList *devices_list;
    /*! Current entry in the topology device list */
    GList *devices;

    /*! List of duplicate operations attached to this operation. Once this operation
     * completes, the duplicate operations will be closed out as well. */
    GList *duplicates;

    /*! The point at which the remote operation completed(nsec) */
    long long completed_nsec;

} remote_fencing_op_t;

/*!
 * \internal
 * \brief Broadcast the result of an operation to the peers.
 * \param op, Operation whose result should be broadcast
 * \param rc, Result of the operation
 */
void stonith_bcast_result_to_peers(remote_fencing_op_t * op, int rc, gboolean op_merged);

// Fencer-specific client flags
enum st_client_flags {
    st_callback_unknown               =  UINT64_C(0),
    st_callback_notify_fence          = (UINT64_C(1) << 0),
    st_callback_device_add            = (UINT64_C(1) << 2),
    st_callback_device_del            = (UINT64_C(1) << 4),
    st_callback_notify_history        = (UINT64_C(1) << 5),
    st_callback_notify_history_synced = (UINT64_C(1) << 6)
};

/*
 * Complex fencing requirements are specified via fencing topologies.
 * A topology consists of levels; each level is a list of fencing devices.
 * Topologies are stored in a hash table by node name. When a node needs to be
 * fenced, if it has an entry in the topology table, the levels are tried
 * sequentially, and the devices in each level are tried sequentially.
 * Fencing is considered successful as soon as any level succeeds;
 * a level is considered successful if all its devices succeed.
 * Essentially, all devices at a given level are "and-ed" and the
 * levels are "or-ed".
 *
 * This structure is used for the topology table entries.
 * Topology levels start from 1, so levels[0] is unused and always NULL.
 */
typedef struct stonith_topology_s {
    int kind;

    /*! Node name regex or attribute name=value for which topology applies */
    char *target;
    char *target_value;
    char *target_pattern;
    char *target_attribute;

    /*! Names of fencing devices at each topology level */
    GList *levels[ST_LEVEL_MAX];

} stonith_topology_t;

void init_device_list(void);
void free_device_list(void);
void init_topology_list(void);
void free_topology_list(void);
void free_stonith_remote_op_list(void);
void init_stonith_remote_op_hash_table(GHashTable **table);
void free_metadata_cache(void);

uint64_t get_stonith_flag(const char *name);

void stonith_command(pcmk__client_t *client, uint32_t id, uint32_t flags,
                            xmlNode *op_request, const char *remote_peer);

int stonith_device_register(xmlNode * msg, const char **desc, gboolean from_cib);

void stonith_device_remove(const char *id, bool from_cib);

char *stonith_level_key(xmlNode * msg, int mode);
int stonith_level_kind(xmlNode * msg);
void fenced_register_level(xmlNode *msg, char **desc,
                           pcmk__action_result_t *result);
void fenced_unregister_level(xmlNode *msg, char **desc,
                             pcmk__action_result_t *result);

stonith_topology_t *find_topology_for_host(const char *host);

void do_local_reply(xmlNode * notify_src, const char *client_id, gboolean sync_reply,
                           gboolean from_peer);

xmlNode *fenced_construct_reply(xmlNode *request, xmlNode *data,
                                pcmk__action_result_t *result);

void
 do_stonith_async_timeout_update(const char *client, const char *call_id, int timeout);

void do_stonith_notify(const char *type, int result, xmlNode *data);
void do_stonith_notify_device(const char *op, int rc, const char *desc);
void do_stonith_notify_level(const char *op, int rc, const char *desc);

remote_fencing_op_t *initiate_remote_stonith_op(pcmk__client_t *client,
                                                xmlNode *request,
                                                gboolean manual_ack);

void fenced_process_fencing_reply(xmlNode *msg);

int process_remote_stonith_query(xmlNode * msg);

void *create_remote_stonith_op(const char *client, xmlNode * request, gboolean peer);

void stonith_fence_history(xmlNode *msg, xmlNode **output,
                           const char *remote_peer, int options);

void stonith_fence_history_trim(void);

bool fencing_peer_active(crm_node_t *peer);

void set_fencing_completed(remote_fencing_op_t * op);

int fenced_handle_manual_confirmation(pcmk__client_t *client, xmlNode *msg);

gboolean node_has_attr(const char *node, const char *name, const char *value);

gboolean node_does_watchdog_fencing(const char *node);

static inline void
fenced_set_protocol_error(pcmk__action_result_t *result)
{
    pcmk__set_result(result, CRM_EX_PROTOCOL, PCMK_EXEC_INVALID,
                     "Fencer API request missing required information (bug?)");
}

extern char *stonith_our_uname;
extern gboolean stand_alone;
extern GHashTable *device_list;
extern GHashTable *topology;
extern long stonith_watchdog_timeout_ms;
extern GList *stonith_watchdog_targets;

extern GHashTable *stonith_remote_op_list;
