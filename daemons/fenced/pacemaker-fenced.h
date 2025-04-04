/*
 * Copyright 2009-2025 the Pacemaker project contributors
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <stdint.h>                 // uint32_t, uint64_t
#include <libxml/tree.h>            // xmlNode

#include <crm/common/mainloop.h>
#include <crm/cluster.h>
#include <crm/stonith-ng.h>
#include <crm/fencing/internal.h>

const char *fenced_get_local_node(void);

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
    GString *on_target_actions;
    GList *targets;
    time_t targets_age;
    gboolean has_attr_map;

    // Whether target's nodeid should be passed as a parameter to the agent
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
    /* @TODO Abstract the overlap with async_command_t (some members have
     * different names for the same thing), which should allow reducing
     * duplication in some functions
     */

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

    /*!
     * Fencing delay (in seconds) requested by API client (used by controller to
     * implement \c PCMK_OPT_PRIORITY_FENCING_DELAY). A value of -1 means
     * disable all configured delays.
     */
    int client_delay;

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

    /*! The (potentially intermediate) result of the operation */
    pcmk__action_result_t result;
} remote_fencing_op_t;

void fenced_broadcast_op_result(const remote_fencing_op_t *op, bool op_merged);

// Fencer-specific client flags
enum st_client_flags {
    st_callback_unknown               =  UINT64_C(0),
    st_callback_notify_fence          = (UINT64_C(1) << 0),
    st_callback_device_add            = (UINT64_C(1) << 2),
    st_callback_device_del            = (UINT64_C(1) << 4),
    st_callback_notify_history        = (UINT64_C(1) << 5),
    st_callback_notify_history_synced = (UINT64_C(1) << 6)
};

// How the user specified the target of a topology level
enum fenced_target_by {
    fenced_target_by_unknown = -1,  // Invalid or not yet parsed
    fenced_target_by_name,          // By target name
    fenced_target_by_pattern,       // By a pattern matching target names
    fenced_target_by_attribute,     // By a node attribute/value on target
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
    enum fenced_target_by kind; // How target was specified

    /*! Node name regex or attribute name=value for which topology applies */
    char *target;
    char *target_value;
    char *target_pattern;
    char *target_attribute;

    /*! Names of fencing devices at each topology level */
    GList *levels[ST__LEVEL_COUNT];

} stonith_topology_t;

void stonith_shutdown(int nsig);

void init_device_list(void);
void free_device_list(void);
void init_topology_list(void);
void free_topology_list(void);
void free_stonith_remote_op_list(void);
void init_stonith_remote_op_hash_table(GHashTable **table);
void free_metadata_cache(void);
void fenced_unregister_handlers(void);

uint64_t get_stonith_flag(const char *name);

void stonith_command(pcmk__client_t *client, uint32_t id, uint32_t flags,
                            xmlNode *op_request, const char *remote_peer);

int stonith_device_register(xmlNode *msg, gboolean from_cib);

void stonith_device_remove(const char *id, bool from_cib);

char *stonith_level_key(const xmlNode *msg, enum fenced_target_by);
void fenced_register_level(xmlNode *msg, char **desc,
                           pcmk__action_result_t *result);
void fenced_unregister_level(xmlNode *msg, char **desc,
                             pcmk__action_result_t *result);

stonith_topology_t *find_topology_for_host(const char *host);

void do_local_reply(const xmlNode *notify_src, pcmk__client_t *client,
                    int call_options);

xmlNode *fenced_construct_reply(const xmlNode *request, xmlNode *data,
                                const pcmk__action_result_t *result);

void
 do_stonith_async_timeout_update(const char *client, const char *call_id, int timeout);

void fenced_send_notification(const char *type,
                              const pcmk__action_result_t *result,
                              xmlNode *data);
void fenced_send_config_notification(const char *op,
                                     const pcmk__action_result_t *result,
                                     const char *desc);

remote_fencing_op_t *initiate_remote_stonith_op(const pcmk__client_t *client,
                                                xmlNode *request,
                                                gboolean manual_ack);

void fenced_process_fencing_reply(xmlNode *msg);

int process_remote_stonith_query(xmlNode * msg);

void *create_remote_stonith_op(const char *client, xmlNode * request, gboolean peer);

void stonith_fence_history(xmlNode *msg, xmlNode **output,
                           const char *remote_peer, int options);

void stonith_fence_history_trim(void);

bool fencing_peer_active(pcmk__node_status_t *peer);

void set_fencing_completed(remote_fencing_op_t * op);

int fenced_handle_manual_confirmation(const pcmk__client_t *client,
                                      xmlNode *msg);

const char *fenced_device_reboot_action(const char *device_id);
bool fenced_device_supports_on(const char *device_id);

gboolean node_has_attr(const char *node, const char *name, const char *value);

gboolean node_does_watchdog_fencing(const char *node);

void fencing_topology_init(void);
void setup_cib(void);
void fenced_cib_cleanup(void);

int fenced_scheduler_init(void);
void fenced_scheduler_cleanup(void);
void fenced_scheduler_run(xmlNode *cib);

static inline void
fenced_set_protocol_error(pcmk__action_result_t *result)
{
    pcmk__set_result(result, CRM_EX_PROTOCOL, PCMK_EXEC_INVALID,
                     "Fencer API request missing required information (bug?)");
}

/*!
 * \internal
 * \brief Get the device flag to use with a given action when searching devices
 *
 * \param[in] action  Action to check
 *
 * \return st_device_supports_on if \p action is "on", otherwise
 *         st_device_supports_none
 */
static inline uint32_t
fenced_support_flag(const char *action)
{
    if (pcmk__str_eq(action, PCMK_ACTION_ON, pcmk__str_none)) {
        return st_device_supports_on;
    }
    return st_device_supports_none;
}

extern GHashTable *device_list;
extern GHashTable *topology;
extern long long stonith_watchdog_timeout_ms;
extern GList *stonith_watchdog_targets;
extern GHashTable *stonith_remote_op_list;
extern crm_exit_t exit_code;
extern gboolean stonith_shutdown_flag;
