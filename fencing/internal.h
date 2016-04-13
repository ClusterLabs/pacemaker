#include <crm/common/mainloop.h>

/*!
 * \internal
 * \brief Check to see if target was fenced in the last few seconds.
 * \param tolerance, The number of seconds to look back in time
 * \param target, The node to search for
 * \param action, The action we want to match.
 *
 * \retval FALSE, not match
 * \retval TRUE, fencing operation took place in the last 'tolerance' number of seconds.
 */
gboolean stonith_check_fence_tolerance(int tolerance, const char *target, const char *action);

enum st_device_flags
{
    st_device_supports_list   = 0x0001,
    st_device_supports_status = 0x0002,
    st_device_supports_reboot = 0x0004,
};

typedef struct stonith_device_s {
    char *id;
    char *agent;
    char *namespace;

    /*! list of actions that must execute on the target node. Used for unfencing */
    char *on_target_actions;
    GListPtr targets;
    time_t targets_age;
    gboolean has_attr_map;
    /* should nodeid parameter for victim be included in agent arguments */
    gboolean include_nodeid;
    /* whether the cluster should automatically unfence nodes with the device */
    gboolean automatic_unfencing;
    guint priority;

    enum st_device_flags flags;

    GHashTable *params;
    GHashTable *aliases;
    GList *pending_ops;
    crm_trigger_t *work;
    xmlNode *agent_metadata;

    /*! A verified device is one that has contacted the
     * agent successfully to perform a monitor operation */
    gboolean verified;

    gboolean cib_registered;
    gboolean api_registered;
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

    /*! Delegate is the node being asked to perform a fencing action
     * on behalf of the node that owns the remote operation. Some operations
     * will involve multiple delegates. This value represents the final delegate
     * that is used. */
    char *delegate;
    /*! The point at which the remote operation completed */
    time_t completed;
    /*! The stonith_call_options associated with this remote operation */
    long long call_options;

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
    GListPtr query_results;
    /*! The original request that initiated the remote stonith operation */
    xmlNode *request;

    /*! The current topology level being executed */
    guint level;
    /*! The current operation phase being executed */
    enum st_remap_phase phase;

    /*! Devices with automatic unfencing (always run if "on" requested, never if remapped) */
    GListPtr automatic_list;
    /*! List of all devices at the currently executing topology level */
    GListPtr devices_list;
    /*! Current entry in the topology device list */
    GListPtr devices;

    /*! List of duplicate operations attached to this operation. Once this operation
     * completes, the duplicate operations will be closed out as well. */
    GListPtr duplicates;

} remote_fencing_op_t;

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
    GListPtr levels[ST_LEVEL_MAX];

} stonith_topology_t;

long long get_stonith_flag(const char *name);

void stonith_command(crm_client_t * client, uint32_t id, uint32_t flags,
                            xmlNode * op_request, const char *remote_peer);

int stonith_device_register(xmlNode * msg, const char **desc, gboolean from_cib);

int stonith_device_remove(const char *id, gboolean from_cib);

char *stonith_level_key(xmlNode * msg, int mode);
int stonith_level_kind(xmlNode * msg);
int stonith_level_register(xmlNode * msg, char **desc);

int stonith_level_remove(xmlNode * msg, char **desc);

stonith_topology_t *find_topology_for_host(const char *host);

void do_local_reply(xmlNode * notify_src, const char *client_id, gboolean sync_reply,
                           gboolean from_peer);

xmlNode *stonith_construct_reply(xmlNode * request, const char *output, xmlNode * data,
                                        int rc);

void
 do_stonith_async_timeout_update(const char *client, const char *call_id, int timeout);

void do_stonith_notify(int options, const char *type, int result, xmlNode * data);
void do_stonith_notify_device(int options, const char *op, int rc, const char *desc);
void do_stonith_notify_level(int options, const char *op, int rc, const char *desc);

remote_fencing_op_t *initiate_remote_stonith_op(crm_client_t * client, xmlNode * request,
                                                       gboolean manual_ack);

int process_remote_stonith_exec(xmlNode * msg);

int process_remote_stonith_query(xmlNode * msg);

void *create_remote_stonith_op(const char *client, xmlNode * request, gboolean peer);

int stonith_fence_history(xmlNode * msg, xmlNode ** output);

void free_device(gpointer data);

void free_topology_entry(gpointer data);

bool fencing_peer_active(crm_node_t *peer);

int stonith_manual_ack(xmlNode * msg, remote_fencing_op_t * op);

void unfence_cb(GPid pid, int rc, const char *output, gpointer user_data);

gboolean string_in_list(GListPtr list, const char *item);

gboolean node_has_attr(const char *node, const char *name, const char *value);

void
schedule_internal_command(const char *origin,
                          stonith_device_t * device,
                          const char *action,
                          const char *victim,
                          int timeout,
                          void *internal_user_data,
                          void (*done_cb) (GPid pid, int rc, const char *output,
                                           gpointer user_data));

char *stonith_get_peer_name(unsigned int nodeid);

extern char *stonith_our_uname;
extern gboolean stand_alone;
extern GHashTable *device_list;
extern GHashTable *topology;
extern long stonith_watchdog_timeout_ms;

extern GHashTable *known_peer_names;
