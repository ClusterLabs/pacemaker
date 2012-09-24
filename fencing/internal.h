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
gboolean
stonith_check_fence_tolerance(int tolerance, const char *target, const char *action);

typedef struct stonith_device_s {
    char *id;
    char *agent;
    char *namespace;

    GListPtr targets;
    time_t targets_age;
    gboolean has_attr_map;
    guint priority;
    guint active_pid;

    GHashTable *params;
    GHashTable *aliases;
    GList *pending_ops;
    crm_trigger_t *work;

} stonith_device_t;

typedef struct stonith_client_s {
    char *id;
    char *name;

    int pid;
    int request_id;

    char *channel_name;
    qb_ipcs_connection_t *channel;

    long long flags;

} stonith_client_t;

typedef struct remote_fencing_op_s {
    char *id;
    char *target;
    char *action;
    guint replies;

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

    char *delegate;
    time_t completed;
    long long call_options;

    enum op_state state;
    char *originator;
    char *client_id;
    char *client_name;
    GListPtr query_results;
    xmlNode *request;

    guint level;
    int topology_device_number;

    GListPtr devices;
    GListPtr duplicates;

    gboolean notify_sent;
} remote_fencing_op_t;

typedef struct stonith_topology_s {
    char *node;
    GListPtr levels[ST_LEVEL_MAX];

} stonith_topology_t;

extern long long get_stonith_flag(const char *name);

extern void stonith_command(stonith_client_t * client, uint32_t id, uint32_t flags, xmlNode * op_request, const char *remote);

extern int stonith_device_register(xmlNode * msg, const char **desc);

extern int stonith_level_register(xmlNode * msg, char **desc);

extern int stonith_level_remove(xmlNode * msg, char **desc);

extern void do_local_reply(xmlNode * notify_src, const char *client_id, gboolean sync_reply,
                           gboolean from_peer);

extern xmlNode *stonith_construct_reply(xmlNode * request, char *output, xmlNode * data, int rc);

void
do_stonith_async_timeout_update(const char *client, const char *call_id, int timeout);

extern void do_stonith_notify(int options, const char *type, int result, xmlNode * data, const char *remote);

extern remote_fencing_op_t *initiate_remote_stonith_op(stonith_client_t * client, xmlNode * request,
                                                       gboolean manual_ack);

extern int process_remote_stonith_exec(xmlNode * msg);

extern int process_remote_stonith_query(xmlNode * msg);

extern void *create_remote_stonith_op(const char *client, xmlNode * request, gboolean peer);

extern int stonith_fence_history(xmlNode * msg, xmlNode ** output);

extern void free_device(gpointer data);

extern void free_topology_entry(gpointer data);


extern char *stonith_our_uname;
extern gboolean stand_alone;
extern GHashTable *device_list;
extern GHashTable *topology;
extern GHashTable *client_list;
