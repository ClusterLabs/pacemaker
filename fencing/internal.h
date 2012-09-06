#include <crm/common/mainloop.h>

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

    guint op_timer;
    guint query_timer;
    guint base_timeout;

    char *delegate;
    time_t completed;
    long long call_options;

    enum op_state state;
    char *originator;
    char *client_id;
    char *client_name;
    GListPtr query_results;
    xmlNode *request;

    guint level;                /* ABI */
    GListPtr devices;           /* ABI */

    int topology_device_number;

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
