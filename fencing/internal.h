typedef struct stonith_device_s 
{
	char *id;
	char *agent;
	char *namespace;

	GListPtr targets;
	time_t targets_age;
	gboolean has_attr_map;
	guint priority;
	
	GHashTable *params;
	GHashTable *aliases;
	
} stonith_device_t;

typedef struct stonith_client_s 
{
	char  *id;
	char  *name;
	char  *callback_id;

	const char  *channel_name;

	IPC_Channel *channel;
	GCHSource   *source;

	long long flags;

} stonith_client_t;

extern long long get_stonith_flag(const char *name);

extern void stonith_command(
    stonith_client_t *client, xmlNode *op_request, const char *remote);

extern void do_local_reply(
    xmlNode *notify_src, const char *client_id, gboolean sync_reply, gboolean from_peer);

extern xmlNode *stonith_construct_reply(
    xmlNode *request, char *output, xmlNode *data, int rc);

extern xmlNode *stonith_construct_async_reply(
    async_command_t *cmd, char *output, xmlNode *data, int rc);;

extern void do_stonith_notify(
    int options, const char *type, enum stonith_errors result, xmlNode *data,
    const char *remote);

extern void initiate_remote_stonith_op(stonith_client_t *client, xmlNode *request);

extern int process_remote_stonith_exec(xmlNode *msg);

extern int process_remote_stonith_query(xmlNode *msg);

extern void *create_remote_stonith_op(const char *client, xmlNode *request, gboolean peer);

extern char *stonith_our_uname;
