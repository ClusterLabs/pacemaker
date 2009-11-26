typedef struct stonith_device_s 
{
	char *id;
	char *agent;
	char *namespace;
	char *targets;

	time_t targets_age;
	
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

extern void stonith_command(stonith_client_t *client, xmlNode *op_request, gboolean remote);
extern void do_local_reply(
    xmlNode *notify_src, const char *client_id, gboolean sync_reply, gboolean from_peer);

extern long long get_stonith_flag(const char *name);

extern void do_stonith_notify(
    int options, const char *op, enum stonith_errors result, xmlNode *data, const char *type);
