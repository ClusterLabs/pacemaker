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

extern void stonith_command(stonith_client_t *client, xmlNode *op_request);
extern void do_local_notify(xmlNode *notify_src, const char *client_id,
			    gboolean sync_reply, gboolean from_peer);
