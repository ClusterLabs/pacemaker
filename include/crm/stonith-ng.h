/* 
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#ifndef STONITH_NG__H
#define STONITH_NG__H

#include <crm/common/ipc.h>
#include <crm/common/xml.h>

enum stonith_state {
    stonith_connected_command,
    stonith_connected_query,
    stonith_disconnected
};

enum stonith_call_options {
    stonith_none            = 0x00000000,
    stonith_verbose         = 0x00000001,
    stonith_discard_reply   = 0x00000010,
    stonith_scope_local     = 0x00000100,
    stonith_sync_call       = 0x00001000,
};

#define stonith_default_options = stonith_none

enum stonith_errors {
    stonith_ok				=  0,
    stonith_not_supported		= -1,
    stonith_connection			= -2,
    stonith_authentication		= -3,
    stonith_callback_register		= -4,
    stonith_missing			= -5,
    stonith_exists			= -6,
    stonith_timeout			= -7,
    stonith_ipc				= -8,
    stonith_peer			= -9,
};

#define F_STONITH_CLIENTID		"st_clientid"
#define F_STONITH_CALLOPTS		"st_callopt"
#define F_STONITH_CALLID		"st_callid"
#define F_STONITH_CALLDATA		"st_calldata"
#define F_STONITH_OPERATION		"st_op"
#define F_STONITH_HOST			"st_host"
#define F_STONITH_RC			"st_rc"
#define F_STONITH_DELEGATED		"st_delegated_from"
#define F_STONITH_TIMEOUT		"st_timeout"
#define F_STONITH_CALLBACK_TOKEN	"st_async_id"
#define F_STONITH_CLIENTNAME		"st_clientname"
#define F_STONITH_NOTIFY_TYPE		"st_notify_type"
#define F_STONITH_NOTIFY_ACTIVATE	"st_notify_activate"

#define T_STONITH_NG		"stonith-ng"

#define F_STONITH_DEVICE	"st_device_id"
#define F_STONITH_ACTION	"st_device_action"

#define T_STONITH_NOTIFY	"st_notify"

#define STONITH_OP_EXEC		"st_execute"
#define STONITH_OP_FENCE	"st_fence"
#define STONITH_OP_UNFENCE	"st_unfence"
#define STONITH_OP_DEVICE_ADD	"st_device_register"
#define STONITH_OP_DEVICE_DEL	"st_device_remove"

#define stonith_channel			"st_command"
#define stonith_channel_callback	"st_callback"

typedef struct stonith_s stonith_t;

typedef struct stonith_api_operations_s
{
	int (*free) (stonith_t *st);
	int (*connect) (stonith_t *st, const char *name, int *async_fd, int *sync_fd);
	int (*disconnect)(stonith_t *st);

	int (*remove_device)(
	    stonith_t *st, int options, const char *name);
	int (*register_device)(
	    stonith_t *st, int options, const char *id,
	    const char *namespace, const char *agent, GHashTable *parameters);

	int (*call)(stonith_t *st, int options, const char *id, const char *action, int timeout);
	int (*fence)(stonith_t *st, int options, const char *node, int timeout);
	int (*unfence)(stonith_t *st, int options, const char *node, int timeout);
		
	int (*register_notification)(
	    stonith_t *st, const char *event, void (*callback)(
		const char *event, xmlNode *msg));
	int (*remove_notification)(
	    stonith_t *st, const char *event, void (*callback)(
		const char *event, xmlNode *msg));

	int (*remove_callback)(int call_id, gboolean all_callbacks);
	int (*register_callback)(
	    stonith_t *st, int call_id, int timeout, gboolean only_success, void *user_data,
	    const char *callback_name, void (*callback)(const xmlNode*, int, int, xmlNode*,void*));
	
} stonith_api_operations_t;

struct stonith_s
{
	enum stonith_state	state;

	int   call_id;
	int   call_timeout;
	void  *private;
	
	GList *notify_list;

	stonith_api_operations_t *cmds;
};

/* Core functions */
extern stonith_t *stonith_api_new(void);
extern void stonith_api_delete(stonith_t *st);

extern const char *stonith_error2string(enum stonith_errors return_code);
extern void stonith_dump_pending_callbacks(void);
extern int num_stonith_op_callbacks(void);
extern void remove_stonith_op_callback(int call_id, gboolean all_callbacks);

#define add_stonith_op_callback(cib, id, flag, data, fn) cib->cmds->register_callback(cib, id, 120, flag, data, #fn, fn)


#endif

