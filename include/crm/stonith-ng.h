/* 
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#ifndef STONITH_NG__H
#  define STONITH_NG__H

#  include <dlfcn.h>
#  include <stdbool.h>

/* TO-DO: Work out how to drop this requirement */
#  include <libxml/tree.h>

/* *INDENT-OFF* */
enum stonith_state {
    stonith_connected_command,
    stonith_connected_query,
    stonith_disconnected,
};

enum stonith_call_options {
    st_opt_none            = 0x00000000,
    st_opt_verbose         = 0x00000001,
    st_opt_allow_suicide   = 0x00000002,

    st_opt_manual_ack	   = 0x00000008,
    st_opt_discard_reply   = 0x00000010,
    st_opt_all_replies	   = 0x00000020,
    st_opt_topology	   = 0x00000040,
    st_opt_scope_local     = 0x00000100,
    st_opt_cs_nodeid       = 0x00000200,
    st_opt_sync_call       = 0x00001000,
};

#define stonith_default_options = stonith_none

enum stonith_errors {
    stonith_ok				=  0,
    stonith_pending			= -1,
    st_err_generic			= -2,
    st_err_internal			= -3,
    st_err_not_supported		= -4,
    st_err_connection			= -5,
    st_err_missing			= -6,
    st_err_exists			= -7,
    st_err_timeout			= -8,
    st_err_ipc				= -9,
    st_err_peer				= -10,
    st_err_unknown_operation		= -11,
    st_err_unknown_device		= -12,
    st_err_unknown_port			= -13,
    st_err_none_available		= -14,
    st_err_authentication		= -15,
    st_err_signal			= -16,
    st_err_agent_fork			= -17,
    st_err_agent_args			= -18,
    st_err_agent			= -19,
    st_err_invalid_target		= -20,
    st_err_invalid_level		= -21,
};

#define ST_LEVEL_MAX 10

#define F_STONITH_CLIENTID		"st_clientid"
#define F_STONITH_CALLOPTS		"st_callopt"
#define F_STONITH_CALLID		"st_callid"
#define F_STONITH_CALLDATA		"st_calldata"
#define F_STONITH_OPERATION		"st_op"
#define F_STONITH_TARGET		"st_target"
#define F_STONITH_REMOTE		"st_remote_op"
#define F_STONITH_RC			"st_rc"
#define F_STONITH_TIMEOUT		"st_timeout"
#define F_STONITH_CALLBACK_TOKEN	"st_async_id"
#define F_STONITH_CLIENTNAME		"st_clientname"
#define F_STONITH_NOTIFY_TYPE		"st_notify_type"
#define F_STONITH_NOTIFY_ACTIVATE	"st_notify_activate"
#define F_STONITH_NOTIFY_DEACTIVATE	"st_notify_deactivate"
#define F_STONITH_DELEGATE		"st_delegate"
#define F_STONITH_ORIGIN		"st_origin"
#define F_STONITH_HISTORY_LIST		"st_history"
#define F_STONITH_DATE			"st_date"
#define F_STONITH_STATE			"st_state"
#define F_STONITH_LEVEL		        "st_level"

#define T_STONITH_NG		"stonith-ng"
#define T_STONITH_REPLY		"st-reply"

#define F_STONITH_DEVICE	"st_device_id"
#define F_STONITH_ACTION	"st_device_action"


#define T_STONITH_NOTIFY		"st_notify"
#define T_STONITH_NOTIFY_DISCONNECT	"st_notify_disconnect"

#define STONITH_ATTR_ARGMAP	"pcmk_arg_map"
#define STONITH_ATTR_HOSTARG	"pcmk_host_argument"
#define STONITH_ATTR_HOSTMAP	"pcmk_host_map"
#define STONITH_ATTR_HOSTLIST	"pcmk_host_list"
#define STONITH_ATTR_HOSTCHECK	"pcmk_host_check"

#define STONITH_ATTR_ACTION_OP	"option" /* To be replaced by 'action' at some point */

#define STONITH_OP_EXEC		"st_execute"
#define STONITH_OP_QUERY	"st_query"
#define STONITH_OP_FENCE	"st_fence"
#define STONITH_OP_CONFIRM	"st_confirm"
#define STONITH_OP_DEVICE_ADD	"st_device_register"
#define STONITH_OP_DEVICE_DEL	"st_device_remove"
#define STONITH_OP_DEVICE_METADATA "st_device_metadata"
#define STONITH_OP_FENCE_HISTORY   "st_fence_history"
#define STONITH_OP_LEVEL_ADD	   "st_level_add"
#define STONITH_OP_LEVEL_DEL	   "st_level_remove"

#define stonith_channel			"st_command"
#define stonith_channel_callback	"st_callback"

enum op_state 
{
    st_query,
    st_exec,
    st_done,
    st_failed,
};

typedef struct stonith_key_value_s {
	char *key;
	char *value;
        struct stonith_key_value_s *next;
} stonith_key_value_t;

typedef struct stonith_history_s {
	char *target;
	char *action;
	char *origin;
	char *delegate;
	int completed;
	int state;
	
        struct stonith_history_s *next;
} stonith_history_t;

typedef struct stonith_s stonith_t;

typedef struct stonith_api_operations_s
{
	int (*free) (stonith_t *st);
	int (*connect) (stonith_t *st, const char *name, int *stonith_fd);
	int (*disconnect)(stonith_t *st);

	int (*remove_device)(
	    stonith_t *st, int options, const char *name);
	int (*register_device)(
	    stonith_t *st, int options, const char *id,
	    const char *namespace, const char *agent, stonith_key_value_t *params);

	int (*remove_level)(
	    stonith_t *st, int options, const char *node, int level);
	int (*register_level)(
	    stonith_t *st, int options, const char *node, int level, stonith_key_value_t *device_list);
        
	int (*metadata)(stonith_t *st, int options,
			const char *device, const char *namespace, char **output, int timeout);
	int (*list)(stonith_t *stonith, int call_options, const char *namespace,
		    stonith_key_value_t **devices, int timeout);

	int (*call)(stonith_t *st, int options, const char *id,
		    const char *action, const char *port, int timeout);

	int (*query)(stonith_t *st, int options, const char *node,
            stonith_key_value_t **devices, int timeout);
	int (*fence)(stonith_t *st, int options, const char *node, const char *action,
            int timeout);
	int (*confirm)(stonith_t *st, int options, const char *node);
	int (*history)(stonith_t *st, int options, const char *node, stonith_history_t **output, int timeout);
		
	int (*register_notification)(
	    stonith_t *st, const char *event,
	    void (*notify)(stonith_t *st, const char *event, xmlNode *msg));
	int (*remove_notification)(stonith_t *st, const char *event);

	int (*register_callback)(
	    stonith_t *st, int call_id, int timeout, bool only_success,
	    void *userdata, const char *callback_name,
	    void (*callback)(stonith_t *st, const xmlNode *msg, int call, int rc, xmlNode *output, void *userdata));
	int (*remove_callback)(stonith_t *st, int call_id, bool all_callbacks);
	
} stonith_api_operations_t;

struct stonith_s
{
	enum stonith_state	state;

	int   call_id;
	int   call_timeout;
	void  *private;
	
	stonith_api_operations_t *cmds;
};
/* *INDENT-ON* */

/* Core functions */
stonith_t *stonith_api_new(void);
void stonith_api_delete(stonith_t * st);

const char *stonith_error2string(enum stonith_errors return_code);
void stonith_dump_pending_callbacks(stonith_t * st);

const char *get_stonith_provider(const char *agent, const char *provider);

bool stonith_dispatch(stonith_t * st);

stonith_key_value_t *stonith_key_value_add(stonith_key_value_t * kvp, const char *key,
                                                  const char *value);
void stonith_key_value_freeall(stonith_key_value_t * kvp, int keys, int values);

/* Basic helpers that allows nodes to be fenced and the history to be
 * queried without mainloop or the caller understanding the full API
 *
 * At least one of nodeid and uname are required
 */
int stonith_api_kick(int nodeid, const char *uname, int timeout, bool off);
time_t stonith_api_time(int nodeid, const char *uname, bool in_progress);

/*
 * Helpers for using the above functions without install-time dependancies
 *
 * Usage:
 *  #include <crm/stonith-ng.h>
 *
 * To turn a node off by corosync nodeid:
 *  stonith_api_kick_helper(nodeid, 120, 1);
 *
 * To check the last fence date/time (also by nodeid):
 *  last = stonith_api_time_helper(nodeid, 0);
 *
 * To check if fencing is in progress:
 *  if(stonith_api_time_helper(nodeid, 1) > 0) { ... }
 *
 * eg.

 #include <stdio.h>
 #include <time.h>
 #include <crm/stonith-ng.h>
 int
 main(int argc, char ** argv)
 {
     int rc = 0;
     int nodeid = 102;

     rc = stonith_api_time_helper(nodeid, 0);
     printf("%d last fenced at %s\n", nodeid, ctime(rc));

     rc = stonith_api_kick_helper(nodeid, 120, 1);
     printf("%d fence result: %d\n", nodeid, rc);

     rc = stonith_api_time_helper(nodeid, 0);
     printf("%d last fenced at %s\n", nodeid, ctime(rc));

     return 0;
 }

 */

#  define STONITH_LIBRARY "libstonithd.so.1"

static inline int
stonith_api_kick_helper(int nodeid, int timeout, bool off)
{
    static void *st_library = NULL;
    static int (*st_kick_fn) (int nodeid, const char *uname, int timeout, bool off) = NULL;

    if (st_library == NULL) {
        st_library = dlopen(STONITH_LIBRARY, RTLD_LAZY);
    }
    if (st_library && st_kick_fn == NULL) {
        st_kick_fn = dlsym(st_library, "stonith_api_kick");
    }
    if (st_kick_fn == NULL) {
        return st_err_not_supported;
    }

    return (*st_kick_fn) (nodeid, NULL, timeout, off);
}

static inline time_t
stonith_api_time_helper(int nodeid, bool in_progress)
{
    static void *st_library = NULL;
    static time_t(*st_time_fn) (int nodeid, const char *uname, bool in_progress) = NULL;

    if (st_library == NULL) {
        st_library = dlopen(STONITH_LIBRARY, RTLD_LAZY);
    }
    if (st_library && st_time_fn == NULL) {
        st_time_fn = dlsym(st_library, "stonith_api_time");
    }
    if (st_time_fn == NULL) {
        return 0;
    }

    return (*st_time_fn) (nodeid, NULL, in_progress);
}

#endif
