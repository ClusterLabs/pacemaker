/* 
 * Copyright (C) 2011 Andrew Beekhof <andrew@beekhof.net>
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
#ifndef STONITH_NG_INTERNAL__H
#  define STONITH_NG_INTERNAL__H

#  include <crm/common/ipc.h>
#  include <crm/common/xml.h>

typedef struct async_command_s {

    int id;
    int pid;
    int stdout;
    int options;
    int timeout;

    char *op;
    char *origin;
    char *client;
    char *remote;

    char *victim;
    char *action;
    char *device;
    char *mode;

    GListPtr device_list;
    GListPtr device_next;

    void (*done)(GPid pid, gint status, gpointer user_data);
    guint timer_sigterm;
    guint timer_sigkill;

} async_command_t;

int run_stonith_agent(const char *agent, const char *action, const char *victim,
                             GHashTable * dev_hash, GHashTable * port_map, int *agent_result,
                             char **output, async_command_t * track);

gboolean is_redhat_agent(const char *agent);

xmlNode *create_level_registration_xml(const char *node, int level,
                                       stonith_key_value_t * device_list);

xmlNode *create_device_registration_xml(const char *id, const char *namespace, const char *agent,
                                        stonith_key_value_t * params);

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
#define F_STONITH_OWNER		        "st_owner"

#define F_STONITH_DEVICE	        "st_device_id"
#define F_STONITH_ACTION	        "st_device_action"
#define F_STONITH_MODE                  "st_mode"

#define T_STONITH_NG		        "stonith-ng"
#define T_STONITH_REPLY		        "st-reply"

#define T_STONITH_NOTIFY	        "st_notify"
#define T_STONITH_NOTIFY_DISCONNECT     "st_notify_disconnect"

#define STONITH_ATTR_ARGMAP	   "pcmk_arg_map"
#define STONITH_ATTR_HOSTARG	   "pcmk_host_argument"
#define STONITH_ATTR_HOSTMAP	   "pcmk_host_map"
#define STONITH_ATTR_HOSTLIST	   "pcmk_host_list"
#define STONITH_ATTR_HOSTCHECK	   "pcmk_host_check"

#define STONITH_ATTR_ACTION_OP	   "option" /* To be replaced by 'action' at some point */

#define STONITH_OP_EXEC		   "st_execute"
#define STONITH_OP_QUERY	   "st_query"
#define STONITH_OP_FENCE	   "st_fence"
#define STONITH_OP_RELAY	   "st_relay"
#define STONITH_OP_CONFIRM	   "st_confirm"
#define STONITH_OP_DEVICE_ADD	   "st_device_register"
#define STONITH_OP_DEVICE_DEL	   "st_device_remove"
#define STONITH_OP_DEVICE_METADATA "st_device_metadata"
#define STONITH_OP_FENCE_HISTORY   "st_fence_history"
#define STONITH_OP_LEVEL_ADD	   "st_level_add"
#define STONITH_OP_LEVEL_DEL	   "st_level_remove"

#define stonith_channel		   "st_command"
#define stonith_channel_callback   "st_callback"

#endif
