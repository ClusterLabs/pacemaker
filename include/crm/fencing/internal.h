/*
 * Copyright 2011-2018 Andrew Beekhof <andrew@beekhof.net>
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef STONITH_NG_INTERNAL__H
#  define STONITH_NG_INTERNAL__H

#  include <crm/common/ipc.h>
#  include <crm/common/xml.h>

struct stonith_action_s;
typedef struct stonith_action_s stonith_action_t;

stonith_action_t *stonith_action_create(const char *agent,
                                        const char *_action,
                                        const char *victim,
                                        uint32_t victim_nodeid,
                                        int timeout,
                                        GHashTable * device_args, GHashTable * port_map);

GPid
stonith_action_execute_async(stonith_action_t * action,
                             void *userdata,
                             void (*done) (GPid pid, int rc, const char *output,
                                           gpointer user_data));

int
 stonith_action_execute(stonith_action_t * action, int *agent_result, char **output);

gboolean is_redhat_agent(const char *agent);

xmlNode *create_level_registration_xml(const char *node, const char *pattern,
                                       const char *attr, const char *value,
                                       int level,
                                       stonith_key_value_t *device_list);

xmlNode *create_device_registration_xml(const char *id,
                                        enum stonith_namespace namespace,
                                        const char *agent,
                                        stonith_key_value_t *params,
                                        const char *rsc_provides);

#  define ST_LEVEL_MAX 10

#  define F_STONITH_CLIENTID      "st_clientid"
#  define F_STONITH_CALLOPTS      "st_callopt"
#  define F_STONITH_CALLID        "st_callid"
#  define F_STONITH_CALLDATA      "st_calldata"
#  define F_STONITH_OPERATION     "st_op"
#  define F_STONITH_TARGET        "st_target"
#  define F_STONITH_REMOTE_OP_ID  "st_remote_op"
#  define F_STONITH_RC            "st_rc"
/*! Timeout period per a device execution */
#  define F_STONITH_TIMEOUT       "st_timeout"
#  define F_STONITH_TOLERANCE     "st_tolerance"
/*! Action specific timeout period returned in query of fencing devices. */
#  define F_STONITH_ACTION_TIMEOUT       "st_action_timeout"
/*! Host in query result is not allowed to run this action */
#  define F_STONITH_ACTION_DISALLOWED     "st_action_disallowed"
/*! Maximum of random fencing delay for a device */
#  define F_STONITH_DELAY_MAX            "st_delay_max"
/*! Base delay used for a fencing delay */
#  define F_STONITH_DELAY_BASE           "st_delay_base"
/*! Has this device been verified using a monitor type
 *  operation (monitor, list, status) */
#  define F_STONITH_DEVICE_VERIFIED   "st_monitor_verified"
/*! device is required for this action */
#  define F_STONITH_DEVICE_REQUIRED   "st_required"
/*! number of available devices in query result */
#  define F_STONITH_AVAILABLE_DEVICES "st-available-devices"
#  define F_STONITH_CALLBACK_TOKEN    "st_async_id"
#  define F_STONITH_CLIENTNAME        "st_clientname"
#  define F_STONITH_CLIENTNODE        "st_clientnode"
#  define F_STONITH_NOTIFY_TYPE       "st_notify_type"
#  define F_STONITH_NOTIFY_ACTIVATE   "st_notify_activate"
#  define F_STONITH_NOTIFY_DEACTIVATE "st_notify_deactivate"
#  define F_STONITH_DELEGATE      "st_delegate"
/*! The node initiating the stonith operation.  If an operation
 * is relayed, this is the last node the operation lands on. When
 * in standalone mode, origin is the client's id that originated the
 * operation. */
#  define F_STONITH_ORIGIN        "st_origin"
#  define F_STONITH_HISTORY_LIST  "st_history"
#  define F_STONITH_DATE          "st_date"
#  define F_STONITH_STATE         "st_state"
#  define F_STONITH_ACTIVE        "st_active"

#  define F_STONITH_DEVICE        "st_device_id"
#  define F_STONITH_ACTION        "st_device_action"
#  define F_STONITH_MODE          "st_mode"

#  define T_STONITH_NG        "stonith-ng"
#  define T_STONITH_REPLY     "st-reply"
/*! For async operations, an event from the server containing
 * the total amount of time the server is allowing for the operation
 * to take place is returned to the client. */
#  define T_STONITH_TIMEOUT_VALUE "st-async-timeout-value"
#  define T_STONITH_NOTIFY    "st_notify"

#  define STONITH_ATTR_ARGMAP    "pcmk_arg_map"
#  define STONITH_ATTR_HOSTARG   "pcmk_host_argument"
#  define STONITH_ATTR_HOSTMAP   "pcmk_host_map"
#  define STONITH_ATTR_HOSTLIST  "pcmk_host_list"
#  define STONITH_ATTR_HOSTCHECK "pcmk_host_check"
#  define STONITH_ATTR_DELAY_MAX "pcmk_delay_max"
#  define STONITH_ATTR_DELAY_BASE   "pcmk_delay_base"
#  define STONITH_ATTR_ACTION_LIMIT "pcmk_action_limit"

#  define STONITH_ATTR_ACTION_OP   "action"

#  define STONITH_OP_EXEC        "st_execute"
#  define STONITH_OP_TIMEOUT_UPDATE        "st_timeout_update"
#  define STONITH_OP_QUERY       "st_query"
#  define STONITH_OP_FENCE       "st_fence"
#  define STONITH_OP_RELAY       "st_relay"
#  define STONITH_OP_CONFIRM     "st_confirm"
#  define STONITH_OP_DEVICE_ADD      "st_device_register"
#  define STONITH_OP_DEVICE_DEL      "st_device_remove"
#  define STONITH_OP_DEVICE_METADATA "st_device_metadata"
#  define STONITH_OP_FENCE_HISTORY   "st_fence_history"
#  define STONITH_OP_LEVEL_ADD       "st_level_add"
#  define STONITH_OP_LEVEL_DEL       "st_level_remove"

#  define stonith_channel            "st_command"
#  define stonith_channel_callback   "st_callback"

#  define STONITH_WATCHDOG_AGENT  "#watchdog"

#endif
