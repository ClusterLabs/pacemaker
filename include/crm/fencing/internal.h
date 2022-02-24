/*
 * Copyright 2011-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef STONITH_NG_INTERNAL__H
#  define STONITH_NG_INTERNAL__H

#  include <glib.h>
#  include <crm/common/ipc.h>
#  include <crm/common/xml.h>
#  include <crm/common/output_internal.h>
#  include <crm/stonith-ng.h>

enum st_device_flags
{
    st_device_supports_list   = 0x0001,
    st_device_supports_status = 0x0002,
    st_device_supports_reboot = 0x0004,
    st_device_supports_parameter_plug = 0x0008,
    st_device_supports_parameter_port = 0x0010,
};

#define stonith__set_device_flags(device_flags, device_id, flags_to_set) do { \
        device_flags = pcmk__set_flags_as(__func__, __LINE__, LOG_TRACE,      \
                                          "Fence device", device_id,          \
                                          (device_flags), (flags_to_set),     \
                                          #flags_to_set);                     \
    } while (0)

#define stonith__set_call_options(st_call_opts, call_for, flags_to_set) do { \
        st_call_opts = pcmk__set_flags_as(__func__, __LINE__, LOG_TRACE,     \
                                          "Fencer call", (call_for),         \
                                          (st_call_opts), (flags_to_set),    \
                                          #flags_to_set);                    \
    } while (0)

#define stonith__clear_call_options(st_call_opts, call_for, flags_to_clear) do { \
        st_call_opts = pcmk__clear_flags_as(__func__, __LINE__, LOG_TRACE,     \
                                            "Fencer call", (call_for),         \
                                            (st_call_opts), (flags_to_clear),  \
                                            #flags_to_clear);                  \
    } while (0)

struct stonith_action_s;
typedef struct stonith_action_s stonith_action_t;

stonith_action_t *stonith_action_create(const char *agent,
                                        const char *_action,
                                        const char *victim,
                                        uint32_t victim_nodeid,
                                        int timeout,
                                        GHashTable * device_args,
                                        GHashTable * port_map,
                                        const char * host_arg);
void stonith__destroy_action(stonith_action_t *action);
pcmk__action_result_t *stonith__action_result(stonith_action_t *action);
int stonith__result2rc(const pcmk__action_result_t *result);
void stonith__xe_set_result(xmlNode *xml, const pcmk__action_result_t *result);
void stonith__xe_get_result(xmlNode *xml, pcmk__action_result_t *result);
xmlNode *stonith__find_xe_with_result(xmlNode *xml);

int
stonith_action_execute_async(stonith_action_t * action,
                             void *userdata,
                             void (*done) (int pid,
                                           const pcmk__action_result_t *result,
                                           void *user_data),
                             void (*fork_cb) (int pid, void *user_data));

xmlNode *create_level_registration_xml(const char *node, const char *pattern,
                                       const char *attr, const char *value,
                                       int level,
                                       stonith_key_value_t *device_list);

xmlNode *create_device_registration_xml(const char *id,
                                        enum stonith_namespace namespace,
                                        const char *agent,
                                        stonith_key_value_t *params,
                                        const char *rsc_provides);

void stonith__register_messages(pcmk__output_t *out);

GList *stonith__parse_targets(const char *hosts);

const char *stonith__later_succeeded(stonith_history_t *event,
                                     stonith_history_t *top_history);
stonith_history_t *stonith__sort_history(stonith_history_t *history);

void stonith__device_parameter_flags(uint32_t *device_flags,
                                     const char *device_name,
                                     xmlNode *metadata);

#  define ST_LEVEL_MAX 10

#  define F_STONITH_CLIENTID      "st_clientid"
#  define F_STONITH_CALLOPTS      "st_callopt"
#  define F_STONITH_CALLID        "st_callid"
#  define F_STONITH_CALLDATA      "st_calldata"
#  define F_STONITH_OPERATION     "st_op"
#  define F_STONITH_TARGET        "st_target"
#  define F_STONITH_REMOTE_OP_ID  "st_remote_op"
#  define F_STONITH_REMOTE_OP_ID_RELAY  "st_remote_op_relay"
#  define F_STONITH_RC            "st_rc"
#  define F_STONITH_OUTPUT        "st_output"
/*! Timeout period per a device execution */
#  define F_STONITH_TIMEOUT       "st_timeout"
#  define F_STONITH_TOLERANCE     "st_tolerance"
#  define F_STONITH_DELAY         "st_delay"
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
#  define F_STONITH_DATE_NSEC     "st_date_nsec"
#  define F_STONITH_STATE         "st_state"
#  define F_STONITH_ACTIVE        "st_active"
#  define F_STONITH_DIFFERENTIAL  "st_differential"

#  define F_STONITH_DEVICE        "st_device_id"
#  define F_STONITH_ACTION        "st_device_action"
#  define F_STONITH_MERGED        "st_op_merged"

#  define T_STONITH_NG        "stonith-ng"
#  define T_STONITH_REPLY     "st-reply"
/*! For async operations, an event from the server containing
 * the total amount of time the server is allowing for the operation
 * to take place is returned to the client. */
#  define T_STONITH_TIMEOUT_VALUE "st-async-timeout-value"
#  define T_STONITH_NOTIFY    "st_notify"

#  define STONITH_ATTR_ACTION_OP   "action"

#  define STONITH_OP_EXEC        "st_execute"
#  define STONITH_OP_TIMEOUT_UPDATE        "st_timeout_update"
#  define STONITH_OP_QUERY       "st_query"
#  define STONITH_OP_FENCE       "st_fence"
#  define STONITH_OP_RELAY       "st_relay"
#  define STONITH_OP_DEVICE_ADD      "st_device_register"
#  define STONITH_OP_DEVICE_DEL      "st_device_remove"
#  define STONITH_OP_FENCE_HISTORY   "st_fence_history"
#  define STONITH_OP_LEVEL_ADD       "st_level_add"
#  define STONITH_OP_LEVEL_DEL       "st_level_remove"

#  define STONITH_WATCHDOG_AGENT          "fence_watchdog"
/* Don't change 2 below as it would break rolling upgrade */
#  define STONITH_WATCHDOG_AGENT_INTERNAL "#watchdog"
#  define STONITH_WATCHDOG_ID             "watchdog"

/* Exported for crm_mon to reference */
int stonith__failed_history(pcmk__output_t *out, va_list args);
int stonith__history(pcmk__output_t *out, va_list args);
int stonith__full_history(pcmk__output_t *out, va_list args);
int stonith__pending_actions(pcmk__output_t *out, va_list args);

stonith_history_t *stonith__first_matching_event(stonith_history_t *history,
                                                 bool (*matching_fn)(stonith_history_t *, void *),
                                                 void *user_data);
bool stonith__event_state_pending(stonith_history_t *history, void *user_data);
bool stonith__event_state_eq(stonith_history_t *history, void *user_data);
bool stonith__event_state_neq(stonith_history_t *history, void *user_data);

int stonith__legacy2status(int rc);

int stonith__exit_status(stonith_callback_data_t *data);
int stonith__execution_status(stonith_callback_data_t *data);
const char *stonith__exit_reason(stonith_callback_data_t *data);

int stonith__event_exit_status(stonith_event_t *event);
int stonith__event_execution_status(stonith_event_t *event);
const char *stonith__event_exit_reason(stonith_event_t *event);
char *stonith__event_description(stonith_event_t *event);
gchar *stonith__history_description(stonith_history_t *event, bool full_history,
                                    const char *later_succeeded);

/*!
 * \internal
 * \brief Is a fencing operation in pending state?
 *
 * \param[in] state     State as enum op_state value
 *
 * \return A boolean
 */
static inline bool
stonith__op_state_pending(enum op_state state)
{
    return state != st_failed && state != st_done;
}

gboolean stonith__watchdog_fencing_enabled_for_node(const char *node);
gboolean stonith__watchdog_fencing_enabled_for_node_api(stonith_t *st, const char *node);

#endif
