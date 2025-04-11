/*
 * Copyright 2011-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_FENCING_INTERNAL__H
#define PCMK__CRM_FENCING_INTERNAL__H

#include <glib.h>
#include <crm/common/ipc.h>
#include <crm/common/xml.h>
#include <crm/common/output_internal.h>
#include <crm/common/results_internal.h>
#include <crm/stonith-ng.h>

#ifdef __cplusplus
extern "C" {
#endif

stonith_t *stonith__api_new(void);
void stonith__api_free(stonith_t *stonith_api);

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

stonith_action_t *stonith__action_create(const char *agent,
                                         const char *action_name,
                                         const char *target,
                                         int timeout_sec,
                                         GHashTable *device_args,
                                         GHashTable *port_map,
                                         const char *host_arg);
void stonith__destroy_action(stonith_action_t *action);
pcmk__action_result_t *stonith__action_result(stonith_action_t *action);
int stonith__result2rc(const pcmk__action_result_t *result);
void stonith__xe_set_result(xmlNode *xml, const pcmk__action_result_t *result);
void stonith__xe_get_result(const xmlNode *xml, pcmk__action_result_t *result);
xmlNode *stonith__find_xe_with_result(xmlNode *xml);

int stonith__execute_async(stonith_action_t *action, void *userdata,
                           void (*done) (int pid,
                                         const pcmk__action_result_t *result,
                                         void *user_data),
                           void (*fork_cb) (int pid, void *user_data));

int stonith__metadata_async(const char *agent, int timeout_sec,
                            void (*callback)(int pid,
                                             const pcmk__action_result_t *result,
                                             void *user_data),
                            void *user_data);

xmlNode *create_level_registration_xml(const char *node, const char *pattern,
                                       const char *attr, const char *value,
                                       int level,
                                       const stonith_key_value_t *device_list);

xmlNode *create_device_registration_xml(const char *id,
                                        enum stonith_namespace standard,
                                        const char *agent,
                                        const stonith_key_value_t *params,
                                        const char *rsc_provides);

void stonith__register_messages(pcmk__output_t *out);

GList *stonith__parse_targets(const char *hosts);

const char *stonith__later_succeeded(const stonith_history_t *event,
                                     const stonith_history_t *top_history);
stonith_history_t *stonith__sort_history(stonith_history_t *history);

const char *stonith__default_host_arg(xmlNode *metadata);

/* Only 1-9 is allowed for fencing topology levels,
 * however, 0 is used to unregister all levels in
 * unregister requests.
 */
#  define ST__LEVEL_COUNT 10

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
#  define STONITH_OP_NOTIFY          "st_notify"
#  define STONITH_OP_POKE            "poke"


#  define STONITH_WATCHDOG_AGENT          "fence_watchdog"
/* Don't change 2 below as it would break rolling upgrade */
#  define STONITH_WATCHDOG_AGENT_INTERNAL "#watchdog"
#  define STONITH_WATCHDOG_ID             "watchdog"

stonith_history_t *stonith__first_matching_event(stonith_history_t *history,
                                                 bool (*matching_fn)(stonith_history_t *, void *),
                                                 void *user_data);
bool stonith__event_state_pending(stonith_history_t *history, void *user_data);
bool stonith__event_state_eq(stonith_history_t *history, void *user_data);
bool stonith__event_state_neq(stonith_history_t *history, void *user_data);

int stonith__legacy2status(int rc);

int stonith__exit_status(const stonith_callback_data_t *data);
int stonith__execution_status(const stonith_callback_data_t *data);
const char *stonith__exit_reason(const stonith_callback_data_t *data);

int stonith__event_exit_status(const stonith_event_t *event);
int stonith__event_execution_status(const stonith_event_t *event);
const char *stonith__event_exit_reason(const stonith_event_t *event);
char *stonith__event_description(const stonith_event_t *event);
gchar *stonith__history_description(const stonith_history_t *event,
                                    bool full_history,
                                    const char *later_succeeded,
                                    uint32_t show_opts);

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

/*!
 * \internal
 * \brief Validate a fencing configuration
 *
 * \param[in,out] st            Fencer connection to use
 * \param[in]     call_options  Group of enum stonith_call_options
 * \param[in]     rsc_id        Resource to validate
 * \param[in]     namespace_s   Type of fence agent to search for
 * \param[in]     agent         Fence agent to validate
 * \param[in,out] params        Fence device configuration parameters
 * \param[in]     timeout_sec   How long to wait for operation to complete
 * \param[in,out] output        If non-NULL, where to store any agent output
 * \param[in,out] error_output  If non-NULL, where to store agent error output
 *
 * \return Standard Pacemaker return code
 */
int stonith__validate(stonith_t *st, int call_options, const char *rsc_id,
                      const char *namespace_s, const char *agent,
                      GHashTable *params, int timeout_sec, char **output,
                      char **error_output);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_FENCING_INTERNAL__H
