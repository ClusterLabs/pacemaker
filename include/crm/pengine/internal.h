/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PE_INTERNAL__H
#  define PE_INTERNAL__H

#  include <stdbool.h>
#  include <stdint.h>
#  include <string.h>
#  include <crm/msg_xml.h>
#  include <crm/pengine/status.h>
#  include <crm/pengine/remote_internal.h>
#  include <crm/common/internal.h>
#  include <crm/common/options_internal.h>
#  include <crm/common/output_internal.h>
#  include <crm/common/scheduler_internal.h>

const char *pe__resource_description(const pcmk_resource_t *rsc,
                                     uint32_t show_opts);

bool pe__clone_is_ordered(const pcmk_resource_t *clone);
int pe__set_clone_flag(pcmk_resource_t *clone, enum pcmk__clone_flags flag);
bool pe__clone_flag_is_set(const pcmk_resource_t *clone, uint32_t flags);

bool pe__group_flag_is_set(const pcmk_resource_t *group, uint32_t flags);
pcmk_resource_t *pe__last_group_member(const pcmk_resource_t *group);

#define pe__set_resource_flags(resource, flags_to_set) do {                 \
        (resource)->flags = pcmk__set_flags_as(__func__, __LINE__,          \
            LOG_TRACE, "Resource", (resource)->id, (resource)->flags,       \
            (flags_to_set), #flags_to_set);                                 \
    } while (0)

#define pe__clear_resource_flags(resource, flags_to_clear) do {             \
        (resource)->flags = pcmk__clear_flags_as(__func__, __LINE__,        \
            LOG_TRACE, "Resource", (resource)->id, (resource)->flags,       \
            (flags_to_clear), #flags_to_clear);                             \
    } while (0)

#define pe__set_action_flags(action, flags_to_set) do {                     \
        (action)->flags = pcmk__set_flags_as(__func__, __LINE__,            \
                                             LOG_TRACE,                     \
                                             "Action", (action)->uuid,      \
                                             (action)->flags,               \
                                             (flags_to_set),                \
                                             #flags_to_set);                \
    } while (0)

#define pe__clear_action_flags(action, flags_to_clear) do {                 \
        (action)->flags = pcmk__clear_flags_as(__func__, __LINE__,          \
                                               LOG_TRACE,                   \
                                               "Action", (action)->uuid,    \
                                               (action)->flags,             \
                                               (flags_to_clear),            \
                                               #flags_to_clear);            \
    } while (0)

#define pe__set_raw_action_flags(action_flags, action_name, flags_to_set) do { \
        action_flags = pcmk__set_flags_as(__func__, __LINE__,               \
                                          LOG_TRACE, "Action", action_name, \
                                          (action_flags),                   \
                                          (flags_to_set), #flags_to_set);   \
    } while (0)

#define pe__clear_raw_action_flags(action_flags, action_name, flags_to_clear) do { \
        action_flags = pcmk__clear_flags_as(__func__, __LINE__,             \
                                            LOG_TRACE,                      \
                                            "Action", action_name,          \
                                            (action_flags),                 \
                                            (flags_to_clear),               \
                                            #flags_to_clear);               \
    } while (0)

#define pe__set_action_flags_as(function, line, action, flags_to_set) do {  \
        (action)->flags = pcmk__set_flags_as((function), (line),            \
                                             LOG_TRACE,                     \
                                             "Action", (action)->uuid,      \
                                             (action)->flags,               \
                                             (flags_to_set),                \
                                             #flags_to_set);                \
    } while (0)

#define pe__clear_action_flags_as(function, line, action, flags_to_clear) do { \
        (action)->flags = pcmk__clear_flags_as((function), (line),          \
                                               LOG_TRACE,                   \
                                               "Action", (action)->uuid,    \
                                               (action)->flags,             \
                                               (flags_to_clear),            \
                                               #flags_to_clear);            \
    } while (0)

#define pe__set_order_flags(order_flags, flags_to_set) do {                 \
        order_flags = pcmk__set_flags_as(__func__, __LINE__, LOG_TRACE,     \
                                         "Ordering", "constraint",          \
                                         order_flags, (flags_to_set),       \
                                         #flags_to_set);                    \
    } while (0)

#define pe__clear_order_flags(order_flags, flags_to_clear) do {               \
        order_flags = pcmk__clear_flags_as(__func__, __LINE__, LOG_TRACE,     \
                                           "Ordering", "constraint",          \
                                           order_flags, (flags_to_clear),     \
                                           #flags_to_clear);                  \
    } while (0)

const pcmk_resource_t *pe__const_top_resource(const pcmk_resource_t *rsc,
                                              bool include_bundle);

int pe__clone_max(const pcmk_resource_t *clone);
int pe__clone_node_max(const pcmk_resource_t *clone);
int pe__clone_promoted_max(const pcmk_resource_t *clone);
int pe__clone_promoted_node_max(const pcmk_resource_t *clone);
void pe__create_clone_notifications(pcmk_resource_t *clone);
void pe__free_clone_notification_data(pcmk_resource_t *clone);
void pe__create_clone_notif_pseudo_ops(pcmk_resource_t *clone,
                                       pcmk_action_t *start,
                                       pcmk_action_t *started,
                                       pcmk_action_t *stop,
                                       pcmk_action_t *stopped);

pcmk_action_t *pe__new_rsc_pseudo_action(pcmk_resource_t *rsc, const char *task,
                                         bool optional, bool runnable);

void pe__create_promotable_pseudo_ops(pcmk_resource_t *clone,
                                      bool any_promoting, bool any_demoting);

bool pe_can_fence(const pcmk_scheduler_t *scheduler, const pcmk_node_t *node);

void add_hash_param(GHashTable * hash, const char *name, const char *value);

char *native_parameter(pcmk_resource_t *rsc, pcmk_node_t *node, gboolean create,
                       const char *name, pcmk_scheduler_t *scheduler);
pcmk_node_t *native_location(const pcmk_resource_t *rsc, GList **list,
                             int current);

void pe_metadata(pcmk__output_t *out);
void verify_pe_options(GHashTable * options);

void native_add_running(pcmk_resource_t *rsc, pcmk_node_t *node,
                        pcmk_scheduler_t *scheduler, gboolean failed);

gboolean native_unpack(pcmk_resource_t *rsc, pcmk_scheduler_t *scheduler);
gboolean group_unpack(pcmk_resource_t *rsc, pcmk_scheduler_t *scheduler);
gboolean clone_unpack(pcmk_resource_t *rsc, pcmk_scheduler_t *scheduler);
gboolean pe__unpack_bundle(pcmk_resource_t *rsc, pcmk_scheduler_t *scheduler);

pcmk_resource_t *native_find_rsc(pcmk_resource_t *rsc, const char *id,
                                 const pcmk_node_t *node, int flags);

gboolean native_active(pcmk_resource_t *rsc, gboolean all);
gboolean group_active(pcmk_resource_t *rsc, gboolean all);
gboolean clone_active(pcmk_resource_t *rsc, gboolean all);
gboolean pe__bundle_active(pcmk_resource_t *rsc, gboolean all);

//! \deprecated This function will be removed in a future release
void native_print(pcmk_resource_t *rsc, const char *pre_text, long options,
                  void *print_data);

//! \deprecated This function will be removed in a future release
void group_print(pcmk_resource_t *rsc, const char *pre_text, long options,
                 void *print_data);

//! \deprecated This function will be removed in a future release
void clone_print(pcmk_resource_t *rsc, const char *pre_text, long options,
                 void *print_data);

//! \deprecated This function will be removed in a future release
void pe__print_bundle(pcmk_resource_t *rsc, const char *pre_text, long options,
                      void *print_data);

gchar *pcmk__native_output_string(const pcmk_resource_t *rsc, const char *name,
                                  const pcmk_node_t *node, uint32_t show_opts,
                                  const char *target_role, bool show_nodes);

int pe__name_and_nvpairs_xml(pcmk__output_t *out, bool is_list, const char *tag_name
                         , size_t pairs_count, ...);
char *pe__node_display_name(pcmk_node_t *node, bool print_detail);


// Clone notifications (pe_notif.c)
void pe__order_notifs_after_fencing(const pcmk_action_t *action,
                                    pcmk_resource_t *rsc,
                                    pcmk_action_t *stonith_op);


static inline const char *
pe__rsc_bool_str(const pcmk_resource_t *rsc, uint64_t rsc_flag)
{
    return pcmk__btoa(pcmk_is_set(rsc->flags, rsc_flag));
}

int pe__clone_xml(pcmk__output_t *out, va_list args);
int pe__clone_default(pcmk__output_t *out, va_list args);
int pe__group_xml(pcmk__output_t *out, va_list args);
int pe__group_default(pcmk__output_t *out, va_list args);
int pe__bundle_xml(pcmk__output_t *out, va_list args);
int pe__bundle_html(pcmk__output_t *out, va_list args);
int pe__bundle_text(pcmk__output_t *out, va_list args);
int pe__node_html(pcmk__output_t *out, va_list args);
int pe__node_text(pcmk__output_t *out, va_list args);
int pe__node_xml(pcmk__output_t *out, va_list args);
int pe__resource_xml(pcmk__output_t *out, va_list args);
int pe__resource_html(pcmk__output_t *out, va_list args);
int pe__resource_text(pcmk__output_t *out, va_list args);

void native_free(pcmk_resource_t *rsc);
void group_free(pcmk_resource_t *rsc);
void clone_free(pcmk_resource_t *rsc);
void pe__free_bundle(pcmk_resource_t *rsc);

enum rsc_role_e native_resource_state(const pcmk_resource_t *rsc,
                                      gboolean current);
enum rsc_role_e group_resource_state(const pcmk_resource_t *rsc,
                                     gboolean current);
enum rsc_role_e clone_resource_state(const pcmk_resource_t *rsc,
                                     gboolean current);
enum rsc_role_e pe__bundle_resource_state(const pcmk_resource_t *rsc,
                                          gboolean current);

void pe__count_common(pcmk_resource_t *rsc);
void pe__count_bundle(pcmk_resource_t *rsc);

void common_free(pcmk_resource_t *rsc);

pcmk_node_t *pe__copy_node(const pcmk_node_t *this_node);
time_t get_effective_time(pcmk_scheduler_t *scheduler);

/* Failure handling utilities (from failcounts.c) */

int pe_get_failcount(const pcmk_node_t *node, pcmk_resource_t *rsc,
                     time_t *last_failure, uint32_t flags,
                     const xmlNode *xml_op);

pcmk_action_t *pe__clear_failcount(pcmk_resource_t *rsc,
                                   const pcmk_node_t *node, const char *reason,
                                   pcmk_scheduler_t *scheduler);

/* Functions for finding/counting a resource's active nodes */

bool pe__count_active_node(const pcmk_resource_t *rsc, pcmk_node_t *node,
                           pcmk_node_t **active, unsigned int *count_all,
                           unsigned int *count_clean);

pcmk_node_t *pe__find_active_requires(const pcmk_resource_t *rsc,
                                    unsigned int *count);

static inline pcmk_node_t *
pe__current_node(const pcmk_resource_t *rsc)
{
    return (rsc == NULL)? NULL : rsc->fns->active_node(rsc, NULL, NULL);
}


/* Binary like operators for lists of nodes */
GHashTable *pe__node_list2table(const GList *list);

pcmk_action_t *get_pseudo_op(const char *name, pcmk_scheduler_t *scheduler);
gboolean order_actions(pcmk_action_t *lh_action, pcmk_action_t *rh_action,
                       uint32_t flags);

void pe__show_node_scores_as(const char *file, const char *function,
                             int line, bool to_log, const pcmk_resource_t *rsc,
                             const char *comment, GHashTable *nodes,
                             pcmk_scheduler_t *scheduler);

#define pe__show_node_scores(level, rsc, text, nodes, scheduler)    \
        pe__show_node_scores_as(__FILE__, __func__, __LINE__,      \
                                (level), (rsc), (text), (nodes), (scheduler))

GHashTable *pcmk__unpack_action_meta(pcmk_resource_t *rsc,
                                     const pcmk_node_t *node,
                                     const char *action_name, guint interval_ms,
                                     const xmlNode *action_config);
GHashTable *pcmk__unpack_action_rsc_params(const xmlNode *action_xml,
                                           GHashTable *node_attrs,
                                           pcmk_scheduler_t *data_set);
xmlNode *pcmk__find_action_config(const pcmk_resource_t *rsc,
                                  const char *action_name, guint interval_ms,
                                  bool include_disabled);

enum rsc_start_requirement pcmk__action_requires(const pcmk_resource_t *rsc,
                                                 const char *action_name);

enum action_fail_response pcmk__parse_on_fail(const pcmk_resource_t *rsc,
                                              const char *action_name,
                                              guint interval_ms,
                                              const char *value);

enum rsc_role_e pcmk__role_after_failure(const pcmk_resource_t *rsc,
                                         const char *action_name,
                                         enum action_fail_response on_fail,
                                         GHashTable *meta);

pcmk_action_t *custom_action(pcmk_resource_t *rsc, char *key, const char *task,
                             const pcmk_node_t *on_node, gboolean optional,
                             pcmk_scheduler_t *scheduler);

#  define delete_key(rsc) pcmk__op_key(rsc->id, PCMK_ACTION_DELETE, 0)
#  define delete_action(rsc, node, optional) custom_action(		\
		rsc, delete_key(rsc), PCMK_ACTION_DELETE, node, \
		optional, rsc->cluster);

#  define stop_key(rsc) pcmk__op_key(rsc->id, PCMK_ACTION_STOP, 0)
#  define stop_action(rsc, node, optional) custom_action(			\
		rsc, stop_key(rsc), PCMK_ACTION_STOP, node,		\
		optional, rsc->cluster);

#  define reload_key(rsc) pcmk__op_key(rsc->id, PCMK_ACTION_RELOAD_AGENT, 0)
#  define start_key(rsc) pcmk__op_key(rsc->id, PCMK_ACTION_START, 0)
#  define start_action(rsc, node, optional) custom_action(		\
		rsc, start_key(rsc), PCMK_ACTION_START, node,           \
		optional, rsc->cluster)

#  define promote_key(rsc) pcmk__op_key(rsc->id, PCMK_ACTION_PROMOTE, 0)
#  define promote_action(rsc, node, optional) custom_action(		\
		rsc, promote_key(rsc), PCMK_ACTION_PROMOTE, node,	\
		optional, rsc->cluster)

#  define demote_key(rsc) pcmk__op_key(rsc->id, PCMK_ACTION_DEMOTE, 0)
#  define demote_action(rsc, node, optional) custom_action(		\
		rsc, demote_key(rsc), PCMK_ACTION_DEMOTE, node, \
		optional, rsc->cluster)

extern int pe_get_configured_timeout(pcmk_resource_t *rsc, const char *action,
                                     pcmk_scheduler_t *scheduler);

pcmk_action_t *find_first_action(const GList *input, const char *uuid,
                                 const char *task, const pcmk_node_t *on_node);

enum action_tasks get_complex_task(const pcmk_resource_t *rsc,
                                   const char *name);

GList *find_actions(GList *input, const char *key, const pcmk_node_t *on_node);
GList *find_actions_exact(GList *input, const char *key,
                          const pcmk_node_t *on_node);
GList *pe__resource_actions(const pcmk_resource_t *rsc, const pcmk_node_t *node,
                            const char *task, bool require_node);

extern void pe_free_action(pcmk_action_t *action);

void resource_location(pcmk_resource_t *rsc, const pcmk_node_t *node, int score,
                       const char *tag, pcmk_scheduler_t *scheduler);

extern int pe__is_newer_op(const xmlNode *xml_a, const xmlNode *xml_b,
                           bool same_node_default);
extern gint sort_op_by_callid(gconstpointer a, gconstpointer b);
gboolean get_target_role(const pcmk_resource_t *rsc, enum rsc_role_e *role);
void pe__set_next_role(pcmk_resource_t *rsc, enum rsc_role_e role,
                       const char *why);

pcmk_resource_t *find_clone_instance(const pcmk_resource_t *rsc,
                                     const char *sub_id);

extern void destroy_ticket(gpointer data);
pcmk_ticket_t *ticket_new(const char *ticket_id, pcmk_scheduler_t *scheduler);

// Resources for manipulating resource names
const char *pe_base_name_end(const char *id);
char *clone_strip(const char *last_rsc_id);
char *clone_zero(const char *last_rsc_id);

static inline bool
pe_base_name_eq(const pcmk_resource_t *rsc, const char *id)
{
    if (id && rsc && rsc->id) {
        // Number of characters in rsc->id before any clone suffix
        size_t base_len = pe_base_name_end(rsc->id) - rsc->id + 1;

        return (strlen(id) == base_len) && !strncmp(id, rsc->id, base_len);
    }
    return false;
}

int pe__target_rc_from_xml(const xmlNode *xml_op);

gint pe__cmp_node_name(gconstpointer a, gconstpointer b);
bool is_set_recursive(const pcmk_resource_t *rsc, long long flag, bool any);

pcmk__op_digest_t *pe__calculate_digests(pcmk_resource_t *rsc, const char *task,
                                         guint *interval_ms,
                                         const pcmk_node_t *node,
                                         const xmlNode *xml_op,
                                         GHashTable *overrides,
                                         bool calc_secure,
                                         pcmk_scheduler_t *scheduler);

void pe__free_digests(gpointer ptr);

pcmk__op_digest_t *rsc_action_digest_cmp(pcmk_resource_t *rsc,
                                         const xmlNode *xml_op,
                                         pcmk_node_t *node,
                                         pcmk_scheduler_t *scheduler);

pcmk_action_t *pe_fence_op(pcmk_node_t *node, const char *op, bool optional,
                           const char *reason, bool priority_delay,
                           pcmk_scheduler_t *scheduler);
void trigger_unfencing(pcmk_resource_t *rsc, pcmk_node_t *node,
                       const char *reason, pcmk_action_t *dependency,
                       pcmk_scheduler_t *scheduler);

char *pe__action2reason(const pcmk_action_t *action, enum pe_action_flags flag);
void pe_action_set_reason(pcmk_action_t *action, const char *reason,
                          bool overwrite);
void pe__add_action_expected_result(pcmk_action_t *action, int expected_result);

void pe__set_resource_flags_recursive(pcmk_resource_t *rsc, uint64_t flags);
void pe__clear_resource_flags_recursive(pcmk_resource_t *rsc, uint64_t flags);
void pe__clear_resource_flags_on_all(pcmk_scheduler_t *scheduler,
                                     uint64_t flag);

gboolean add_tag_ref(GHashTable * tags, const char * tag_name,  const char * obj_ref);

//! \deprecated This function will be removed in a future release
void print_rscs_brief(GList *rsc_list, const char * pre_text, long options,
                      void * print_data, gboolean print_all);
int pe__rscs_brief_output(pcmk__output_t *out, GList *rsc_list, unsigned int options);
void pe_fence_node(pcmk_scheduler_t *scheduler, pcmk_node_t *node,
                   const char *reason, bool priority_delay);

pcmk_node_t *pe_create_node(const char *id, const char *uname, const char *type,
                            const char *score, pcmk_scheduler_t *scheduler);

//! \deprecated This function will be removed in a future release
void common_print(pcmk_resource_t *rsc, const char *pre_text, const char *name,
                  const pcmk_node_t *node, long options, void *print_data);
int pe__common_output_text(pcmk__output_t *out, const pcmk_resource_t *rsc,
                           const char *name, const pcmk_node_t *node,
                           unsigned int options);
int pe__common_output_html(pcmk__output_t *out, const pcmk_resource_t *rsc,
                           const char *name, const pcmk_node_t *node,
                           unsigned int options);

GList *pe__bundle_containers(const pcmk_resource_t *bundle);

int pe__bundle_max(const pcmk_resource_t *rsc);
bool pe__node_is_bundle_instance(const pcmk_resource_t *bundle,
                                 const pcmk_node_t *node);
pcmk_resource_t *pe__bundled_resource(const pcmk_resource_t *rsc);
const pcmk_resource_t *pe__get_rsc_in_container(const pcmk_resource_t *instance);
pcmk_resource_t *pe__first_container(const pcmk_resource_t *bundle);
void pe__foreach_bundle_replica(pcmk_resource_t *bundle,
                                bool (*fn)(pcmk__bundle_replica_t *, void *),
                                void *user_data);
void pe__foreach_const_bundle_replica(const pcmk_resource_t *bundle,
                                      bool (*fn)(const pcmk__bundle_replica_t *,
                                                 void *),
                                      void *user_data);
pcmk_resource_t *pe__find_bundle_replica(const pcmk_resource_t *bundle,
                                         const pcmk_node_t *node);
bool pe__bundle_needs_remote_name(pcmk_resource_t *rsc);
const char *pe__add_bundle_remote_name(pcmk_resource_t *rsc,
                                       pcmk_scheduler_t *scheduler,
                                       xmlNode *xml, const char *field);

const char *pe__node_attribute_calculated(const pcmk_node_t *node,
                                          const char *name,
                                          const pcmk_resource_t *rsc,
                                          enum pcmk__rsc_node node_type,
                                          bool force_host);
const char *pe_node_attribute_raw(const pcmk_node_t *node, const char *name);
bool pe__is_universal_clone(const pcmk_resource_t *rsc,
                            const pcmk_scheduler_t *scheduler);
void pe__add_param_check(const xmlNode *rsc_op, pcmk_resource_t *rsc,
                         pcmk_node_t *node, enum pcmk__check_parameters,
                         pcmk_scheduler_t *scheduler);
void pe__foreach_param_check(pcmk_scheduler_t *scheduler,
                             void (*cb)(pcmk_resource_t*, pcmk_node_t*,
                                        const xmlNode*,
                                        enum pcmk__check_parameters));
void pe__free_param_checks(pcmk_scheduler_t *scheduler);

bool pe__shutdown_requested(const pcmk_node_t *node);
void pe__update_recheck_time(time_t recheck, pcmk_scheduler_t *scheduler,
                             const char *reason);

/*!
 * \internal
 * \brief Register xml formatting message functions.
 *
 * \param[in,out] out  Output object to register messages with
 */
void pe__register_messages(pcmk__output_t *out);

void pe__unpack_dataset_nvpairs(const xmlNode *xml_obj, const char *set_name,
                                const pe_rule_eval_data_t *rule_data,
                                GHashTable *hash, const char *always_first,
                                gboolean overwrite,
                                pcmk_scheduler_t *scheduler);

bool pe__resource_is_disabled(const pcmk_resource_t *rsc);
void pe__clear_resource_history(pcmk_resource_t *rsc, const pcmk_node_t *node);

GList *pe__rscs_with_tag(pcmk_scheduler_t *scheduler, const char *tag_name);
GList *pe__unames_with_tag(pcmk_scheduler_t *scheduler, const char *tag_name);
bool pe__rsc_has_tag(pcmk_scheduler_t *scheduler, const char *rsc,
                     const char *tag);
bool pe__uname_has_tag(pcmk_scheduler_t *scheduler, const char *node,
                       const char *tag);

bool pe__rsc_running_on_only(const pcmk_resource_t *rsc,
                             const pcmk_node_t *node);
bool pe__rsc_running_on_any(pcmk_resource_t *rsc, GList *node_list);
GList *pe__filter_rsc_list(GList *rscs, GList *filter);
GList * pe__build_node_name_list(pcmk_scheduler_t *scheduler, const char *s);
GList * pe__build_rsc_list(pcmk_scheduler_t *scheduler, const char *s);

bool pcmk__rsc_filtered_by_node(pcmk_resource_t *rsc, GList *only_node);

gboolean pe__bundle_is_filtered(const pcmk_resource_t *rsc, GList *only_rsc,
                                gboolean check_parent);
gboolean pe__clone_is_filtered(const pcmk_resource_t *rsc, GList *only_rsc,
                               gboolean check_parent);
gboolean pe__group_is_filtered(const pcmk_resource_t *rsc, GList *only_rsc,
                               gboolean check_parent);
gboolean pe__native_is_filtered(const pcmk_resource_t *rsc, GList *only_rsc,
                                gboolean check_parent);

xmlNode *pe__failed_probe_for_rsc(const pcmk_resource_t *rsc, const char *name);

const char *pe__clone_child_id(const pcmk_resource_t *rsc);

int pe__sum_node_health_scores(const pcmk_node_t *node, int base_health);
int pe__node_health(pcmk_node_t *node);

static inline enum pcmk__health_strategy
pe__health_strategy(pcmk_scheduler_t *scheduler)
{
    return pcmk__parse_health_strategy(pe_pref(scheduler->config_hash,
                                               PCMK_OPT_NODE_HEALTH_STRATEGY));
}

static inline int
pe__health_score(const char *option, pcmk_scheduler_t *scheduler)
{
    return char2score(pe_pref(scheduler->config_hash, option));
}

/*!
 * \internal
 * \brief Return a string suitable for logging as a node name
 *
 * \param[in] node  Node to return a node name string for
 *
 * \return Node name if available, otherwise node ID if available,
 *         otherwise "unspecified node" if node is NULL or "unidentified node"
 *         if node has neither a name nor ID.
 */
static inline const char *
pe__node_name(const pcmk_node_t *node)
{
    if (node == NULL) {
        return "unspecified node";

    } else if (node->details->uname != NULL) {
        return node->details->uname;

    } else if (node->details->id != NULL) {
        return node->details->id;

    } else {
        return "unidentified node";
    }
}

/*!
 * \internal
 * \brief Check whether two node objects refer to the same node
 *
 * \param[in] node1  First node object to compare
 * \param[in] node2  Second node object to compare
 *
 * \return true if \p node1 and \p node2 refer to the same node
 */
static inline bool
pe__same_node(const pcmk_node_t *node1, const pcmk_node_t *node2)
{
    return (node1 != NULL) && (node2 != NULL)
           && (node1->details == node2->details);
}

/*!
 * \internal
 * \brief Get the operation key from an action history entry
 *
 * \param[in] xml  Action history entry
 *
 * \return Entry's operation key
 */
static inline const char *
pe__xe_history_key(const xmlNode *xml)
{
    if (xml == NULL) {
        return NULL;
    } else {
        /* @COMPAT Pacemaker <= 1.1.5 did not add the key, and used the ID
         * instead. Checking for that allows us to process old saved CIBs,
         * including some regression tests.
         */
        const char *key = crm_element_value(xml, XML_LRM_ATTR_TASK_KEY);

        return pcmk__str_empty(key)? ID(xml) : key;
    }
}

#endif
