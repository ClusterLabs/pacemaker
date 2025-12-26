/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_PENGINE_INTERNAL__H
#define PCMK__CRM_PENGINE_INTERNAL__H

#include <stdbool.h>
#include <stdint.h>                         // uint32_t
#include <string.h>
#include <crm/common/xml.h>
#include <crm/pengine/status.h>
#include <crm/pengine/remote_internal.h>
#include <crm/common/internal.h>

#ifdef __cplusplus
extern "C" {
#endif

const char *pe__resource_description(const pcmk_resource_t *rsc,
                                     uint32_t show_opts);

bool pe__clone_is_ordered(const pcmk_resource_t *clone);
int pe__set_clone_flag(pcmk_resource_t *clone, enum pcmk__clone_flags flag);
bool pe__clone_flag_is_set(const pcmk_resource_t *clone, uint32_t flags);

bool pe__group_flag_is_set(const pcmk_resource_t *group, uint32_t flags);
pcmk_resource_t *pe__last_group_member(const pcmk_resource_t *group);

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

pcmk_node_t *native_location(const pcmk_resource_t *rsc, GList **list,
                             uint32_t target);
void native_add_running(pcmk_resource_t *rsc, pcmk_node_t *node,
                        pcmk_scheduler_t *scheduler, gboolean failed);

bool native_unpack(pcmk_resource_t *rsc);
bool group_unpack(pcmk_resource_t *rsc);
bool clone_unpack(pcmk_resource_t *rsc);
bool pe__unpack_bundle(pcmk_resource_t *rsc);

pcmk_resource_t *native_find_rsc(pcmk_resource_t *rsc, const char *id,
                                 const pcmk_node_t *node, uint32_t flags);

bool native_active(const pcmk_resource_t *rsc, bool all);
bool group_active(const pcmk_resource_t *rsc, bool all);
bool clone_active(const pcmk_resource_t *rsc, bool all);
bool pe__bundle_active(const pcmk_resource_t *rsc, bool all);

gchar *pcmk__native_output_string(const pcmk_resource_t *rsc, const char *name,
                                  const pcmk_node_t *node, uint32_t show_opts,
                                  const char *target_role, bool show_nodes);

int pe__name_and_nvpairs_xml(pcmk__output_t *out, bool is_list, const char *tag_name,
                             ...) G_GNUC_NULL_TERMINATED;
char *pe__node_display_name(pcmk_node_t *node, bool print_detail);


// Clone notifications (pe_notif.c)
void pe__order_notifs_after_fencing(const pcmk_action_t *action,
                                    pcmk_resource_t *rsc,
                                    pcmk_action_t *stonith_op);


// Resource output methods
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

enum rsc_role_e native_resource_state(const pcmk_resource_t *rsc, bool current);
enum rsc_role_e group_resource_state(const pcmk_resource_t *rsc, bool current);
enum rsc_role_e clone_resource_state(const pcmk_resource_t *rsc, bool current);
enum rsc_role_e pe__bundle_resource_state(const pcmk_resource_t *rsc,
                                          bool current);

void pe__count_common(pcmk_resource_t *rsc);
void pe__count_bundle(pcmk_resource_t *rsc);

void common_free(pcmk_resource_t *rsc);

pcmk_node_t *pe__copy_node(const pcmk_node_t *this_node);

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

/* Binary like operators for lists of nodes */
GHashTable *pe__node_list2table(const GList *list);

pcmk_action_t *get_pseudo_op(const char *name, pcmk_scheduler_t *scheduler);
gboolean order_actions(pcmk_action_t *first, pcmk_action_t *then,
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

enum pcmk__requires pcmk__action_requires(const pcmk_resource_t *rsc,
                                          const char *action_name);

enum pcmk__on_fail pcmk__parse_on_fail(const pcmk_resource_t *rsc,
                                       const char *action_name,
                                       guint interval_ms, const char *value);

enum rsc_role_e pcmk__role_after_failure(const pcmk_resource_t *rsc,
                                         const char *action_name,
                                         enum pcmk__on_fail on_fail,
                                         GHashTable *meta);

pcmk_action_t *custom_action(pcmk_resource_t *rsc, char *key, const char *task,
                             const pcmk_node_t *on_node, gboolean optional,
                             pcmk_scheduler_t *scheduler);

#define delete_key(rsc)  pcmk__op_key((rsc)->id, PCMK_ACTION_DELETE, 0)
#define stop_key(rsc)    pcmk__op_key((rsc)->id, PCMK_ACTION_STOP, 0)
#define reload_key(rsc)  pcmk__op_key((rsc)->id, PCMK_ACTION_RELOAD_AGENT, 0)
#define start_key(rsc)   pcmk__op_key((rsc)->id, PCMK_ACTION_START, 0)
#define promote_key(rsc) pcmk__op_key((rsc)->id, PCMK_ACTION_PROMOTE, 0)
#define demote_key(rsc)  pcmk__op_key((rsc)->id, PCMK_ACTION_DEMOTE, 0)

#define delete_action(rsc, node, optional)                          \
    custom_action((rsc), delete_key(rsc), PCMK_ACTION_DELETE,       \
                  (node), (optional), (rsc)->priv->scheduler)

#define stop_action(rsc, node, optional)                            \
    custom_action((rsc), stop_key(rsc), PCMK_ACTION_STOP,           \
                  (node), (optional), (rsc)->priv->scheduler)

#define start_action(rsc, node, optional)                           \
    custom_action((rsc), start_key(rsc), PCMK_ACTION_START,         \
                  (node), (optional), (rsc)->priv->scheduler)

#define promote_action(rsc, node, optional)                         \
    custom_action((rsc), promote_key(rsc), PCMK_ACTION_PROMOTE,     \
                  (node), (optional), (rsc)->priv->scheduler)

#define demote_action(rsc, node, optional)                          \
    custom_action((rsc), demote_key(rsc), PCMK_ACTION_DEMOTE,       \
                  (node), (optional), (rsc)->priv->scheduler)

pcmk_action_t *find_first_action(const GList *input, const char *uuid,
                                 const char *task, const pcmk_node_t *on_node);

enum pcmk__action_type get_complex_task(const pcmk_resource_t *rsc,
                                        const char *name);

GList *find_actions(GList *input, const char *key, const pcmk_node_t *on_node);
GList *find_actions_exact(GList *input, const char *key,
                          const pcmk_node_t *on_node);
GList *pe__resource_actions(const pcmk_resource_t *rsc, const pcmk_node_t *node,
                            const char *task, bool require_node);

void resource_location(pcmk_resource_t *rsc, const pcmk_node_t *node, int score,
                       const char *tag, pcmk_scheduler_t *scheduler);

int pe__is_newer_op(const xmlNode *xml_a, const xmlNode *xml_b);
extern gint sort_op_by_callid(gconstpointer a, gconstpointer b);
gboolean get_target_role(const pcmk_resource_t *rsc, enum rsc_role_e *role);
void pe__set_next_role(pcmk_resource_t *rsc, enum rsc_role_e role,
                       const char *why);

extern void destroy_ticket(gpointer data);
pcmk__ticket_t *ticket_new(const char *ticket_id, pcmk_scheduler_t *scheduler);

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

        return (strlen(id) == base_len) && g_str_has_prefix(rsc->id, id);
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

char *pe__action2reason(const pcmk_action_t *action,
                        enum pcmk__action_flags flag);
void pe_action_set_reason(pcmk_action_t *action, const char *reason,
                          bool overwrite);
void pe__add_action_expected_result(pcmk_action_t *action, int expected_result);

void pe__set_resource_flags_recursive(pcmk_resource_t *rsc, uint64_t flags);
void pe__clear_resource_flags_recursive(pcmk_resource_t *rsc, uint64_t flags);
void pe__clear_resource_flags_on_all(pcmk_scheduler_t *scheduler,
                                     uint64_t flag);

int pe__rscs_brief_output(pcmk__output_t *out, GList *rsc_list, unsigned int options);
void pe_fence_node(pcmk_scheduler_t *scheduler, pcmk_node_t *node,
                   const char *reason, bool priority_delay);

pcmk_node_t *pe_create_node(const char *id, const char *uname, const char *type,
                            int score, pcmk_scheduler_t *scheduler);

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
const char *pe__add_bundle_remote_name(pcmk_resource_t *rsc, xmlNode *xml,
                                       const char *field);
bool pe__is_universal_clone(const pcmk_resource_t *rsc,
                            const pcmk_scheduler_t *scheduler);

bool pe__shutdown_requested(const pcmk_node_t *node);

/*!
 * \internal
 * \brief Register xml formatting message functions.
 *
 * \param[in,out] out  Output object to register messages with
 */
void pe__register_messages(pcmk__output_t *out);

void pe__unpack_dataset_nvpairs(const xmlNode *xml_obj, const char *set_name,
                                const pcmk_rule_input_t *rule_input,
                                GHashTable *hash, const char *always_first,
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

bool pe__bundle_is_filtered(const pcmk_resource_t *rsc, const GList *only_rsc,
                            bool check_parent);
bool pe__clone_is_filtered(const pcmk_resource_t *rsc, const GList *only_rsc,
                           bool check_parent);
bool pe__group_is_filtered(const pcmk_resource_t *rsc, const GList *only_rsc,
                           bool check_parent);
bool pe__native_is_filtered(const pcmk_resource_t *rsc, const GList *only_rsc,
                            bool check_parent);

xmlNode *pe__failed_probe_for_rsc(const pcmk_resource_t *rsc, const char *name);

const char *pe__clone_child_id(const pcmk_resource_t *rsc);

int pe__sum_node_health_scores(const pcmk_node_t *node, int base_health);
int pe__node_health(pcmk_node_t *node);

static inline enum pcmk__health_strategy
pe__health_strategy(pcmk_scheduler_t *scheduler)
{
    const char *strategy = pcmk__cluster_option(scheduler->priv->options,
                                                PCMK_OPT_NODE_HEALTH_STRATEGY);

    return pcmk__parse_health_strategy(strategy);
}

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_PENGINE_INTERNAL__H
