/*
 * Copyright 2004-2023 the Pacemaker project contributors
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

const char *pe__resource_description(const pe_resource_t *rsc, uint32_t show_opts);

enum pe__clone_flags {
    // Whether instances should be started sequentially
    pe__clone_ordered               = (1 << 0),

    // Whether promotion scores have been added
    pe__clone_promotion_added       = (1 << 1),

    // Whether promotion constraints have been added
    pe__clone_promotion_constrained = (1 << 2),
};

bool pe__clone_is_ordered(const pe_resource_t *clone);
int pe__set_clone_flag(pe_resource_t *clone, enum pe__clone_flags flag);


enum pe__group_flags {
    pe__group_ordered       = (1 << 0), // Members start sequentially
    pe__group_colocated     = (1 << 1), // Members must be on same node
};

bool pe__group_flag_is_set(const pe_resource_t *group, uint32_t flags);
pe_resource_t *pe__last_group_member(const pe_resource_t *group);


#  define pe_rsc_info(rsc, fmt, args...)  crm_log_tag(LOG_INFO,  rsc ? rsc->id : "<NULL>", fmt, ##args)
#  define pe_rsc_debug(rsc, fmt, args...) crm_log_tag(LOG_DEBUG, rsc ? rsc->id : "<NULL>", fmt, ##args)
#  define pe_rsc_trace(rsc, fmt, args...) crm_log_tag(LOG_TRACE, rsc ? rsc->id : "<NULL>", fmt, ##args)

#  define pe_err(fmt...) do {           \
        was_processing_error = TRUE;    \
        pcmk__config_err(fmt);          \
    } while (0)

#  define pe_warn(fmt...) do {          \
        was_processing_warning = TRUE;  \
        pcmk__config_warn(fmt);         \
    } while (0)

#  define pe_proc_err(fmt...) { was_processing_error = TRUE; crm_err(fmt); }
#  define pe_proc_warn(fmt...) { was_processing_warning = TRUE; crm_warn(fmt); }

#define pe__set_working_set_flags(working_set, flags_to_set) do {           \
        (working_set)->flags = pcmk__set_flags_as(__func__, __LINE__,       \
            LOG_TRACE, "Working set", crm_system_name,                      \
            (working_set)->flags, (flags_to_set), #flags_to_set);           \
    } while (0)

#define pe__clear_working_set_flags(working_set, flags_to_clear) do {       \
        (working_set)->flags = pcmk__clear_flags_as(__func__, __LINE__,     \
            LOG_TRACE, "Working set", crm_system_name,                      \
            (working_set)->flags, (flags_to_clear), #flags_to_clear);       \
    } while (0)

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

// Some warnings we don't want to print every transition

enum pe_warn_once_e {
    pe_wo_blind         = (1 << 0),
    pe_wo_restart_type  = (1 << 1),
    pe_wo_role_after    = (1 << 2),
    pe_wo_poweroff      = (1 << 3),
    pe_wo_require_all   = (1 << 4),
    pe_wo_order_score   = (1 << 5),
    pe_wo_neg_threshold = (1 << 6),
    pe_wo_remove_after  = (1 << 7),
    pe_wo_ping_node     = (1 << 8),
    pe_wo_order_inst    = (1 << 9),
    pe_wo_coloc_inst    = (1 << 10),
    pe_wo_group_order   = (1 << 11),
    pe_wo_group_coloc   = (1 << 12),
    pe_wo_upstart       = (1 << 13),
    pe_wo_nagios        = (1 << 14),
};

extern uint32_t pe_wo;

#define pe_warn_once(pe_wo_bit, fmt...) do {    \
        if (!pcmk_is_set(pe_wo, pe_wo_bit)) {  \
            if (pe_wo_bit == pe_wo_blind) {     \
                crm_warn(fmt);                  \
            } else {                            \
                pe_warn(fmt);                   \
            }                                   \
            pe_wo = pcmk__set_flags_as(__func__, __LINE__, LOG_TRACE,       \
                                      "Warn-once", "logging", pe_wo,        \
                                      (pe_wo_bit), #pe_wo_bit);             \
        }                                       \
    } while (0);


typedef struct pe__location_constraint_s {
    char *id;                           // Constraint XML ID
    pe_resource_t *rsc_lh;              // Resource being located
    enum rsc_role_e role_filter;        // Role to locate
    enum pe_discover_e discover_mode;   // Resource discovery
    GList *node_list_rh;              // List of pe_node_t*
} pe__location_t;

typedef struct pe__order_constraint_s {
    int id;
    uint32_t flags; // Group of enum pe_ordering flags

    void *lh_opaque;
    pe_resource_t *lh_rsc;
    pe_action_t *lh_action;
    char *lh_action_task;

    void *rh_opaque;
    pe_resource_t *rh_rsc;
    pe_action_t *rh_action;
    char *rh_action_task;
} pe__ordering_t;

const pe_resource_t *pe__const_top_resource(const pe_resource_t *rsc,
                                            bool include_bundle);

int pe__clone_max(const pe_resource_t *clone);
int pe__clone_node_max(const pe_resource_t *clone);
int pe__clone_promoted_max(const pe_resource_t *clone);
int pe__clone_promoted_node_max(const pe_resource_t *clone);
void pe__create_clone_notifications(pe_resource_t *clone);
void pe__free_clone_notification_data(pe_resource_t *clone);
void pe__create_clone_notif_pseudo_ops(pe_resource_t *clone,
                                       pe_action_t *start, pe_action_t *started,
                                       pe_action_t *stop, pe_action_t *stopped);


pe_action_t *pe__new_rsc_pseudo_action(pe_resource_t *rsc, const char *task,
                                       bool optional, bool runnable);

void pe__create_promotable_pseudo_ops(pe_resource_t *clone, bool any_promoting,
                                      bool any_demoting);

bool pe_can_fence(const pe_working_set_t *data_set, const pe_node_t *node);

void add_hash_param(GHashTable * hash, const char *name, const char *value);

/*!
 * \internal
 * \enum pe__rsc_node
 * \brief Type of resource location lookup to perform
 */
enum pe__rsc_node {
    pe__rsc_node_assigned = 0,  //!< Where resource is assigned
    pe__rsc_node_current  = 1,  //!< Where resource is running

    // @COMPAT: Use in native_location() at a compatibility break
    pe__rsc_node_pending  = 2,  //!< Where resource is pending
};

char *native_parameter(pe_resource_t * rsc, pe_node_t * node, gboolean create, const char *name,
                       pe_working_set_t * data_set);
pe_node_t *native_location(const pe_resource_t *rsc, GList **list, int current);

void pe_metadata(pcmk__output_t *out);
void verify_pe_options(GHashTable * options);

void native_add_running(pe_resource_t * rsc, pe_node_t * node, pe_working_set_t * data_set, gboolean failed);

gboolean native_unpack(pe_resource_t * rsc, pe_working_set_t * data_set);
gboolean group_unpack(pe_resource_t * rsc, pe_working_set_t * data_set);
gboolean clone_unpack(pe_resource_t * rsc, pe_working_set_t * data_set);
gboolean pe__unpack_bundle(pe_resource_t *rsc, pe_working_set_t *data_set);

pe_resource_t *native_find_rsc(pe_resource_t *rsc, const char *id, const pe_node_t *node,
                               int flags);

gboolean native_active(pe_resource_t * rsc, gboolean all);
gboolean group_active(pe_resource_t * rsc, gboolean all);
gboolean clone_active(pe_resource_t * rsc, gboolean all);
gboolean pe__bundle_active(pe_resource_t *rsc, gboolean all);

//! \deprecated This function will be removed in a future release
void native_print(pe_resource_t *rsc, const char *pre_text, long options,
                  void *print_data);

//! \deprecated This function will be removed in a future release
void group_print(pe_resource_t *rsc, const char *pre_text, long options,
                 void *print_data);

//! \deprecated This function will be removed in a future release
void clone_print(pe_resource_t *rsc, const char *pre_text, long options,
                 void *print_data);

//! \deprecated This function will be removed in a future release
void pe__print_bundle(pe_resource_t *rsc, const char *pre_text, long options,
                      void *print_data);

gchar *pcmk__native_output_string(const pe_resource_t *rsc, const char *name,
                                  const pe_node_t *node, uint32_t show_opts,
                                  const char *target_role, bool show_nodes);

int pe__name_and_nvpairs_xml(pcmk__output_t *out, bool is_list, const char *tag_name
                         , size_t pairs_count, ...);
char *pe__node_display_name(pe_node_t *node, bool print_detail);


// Clone notifications (pe_notif.c)
void pe__order_notifs_after_fencing(const pe_action_t *action,
                                    pe_resource_t *rsc,
                                    pe_action_t *stonith_op);


static inline const char *
pe__rsc_bool_str(const pe_resource_t *rsc, uint64_t rsc_flag)
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

void native_free(pe_resource_t * rsc);
void group_free(pe_resource_t * rsc);
void clone_free(pe_resource_t * rsc);
void pe__free_bundle(pe_resource_t *rsc);

enum rsc_role_e native_resource_state(const pe_resource_t * rsc, gboolean current);
enum rsc_role_e group_resource_state(const pe_resource_t * rsc, gboolean current);
enum rsc_role_e clone_resource_state(const pe_resource_t * rsc, gboolean current);
enum rsc_role_e pe__bundle_resource_state(const pe_resource_t *rsc,
                                          gboolean current);

void pe__count_common(pe_resource_t *rsc);
void pe__count_bundle(pe_resource_t *rsc);

void common_free(pe_resource_t * rsc);

pe_node_t *pe__copy_node(const pe_node_t *this_node);
extern time_t get_effective_time(pe_working_set_t * data_set);

/* Failure handling utilities (from failcounts.c) */

// bit flags for fail count handling options
enum pe_fc_flags_e {
    pe_fc_default   = (1 << 0),
    pe_fc_effective = (1 << 1), // don't count expired failures
    pe_fc_fillers   = (1 << 2), // if container, include filler failures in count
};

int pe_get_failcount(const pe_node_t *node, pe_resource_t *rsc,
                     time_t *last_failure, uint32_t flags,
                     const xmlNode *xml_op);

pe_action_t *pe__clear_failcount(pe_resource_t *rsc, const pe_node_t *node,
                                 const char *reason,
                                 pe_working_set_t *data_set);

/* Functions for finding/counting a resource's active nodes */

bool pe__count_active_node(const pe_resource_t *rsc, pe_node_t *node,
                           pe_node_t **active, unsigned int *count_all,
                           unsigned int *count_clean);

pe_node_t *pe__find_active_requires(const pe_resource_t *rsc,
                                    unsigned int *count);

static inline pe_node_t *
pe__current_node(const pe_resource_t *rsc)
{
    return (rsc == NULL)? NULL : rsc->fns->active_node(rsc, NULL, NULL);
}


/* Binary like operators for lists of nodes */
extern void node_list_exclude(GHashTable * list, GList *list2, gboolean merge_scores);

GHashTable *pe__node_list2table(const GList *list);

static inline gpointer
pe_hash_table_lookup(GHashTable * hash, gconstpointer key)
{
    if (hash) {
        return g_hash_table_lookup(hash, key);
    }
    return NULL;
}

extern pe_action_t *get_pseudo_op(const char *name, pe_working_set_t * data_set);
extern gboolean order_actions(pe_action_t * lh_action, pe_action_t * rh_action, enum pe_ordering order);

void pe__show_node_scores_as(const char *file, const char *function,
                             int line, bool to_log, const pe_resource_t *rsc,
                             const char *comment, GHashTable *nodes,
                             pe_working_set_t *data_set);

#define pe__show_node_scores(level, rsc, text, nodes, data_set)    \
        pe__show_node_scores_as(__FILE__, __func__, __LINE__,      \
                                (level), (rsc), (text), (nodes), (data_set))

xmlNode *find_rsc_op_entry(const pe_resource_t *rsc, const char *key);

pe_action_t *custom_action(pe_resource_t *rsc, char *key, const char *task,
                           const pe_node_t *on_node, gboolean optional,
                           gboolean foo, pe_working_set_t *data_set);

#  define delete_key(rsc) pcmk__op_key(rsc->id, CRMD_ACTION_DELETE, 0)
#  define delete_action(rsc, node, optional) custom_action(		\
		rsc, delete_key(rsc), CRMD_ACTION_DELETE, node,		\
		optional, TRUE, rsc->cluster);

#  define stopped_key(rsc) pcmk__op_key(rsc->id, CRMD_ACTION_STOPPED, 0)
#  define stopped_action(rsc, node, optional) custom_action(		\
		rsc, stopped_key(rsc), CRMD_ACTION_STOPPED, node,	\
		optional, TRUE, rsc->cluster);

#  define stop_key(rsc) pcmk__op_key(rsc->id, CRMD_ACTION_STOP, 0)
#  define stop_action(rsc, node, optional) custom_action(			\
		rsc, stop_key(rsc), CRMD_ACTION_STOP, node,		\
		optional, TRUE, rsc->cluster);

#  define reload_key(rsc) pcmk__op_key(rsc->id, CRMD_ACTION_RELOAD_AGENT, 0)
#  define start_key(rsc) pcmk__op_key(rsc->id, CRMD_ACTION_START, 0)
#  define start_action(rsc, node, optional) custom_action(		\
		rsc, start_key(rsc), CRMD_ACTION_START, node,		\
		optional, TRUE, rsc->cluster)

#  define started_key(rsc) pcmk__op_key(rsc->id, CRMD_ACTION_STARTED, 0)
#  define started_action(rsc, node, optional) custom_action(		\
		rsc, started_key(rsc), CRMD_ACTION_STARTED, node,	\
		optional, TRUE, rsc->cluster)

#  define promote_key(rsc) pcmk__op_key(rsc->id, CRMD_ACTION_PROMOTE, 0)
#  define promote_action(rsc, node, optional) custom_action(		\
		rsc, promote_key(rsc), CRMD_ACTION_PROMOTE, node,	\
		optional, TRUE, rsc->cluster)

#  define promoted_key(rsc) pcmk__op_key(rsc->id, CRMD_ACTION_PROMOTED, 0)
#  define promoted_action(rsc, node, optional) custom_action(		\
		rsc, promoted_key(rsc), CRMD_ACTION_PROMOTED, node,	\
		optional, TRUE, rsc->cluster)

#  define demote_key(rsc) pcmk__op_key(rsc->id, CRMD_ACTION_DEMOTE, 0)
#  define demote_action(rsc, node, optional) custom_action(		\
		rsc, demote_key(rsc), CRMD_ACTION_DEMOTE, node,		\
		optional, TRUE, rsc->cluster)

#  define demoted_key(rsc) pcmk__op_key(rsc->id, CRMD_ACTION_DEMOTED, 0)
#  define demoted_action(rsc, node, optional) custom_action(		\
		rsc, demoted_key(rsc), CRMD_ACTION_DEMOTED, node,	\
		optional, TRUE, rsc->cluster)

extern int pe_get_configured_timeout(pe_resource_t *rsc, const char *action,
                                     pe_working_set_t *data_set);

pe_action_t *find_first_action(const GList *input, const char *uuid,
                               const char *task, const pe_node_t *on_node);

enum action_tasks get_complex_task(const pe_resource_t *rsc, const char *name);

extern GList *find_actions(GList *input, const char *key, const pe_node_t *on_node);
GList *find_actions_exact(GList *input, const char *key,
                          const pe_node_t *on_node);
GList *pe__resource_actions(const pe_resource_t *rsc, const pe_node_t *node,
                            const char *task, bool require_node);

extern void pe_free_action(pe_action_t * action);

void resource_location(pe_resource_t *rsc, const pe_node_t *node, int score,
                       const char *tag, pe_working_set_t *data_set);

extern int pe__is_newer_op(const xmlNode *xml_a, const xmlNode *xml_b,
                           bool same_node_default);
extern gint sort_op_by_callid(gconstpointer a, gconstpointer b);
gboolean get_target_role(const pe_resource_t *rsc, enum rsc_role_e *role);
void pe__set_next_role(pe_resource_t *rsc, enum rsc_role_e role,
                       const char *why);

pe_resource_t *find_clone_instance(const pe_resource_t *rsc,
                                   const char *sub_id);

extern void destroy_ticket(gpointer data);
extern pe_ticket_t *ticket_new(const char *ticket_id, pe_working_set_t * data_set);

// Resources for manipulating resource names
const char *pe_base_name_end(const char *id);
char *clone_strip(const char *last_rsc_id);
char *clone_zero(const char *last_rsc_id);

static inline bool
pe_base_name_eq(const pe_resource_t *rsc, const char *id)
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
bool is_set_recursive(const pe_resource_t *rsc, long long flag, bool any);

enum rsc_digest_cmp_val {
    /*! Digests are the same */
    RSC_DIGEST_MATCH = 0,
    /*! Params that require a restart changed */
    RSC_DIGEST_RESTART,
    /*! Some parameter changed.  */
    RSC_DIGEST_ALL,
    /*! rsc op didn't have a digest associated with it, so
     *  it is unknown if parameters changed or not. */
    RSC_DIGEST_UNKNOWN,
};

typedef struct op_digest_cache_s {
    enum rsc_digest_cmp_val rc;
    xmlNode *params_all;
    xmlNode *params_secure;
    xmlNode *params_restart;
    char *digest_all_calc;
    char *digest_secure_calc;
    char *digest_restart_calc;
} op_digest_cache_t;

op_digest_cache_t *pe__calculate_digests(pe_resource_t *rsc, const char *task,
                                         guint *interval_ms,
                                         const pe_node_t *node,
                                         const xmlNode *xml_op,
                                         GHashTable *overrides,
                                         bool calc_secure,
                                         pe_working_set_t *data_set);

void pe__free_digests(gpointer ptr);

op_digest_cache_t *rsc_action_digest_cmp(pe_resource_t *rsc,
                                         const xmlNode *xml_op,
                                         pe_node_t *node,
                                         pe_working_set_t *data_set);

pe_action_t *pe_fence_op(pe_node_t *node, const char *op, bool optional,
                         const char *reason, bool priority_delay,
                         pe_working_set_t *data_set);
void trigger_unfencing(pe_resource_t *rsc, pe_node_t *node,
                       const char *reason, pe_action_t *dependency,
                       pe_working_set_t *data_set);

char *pe__action2reason(const pe_action_t *action, enum pe_action_flags flag);
void pe_action_set_reason(pe_action_t *action, const char *reason, bool overwrite);
void pe__add_action_expected_result(pe_action_t *action, int expected_result);

void pe__set_resource_flags_recursive(pe_resource_t *rsc, uint64_t flags);
void pe__clear_resource_flags_recursive(pe_resource_t *rsc, uint64_t flags);
void pe__clear_resource_flags_on_all(pe_working_set_t *data_set, uint64_t flag);

gboolean add_tag_ref(GHashTable * tags, const char * tag_name,  const char * obj_ref);

//! \deprecated This function will be removed in a future release
void print_rscs_brief(GList *rsc_list, const char * pre_text, long options,
                      void * print_data, gboolean print_all);
int pe__rscs_brief_output(pcmk__output_t *out, GList *rsc_list, unsigned int options);
void pe_fence_node(pe_working_set_t * data_set, pe_node_t * node, const char *reason, bool priority_delay);

pe_node_t *pe_create_node(const char *id, const char *uname, const char *type,
                          const char *score, pe_working_set_t * data_set);

//! \deprecated This function will be removed in a future release
void common_print(pe_resource_t *rsc, const char *pre_text, const char *name,
                  const pe_node_t *node, long options, void *print_data);
int pe__common_output_text(pcmk__output_t *out, const pe_resource_t *rsc,
                           const char *name, const pe_node_t *node,
                           unsigned int options);
int pe__common_output_html(pcmk__output_t *out, const pe_resource_t *rsc,
                           const char *name, const pe_node_t *node,
                           unsigned int options);

//! A single instance of a bundle
typedef struct {
    int offset;                 //!< 0-origin index of this instance in bundle
    char *ipaddr;               //!< IP address associated with this instance
    pe_node_t *node;            //!< Node created for this instance
    pe_resource_t *ip;          //!< IP address resource for ipaddr
    pe_resource_t *child;       //!< Instance of bundled resource
    pe_resource_t *container;   //!< Container associated with this instance
    pe_resource_t *remote;      //!< Pacemaker Remote connection into container
} pe__bundle_replica_t;

GList *pe__bundle_containers(const pe_resource_t *bundle);

int pe__bundle_max(const pe_resource_t *rsc);
bool pe__node_is_bundle_instance(const pe_resource_t *bundle,
                                 const pe_node_t *node);
pe_resource_t *pe__bundled_resource(const pe_resource_t *rsc);
const pe_resource_t *pe__get_rsc_in_container(const pe_resource_t *instance);
pe_resource_t *pe__first_container(const pe_resource_t *bundle);
void pe__foreach_bundle_replica(pe_resource_t *bundle,
                                bool (*fn)(pe__bundle_replica_t *, void *),
                                void *user_data);
void pe__foreach_const_bundle_replica(const pe_resource_t *bundle,
                                      bool (*fn)(const pe__bundle_replica_t *,
                                                 void *),
                                      void *user_data);
pe_resource_t *pe__find_bundle_replica(const pe_resource_t *bundle,
                                       const pe_node_t *node);
bool pe__bundle_needs_remote_name(pe_resource_t *rsc);
const char *pe__add_bundle_remote_name(pe_resource_t *rsc,
                                       pe_working_set_t *data_set,
                                       xmlNode *xml, const char *field);

const char *pe_node_attribute_calculated(const pe_node_t *node,
                                         const char *name,
                                         const pe_resource_t *rsc,
                                         enum pe__rsc_node node_type);
const char *pe_node_attribute_raw(const pe_node_t *node, const char *name);
bool pe__is_universal_clone(const pe_resource_t *rsc,
                            const pe_working_set_t *data_set);
void pe__add_param_check(const xmlNode *rsc_op, pe_resource_t *rsc,
                         pe_node_t *node, enum pe_check_parameters,
                         pe_working_set_t *data_set);
void pe__foreach_param_check(pe_working_set_t *data_set,
                             void (*cb)(pe_resource_t*, pe_node_t*,
                                        const xmlNode*,
                                        enum pe_check_parameters));
void pe__free_param_checks(pe_working_set_t *data_set);

bool pe__shutdown_requested(const pe_node_t *node);
void pe__update_recheck_time(time_t recheck, pe_working_set_t *data_set);

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
                                gboolean overwrite, pe_working_set_t *data_set);

bool pe__resource_is_disabled(const pe_resource_t *rsc);
pe_action_t *pe__clear_resource_history(pe_resource_t *rsc,
                                        const pe_node_t *node,
                                        pe_working_set_t *data_set);

GList *pe__rscs_with_tag(pe_working_set_t *data_set, const char *tag_name);
GList *pe__unames_with_tag(pe_working_set_t *data_set, const char *tag_name);
bool pe__rsc_has_tag(pe_working_set_t *data_set, const char *rsc, const char *tag);
bool pe__uname_has_tag(pe_working_set_t *data_set, const char *node, const char *tag);

bool pe__rsc_running_on_only(const pe_resource_t *rsc, const pe_node_t *node);
bool pe__rsc_running_on_any(pe_resource_t *rsc, GList *node_list);
GList *pe__filter_rsc_list(GList *rscs, GList *filter);
GList * pe__build_node_name_list(pe_working_set_t *data_set, const char *s);
GList * pe__build_rsc_list(pe_working_set_t *data_set, const char *s);

bool pcmk__rsc_filtered_by_node(pe_resource_t *rsc, GList *only_node);

gboolean pe__bundle_is_filtered(const pe_resource_t *rsc, GList *only_rsc,
                                gboolean check_parent);
gboolean pe__clone_is_filtered(const pe_resource_t *rsc, GList *only_rsc,
                               gboolean check_parent);
gboolean pe__group_is_filtered(const pe_resource_t *rsc, GList *only_rsc,
                               gboolean check_parent);
gboolean pe__native_is_filtered(const pe_resource_t *rsc, GList *only_rsc,
                                gboolean check_parent);

xmlNode *pe__failed_probe_for_rsc(const pe_resource_t *rsc, const char *name);

const char *pe__clone_child_id(const pe_resource_t *rsc);

int pe__sum_node_health_scores(const pe_node_t *node, int base_health);
int pe__node_health(pe_node_t *node);

static inline enum pcmk__health_strategy
pe__health_strategy(pe_working_set_t *data_set)
{
    return pcmk__parse_health_strategy(pe_pref(data_set->config_hash,
                                               PCMK__OPT_NODE_HEALTH_STRATEGY));
}

static inline int
pe__health_score(const char *option, pe_working_set_t *data_set)
{
    return char2score(pe_pref(data_set->config_hash, option));
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
pe__node_name(const pe_node_t *node)
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
pe__same_node(const pe_node_t *node1, const pe_node_t *node2)
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
