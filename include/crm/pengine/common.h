/*
 * Copyright 2004-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_PENGINE_COMMON__H
#  define PCMK__CRM_PENGINE_COMMON__H

#  include <glib.h>
#  include <regex.h>
#  include <crm/common/iso8601.h>

#ifdef __cplusplus
extern "C" {
#endif

extern gboolean was_processing_error;
extern gboolean was_processing_warning;

/* The order is (partially) significant here; the values from action_fail_ignore
 * through action_fail_fence are in order of increasing severity.
 *
 * @COMPAT The values should be ordered and numbered per the "TODO" comments
 *         below, so all values are in order of severity and there is room for
 *         future additions, but that would break API compatibility.
 * @TODO   For now, we just use a function to compare the values specially, but
 *         at the next compatibility break, we should arrange things properly.
 */
enum action_fail_response {
    action_fail_ignore,     // @TODO = 10
    // @TODO action_fail_demote = 20,
    action_fail_recover,    // @TODO = 30
    // @TODO action_fail_reset_remote = 40,
    // @TODO action_fail_restart_container = 50,
    action_fail_migrate,    // @TODO = 60
    action_fail_block,      // @TODO = 70
    action_fail_stop,       // @TODO = 80
    action_fail_standby,    // @TODO = 90
    action_fail_fence,      // @TODO = 100

    // @COMPAT Values below here are out of order for API compatibility

    action_fail_restart_container,

    /* This is reserved for internal use for remote node connection resources.
     * Fence the remote node if stonith is enabled, otherwise attempt to recover
     * the connection resource. This allows us to specify types of connection
     * resource failures that should result in fencing the remote node
     * (for example, recurring monitor failures).
     */
    action_fail_reset_remote,

    action_fail_demote,
};

/* the "done" action must be the "pre" action +1 */
enum action_tasks {
    no_action,
    monitor_rsc,
    stop_rsc,
    stopped_rsc,
    start_rsc,
    started_rsc,
    action_notify,
    action_notified,
    action_promote,
    action_promoted,
    action_demote,
    action_demoted,
    shutdown_crm,
    stonith_node
};

enum rsc_recovery_type {
    recovery_stop_start,
    recovery_stop_only,
    recovery_block,
    recovery_stop_unexpected,
};

enum rsc_start_requirement {
    rsc_req_nothing,            /* Allowed by custom_action() */
    rsc_req_quorum,             /* Enforced by custom_action() */
    rsc_req_stonith             /* Enforced by native_start_constraints() */
};

//! Possible roles that a resource can be in
enum rsc_role_e {
    RSC_ROLE_UNKNOWN    = 0,
    RSC_ROLE_STOPPED    = 1,
    RSC_ROLE_STARTED    = 2,
    RSC_ROLE_UNPROMOTED = 3,
    RSC_ROLE_PROMOTED   = 4,

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
    //! \deprecated Use RSC_ROLE_UNPROMOTED instead
    RSC_ROLE_SLAVE      = RSC_ROLE_UNPROMOTED,

    //! \deprecated Use RSC_ROLE_PROMOTED instead
    RSC_ROLE_MASTER     = RSC_ROLE_PROMOTED,
#endif
};

#  define RSC_ROLE_MAX  (RSC_ROLE_PROMOTED + 1)

#  define RSC_ROLE_UNKNOWN_S "Unknown"
#  define RSC_ROLE_STOPPED_S "Stopped"
#  define RSC_ROLE_STARTED_S "Started"
#  define RSC_ROLE_UNPROMOTED_S         "Unpromoted"
#  define RSC_ROLE_PROMOTED_S           "Promoted"
#  define RSC_ROLE_UNPROMOTED_LEGACY_S  "Slave"
#  define RSC_ROLE_PROMOTED_LEGACY_S    "Master"

//! Deprecated
enum pe_print_options {
    pe_print_log            = (1 << 0),
    pe_print_html           = (1 << 1),
    pe_print_ncurses        = (1 << 2),
    pe_print_printf         = (1 << 3),
    pe_print_dev            = (1 << 4),  //! Ignored
    pe_print_details        = (1 << 5),  //! Ignored
    pe_print_max_details    = (1 << 6),  //! Ignored
    pe_print_rsconly        = (1 << 7),
    pe_print_ops            = (1 << 8),
    pe_print_suppres_nl     = (1 << 9),
    pe_print_xml            = (1 << 10),
    pe_print_brief          = (1 << 11),
    pe_print_pending        = (1 << 12),
    pe_print_clone_details  = (1 << 13),
    pe_print_clone_active   = (1 << 14), // Print clone instances only if active
    pe_print_implicit       = (1 << 15)  // Print implicitly created resources
};

const char *task2text(enum action_tasks task);
enum action_tasks text2task(const char *task);
enum rsc_role_e text2role(const char *role);
const char *role2text(enum rsc_role_e role);
const char *fail2text(enum action_fail_response fail);

const char *pe_pref(GHashTable * options, const char *name);
void calculate_active_ops(GList * sorted_op_list, int *start_index, int *stop_index);

/*!
 * \brief Get readable description of a recovery type
 *
 * \param[in] type  Recovery type
 *
 * \return Static string describing \p type
 */
static inline const char *
recovery2text(enum rsc_recovery_type type)
{
    switch (type) {
        case recovery_stop_only:
            return "shutting it down";
        case recovery_stop_start:
            return "attempting recovery";
        case recovery_block:
            return "waiting for an administrator";
        case recovery_stop_unexpected:
            return "stopping unexpected instances";
    }
    return "Unknown";
}

typedef struct pe_re_match_data {
    char *string;
    int nregs;
    regmatch_t *pmatch;
} pe_re_match_data_t;

typedef struct pe_match_data {
    pe_re_match_data_t *re;
    GHashTable *params;
    GHashTable *meta;
} pe_match_data_t;

typedef struct pe_rsc_eval_data {
    const char *standard;
    const char *provider;
    const char *agent;
} pe_rsc_eval_data_t;

typedef struct pe_op_eval_data {
    const char *op_name;
    guint interval;
} pe_op_eval_data_t;

typedef struct pe_rule_eval_data {
    GHashTable *node_hash;
    enum rsc_role_e role;
    crm_time_t *now;
    pe_match_data_t *match_data;
    pe_rsc_eval_data_t *rsc_data;
    pe_op_eval_data_t *op_data;
} pe_rule_eval_data_t;

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
#include <crm/pengine/common_compat.h>
#endif

#ifdef __cplusplus
}
#endif

#endif
