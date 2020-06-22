/*
 * Copyright 2004-2020 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PE_COMMON__H
#  define PE_COMMON__H

#ifdef __cplusplus
extern "C" {
#endif

#  include <glib.h>
#  include <regex.h>

#  include <crm/common/iso8601.h>

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
    recovery_block
};

enum rsc_start_requirement {
    rsc_req_nothing,            /* Allowed by custom_action() */
    rsc_req_quorum,             /* Enforced by custom_action() */
    rsc_req_stonith             /* Enforced by native_start_constraints() */
};

enum rsc_role_e {
    RSC_ROLE_UNKNOWN,
    RSC_ROLE_STOPPED,
    RSC_ROLE_STARTED,
    RSC_ROLE_SLAVE,
    RSC_ROLE_MASTER,
};

#  define RSC_ROLE_MAX  RSC_ROLE_MASTER+1

#  define RSC_ROLE_UNKNOWN_S "Unknown"
#  define RSC_ROLE_STOPPED_S "Stopped"
#  define RSC_ROLE_STARTED_S "Started"
#  define RSC_ROLE_SLAVE_S   "Slave"
#  define RSC_ROLE_MASTER_S  "Master"

enum pe_print_options {
    pe_print_log            = 0x0001,
    pe_print_html           = 0x0002,
    pe_print_ncurses        = 0x0004,
    pe_print_printf         = 0x0008,
    pe_print_dev            = 0x0010, // Debugging (@COMPAT probably not useful)
    pe_print_details        = 0x0020,
    pe_print_max_details    = 0x0040,
    pe_print_rsconly        = 0x0080,
    pe_print_ops            = 0x0100,
    pe_print_suppres_nl     = 0x0200,
    pe_print_xml            = 0x0400,
    pe_print_brief          = 0x0800,
    pe_print_pending        = 0x1000,
    pe_print_clone_details  = 0x2000,
    pe_print_clone_active   = 0x4000, // Print clone instances only if active
    pe_print_implicit       = 0x8000, // Print implicitly created resources
};

const char *task2text(enum action_tasks task);
enum action_tasks text2task(const char *task);
enum rsc_role_e text2role(const char *role);
const char *role2text(enum rsc_role_e role);
const char *fail2text(enum action_fail_response fail);

const char *pe_pref(GHashTable * options, const char *name);
void calculate_active_ops(GList * sorted_op_list, int *start_index, int *stop_index);

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

#ifdef __cplusplus
}
#endif

#endif
