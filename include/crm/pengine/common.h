/*
 * Copyright 2004-2023 the Pacemaker project contributors
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
#  include <crm/common/scheduler.h>

#ifdef __cplusplus
extern "C" {
#endif

extern gboolean was_processing_error;
extern gboolean was_processing_warning;

const char *task2text(enum action_tasks task);
enum action_tasks text2task(const char *task);
enum rsc_role_e text2role(const char *role);
const char *role2text(enum rsc_role_e role);
const char *fail2text(enum action_fail_response fail);

const char *pe_pref(GHashTable * options, const char *name);

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
        case pcmk_multiply_active_stop:
            return "shutting it down";
        case pcmk_multiply_active_restart:
            return "attempting recovery";
        case pcmk_multiply_active_block:
            return "waiting for an administrator";
        case pcmk_multiply_active_unexpected:
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
    GHashTable *node_hash;          // Only used with g_hash_table_lookup()
    enum rsc_role_e role;
    crm_time_t *now;                // @COMPAT could be const
    pe_match_data_t *match_data;    // @COMPAT could be const
    pe_rsc_eval_data_t *rsc_data;   // @COMPAT could be const
    pe_op_eval_data_t *op_data;     // @COMPAT could be const
} pe_rule_eval_data_t;

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
#include <crm/pengine/common_compat.h>
#endif

#ifdef __cplusplus
}
#endif

#endif
