/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_PENGINE_COMMON_COMPAT__H
#define PCMK__CRM_PENGINE_COMMON_COMPAT__H

#include <glib.h>                   // guint, GHashTable

#include <crm/common/iso8601.h>     // crm_time_t
#include <crm/common/roles.h>       // enum rsc_role_e

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Deprecated Pacemaker shared API for scheduler and rules
 * \ingroup pengine
 * \deprecated Do not include this header directly. The APIs in this
 *             header, and the header itself, will be removed in a future
 *             release.
 */

//!@{
//! \deprecated Use pcmk_rule_input_t instead

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

//!@}

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_PENGINE_COMMON_COMPAT__H
