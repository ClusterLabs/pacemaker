/*
 * Copyright 2004-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_RULES_COMPAT__H
#define PCMK__CRM_COMMON_RULES_COMPAT__H

#include <libxml/tree.h>        // xmlNode

#include <crm/common/iso8601.h> // crm_time_t

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Deprecated Pacemaker rules API
 * \ingroup core
 * \deprecated Do not include this header directly. The nvpair APIs in this
 *             header, and the header itself, will be removed in a future
 *             release.
 */

typedef struct pcmk_rule_input {
    const crm_time_t *now;
    const char *rsc_standard;
    const char *rsc_provider;
    const char *rsc_agent;
    const char *op_name;
    guint op_interval_ms;
    GHashTable *node_attrs;
    GHashTable *rsc_params;
    GHashTable *rsc_meta;
    const char *rsc_id;
    const regmatch_t *rsc_id_submatches;
    int rsc_id_nmatches;
} pcmk_rule_input_t;

//! \deprecated Do not use
int pcmk_evaluate_rule(xmlNode *rule, const pcmk_rule_input_t *rule_input,
                       crm_time_t *next_change);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_RULES_COMPAT__H
