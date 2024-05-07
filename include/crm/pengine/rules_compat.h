/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_PENGINE_RULES_COMPAT__H
#  define PCMK__CRM_PENGINE_RULES_COMPAT__H

#include <glib.h>
#include <libxml/tree.h>        // xmlNode
#include <crm/common/iso8601.h> // crm_time_t
#include <crm/pengine/pe_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Deprecated Pacemaker rule API
 * \ingroup pengine
 * \deprecated Do not include this header directly. The rule APIs in this
 *             header, and the header itself, will be removed in a future
 *             release.
 */

//! \deprecated Use pcmk_evaluate_rule() on each rule instead
gboolean pe_evaluate_rules(xmlNode *ruleset, GHashTable *node_hash,
                           crm_time_t *now, crm_time_t *next_change);

//! \deprecated Use pcmk_evaluate_rule() on each rule instead
gboolean pe_eval_rules(xmlNode *ruleset, const pe_rule_eval_data_t *rule_data,
                       crm_time_t *next_change);

// @COMPAT sbd's configure script checks for this (as of at least 1.5.2)
//! \deprecated Use pcmk_evaluate_rule() instead
gboolean test_rule(xmlNode *rule, GHashTable *node_hash, enum rsc_role_e role,
                   crm_time_t *now);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_PENGINE_RULES_COMPAT__H
