/*
 * Copyright 2004-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_RULES__H
#define PCMK__CRM_COMMON_RULES__H

#include <regex.h>                  // regmatch_t

#include <glib.h>                   // guint, GHashTable
#include <libxml/tree.h>            // xmlNode

#include <crm/common/iso8601.h>     // crm_time_t

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * \file
 * \brief Scheduler API for rules
 * \ingroup core
 */

/* Allowed subexpressions of a rule
 * @COMPAT This should be made internal at an API compatibility break
 */
//!@{
//! \deprecated For Pacemaker use only
enum expression_type {
    pcmk__condition_unknown   = 0,  // Unknown or invalid condition
    pcmk__condition_rule      = 1,  // Nested rule
    pcmk__condition_attribute = 2,  // Node attribute expression
    pcmk__condition_location  = 3,  // Node location expression
    pcmk__condition_datetime  = 5,  // Date/time expression
    pcmk__condition_resource  = 7,  // Resource agent expression
    pcmk__condition_operation = 8,  // Operation expression

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
    not_expr        = pcmk__condition_unknown,
    nested_rule     = pcmk__condition_rule,
    attr_expr       = pcmk__condition_attribute,
    loc_expr        = pcmk__condition_location,
    role_expr       = 4,
    time_expr       = pcmk__condition_datetime,
    version_expr    = 6,
    rsc_expr        = pcmk__condition_resource,
    op_expr         = pcmk__condition_operation,
#endif
};
//!@}

/*!
 * \brief Data used to evaluate a rule (any \c NULL items are ignored)
 *
 * \deprecated Use \c pcmk_rule_input_t instead of
 *             <tt>struct pcmk_rule_input</tt>.
 */
typedef struct pcmk_rule_input {
    // Used to evaluate date expressions
    const crm_time_t *now; //!< Current time for rule evaluation purposes

    // Used to evaluate resource type expressions
    const char *rsc_standard;   //!< Resource standard that rule applies to
    const char *rsc_provider;   //!< Resource provider that rule applies to
    const char *rsc_agent;      //!< Resource agent that rule applies to

    // Used to evaluate operation type expressions
    const char *op_name;        //!< Operation name that rule applies to
    guint op_interval_ms;       //!< Operation interval that rule applies to

    // Remaining members are used to evaluate node attribute expressions

    /*!
     * Node attributes for rule evaluation purposes
     *
     * \note Though not const, this is used only with g_hash_table_lookup().
     */
    GHashTable *node_attrs;

    // Remaining members are used only within location constraint rules

    /*!
     * Resource parameters that can be used as the reference value source
     *
     * \note Though not const, this is used only with g_hash_table_lookup().
     */
    GHashTable *rsc_params;

    /*!
     * Resource meta-attributes that can be used as the reference value source
     *
     * \note Though not const, this is used only with g_hash_table_lookup().
     */
    GHashTable *rsc_meta;

    //! Resource ID to compare against a location constraint's resource pattern
    const char *rsc_id;

    //! Resource pattern submatches (as set by regexec()) for rsc_id
    const regmatch_t *rsc_id_submatches;

    //! Number of entries in rsc_id_submatches
    int rsc_id_nmatches;
} pcmk_rule_input_t;

int pcmk_evaluate_rule(xmlNode *rule, const pcmk_rule_input_t *rule_input,
                       crm_time_t *next_change);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_RULES__H
