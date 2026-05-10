/*
 * Copyright 2004-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__INCLUDED_CRM_COMMON_INTERNAL_H
#error "Include <crm/common/internal.h> instead of <rules_internal.h> directly"
#endif

#ifndef PCMK__CRM_COMMON_RULES_INTERNAL__H
#define PCMK__CRM_COMMON_RULES_INTERNAL__H

#include <regex.h>                      // regmatch_t

#include <glib.h>                       // GHashTable
#include <libxml/tree.h>                // xmlNode

#include <crm/common/iso8601.h>         // crm_time_t
#include <crm/common/rules.h>           // enum expression_type, etc.

#ifdef __cplusplus
extern "C" {
#endif

enum pcmk__combine {
    pcmk__combine_unknown,
    pcmk__combine_and,
    pcmk__combine_or,
};

/*!
 * \internal
 * \brief Data used to evaluate a rule (any \c NULL items are ignored)
 */
typedef struct {
    // Used to evaluate date expressions
    const crm_time_t *now;          //!< Current time to use for rule evaluation

    // Used to evaluate resource type expressions
    const char *rsc_standard;       //!< Resource standard that rule applies to
    const char *rsc_provider;       //!< Resource provider that rule applies to
    const char *rsc_agent;          //!< Resource agent that rule applies to

    // Used to evaluate operation type expressions
    const char *op_name;            //!< Operation name that rule applies to
    unsigned int op_interval_ms;    //!< Operation interval that rule applies to

    // Remaining members are used to evaluate node attribute expressions

    /*!
     * Node attributes for rule evaluation purposes
     *
     * \note Though not const, this is used only with \c g_hash_table_lookup().
     */
    GHashTable *node_attrs;

    // Remaining members are used only within location constraint rules

    /*!
     * Resource parameters that can be used as the reference value source
     *
     * \note Though not const, this is used only with \c g_hash_table_lookup().
     */
    GHashTable *rsc_params;

    /*!
     * Resource meta-attributes that can be used as the reference value source
     *
     * \note Though not const, this is used only with \c g_hash_table_lookup().
     */
    GHashTable *rsc_meta;

    //! Resource ID to compare against a location constraint's resource pattern
    const char *rsc_id;

    //! Resource pattern submatches (as set by \c regexec()) for \c rsc_id
    const regmatch_t *rsc_id_submatches;

    //! Number of entries in rsc_id_submatches
    int rsc_id_nmatches;
} pcmk__rule_input_t;

void pcmk__rule_input_convert(const pcmk_rule_input_t *source,
                              pcmk__rule_input_t *target);

enum expression_type pcmk__condition_type(const xmlNode *condition);
char *pcmk__replace_submatches(const char *string, const char *match,
                               const regmatch_t submatches[], int nmatches);
enum pcmk__combine pcmk__parse_combine(const char *combine);

int pcmk__evaluate_date_expression(const xmlNode *date_expression,
                                   const crm_time_t *now,
                                   crm_time_t *next_change);
int pcmk__evaluate_condition(xmlNode *expr, const pcmk_rule_input_t *rule_input,
                             crm_time_t *next_change);

int pcmk__evaluate_rule(xmlNode *rule, const pcmk_rule_input_t *rule_input,
                        crm_time_t *next_change);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_RULES_INTERNAL__H
