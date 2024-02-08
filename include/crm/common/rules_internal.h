/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_RULES_INTERNAL__H
#define PCMK__CRM_COMMON_RULES_INTERNAL__H

#include <regex.h>                      // regmatch_t
#include <libxml/tree.h>                // xmlNode

#include <crm/common/rules.h>           // enum expression_type, etc.
#include <crm/common/iso8601.h>         // crm_time_t

enum expression_type pcmk__expression_type(const xmlNode *expr);
char *pcmk__replace_submatches(const char *string, const char *match,
                               const regmatch_t submatches[], int nmatches);

int pcmk__evaluate_date_expression(const xmlNode *date_expression,
                                   const crm_time_t *now,
                                   crm_time_t *next_change);
int pcmk__evaluate_attr_expression(const xmlNode *expression,
                                   const pcmk_rule_input_t *rule_input);
int pcmk__evaluate_op_expression(const xmlNode *expr,
                                 const pcmk_rule_input_t *rule_input);

#endif // PCMK__CRM_COMMON_RULES_INTERNAL__H
