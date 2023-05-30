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

#include <crm/common/rules.h>           // enum expression_type
#include <crm/common/iso8601.h>         // crm_time_t

// How node attribute values may be compared in rules
enum pcmk__comparison {
    pcmk__comparison_unknown,
    pcmk__comparison_defined,
    pcmk__comparison_undefined,
    pcmk__comparison_eq,
    pcmk__comparison_ne,
    pcmk__comparison_lt,
    pcmk__comparison_lte,
    pcmk__comparison_gt,
    pcmk__comparison_gte,
};

// How node attribute values may be parsed in rules
enum pcmk__type {
    pcmk__type_unknown,
    pcmk__type_string,
    pcmk__type_integer,
    pcmk__type_number,
    pcmk__type_version,
};

enum expression_type pcmk__expression_type(const xmlNode *expr);
enum pcmk__comparison pcmk__parse_comparison(const char *op);
enum pcmk__type pcmk__parse_type(const char *type, enum pcmk__comparison op,
                                 const char *value1, const char *value2);
int pcmk__cmp_by_type(const char *value1, const char *value2,
                      enum pcmk__type type);
char *pcmk__replace_submatches(const char *string, const char *match,
                               const regmatch_t submatches[], int nmatches);

int pcmk__evaluate_date_expression(const xmlNode *date_expression,
                                   const crm_time_t *now,
                                   crm_time_t *next_change);

#endif // PCMK__CRM_COMMON_RULES_INTERNAL__H
