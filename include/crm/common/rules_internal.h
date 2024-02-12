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

#include <libxml/tree.h>                // xmlNode

#include <crm/common/rules.h>           // enum expression_type
#include <crm/common/iso8601.h>         // crm_time_t

enum expression_type pcmk__expression_type(const xmlNode *expr);
int pcmk__unpack_duration(const xmlNode *duration, const crm_time_t *start,
                          crm_time_t **end);

int pcmk__evaluate_date_spec(const xmlNode *date_spec, const crm_time_t *now);

#endif // PCMK__CRM_COMMON_RULES_INTERNAL__H
