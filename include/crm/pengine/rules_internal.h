/*
 * Copyright 2015-2019 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */
#ifndef RULES_INTERNAL_H
#define RULES_INTERNAL_H

#include <glib.h>
#include <libxml/tree.h>

#include <crm/common/iso8601.h>
#include <crm/pengine/common.h>
#include <crm/pengine/rules.h>

typedef enum {
    pe_date_before_range,
    pe_date_within_range,
    pe_date_after_range,
    pe_date_result_undetermined,
    pe_date_op_satisfied,
    pe_date_op_unsatisfied
} pe_eval_date_result_t;

GListPtr pe_unpack_alerts(xmlNode *alerts);
void pe_free_alert_list(GListPtr alert_list);

crm_time_t *pe_parse_xml_duration(crm_time_t * start, xmlNode * duration_spec);

pe_eval_date_result_t pe_eval_date_expression(xmlNode *time_expr,
                                              crm_time_t *now,
                                              crm_time_t *next_change);
gboolean pe_test_date_expression(xmlNode *time_expr, crm_time_t *now,
                                 crm_time_t *next_change);
pe_eval_date_result_t pe_cron_range_satisfied(crm_time_t * now, xmlNode * cron_spec);
gboolean pe_test_attr_expression(xmlNode *expr, GHashTable *hash, crm_time_t *now,
                                 pe_match_data_t *match_data);
gboolean pe_test_role_expression(xmlNode * expr, enum rsc_role_e role, crm_time_t * now);

#endif
