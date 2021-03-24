/*
 * Copyright 2015-2020 the Pacemaker project contributors
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

GList *pe_unpack_alerts(xmlNode *alerts);
void pe_free_alert_list(GList *alert_list);

crm_time_t *pe_parse_xml_duration(crm_time_t * start, xmlNode * duration_spec);

gboolean pe__eval_attr_expr(xmlNode *expr, pe_rule_eval_data_t *rule_data);
int pe__eval_date_expr(xmlNode *expr, pe_rule_eval_data_t *rule_data,
                       crm_time_t *next_change);
gboolean pe__eval_op_expr(xmlNodePtr expr, pe_rule_eval_data_t *rule_data);
gboolean pe__eval_role_expr(xmlNode *expr, pe_rule_eval_data_t *rule_data);
gboolean pe__eval_rsc_expr(xmlNodePtr expr, pe_rule_eval_data_t *rule_data);

int pe_cron_range_satisfied(crm_time_t * now, xmlNode * cron_spec);

#endif
