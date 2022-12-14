/*
 * Copyright 2015-2022 the Pacemaker project contributors
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

GList *pe_unpack_alerts(const xmlNode *alerts);
void pe_free_alert_list(GList *alert_list);

gboolean pe__eval_attr_expr(const xmlNode *expr,
                            const pe_rule_eval_data_t *rule_data);
int pe__eval_date_expr(const xmlNode *expr,
                       const pe_rule_eval_data_t *rule_data,
                       crm_time_t *next_change);
gboolean pe__eval_op_expr(const xmlNode *expr,
                          const pe_rule_eval_data_t *rule_data);
gboolean pe__eval_role_expr(const xmlNode *expr,
                            const pe_rule_eval_data_t *rule_data);
gboolean pe__eval_rsc_expr(const xmlNode *expr,
                           const pe_rule_eval_data_t *rule_data);

int pe_cron_range_satisfied(const crm_time_t *now, const xmlNode *cron_spec);

#endif
