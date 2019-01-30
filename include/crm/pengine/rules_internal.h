/*
 * Copyright (C) 2015-2017 Andrew Beekhof <andrew@beekhof.net>
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

GListPtr pe_unpack_alerts(xmlNode *alerts);
void pe_free_alert_list(GListPtr alert_list);

crm_time_t *pe_parse_xml_duration(crm_time_t * start, xmlNode * duration_spec);

gboolean pe_test_date_expression(xmlNode * time_expr, crm_time_t * now);
gboolean pe_cron_range_satisfied(crm_time_t * now, xmlNode * cron_spec);
gboolean pe_test_attr_expression(xmlNode * expr, GHashTable * hash, crm_time_t * now);
gboolean pe_test_attr_expression_full(xmlNode * expr, GHashTable * hash, crm_time_t * now, pe_match_data_t * match_data);
gboolean pe_test_role_expression(xmlNode * expr, enum rsc_role_e role, crm_time_t * now);

#endif
