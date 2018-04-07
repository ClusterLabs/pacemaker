/* 
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#ifndef PENGINE_RULES__H
#  define PENGINE_RULES__H

#ifdef __cplusplus
extern "C" {
#endif

#  include <glib.h>
#  include <regex.h>

#  include <crm/crm.h>
#  include <crm/common/iso8601.h>
#  include <crm/pengine/common.h>

enum expression_type {
    not_expr,
    nested_rule,
    attr_expr,
    loc_expr,
    role_expr,
    time_expr,
    version_expr
};

typedef struct pe_re_match_data {
    char *string;
    int nregs;
    regmatch_t *pmatch;
} pe_re_match_data_t;

typedef struct pe_match_data {
    pe_re_match_data_t *re;
    GHashTable *params;
    GHashTable *meta;
} pe_match_data_t;

enum expression_type find_expression_type(xmlNode * expr);

gboolean test_ruleset(xmlNode * ruleset, GHashTable * node_hash, crm_time_t * now);

gboolean test_rule(xmlNode * rule, GHashTable * node_hash, enum rsc_role_e role, crm_time_t * now);

gboolean pe_test_rule_re(xmlNode * rule, GHashTable * node_hash, enum rsc_role_e role, crm_time_t * now,
                         pe_re_match_data_t * re_match_data);

gboolean pe_test_rule_full(xmlNode * rule, GHashTable * node_hash, enum rsc_role_e role, crm_time_t * now,
                         pe_match_data_t * match_data);

gboolean test_expression(xmlNode * expr, GHashTable * node_hash,
                         enum rsc_role_e role, crm_time_t * now);

gboolean pe_test_expression_re(xmlNode * expr, GHashTable * node_hash,
                         enum rsc_role_e role, crm_time_t * now, pe_re_match_data_t * re_match_data);

gboolean pe_test_expression_full(xmlNode * expr, GHashTable * node_hash,
                         enum rsc_role_e role, crm_time_t * now, pe_match_data_t * match_data);

void unpack_instance_attributes(xmlNode * top, xmlNode * xml_obj, const char *set_name,
                                GHashTable * node_hash, GHashTable * hash,
                                const char *always_first, gboolean overwrite, crm_time_t * now);

#ifdef ENABLE_VERSIONED_ATTRS
void pe_unpack_versioned_attributes(xmlNode * top, xmlNode * xml_obj, const char *set_name,
                                    GHashTable * node_hash, xmlNode * hash, crm_time_t * now);
GHashTable *pe_unpack_versioned_parameters(xmlNode *versioned_params, const char *ra_version);
#endif

char *pe_expand_re_matches(const char *string, pe_re_match_data_t * match_data);

#ifdef __cplusplus
}
#endif

#endif
