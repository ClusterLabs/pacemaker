/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_PENGINE_RULES__H
#  define PCMK__CRM_PENGINE_RULES__H

#  include <glib.h>
#  include <crm/crm.h>
#  include <crm/common/iso8601.h>
#  include <crm/common/scheduler.h>
#  include <crm/pengine/common.h>

#ifdef __cplusplus
extern "C" {
#endif

void pe_eval_nvpairs(xmlNode *top, const xmlNode *xml_obj, const char *set_name,
                     const pe_rule_eval_data_t *rule_data, GHashTable *hash,
                     const char *always_first, gboolean overwrite,
                     crm_time_t *next_change);

void pe_unpack_nvpairs(xmlNode *top, const xmlNode *xml_obj,
                       const char *set_name, GHashTable *node_hash,
                       GHashTable *hash, const char *always_first,
                       gboolean overwrite, crm_time_t *now,
                       crm_time_t *next_change);

gboolean pe_eval_rules(xmlNode *ruleset, const pe_rule_eval_data_t *rule_data,
                       crm_time_t *next_change);

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
#include <crm/pengine/rules_compat.h>
#endif

#ifdef __cplusplus
}
#endif

#endif
