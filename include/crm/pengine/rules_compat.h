/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_PENGINE_RULES_COMPAT__H
#  define PCMK__CRM_PENGINE_RULES_COMPAT__H

#include <glib.h>                   // gboolean, GHashTable
#include <libxml/tree.h>            // xmlNode
#include <crm/common/iso8601.h>     // crm_time_t
#include <crm/common/roles.h>       // enum rsc_role_e
#include <crm/pengine/common_compat.h>  // pe_rule_eval_data_t

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Deprecated Pacemaker rule API
 * \ingroup pengine
 * \deprecated Do not include this header directly. The rule APIs in this
 *             header, and the header itself, will be removed in a future
 *             release.
 */

// @COMPAT sbd's configure script checks for this (as of at least 1.5.2)
//! \deprecated Use pcmk_evaluate_rule() instead
gboolean test_rule(xmlNode *rule, GHashTable *node_hash, enum rsc_role_e role,
                   crm_time_t *now);

//! \deprecated Use pcmk_unpack_nvpair_blocks() instead
void pe_unpack_nvpairs(xmlNode *top, const xmlNode *xml_obj,
                       const char *set_name, GHashTable *node_hash,
                       GHashTable *hash, const char *always_first,
                       gboolean overwrite, crm_time_t *now,
                       crm_time_t *next_change);

//! \deprecated Use pcmk_unpack_nvpair_blocks() instead
void pe_eval_nvpairs(xmlNode *top, const xmlNode *xml_obj, const char *set_name,
                     const pe_rule_eval_data_t *rule_data, GHashTable *hash,
                     const char *always_first, gboolean overwrite,
                     crm_time_t *next_change);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_PENGINE_RULES_COMPAT__H
