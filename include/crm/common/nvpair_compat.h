/*
 * Copyright 2004-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_NVPAIR_COMPAT__H
#define PCMK__CRM_COMMON_NVPAIR_COMPAT__H

#include <glib.h>               // GHashTable, gpointer, GSList
#include <libxml/tree.h>        // xmlNode

#include <crm/common/iso8601.h> // crm_time_t
#include <crm/common/rules.h>   // pcmk_rule_input_t

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Deprecated Pacemaker name-value pair API
 * \ingroup core
 * \deprecated Do not include this header directly. The nvpair APIs in this
 *             header, and the header itself, will be removed in a future
 *             release.
 */

//! \deprecated Do not use
GSList *pcmk_sort_nvpairs(GSList *list);

//! \deprecated Do not use
GSList *pcmk_xml_attrs2nvpairs(const xmlNode *xml);

//! \deprecated Do not use
void pcmk_nvpairs2xml_attrs(GSList *list, xmlNode *xml);

//! \deprecated Do not use
void hash2nvpair(gpointer key, gpointer value, gpointer user_data);

//! \deprecated Do not use
void pcmk_unpack_nvpair_blocks(const xmlNode *xml, const char *element_name,
                               const char *first_id,
                               const pcmk_rule_input_t *rule_input,
                               GHashTable *values, crm_time_t *next_change);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_NVPAIR_COMPAT__H
