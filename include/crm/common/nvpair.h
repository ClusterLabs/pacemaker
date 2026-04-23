/*
 * Copyright 2004-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_NVPAIR__H
#define PCMK__CRM_COMMON_NVPAIR__H

#include <glib.h>         // gpointer, GHashTable
#include <libxml/tree.h>  // xmlNode

#include <crm/crm.h>
#include <crm/common/iso8601.h> // crm_time_t
#include <crm/common/rules.h>   // pcmk_rule_input_t


#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Functionality for manipulating name/value pairs
 * \ingroup core
 */

//! \deprecated Use \c pcmk_nvpair_t instead of <tt>struct pcmk_nvpair_s</tt>
typedef struct pcmk_nvpair_s {
    char *name;
    char *value;
} pcmk_nvpair_t;

GSList *pcmk_prepend_nvpair(GSList *nvpairs, const char *name, const char *value);
void pcmk_free_nvpairs(GSList *nvpairs);

xmlNode *crm_create_nvpair_xml(xmlNode *parent, const char *id,
                               const char *name, const char *value);
void hash2field(gpointer key, gpointer value, gpointer user_data);
void hash2metafield(gpointer key, gpointer value, gpointer user_data);
void hash2smartfield(gpointer key, gpointer value, gpointer user_data);
GHashTable *xml2list(const xmlNode *parent);

void pcmk_unpack_nvpair_blocks(const xmlNode *xml, const char *element_name,
                               const char *first_id,
                               const pcmk_rule_input_t *rule_input,
                               GHashTable *values, crm_time_t *next_change);

char *crm_meta_name(const char *field);
const char *crm_meta_value(GHashTable *hash, const char *field);

#ifdef __cplusplus
}
#endif

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
#include <crm/common/nvpair_compat.h>
#endif

#endif // PCMK__CRM_COMMON_NVPAIR__H
