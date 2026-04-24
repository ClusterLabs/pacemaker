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

#include <glib.h>         // GHashTable, gpointer, GSList
#include <libxml/tree.h>  // xmlNode

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

char *crm_meta_name(const char *field);
const char *crm_meta_value(GHashTable *hash, const char *field);

#ifdef __cplusplus
}
#endif

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
#include <crm/common/nvpair_compat.h>
#endif

#endif // PCMK__CRM_COMMON_NVPAIR__H
