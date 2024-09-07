/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_NVPAIR_COMPAT__H
#define PCMK__CRM_COMMON_NVPAIR_COMPAT__H

#include <glib.h>               // GSList
#include <libxml/tree.h>        // xmlNode

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

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_NVPAIR_COMPAT__H
