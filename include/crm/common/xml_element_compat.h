/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_XML_ELEMENT_COMPAT__H
#define PCMK__CRM_COMMON_XML_ELEMENT_COMPAT__H

#include <sys/time.h>       // struct timeval

#include <glib.h>           // gboolean, guint
#include <libxml/tree.h>    // xmlNode

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Deprecated Pacemaker XML element API
 * \ingroup core
 * \deprecated Do not include this header directly. The nvpair APIs in this
 *             header, and the header itself, will be removed in a future
 *             release.
 */

//! \deprecated Do not use Pacemaker for general-purpose XML manipulation
xmlNode *expand_idref(xmlNode *input, xmlNode *top);

//! \deprecated Do not use Pacemaker for general-purpose XML manipulation
void crm_xml_set_id(xmlNode *xml, const char *format, ...) G_GNUC_PRINTF(2, 3);

//! \deprecated Do not use
xmlNode *sorted_xml(xmlNode *input, xmlNode *parent, gboolean recursive);

//! \deprecated Do not use
const char *crm_copy_xml_element(const xmlNode *obj1, xmlNode *obj2,
                                 const char *element);

//! \deprecated Do not use
int crm_element_value_timeval(const xmlNode *data, const char *name_sec,
                              const char *name_usec, struct timeval *dest);

//! \deprecated Do not use
int crm_element_value_epoch(const xmlNode *xml, const char *name, time_t *dest);

//! \deprecated Do not use
int crm_element_value_ms(const xmlNode *data, const char *name, guint *dest);

//! \deprecated Do not use
int crm_element_value_ll(const xmlNode *data, const char *name,
                         long long *dest);

//! \deprecated Do not use
int crm_element_value_int(const xmlNode *data, const char *name, int *dest);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_XML_ELEMENT_COMPAT__H
