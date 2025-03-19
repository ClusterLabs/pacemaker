/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_XML_ELEMENT__H
#define PCMK__CRM_COMMON_XML_ELEMENT__H

#include <sys/time.h>     // struct timeval

#include <glib.h>         // guint
#include <libxml/tree.h>  // xmlNode

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Wrappers for and extensions to libxml2 for XML elements
 * \ingroup core
 */

const char *crm_xml_add(xmlNode *node, const char *name, const char *value);
const char *crm_xml_add_int(xmlNode *node, const char *name, int value);
const char *crm_xml_add_ll(xmlNode *node, const char *name, long long value);
const char *crm_xml_add_ms(xmlNode *node, const char *name, guint ms);

#ifdef __cplusplus
}
#endif

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
#include <crm/common/xml_element_compat.h>
#endif

#endif // PCMK__CRM_COMMON_XML_ELEMENT__H
