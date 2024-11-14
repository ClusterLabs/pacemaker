/*
 * Copyright 2004-2024 the Pacemaker project contributors
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
const char *crm_xml_add_timeval(xmlNode *xml, const char *name_sec,
                                const char *name_usec,
                                const struct timeval *value);

const char *crm_element_value(const xmlNode *data, const char *name);
int crm_element_value_int(const xmlNode *data, const char *name, int *dest);
int crm_element_value_ll(const xmlNode *data, const char *name, long long *dest);
int crm_element_value_ms(const xmlNode *data, const char *name, guint *dest);
int crm_element_value_epoch(const xmlNode *xml, const char *name, time_t *dest);
int crm_element_value_timeval(const xmlNode *data, const char *name_sec,
                              const char *name_usec, struct timeval *dest);
char *crm_element_value_copy(const xmlNode *data, const char *name);

/*!
 * \brief Copy an element from one XML object to another
 *
 * \param[in]     obj1     Source XML
 * \param[in,out] obj2     Destination XML
 * \param[in]     element  Name of element to copy
 *
 * \return Pointer to copied value (from source)
 */
static inline const char *
crm_copy_xml_element(const xmlNode *obj1, xmlNode *obj2, const char *element)
{
    const char *value = crm_element_value(obj1, element);

    crm_xml_add(obj2, element, value);
    return value;
}

#ifdef __cplusplus
}
#endif

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
#include <crm/common/xml_element_compat.h>
#endif

#endif // PCMK__CRM_COMMON_XML_ELEMENT__H
