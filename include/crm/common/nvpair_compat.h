/*
 * Copyright 2017-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_NVPAIR_COMPAT__H
#define PCMK__CRM_COMMON_NVPAIR_COMPAT__H

#include <libxml/tree.h>        // xmlNode

#include <crm/common/nvpair.h>  // crm_element_value(), crm_xml_add()

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Deprecated functionality for manipulating name/value pairs
 * \ingroup core
 * \deprecated Do not include this header directly. The XML APIs in this
 *             header, and the header itself, will be removed in a future
 *             release.
 */

//! \deprecated Do not use
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

#endif  // PCMK__CRM_COMMON_NVPAIR_COMPAT__H
