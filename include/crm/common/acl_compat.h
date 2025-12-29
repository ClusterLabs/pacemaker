/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_ACL_COMPAT__H
#define PCMK__CRM_COMMON_ACL_COMPAT__H

#include <stdbool.h>            // bool

#include <libxml/tree.h>        // xmlNode

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Deprecated Pacemaker ACL API
 * \ingroup core
 * \deprecated Do not include this header directly. The XML APIs in this
 *             header, and the header itself, will be removed in a future
 *             release.
 */

//! \deprecated Do not use
bool xml_acl_enabled(const xmlNode *xml);

//! \deprecated Do not use
bool xml_acl_filtered_copy(const char *user, xmlNode *acl_source, xmlNode *xml,
                           xmlNode **result);

#ifdef __cplusplus
}
#endif

#endif  // PCMK__CRM_COMMON_ACL_COMPAT__H
