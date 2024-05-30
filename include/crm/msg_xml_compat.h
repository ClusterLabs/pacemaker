/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_MSG_XML_COMPAT__H
#define PCMK__CRM_MSG_XML_COMPAT__H

#include <crm/common/xml.h> // PCMK_XE_CIB

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Deprecated Pacemaker XML constants API
 * \ingroup core
 * \deprecated Do not include this header directly. The XML constants in this
 *             header, and the header itself, will be removed in a future
 *             release.
 */

// NOTE: sbd (as of at least 1.5.2) uses this
//! \deprecated Use \c PCMK_XE_CIB instead
#define XML_TAG_CIB PCMK_XE_CIB

// NOTE: sbd (as of at least 1.5.2) uses this
//! \deprecated Do not use
#define XML_CIB_TAG_STATE "node_state"

// NOTE: sbd (as of at least 1.5.2) uses this
//! \deprecated Do not use
#define XML_TAG_TRANSIENT_NODEATTRS "transient_attributes"

// NOTE: sbd (as of at least 1.5.2) uses this
//! \deprecated Use \c PCMK_XE_INSTANCE_ATTRIBUTES instead
#define XML_TAG_ATTR_SETS PCMK_XE_INSTANCE_ATTRIBUTES

// NOTE: sbd (as of at least 1.5.2) uses this
//! \deprecated Use \c PCMK_XE_NVPAIR instead
#define XML_CIB_TAG_NVPAIR PCMK_XE_NVPAIR

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_MSG_XML_COMPAT__H
