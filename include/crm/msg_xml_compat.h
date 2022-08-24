/*
 * Copyright 2004-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_MSG_XML_COMPAT__H
#  define PCMK__CRM_MSG_XML_COMPAT__H

#include <crm/common/agents.h>      // PCMK_STONITH_PROVIDES

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

//! \deprecated Use PCMK_STONITH_PROVIDES instead
#define XML_RSC_ATTR_PROVIDES PCMK_STONITH_PROVIDES

//! \deprecated Use PCMK_XE_PROMOTABLE_LEGACY instead
#define XML_CIB_TAG_MASTER PCMK_XE_PROMOTABLE_LEGACY

//! \deprecated Use PCMK_XA_PROMOTED_MAX_LEGACY instead
#define PCMK_XE_PROMOTED_MAX_LEGACY PCMK_XA_PROMOTED_MAX_LEGACY

//! \deprecated Use PCMK_XA_PROMOTED_MAX_LEGACY instead
#define XML_RSC_ATTR_MASTER_MAX PCMK_XA_PROMOTED_MAX_LEGACY

//! \deprecated Use PCMK_XA_PROMOTED_NODE_MAX_LEGACY instead
#define PCMK_XE_PROMOTED_NODE_MAX_LEGACY PCMK_XA_PROMOTED_NODE_MAX_LEGACY

//! \deprecated Use PCMK_XA_PROMOTED_NODE_MAX_LEGACY instead
#define XML_RSC_ATTR_MASTER_NODEMAX PCMK_XA_PROMOTED_NODE_MAX_LEGACY

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_MSG_XML_COMPAT__H
