/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_MSG_XML_COMPAT__H
#  define PCMK__CRM_MSG_XML_COMPAT__H

#include <crm/common/agents.h>      // PCMK_STONITH_PROVIDES
#include <crm/common/xml.h>

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

//! \deprecated Use PCMK_META_CLONE_MAX instead
#define XML_RSC_ATTR_INCARNATION_MAX PCMK_META_CLONE_MAX

//! \deprecated Use PCMK_META_CLONE_MIN instead
#define XML_RSC_ATTR_INCARNATION_MIN PCMK_META_CLONE_MIN

//! \deprecated Use PCMK_META_CLONE_NODE_MAX instead
#define XML_RSC_ATTR_INCARNATION_NODEMAX PCMK_META_CLONE_NODE_MAX

//! \deprecated Use PCMK_META_PROMOTED_MAX instead
#define XML_RSC_ATTR_PROMOTED_MAX PCMK_META_PROMOTED_MAX

//! \deprecated Use PCMK_META_PROMOTED_NODE_MAX instead
#define XML_RSC_ATTR_PROMOTED_NODEMAX PCMK_META_PROMOTED_NODE_MAX

//! \deprecated Use PCMK_STONITH_PROVIDES instead
#define XML_RSC_ATTR_PROVIDES PCMK_STONITH_PROVIDES

//! \deprecated Do not use
#define PCMK_XE_PROMOTABLE_LEGACY "master"

//! \deprecated Do not use
#define XML_CIB_TAG_MASTER PCMK_XE_PROMOTABLE_LEGACY

//! \deprecated Do not use
#define PCMK_XA_PROMOTED_MAX_LEGACY "master-max"

//! \deprecated Do not use
#define PCMK_XE_PROMOTED_MAX_LEGACY PCMK_XA_PROMOTED_MAX_LEGACY

//! \deprecated Do not use
#define XML_RSC_ATTR_MASTER_MAX PCMK_XA_PROMOTED_MAX_LEGACY

//! \deprecated Do not use
#define PCMK_XA_PROMOTED_NODE_MAX_LEGACY "master-node-max"

//! \deprecated Do not use
#define PCMK_XE_PROMOTED_NODE_MAX_LEGACY PCMK_XA_PROMOTED_NODE_MAX_LEGACY

//! \deprecated Do not use
#define XML_RSC_ATTR_MASTER_NODEMAX PCMK_XA_PROMOTED_NODE_MAX_LEGACY

//! \deprecated Use PCMK_META_MIGRATION_THRESHOLD instead
#define XML_RSC_ATTR_FAIL_STICKINESS PCMK_META_MIGRATION_THRESHOLD

//! \deprecated Use PCMK_META_FAILURE_TIMEOUT instead
#define XML_RSC_ATTR_FAIL_TIMEOUT PCMK_META_FAILURE_TIMEOUT

//! \deprecated Do not use (will be removed in a future release)
#define XML_ATTR_RA_VERSION "ra-version"

//! \deprecated Do not use (will be removed in a future release)
#define XML_TAG_FRAGMENT "cib_fragment"

//! \deprecated Do not use (will be removed in a future release)
#define XML_TAG_RSC_VER_ATTRS "rsc_versioned_attrs"

//! \deprecated Do not use (will be removed in a future release)
#define XML_TAG_OP_VER_ATTRS "op_versioned_attrs"

//! \deprecated Do not use (will be removed in a future release)
#define XML_TAG_OP_VER_META "op_versioned_meta"

//! \deprecated Use \p PCMK_XA_ID instead
#define XML_ATTR_UUID "id"

//! \deprecated Do not use (will be removed in a future release)
#define XML_ATTR_VERBOSE "verbose"

// NOTE: sbd (as of at least 1.5.2) uses this
//! \deprecated Use \c PCMK_XE_CIB instead
#define XML_TAG_CIB PCMK_XE_CIB

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_MSG_XML_COMPAT__H
