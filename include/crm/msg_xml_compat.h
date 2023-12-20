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

//! \deprecated Use PCMK_XE_PROMOTABLE_LEGACY instead
#define XML_CIB_TAG_MASTER PCMK_XE_PROMOTABLE_LEGACY

//! \deprecated Use PCMK_XA_PROMOTED_MAX_LEGACY instead
#define PCMK_XE_PROMOTED_MAX_LEGACY PCMK_XA_PROMOTED_MAX_LEGACY

//! \deprecated Use PCMK_XA_PROMOTED_MAX_LEGACY instead
#define XML_RSC_ATTR_MASTER_MAX PCMK_XA_PROMOTED_MAX_LEGACY

//! \deprecated Use PCMK_XA_PROMOTED_NODE_MAX_LEGACY instead
#define PCMK_XE_PROMOTED_NODE_MAX_LEGACY PCMK_XA_PROMOTED_NODE_MAX_LEGACY

//! \deprecated Use PCMK_META_MIGRATION_THRESHOLD instead
#define XML_RSC_ATTR_FAIL_STICKINESS PCMK_META_MIGRATION_THRESHOLD

//! \deprecated Use PCMK_META_FAILURE_TIMEOUT instead
#define XML_RSC_ATTR_FAIL_TIMEOUT PCMK_META_FAILURE_TIMEOUT

//! \deprecated Use PCMK_XA_PROMOTED_NODE_MAX_LEGACY instead
#define XML_RSC_ATTR_MASTER_NODEMAX PCMK_XA_PROMOTED_NODE_MAX_LEGACY

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

//! \deprecated Use \p XML_ATTR_ID instead
#define XML_ATTR_UUID "id"

//! \deprecated Do not use (will be removed in a future release)
#define XML_ATTR_VERBOSE "verbose"

//! \deprecated Do not use (will be removed in a future release)
#define XML_CIB_TAG_DOMAINS "domains"

//! \deprecated Do not use (will be removed in a future release)
#define XML_CIB_ATTR_SOURCE "source"

//! \deprecated Do not use
#define XML_NODE_EXPECTED "expected"

//! \deprecated Do not use
#define XML_NODE_IN_CLUSTER "in_ccm"

//! \deprecated Do not use
#define XML_NODE_IS_PEER "crmd"

//! \deprecated Do not use
#define XML_NODE_JOIN_STATE "join"

//! \deprecated Do not use (will be removed in a future release)
#define XML_RSC_OP_LAST_RUN "last-run"

//! \deprecated Use name member directly
#define TYPE(x) (((x) == NULL)? NULL : (const char *) ((x)->name))

//! \deprecated Use \c PCMK_OPT_CLUSTER_RECHECK_INTERVAL instead
#define XML_CONFIG_ATTR_RECHECK PCMK_OPT_CLUSTER_RECHECK_INTERVAL

//! \deprecated Use \c PCMK_OPT_DC_DEADTIME instead
#define XML_CONFIG_ATTR_DC_DEADTIME PCMK_OPT_DC_DEADTIME

//! \deprecated Use \c PCMK_OPT_ELECTION_TIMEOUT instead
#define XML_CONFIG_ATTR_ELECTION_FAIL PCMK_OPT_ELECTION_TIMEOUT

//! \deprecated Use \c PCMK_OPT_FENCE_REACTION instead
#define XML_CONFIG_ATTR_FENCE_REACTION PCMK_OPT_FENCE_REACTION

//! \deprecated Use \c PCMK_OPT_HAVE_WATCHDOG instead
#define XML_ATTR_HAVE_WATCHDOG PCMK_OPT_HAVE_WATCHDOG

//! \deprecated Use \c PCMK_OPT_NODE_PENDING_TIMEOUT instead
#define XML_CONFIG_ATTR_NODE_PENDING_TIMEOUT PCMK_OPT_NODE_PENDING_TIMEOUT

//! \deprecated Use \c PCMK_OPT_PRIORITY_FENCING_DELAY instead
#define XML_CONFIG_ATTR_PRIORITY_FENCING_DELAY PCMK_OPT_PRIORITY_FENCING_DELAY

//! \deprecated Use \c PCMK_OPT_SHUTDOWN_ESCALATION instead
#define XML_CONFIG_ATTR_FORCE_QUIT PCMK_OPT_SHUTDOWN_ESCALATION

//! \deprecated Use \c PCMK_OPT_SHUTDOWN_LOCK instead
#define XML_CONFIG_ATTR_SHUTDOWN_LOCK PCMK_OPT_SHUTDOWN_LOCK

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_MSG_XML_COMPAT__H
