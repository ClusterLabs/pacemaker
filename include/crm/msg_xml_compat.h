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

//! \deprecated Use \c PCMK_OPT_SHUTDOWN_LOCK_LIMIT instead
#define XML_CONFIG_ATTR_SHUTDOWN_LOCK_LIMIT PCMK_OPT_SHUTDOWN_LOCK_LIMIT

//! \deprecated Use \c PCMK_XA_CRM_FEATURE_SET instead
#define XML_ATTR_CRM_VERSION PCMK_XA_CRM_FEATURE_SET

//! \deprecated Do not use
#define XML_ATTR_DIGEST "digest"

//! \deprecated Use \c PCMK_XA_VALIDATE_WITH instead
#define XML_ATTR_VALIDATION PCMK_XA_VALIDATE_WITH

//! \deprecated Use \c PCMK_XA_NO_QUORUM_PANIC instead
#define XML_ATTR_QUORUM_PANIC PCMK_XA_NO_QUORUM_PANIC

//! \deprecated Use \c PCMK_XA_HAVE_QUORUM instead
#define XML_ATTR_HAVE_QUORUM PCMK_XA_HAVE_QUORUM

//! \deprecated Use \c PCMK_XA_EPOCH instead
#define XML_ATTR_GENERATION PCMK_XA_EPOCH

//! \deprecated Use \c PCMK_XA_ADMIN_EPOCH instead
#define XML_ATTR_GENERATION_ADMIN PCMK_XA_ADMIN_EPOCH

//! \deprecated Use \c PCMK_XA_NUM_UPDATES instead
#define XML_ATTR_NUMUPDATES PCMK_XA_NUM_UPDATES

//! \deprecated Use \c PCMK_XA_CRM_DEBUG_ORIGIN instead
#define XML_ATTR_ORIGIN PCMK_XA_CRM_DEBUG_ORIGIN

//! \deprecated Use \c PCMK_XA_CRM_TIMESTAMP instead
#define XML_ATTR_TSTAMP PCMK_XA_CRM_TIMESTAMP

//! \deprecated Use \c PCMK_XA_CIB_LAST_WRITTEN instead
#define XML_CIB_ATTR_WRITTEN PCMK_XA_CIB_LAST_WRITTEN

//! \deprecated Use \c PCMK_XA_VERSION instead
#define XML_ATTR_VERSION PCMK_XA_VERSION

//! \deprecated Use \c PCMK_XA_DESCRIPTION instead
#define XML_ATTR_DESC PCMK_XA_DESCRIPTION

//! \deprecated Use \c PCMK_XA_ID instead
#define XML_ATTR_ID PCMK_XA_ID

//! \deprecated Use \c PCMK_XA_ID instead
#define XML_FAILCIB_ATTR_ID PCMK_XA_ID

//! \deprecated Use \c PCMK_META_CONTAINER_ATTR_TARGET instead
#define XML_RSC_ATTR_TARGET PCMK_META_CONTAINER_ATTR_TARGET

//! \deprecated Do not use
#define XML_RSC_ATTR_RESTART "restart-type"

//! \deprecated Use \c PCMK_META_ORDERED instead
#define XML_RSC_ATTR_ORDERED PCMK_META_ORDERED

//! \deprecated Use \c PCMK_META_INTERLEAVE instead
#define XML_RSC_ATTR_INTERLEAVE PCMK_META_INTERLEAVE

//! \deprecated Do not use
#define XML_RSC_ATTR_INCARNATION "clone"

//! \deprecated Use \c PCMK_META_PROMOTABLE instead
#define XML_RSC_ATTR_PROMOTABLE PCMK_META_PROMOTABLE

//! \deprecated Use \c PCMK_META_IS_MANAGED instead
#define XML_RSC_ATTR_MANAGED PCMK_META_IS_MANAGED

//! \deprecated Use \c PCMK_META_TARGET_ROLE instead
#define XML_RSC_ATTR_TARGET_ROLE PCMK_META_TARGET_ROLE

//! \deprecated Use \c PCMK_META_GLOBALLY_UNIQUE instead
#define XML_RSC_ATTR_UNIQUE PCMK_META_GLOBALLY_UNIQUE

//! \deprecated Use \c PCMK_META_NOTIFY instead
#define XML_RSC_ATTR_NOTIFY PCMK_META_NOTIFY

//! \deprecated Use \c PCMK_META_RESOURCE_STICKINESS instead
#define XML_RSC_ATTR_STICKINESS PCMK_META_RESOURCE_STICKINESS

//! \deprecated Use \c PCMK_META_MULTIPLE_ACTIVE instead
#define XML_RSC_ATTR_MULTIPLE PCMK_META_MULTIPLE_ACTIVE

//! \deprecated Use \c PCMK_META_REQUIRES instead
#define XML_RSC_ATTR_REQUIRES PCMK_META_REQUIRES

//! \deprecated Do not use
#define XML_RSC_ATTR_CONTAINER "container"

//! \deprecated Do not use
#define XML_RSC_ATTR_INTERNAL_RSC "internal_rsc"

//! \deprecated Use \c PCMK_META_MAINTENANCE instead
#define XML_RSC_ATTR_MAINTENANCE PCMK_META_MAINTENANCE

//! \deprecated Use \c PCMK_META_REMOTE_NODE instead
#define XML_RSC_ATTR_REMOTE_NODE PCMK_META_REMOTE_NODE

//! \deprecated Do not use
#define XML_RSC_ATTR_CLEAR_OP "clear_failure_op"

//! \deprecated Do not use
#define XML_RSC_ATTR_CLEAR_INTERVAL "clear_failure_interval"

//! \deprecated Use \c PCMK_META_CRITICAL instead
#define XML_RSC_ATTR_CRITICAL PCMK_META_CRITICAL

//! \deprecated Use \c PCMK_META_ALLOW_MIGRATE instead
#define XML_OP_ATTR_ALLOW_MIGRATE PCMK_META_ALLOW_MIGRATE

//! \deprecated Use \c PCMK_VALUE_TRUE instead
#define XML_BOOLEAN_YES PCMK_VALUE_TRUE

//! \deprecated Use \c PCMK_VALUE_FALSE instead
#define XML_BOOLEAN_NO PCMK_VALUE_FALSE

//! \deprecated Use \c PCMK_REMOTE_RA_ADDR instead
#define XML_RSC_ATTR_REMOTE_RA_ADDR PCMK_REMOTE_RA_ADDR

//! \deprecated Use \c PCMK_REMOTE_RA_SERVER instead
#define XML_RSC_ATTR_REMOTE_RA_SERVER PCMK_REMOTE_RA_SERVER

//! \deprecated Use \c PCMK_REMOTE_RA_PORT instead
#define XML_RSC_ATTR_REMOTE_RA_PORT PCMK_REMOTE_RA_PORT

//! \deprecated Use \c PCMK_REMOTE_RA_RECONNECT_INTERVAL instead
#define XML_REMOTE_ATTR_RECONNECT_INTERVAL PCMK_REMOTE_RA_RECONNECT_INTERVAL

//! \deprecated Use \c PCMK_XA_NAME instead
#define XML_ATTR_NAME PCMK_XA_NAME

//! \deprecated Use \c PCMK_XA_NAME instead
#define XML_NVPAIR_ATTR_NAME PCMK_XA_NAME

//! \deprecated Use \c PCMK_XA_VALUE instead
#define XML_EXPR_ATTR_VALUE PCMK_XA_VALUE

//! \deprecated Use \c PCMK_XA_VALUE instead
#define XML_NVPAIR_ATTR_VALUE PCMK_XA_VALUE

//! \deprecated Use \c PCMK_XA_VALUE instead
#define XML_ALERT_ATTR_REC_VALUE PCMK_XA_VALUE

//! \deprecated Use \c PCMK_XA_ID_REF instead
#define XML_ATTR_IDREF PCMK_XA_ID_REF

//! \deprecated Do not use
#define XML_ATTR_ID_LONG "long-id"

//! \deprecated Use \c PCMK_XA_TYPE instead
#define XML_ATTR_TYPE PCMK_XA_TYPE

//! \deprecated Use \c PCMK_XA_TYPE instead
#define XML_EXPR_ATTR_TYPE PCMK_XA_TYPE

//! \deprecated Use \c PCMK_XA_PROVIDER instead
#define XML_AGENT_ATTR_PROVIDER PCMK_XA_PROVIDER

//! \deprecated Use \c PCMK_XA_CLASS instead
#define XML_AGENT_ATTR_CLASS PCMK_XA_CLASS

//! \deprecated Use \c PCMK_XE_OP instead
#define XML_ATTR_OP PCMK_XE_OP

//! \deprecated Use \c PCMK_XA_DC_UUID instead
#define XML_ATTR_DC_UUID PCMK_XA_DC_UUID

//! \deprecated Use \c PCMK_XA_UPDATE_ORIGIN instead
#define XML_ATTR_UPDATE_ORIG PCMK_XA_UPDATE_ORIGIN

//! \deprecated Use \c PCMK_XA_UPDATE_CLIENT instead
#define XML_ATTR_UPDATE_CLIENT PCMK_XA_UPDATE_CLIENT

//! \deprecated Use \c PCMK_XA_UPDATE_USER instead
#define XML_ATTR_UPDATE_USER PCMK_XA_UPDATE_USER

//! \deprecated Use \c PCMK_XA_REQUEST instead
#define XML_ATTR_REQUEST PCMK_XA_REQUEST

//! \deprecated Do not use
#define XML_ATTR_RESPONSE "response"

//! \deprecated Use \c PCMK_XA_UNAME instead
#define XML_ATTR_UNAME PCMK_XA_UNAME

//! \deprecated Use \c PCMK_XA_REFERENCE instead
#define XML_ATTR_REFERENCE PCMK_XA_REFERENCE

//! \deprecated Use \c PCMK_XA_REFERENCE instead
#define XML_ACL_ATTR_REF PCMK_XA_REFERENCE

//! \deprecated Use \c PCMK_XA_REFERENCE instead
#define F_CRM_REFERENCE PCMK_XA_REFERENCE

//! \deprecated Do not use
#define XML_ATTR_TRANSITION_MAGIC "transition-magic"

//! \deprecated Do not use
#define XML_ATTR_TRANSITION_KEY	"transition-key"

//! \deprecated Use \c PCMK_XA_INDEX instead
#define XML_ATTR_STONITH_INDEX PCMK_XA_INDEX

//! \deprecated Use \c PCMK_XA_TARGET instead
#define XML_ATTR_STONITH_TARGET PCMK_XA_TARGET

//! \deprecated Use \c PCMK_XA_TARGET_VALUE instead
#define XML_ATTR_STONITH_TARGET_VALUE PCMK_XA_TARGET_VALUE

//! \deprecated Use \c PCMK_XA_TARGET_PATTERN instead
#define XML_ATTR_STONITH_TARGET_PATTERN PCMK_XA_TARGET_PATTERN

//! \deprecated Use \c PCMK_XA_TARGET_ATTRIBUTE instead
#define XML_ATTR_STONITH_TARGET_ATTRIBUTE PCMK_XA_TARGET_ATTRIBUTE

//! \deprecated Use \c PCMK_XA_DEVICES instead
#define XML_ATTR_STONITH_DEVICES PCMK_XA_DEVICES

#ifndef F_ORIG
//! \deprecated Do not use
#define F_ORIG "src"
#endif

//! \deprecated Do not use
#define F_CRM_HOST_FROM F_ORIG

#ifndef F_SEQ
//! \deprecated Do not use
#define F_SEQ "seq"
#endif

#ifndef F_SUBTYPE
//! \deprecated Do not use
#define F_SUBTYPE "subt"
#endif

//! \deprecated Do not use
#define F_CRM_MSG_TYPE F_SUBTYPE

#ifndef F_TYPE
//! \deprecated Do not use
#define F_TYPE "t"
#endif

#ifndef F_CLIENTNAME
//! \deprecated Do not use
#define	F_CLIENTNAME "cn"
#endif

#ifndef F_XML_TAGNAME
//! \deprecated Do not use
#define F_XML_TAGNAME "__name__"
#endif

//! \deprecated Use \c PCMK_VALUE_TRUE instead
#define XML_BOOLEAN_TRUE PCMK_VALUE_TRUE

//! \deprecated Use \c PCMK_VALUE_FALSE instead
#define XML_BOOLEAN_FALSE PCMK_VALUE_FALSE

//! \deprecated Do not use
#define F_CRM_TASK "crm_task"

//! \deprecated Do not use
#define F_CRM_HOST_TO "crm_host_to"

//! \deprecated Do not use
#define F_CRM_SYS_TO "crm_sys_to"

//! \deprecated Do not use
#define F_CRM_SYS_FROM "crm_sys_from"

//! \deprecated Use \c PCMK_XA_VERSION instead
#define F_CRM_VERSION PCMK_XA_VERSION

//! \deprecated Use \c PCMK_XA_ORIGIN instead
#define F_CRM_ORIGIN PCMK_XA_ORIGIN

//! \deprecated Do not use
#define F_CRM_USER "crm_user"

//! \deprecated Do not use
#define F_CRM_JOIN_ID "join_id"

//! \deprecated Do not use
#define F_CRM_DC_LEAVING "dc-leaving"

//! \deprecated Do not use
#define F_CRM_ELECTION_ID "election-id"

//! \deprecated Do not use
#define F_CRM_ELECTION_AGE_S "election-age-sec"

//! \deprecated Do not use
#define F_CRM_ELECTION_AGE_US "election-age-nano-sec"

//! \deprecated Do not use
#define F_CRM_ELECTION_OWNER "election-owner"

//! \deprecated Do not use
#define F_CRM_TGRAPH "crm-tgraph-file"

//! \deprecated Do not use
#define F_CRM_TGRAPH_INPUT "crm-tgraph-in"

//! \deprecated Do not use
#define F_CRM_THROTTLE_MODE "crm-limit-mode"

//! \deprecated Do not use
#define F_CRM_THROTTLE_MAX "crm-limit-max"

//! \deprecated Use \c PCMK_XA_RESULT instead
#define XML_PING_ATTR_STATUS PCMK_XA_RESULT

//! \deprecated Do not use
#define XML_PING_ATTR_SYSFROM "crm_subsystem"

//! \deprecated Do not use
#define XML_PING_ATTR_CRMDSTATE "crmd_state"

//! \deprecated Do not use
#define XML_PING_ATTR_PACEMAKERDSTATE "pacemakerd_state"

//! \deprecated Do not use
#define XML_FAILCIB_ATTR_OBJTYPE "object_type"

//! \deprecated Use \c PCMK_XA_OPERATION instead
#define XML_FAILCIB_ATTR_OP PCMK_XA_OPERATION

//! \deprecated Use \c PCMK_XA_OPERATION instead
#define XML_LRM_ATTR_TASK PCMK_XA_OPERATION

//! \deprecated Use \c PCMK_XA_OPERATION instead
#define XML_EXPR_ATTR_OPERATION PCMK_XA_OPERATION

//! \deprecated Use \c PCMK_XA_OPERATION instead
#define XML_DIFF_OP PCMK_XA_OPERATION

//! \deprecated Use \c PCMK_XA_REASON instead
#define XML_FAILCIB_ATTR_REASON PCMK_XA_REASON

//! \deprecated Use \c PCMK_META_TIMEOUT instead
#define XML_ATTR_TIMEOUT PCMK_META_TIMEOUT

//! \deprecated Use \c PCMK_META_TIMEOUT instead
#define XML_ALERT_ATTR_TIMEOUT PCMK_META_TIMEOUT

//! \deprecated Use \c PCMK_XA_PATH instead
#define XML_ALERT_ATTR_PATH PCMK_XA_PATH

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_MSG_XML_COMPAT__H
