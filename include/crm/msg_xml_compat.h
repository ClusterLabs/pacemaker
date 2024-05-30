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

//! \deprecated Use \c PCMK_META_CONTAINER_ATTRIBUTE_TARGET instead
#define XML_RSC_ATTR_TARGET PCMK_META_CONTAINER_ATTRIBUTE_TARGET

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

//! \deprecated Use \c PCMK_XA_PATH instead
#define XML_DIFF_PATH PCMK_XA_PATH

//! \deprecated Use \c PCMK_META_TIMESTAMP_FORMAT instead
#define XML_ALERT_ATTR_TSTAMP_FORMAT PCMK_META_TIMESTAMP_FORMAT

//! \deprecated Use \c PCMK_META_INTERVAL instead
#define XML_LRM_ATTR_INTERVAL PCMK_META_INTERVAL

//! \deprecated Use \c PCMK_META_INTERVAL instead
#define XML_LRM_ATTR_INTERVAL_MS PCMK_META_INTERVAL

//! \deprecated Do not use
#define XML_CIB_ATTR_REPLACE "replace"

//! \deprecated Do not use
#define XML_COLOC_ATTR_SOURCE_INSTANCE "rsc-instance"

//! \deprecated Do not use
#define XML_COLOC_ATTR_TARGET_INSTANCE "with-rsc-instance"

//! \deprecated Use \c PCMK_META_ON_FAIL instead
#define XML_OP_ATTR_ON_FAIL PCMK_META_ON_FAIL

//! \deprecated Use \c PCMK_META_START_DELAY instead
#define XML_OP_ATTR_START_DELAY PCMK_META_START_DELAY

//! \deprecated Use \c PCMK_META_INTERVAL_ORIGIN instead
#define XML_OP_ATTR_ORIGIN PCMK_META_INTERVAL_ORIGIN

//! \deprecated Use \c PCMK_META_RECORD_PENDING instead
#define XML_OP_ATTR_PENDING PCMK_META_RECORD_PENDING

//! \deprecated Do not use
#define XML_OP_ATTR_DIGESTS_ALL "digests-all"

//! \deprecated Do not use
#define XML_OP_ATTR_DIGESTS_SECURE "digests-secure"

//! \deprecated Do not use
#define XML_CIB_ATTR_PRIORITY "priority"

//! \deprecated Do not use
#define XML_LRM_ATTR_TASK_KEY "operation_key"

//! \deprecated Do not use
#define XML_LRM_ATTR_TARGET "on_node"

//! \deprecated Do not use
#define XML_LRM_ATTR_TARGET_UUID "on_node_uuid"

//! \deprecated Do not use
#define XML_ORDER_ATTR_FIRST_INSTANCE "first-instance"

//! \deprecated Do not use
#define XML_ORDER_ATTR_THEN_INSTANCE "then-instance"

//! \deprecated Do not use
#define XML_TAG_DIFF_ADDED "diff-added"

//! \deprecated Do not use
#define XML_TAG_DIFF_REMOVED "diff-removed"

//! \deprecated Do not use
#define XML_ATTR_TE_NOWAIT "op_no_wait"

//! \deprecated Do not use
#define XML_ATTR_TE_TARGET_RC "op_target_rc"

//! \deprecated Do not use
#define XML_LRM_ATTR_ROUTER_NODE "router_node"

//! \deprecated Do not use
#define XML_LRM_ATTR_RSCID "rsc-id"

//! \deprecated Do not use
#define XML_LRM_ATTR_OPSTATUS "op-status"

//! \deprecated Do not use
#define XML_LRM_ATTR_RC "rc-code"

//! \deprecated Do not use
#define XML_LRM_ATTR_CALLID "call-id"

//! \deprecated Do not use
#define XML_LRM_ATTR_OP_DIGEST "op-digest"

//! \deprecated Do not use
#define XML_LRM_ATTR_OP_RESTART "op-force-restart"

//! \deprecated Do not use
#define XML_LRM_ATTR_OP_SECURE "op-secure-params"

//! \deprecated Do not use
#define XML_LRM_ATTR_RESTART_DIGEST "op-restart-digest"

//! \deprecated Do not use
#define XML_LRM_ATTR_SECURE_DIGEST "op-secure-digest"

//! \deprecated Use \c PCMK_XA_EXIT_REASON instead
#define XML_LRM_ATTR_EXIT_REASON PCMK_XA_EXIT_REASON

//! \deprecated Use \c PCMK_XA_LAST_RC_CHANGE instead
#define XML_RSC_OP_LAST_CHANGE PCMK_XA_LAST_RC_CHANGE

//! \deprecated Use \c PCMK_XA_EXEC_TIME instead
#define XML_RSC_OP_T_EXEC PCMK_XA_EXEC_TIME

//! \deprecated Use \c PCMK_XA_QUEUE_TIME instead
#define XML_RSC_OP_T_QUEUE PCMK_XA_QUEUE_TIME

//! \deprecated Do not use
#define XML_LRM_ATTR_MIGRATE_SOURCE "migrate_source"

//! \deprecated Do not use
#define XML_LRM_ATTR_MIGRATE_TARGET "migrate_target"

//! \deprecated Use \c PCMK_XA_SCORE instead
#define XML_RULE_ATTR_SCORE PCMK_XA_SCORE

//! \deprecated Use \c PCMK_XA_SCORE_ATTRIBUTE instead
#define XML_RULE_ATTR_SCORE_ATTRIBUTE PCMK_XA_SCORE_ATTRIBUTE

//! \deprecated Use \c PCMK_XE_ROLE instead
#define XML_ACL_TAG_ROLE_REF PCMK_XE_ROLE

//! \deprecated Use \c PCMK_XA_ROLE instead
#define XML_RULE_ATTR_ROLE PCMK_XA_ROLE

//! \deprecated Use \c PCMK_XA_BOOLEAN_OP instead
#define XML_RULE_ATTR_BOOLEAN_OP PCMK_XA_BOOLEAN_OP

//! \deprecated Use \c PCMK_XA_ATTRIBUTE instead
#define XML_EXPR_ATTR_ATTRIBUTE PCMK_XA_ATTRIBUTE

//! \deprecated Use \c PCMK_XA_ATTRIBUTE instead
#define XML_ACL_ATTR_ATTRIBUTE PCMK_XA_ATTRIBUTE

//! \deprecated Use \c PCMK_XA_VALUE_SOURCE instead
#define XML_EXPR_ATTR_VALUE_SOURCE PCMK_XA_VALUE_SOURCE

//! \deprecated Use \c PCMK_XA_SYMMETRICAL instead
#define XML_CONS_ATTR_SYMMETRICAL PCMK_XA_SYMMETRICAL

//! \deprecated Use \c PCMK_XA_RESOURCE_DISCOVERY instead
#define XML_LOCATION_ATTR_DISCOVERY PCMK_XA_RESOURCE_DISCOVERY

//! \deprecated Use \c PCMK_XE_PARAMETERS instead
#define XML_TAG_PARAMS PCMK_XE_PARAMETERS

//! \deprecated Use \c PCMK_XA_RSC instead
#define XML_COLOC_ATTR_SOURCE PCMK_XA_RSC

//! \deprecated Use \c PCMK_XA_RSC instead
#define XML_LOC_ATTR_SOURCE PCMK_XA_RSC

//! \deprecated Use \c PCMK_XA_RSC_ROLE instead
#define XML_COLOC_ATTR_SOURCE_ROLE PCMK_XA_RSC_ROLE

//! \deprecated Use \c PCMK_XA_WITH_RSC instead
#define XML_COLOC_ATTR_TARGET PCMK_XA_WITH_RSC

//! \deprecated Use \c PCMK_XA_WITH_RSC_ROLE instead
#define XML_COLOC_ATTR_TARGET_ROLE PCMK_XA_WITH_RSC_ROLE

//! \deprecated Use \c PCMK_XA_NODE_ATTRIBUTE instead
#define XML_COLOC_ATTR_NODE_ATTR PCMK_XA_NODE_ATTRIBUTE

//! \deprecated Use \c PCMK_XA_INFLUENCE instead
#define XML_COLOC_ATTR_INFLUENCE PCMK_XA_INFLUENCE

//! \deprecated Use \c PCMK_XA_RSC_PATTERN instead
#define XML_LOC_ATTR_SOURCE_PATTERN PCMK_XA_RSC_PATTERN

//! \deprecated Use \c PCMK_XA_FIRST instead
#define XML_ORDER_ATTR_FIRST PCMK_XA_FIRST

//! \deprecated Use \c PCMK_XA_THEN instead
#define XML_ORDER_ATTR_THEN PCMK_XA_THEN

//! \deprecated Use \c PCMK_XA_FIRST_ACTION instead
#define XML_ORDER_ATTR_FIRST_ACTION PCMK_XA_FIRST_ACTION

//! \deprecated Use \c PCMK_XA_THEN_ACTION instead
#define XML_ORDER_ATTR_THEN_ACTION PCMK_XA_THEN_ACTION

//! \deprecated Use \c PCMK_XA_KIND instead
#define XML_ORDER_ATTR_KIND PCMK_XA_KIND

//! \deprecated Use \c PCMK_XA_KIND instead
#define XML_ACL_ATTR_KIND PCMK_XA_KIND

//! \deprecated Use \c PCMK_XA_TICKET instead
#define XML_TICKET_ATTR_TICKET PCMK_XA_TICKET

//! \deprecated Use \c PCMK_XA_LOSS_POLICY instead
#define XML_TICKET_ATTR_LOSS_POLICY PCMK_XA_LOSS_POLICY

//! \deprecated Do not use
#define XML_ACL_ATTR_REFv1 "ref"

//! \deprecated Use \c PCMK_XA_OBJECT_TYPE instead
#define XML_ACL_ATTR_TAG PCMK_XA_OBJECT_TYPE

//! \deprecated Do not use
#define XML_ACL_ATTR_TAGv1 "tag"

//! \deprecated Use \c PCMK_XA_XPATH instead
#define XML_ACL_ATTR_XPATH PCMK_XA_XPATH

//! \deprecated Do not use
#define XML_CRM_TAG_PING "ping_response"

// NOTE: sbd (as of at least 1.5.2) uses this
//! \deprecated Use \c PCMK_XE_CIB instead
#define XML_TAG_CIB PCMK_XE_CIB

//! \deprecated Use \c PCMK_XE_CONFIGURATION instead
#define XML_CIB_TAG_CONFIGURATION PCMK_XE_CONFIGURATION

//! \deprecated Use \c PCMK_XE_STATUS instead
#define XML_CIB_TAG_STATUS PCMK_XE_STATUS

//! \deprecated Use \c PCMK_XE_RESOURCES instead
#define XML_CIB_TAG_RESOURCES PCMK_XE_RESOURCES

//! \deprecated Use \c PCMK_XE_NODES instead
#define XML_CIB_TAG_NODES PCMK_XE_NODES

//! \deprecated Use \c PCMK_XE_CONSTRAINTS instead
#define XML_CIB_TAG_CONSTRAINTS PCMK_XE_CONSTRAINTS

//! \deprecated Use \c PCMK_XE_CRM_CONFIG instead
#define XML_CIB_TAG_CRMCONFIG PCMK_XE_CRM_CONFIG

//! \deprecated Use \c PCMK_XE_OP_DEFAULTS instead
#define XML_CIB_TAG_OPCONFIG PCMK_XE_OP_DEFAULTS

//! \deprecated Use \c PCMK_XE_RSC_DEFAULTS instead
#define XML_CIB_TAG_RSCCONFIG PCMK_XE_RSC_DEFAULTS

//! \deprecated Use \c PCMK_XE_ACLS instead
#define XML_CIB_TAG_ACLS PCMK_XE_ACLS

//! \deprecated Use \c PCMK_XE_ALERTS instead
#define XML_CIB_TAG_ALERTS PCMK_XE_ALERTS

//! \deprecated Use \c PCMK_XE_ALERT instead
#define XML_CIB_TAG_ALERT PCMK_XE_ALERT

//! \deprecated Use \c PCMK_XE_RECIPIENT instead
#define XML_CIB_TAG_ALERT_RECIPIENT PCMK_XE_RECIPIENT

//! \deprecated Use \c PCMK_XE_SELECT instead
#define XML_CIB_TAG_ALERT_SELECT PCMK_XE_SELECT

//! \deprecated Use \c PCMK_XE_SELECT_ATTRIBUTES instead
#define XML_CIB_TAG_ALERT_ATTRIBUTES PCMK_XE_SELECT_ATTRIBUTES

//! \deprecated Use \c PCMK_XE_SELECT_FENCING instead
#define XML_CIB_TAG_ALERT_FENCING PCMK_XE_SELECT_FENCING

//! \deprecated Use \c PCMK_XE_SELECT_NODES instead
#define XML_CIB_TAG_ALERT_NODES PCMK_XE_SELECT_NODES

//! \deprecated Use \c PCMK_XE_SELECT_RESOURCES instead
#define XML_CIB_TAG_ALERT_RESOURCES PCMK_XE_SELECT_RESOURCES

//! \deprecated Use \c PCMK_XE_ATTRIBUTE instead
#define XML_CIB_TAG_ALERT_ATTR PCMK_XE_ATTRIBUTE

//! \deprecated Do not use
#define XML_CIB_TAG_STATE "node_state"

//! \deprecated Use \c PCMK_XE_NODE instead
#define XML_CIB_TAG_NODE PCMK_XE_NODE

//! \deprecated Use \c PCMK_XE_NVPAIR instead
#define XML_CIB_TAG_NVPAIR PCMK_XE_NVPAIR

//! \deprecated Use \c PCMK_XE_CLUSTER_PROPERTY_SET instead
#define XML_CIB_TAG_PROPSET PCMK_XE_CLUSTER_PROPERTY_SET

//! \deprecated Use \c PCMK_XE_INSTANCE_ATTRIBUTES instead
#define XML_TAG_ATTR_SETS PCMK_XE_INSTANCE_ATTRIBUTES

//! \deprecated Use \c PCMK_XE_META_ATTRIBUTES instead
#define XML_TAG_META_SETS PCMK_XE_META_ATTRIBUTES

//! \deprecated Do not use
#define XML_TAG_ATTRS "attributes"

//! \deprecated Do not use
#define XML_TAG_PARAM "param"

//! \deprecated Use \c PCMK_XE_UTILIZATION instead
#define XML_TAG_UTILIZATION PCMK_XE_UTILIZATION

//! \deprecated Use \c PCMK_XE_RESOURCE_REF instead
#define XML_TAG_RESOURCE_REF PCMK_XE_RESOURCE_REF

//! \deprecated Use \c PCMK_XE_PRIMITIVE instead
#define XML_CIB_TAG_RESOURCE PCMK_XE_PRIMITIVE

//! \deprecated Use \c PCMK_XE_GROUP instead
#define XML_CIB_TAG_GROUP PCMK_XE_GROUP

//! \deprecated Use \c PCMK_XE_CLONE instead
#define XML_CIB_TAG_INCARNATION PCMK_XE_CLONE

//! \deprecated Use \c PCMK_XE_BUNDLE instead
#define XML_CIB_TAG_CONTAINER PCMK_XE_BUNDLE

//! \deprecated Use \c PCMK_XE_TEMPLATE instead
#define XML_CIB_TAG_RSC_TEMPLATE PCMK_XE_TEMPLATE

//! \deprecated Do not use
#define XML_CIB_TAG_LRM "lrm"

//! \deprecated Do not use
#define XML_LRM_TAG_RESOURCES "lrm_resources"

//! \deprecated Do not use
#define XML_LRM_TAG_RESOURCE "lrm_resource"

//! \deprecated Do not use
#define XML_LRM_TAG_RSC_OP "lrm_rsc_op"

//! \deprecated Do not use
#define XML_TAG_GRAPH "transition_graph"

//! \deprecated Do not use
#define XML_GRAPH_TAG_RSC_OP "rsc_op"

//! \deprecated Do not use
#define XML_GRAPH_TAG_PSEUDO_EVENT "pseudo_event"

//! \deprecated Do not use
#define XML_GRAPH_TAG_CRM_EVENT "crm_event"

//! \deprecated Do not use
#define XML_GRAPH_TAG_DOWNED "downed"

//! \deprecated Do not use
#define XML_GRAPH_TAG_MAINTENANCE "maintenance"

//! \deprecated Use \c PCMK_XE_RULE instead
#define XML_TAG_RULE PCMK_XE_RULE

//! \deprecated Use \c PCMK_XE_EXPRESSION instead
#define XML_TAG_EXPRESSION PCMK_XE_EXPRESSION

//! \deprecated Use \c PCMK_XE_RSC_COLOCATION instead
#define XML_CONS_TAG_RSC_DEPEND PCMK_XE_RSC_COLOCATION

//! \deprecated Use \c PCMK_XE_RSC_ORDER instead
#define XML_CONS_TAG_RSC_ORDER PCMK_XE_RSC_ORDER

//! \deprecated Use \c PCMK_XE_RSC_LOCATION instead
#define XML_CONS_TAG_RSC_LOCATION PCMK_XE_RSC_LOCATION

//! \deprecated Use \c PCMK_XE_RSC_TICKET instead
#define XML_CONS_TAG_RSC_TICKET PCMK_XE_RSC_TICKET

//! \deprecated Use \c PCMK_XE_RESOURCE_SET instead
#define XML_CONS_TAG_RSC_SET PCMK_XE_RESOURCE_SET

//! \deprecated Do not use
#define XML_CIB_TAG_GENERATION_TUPPLE "generation_tuple"

//! \deprecated Do not use
#define XML_TAG_TRANSIENT_NODEATTRS "transient_attributes"

//! \deprecated Use \c PCMK_XE_ACL_TARGET instead
#define XML_ACL_TAG_USER PCMK_XE_ACL_TARGET

//! \deprecated Do not use
#define XML_ACL_TAG_USERv1 "acl_user"

//! \deprecated Use \c PCMK_XE_ACL_GROUP instead
#define XML_ACL_TAG_GROUP PCMK_XE_ACL_GROUP

//! \deprecated Use \c PCMK_XE_ACL_ROLE instead
#define XML_ACL_TAG_ROLE PCMK_XE_ACL_ROLE

//! \deprecated Use \c PCMK_XE_ACL_PERMISSION instead
#define XML_ACL_TAG_PERMISSION PCMK_XE_ACL_PERMISSION

//! \deprecated Do not use
#define XML_ACL_TAG_ROLE_REFv1 "role_ref"

//! \deprecated Do not use
#define XML_ACL_TAG_READ "read"

//! \deprecated Do not use
#define XML_ACL_TAG_WRITE "write"

//! \deprecated Do not use
#define XML_ACL_TAG_DENY "deny"

//! \deprecated Use \c PCMK_XE_TICKETS instead
#define XML_CIB_TAG_TICKETS PCMK_XE_TICKETS

//! \deprecated Do not use
#define XML_CIB_TAG_TICKET_STATE "ticket_state"

//! \deprecated Use \c PCMK_XE_TAGS instead
#define XML_CIB_TAG_TAGS PCMK_XE_TAGS

//! \deprecated Use \c PCMK_XE_TAG instead
#define XML_CIB_TAG_TAG PCMK_XE_TAG

//! \deprecated Use \c PCMK_XE_OBJ_REF instead
#define XML_CIB_TAG_OBJ_REF PCMK_XE_OBJ_REF

//! \deprecated Use \c PCMK_XE_FENCING_TOPOLOGY instead
#define XML_TAG_FENCING_TOPOLOGY PCMK_XE_FENCING_TOPOLOGY

//! \deprecated Use \c PCMK_XE_FENCING_LEVEL instead
#define XML_TAG_FENCING_LEVEL PCMK_XE_FENCING_LEVEL

//! \deprecated Use \c PCMK_XE_DIFF instead
#define XML_TAG_DIFF PCMK_XE_DIFF

//! \deprecated Use \c PCMK_XE_VERSION instead
#define XML_DIFF_VERSION PCMK_XE_VERSION

//! \deprecated Use \c PCMK_XE_SOURCE instead
#define XML_DIFF_VSOURCE PCMK_XE_SOURCE

//! \deprecated Use \c PCMK_XE_TARGET instead
#define XML_DIFF_VTARGET PCMK_XE_TARGET

//! \deprecated Use \c PCMK_XE_CHANGE instead
#define XML_DIFF_CHANGE PCMK_XE_CHANGE

//! \deprecated Use \c PCMK_XE_CHANGE_LIST instead
#define XML_DIFF_LIST PCMK_XE_CHANGE_LIST

//! \deprecated Use \c PCMK_XE_CHANGE_ATTR instead
#define XML_DIFF_ATTR PCMK_XE_CHANGE_ATTR

//! \deprecated Use \c PCMK_XE_CHANGE_RESULT instead
#define XML_DIFF_RESULT PCMK_XE_CHANGE_RESULT

//! \deprecated Use \c PCMK_XE_POSITION instead
#define XML_DIFF_POSITION PCMK_XE_POSITION

//! \deprecated Do not use
#define F_CRM_DATA "crm_xml"

//! \deprecated Do not use
#define XML_DIFF_MARKER "__crm_diff_marker__"

//! \deprecated Do not use
#define XML_TAG_FAILED "failed"

//! \deprecated Do not use
#define XML_TAG_OPTIONS "options"

//! \deprecated Do not use
#define XML_FAIL_TAG_CIB "failed_update"

//! \deprecated Use \c PCMK_VALUE_CIB_BOOTSTRAP_OPTIONS instead
#define CIB_OPTIONS_FIRST PCMK_VALUE_CIB_BOOTSTRAP_OPTIONS

//! \deprecated Do not use
#define XML_PING_ATTR_PACEMAKERDSTATE_INIT "init"

//! \deprecated Do not use
#define XML_PING_ATTR_PACEMAKERDSTATE_STARTINGDAEMONS "starting_daemons"

//! \deprecated Do not use
#define XML_PING_ATTR_PACEMAKERDSTATE_WAITPING "wait_for_ping"

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_MSG_XML_COMPAT__H
