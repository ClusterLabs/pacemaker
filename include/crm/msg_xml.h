/*
 * Copyright 2004-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_MSG_XML__H
#  define PCMK__CRM_MSG_XML__H

#  include <crm/common/xml.h>

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
#include <crm/msg_xml_compat.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* This file defines constants for various XML syntax (mainly element and
 * attribute names).
 *
 * For consistency, new constants should start with "PCMK_", followed by "XE"
 * for XML element names, "XA" for XML attribute names, and "META" for meta
 * attribute names. Old names that don't follow this policy should eventually be
 * deprecated and replaced with names that do.
 */

/*
 * XML elements
 */

#define PCMK_XE_DATE_EXPRESSION             "date_expression"
#define PCMK_XE_OP_EXPRESSION               "op_expression"

/* This has been deprecated as a CIB element (an alias for <clone> with
 * "promotable" set to "true") since 2.0.0.
 */
#define PCMK_XE_PROMOTABLE_LEGACY           "master"

#define PCMK_XE_RSC_EXPRESSION              "rsc_expression"


/*
 * XML attributes
 */

/* These have been deprecated as CIB <clone> element attributes (aliases for
 * "promoted-max" and "promoted-node-max") since 2.0.0.
 */
#define PCMK_XA_PROMOTED_MAX_LEGACY         "master-max"
#define PCMK_XA_PROMOTED_NODE_MAX_LEGACY    "master-node-max"


/*
 * Meta attributes
 */

#define PCMK_META_ENABLED                   "enabled"


/*
 * Older constants that don't follow current naming
 */

#  ifndef F_ORIG
#    define F_ORIG    "src"
#  endif

#  ifndef F_SEQ
#    define F_SEQ		"seq"
#  endif

#  ifndef F_SUBTYPE
#    define F_SUBTYPE "subt"
#  endif

#  ifndef F_TYPE
#    define F_TYPE    "t"
#  endif

#  ifndef F_CLIENTNAME
#    define	F_CLIENTNAME	"cn"
#  endif

#  ifndef F_XML_TAGNAME
#    define F_XML_TAGNAME	"__name__"
#  endif

#  ifndef T_CRM
#    define T_CRM     "crmd"
#  endif

#  ifndef T_ATTRD
#    define T_ATTRD     "attrd"
#  endif

#  define CIB_OPTIONS_FIRST "cib-bootstrap-options"

#  define F_CRM_DATA			"crm_xml"
#  define F_CRM_TASK			"crm_task"
#  define F_CRM_HOST_TO			"crm_host_to"
#  define F_CRM_MSG_TYPE		F_SUBTYPE
#  define F_CRM_SYS_TO			"crm_sys_to"
#  define F_CRM_SYS_FROM		"crm_sys_from"
#  define F_CRM_HOST_FROM		F_ORIG
#  define F_CRM_REFERENCE		XML_ATTR_REFERENCE
#  define F_CRM_VERSION			XML_ATTR_VERSION
#  define F_CRM_ORIGIN			"origin"
#  define F_CRM_USER			"crm_user"
#  define F_CRM_JOIN_ID			"join_id"
#  define F_CRM_DC_LEAVING      "dc-leaving"
#  define F_CRM_ELECTION_ID		"election-id"
#  define F_CRM_ELECTION_AGE_S		"election-age-sec"
#  define F_CRM_ELECTION_AGE_US		"election-age-nano-sec"
#  define F_CRM_ELECTION_OWNER		"election-owner"
#  define F_CRM_TGRAPH			"crm-tgraph-file"
#  define F_CRM_TGRAPH_INPUT		"crm-tgraph-in"

#  define F_CRM_THROTTLE_MODE		"crm-limit-mode"
#  define F_CRM_THROTTLE_MAX		"crm-limit-max"

/*---- Common tags/attrs */
#  define XML_DIFF_MARKER		"__crm_diff_marker__"
#  define XML_TAG_CIB			"cib"
#  define XML_TAG_FAILED		"failed"

#  define XML_ATTR_CRM_VERSION		"crm_feature_set"
#  define XML_ATTR_DIGEST		"digest"
#  define XML_ATTR_VALIDATION		"validate-with"

#  define XML_ATTR_QUORUM_PANIC		"no-quorum-panic"
#  define XML_ATTR_HAVE_QUORUM		"have-quorum"
#  define XML_ATTR_HAVE_WATCHDOG	"have-watchdog"
#  define XML_ATTR_GENERATION		"epoch"
#  define XML_ATTR_GENERATION_ADMIN	"admin_epoch"
#  define XML_ATTR_NUMUPDATES		"num_updates"
#  define XML_ATTR_TIMEOUT		"timeout"
#  define XML_ATTR_ORIGIN		"crm-debug-origin"
#  define XML_ATTR_TSTAMP		"crm-timestamp"
#  define XML_CIB_ATTR_WRITTEN		"cib-last-written"
#  define XML_ATTR_VERSION		"version"
#  define XML_ATTR_DESC			"description"
#  define XML_ATTR_ID			"id"
#  define XML_ATTR_NAME			"name"
#  define XML_ATTR_IDREF			"id-ref"
#  define XML_ATTR_ID_LONG		"long-id"
#  define XML_ATTR_TYPE			"type"
#  define XML_ATTR_VERBOSE		"verbose"
#  define XML_ATTR_OP			"op"
#  define XML_ATTR_DC_UUID		"dc-uuid"
#  define XML_ATTR_UPDATE_ORIG		"update-origin"
#  define XML_ATTR_UPDATE_CLIENT	"update-client"
#  define XML_ATTR_UPDATE_USER		"update-user"

#  define XML_BOOLEAN_TRUE		"true"
#  define XML_BOOLEAN_FALSE		"false"
#  define XML_BOOLEAN_YES		XML_BOOLEAN_TRUE
#  define XML_BOOLEAN_NO		XML_BOOLEAN_FALSE

#  define XML_TAG_OPTIONS		"options"

/*---- top level tags/attrs */
#  define XML_ATTR_REQUEST		"request"
#  define XML_ATTR_RESPONSE		"response"

#  define XML_ATTR_UNAME		"uname"
#  define XML_ATTR_REFERENCE		"reference"

#  define XML_CRM_TAG_PING		"ping_response"
#  define XML_PING_ATTR_STATUS		"result"
#  define XML_PING_ATTR_SYSFROM		"crm_subsystem"
#  define XML_PING_ATTR_CRMDSTATE   "crmd_state"
#  define XML_PING_ATTR_PACEMAKERDSTATE "pacemakerd_state"
#  define XML_PING_ATTR_PACEMAKERDSTATE_INIT "init"
#  define XML_PING_ATTR_PACEMAKERDSTATE_STARTINGDAEMONS "starting_daemons"
#  define XML_PING_ATTR_PACEMAKERDSTATE_WAITPING "wait_for_ping"
#  define XML_PING_ATTR_PACEMAKERDSTATE_RUNNING "running"
#  define XML_PING_ATTR_PACEMAKERDSTATE_SHUTTINGDOWN "shutting_down"
#  define XML_PING_ATTR_PACEMAKERDSTATE_SHUTDOWNCOMPLETE "shutdown_complete"
#  define XML_PING_ATTR_PACEMAKERDSTATE_REMOTE "remote"

#  define XML_TAG_FRAGMENT		"cib_fragment"

#  define XML_FAIL_TAG_CIB		"failed_update"

#  define XML_FAILCIB_ATTR_ID		"id"
#  define XML_FAILCIB_ATTR_OBJTYPE	"object_type"
#  define XML_FAILCIB_ATTR_OP		"operation"
#  define XML_FAILCIB_ATTR_REASON	"reason"

/*---- CIB specific tags/attrs */
#  define XML_CIB_TAG_SECTION_ALL	"all"
#  define XML_CIB_TAG_CONFIGURATION	"configuration"
#  define XML_CIB_TAG_STATUS       	"status"
#  define XML_CIB_TAG_RESOURCES		"resources"
#  define XML_CIB_TAG_NODES         	"nodes"
#  define XML_CIB_TAG_DOMAINS         	"domains"
#  define XML_CIB_TAG_CONSTRAINTS   	"constraints"
#  define XML_CIB_TAG_CRMCONFIG   	"crm_config"
#  define XML_CIB_TAG_OPCONFIG		"op_defaults"
#  define XML_CIB_TAG_RSCCONFIG   	"rsc_defaults"
#  define XML_CIB_TAG_ACLS   		"acls"
#  define XML_CIB_TAG_ALERTS    	"alerts"
#  define XML_CIB_TAG_ALERT   		"alert"
#  define XML_CIB_TAG_ALERT_RECIPIENT	"recipient"
#  define XML_CIB_TAG_ALERT_SELECT      "select"
#  define XML_CIB_TAG_ALERT_ATTRIBUTES  "select_attributes"
#  define XML_CIB_TAG_ALERT_FENCING     "select_fencing"
#  define XML_CIB_TAG_ALERT_NODES       "select_nodes"
#  define XML_CIB_TAG_ALERT_RESOURCES   "select_resources"
#  define XML_CIB_TAG_ALERT_ATTR        "attribute"

#  define XML_CIB_TAG_STATE         	"node_state"
#  define XML_CIB_TAG_NODE          	"node"
#  define XML_CIB_TAG_NVPAIR        	"nvpair"

#  define XML_CIB_TAG_PROPSET	   	"cluster_property_set"
#  define XML_TAG_ATTR_SETS	   	"instance_attributes"
#  define XML_TAG_META_SETS	   	"meta_attributes"
#  define XML_TAG_ATTRS			"attributes"
#  define XML_TAG_PARAMS		"parameters"
#  define XML_TAG_PARAM			"param"
#  define XML_TAG_UTILIZATION		"utilization"

#  define XML_TAG_RESOURCE_REF		"resource_ref"
#  define XML_CIB_TAG_RESOURCE	  	"primitive"
#  define XML_CIB_TAG_GROUP	  	"group"
#  define XML_CIB_TAG_INCARNATION	"clone"
#  define XML_CIB_TAG_CONTAINER		"bundle"

#  define XML_CIB_TAG_RSC_TEMPLATE	"template"

#  define XML_RSC_ATTR_TARGET           "container-attribute-target"
#  define XML_RSC_ATTR_RESTART	  	"restart-type"
#  define XML_RSC_ATTR_ORDERED		"ordered"
#  define XML_RSC_ATTR_INTERLEAVE	"interleave"
#  define XML_RSC_ATTR_INCARNATION	"clone"
#  define XML_RSC_ATTR_INCARNATION_MAX	"clone-max"
#  define XML_RSC_ATTR_INCARNATION_MIN	"clone-min"
#  define XML_RSC_ATTR_INCARNATION_NODEMAX	"clone-node-max"
#  define XML_RSC_ATTR_PROMOTABLE       "promotable"
#  define XML_RSC_ATTR_PROMOTED_MAX     "promoted-max"
#  define XML_RSC_ATTR_PROMOTED_NODEMAX "promoted-node-max"
#  define XML_RSC_ATTR_MANAGED		"is-managed"
#  define XML_RSC_ATTR_TARGET_ROLE	"target-role"
#  define XML_RSC_ATTR_UNIQUE		"globally-unique"
#  define XML_RSC_ATTR_NOTIFY		"notify"
#  define XML_RSC_ATTR_STICKINESS	"resource-stickiness"
#  define XML_RSC_ATTR_FAIL_STICKINESS	"migration-threshold"
#  define XML_RSC_ATTR_FAIL_TIMEOUT	"failure-timeout"
#  define XML_RSC_ATTR_MULTIPLE		"multiple-active"
#  define XML_RSC_ATTR_REQUIRES		"requires"
#  define XML_RSC_ATTR_CONTAINER	"container"
#  define XML_RSC_ATTR_INTERNAL_RSC	"internal_rsc"
#  define XML_RSC_ATTR_MAINTENANCE	"maintenance"
#  define XML_RSC_ATTR_REMOTE_NODE  	"remote-node"
#  define XML_RSC_ATTR_CLEAR_OP         "clear_failure_op"
#  define XML_RSC_ATTR_CLEAR_INTERVAL   "clear_failure_interval"
#  define XML_RSC_ATTR_REMOTE_RA_ADDR   "addr"
#  define XML_RSC_ATTR_REMOTE_RA_SERVER "server"
#  define XML_RSC_ATTR_REMOTE_RA_PORT   "port"
#  define XML_RSC_ATTR_CRITICAL         "critical"

#  define XML_REMOTE_ATTR_RECONNECT_INTERVAL "reconnect_interval"

#  define XML_OP_ATTR_ON_FAIL		"on-fail"
#  define XML_OP_ATTR_START_DELAY	"start-delay"
#  define XML_OP_ATTR_ALLOW_MIGRATE	"allow-migrate"
#  define XML_OP_ATTR_ORIGIN		"interval-origin"
#  define XML_OP_ATTR_PENDING		"record-pending"
#  define XML_OP_ATTR_DIGESTS_ALL       "digests-all"
#  define XML_OP_ATTR_DIGESTS_SECURE    "digests-secure"

#  define XML_CIB_TAG_LRM		"lrm"
#  define XML_LRM_TAG_RESOURCES     	"lrm_resources"
#  define XML_LRM_TAG_RESOURCE     	"lrm_resource"
#  define XML_LRM_TAG_RSC_OP		"lrm_rsc_op"
#  define XML_AGENT_ATTR_CLASS		"class"
#  define XML_AGENT_ATTR_PROVIDER	"provider"

//! \deprecated Do not use (will be removed in a future release)
#  define XML_CIB_ATTR_REPLACE       	"replace"

#  define XML_CIB_ATTR_SOURCE       	"source"

#  define XML_CIB_ATTR_PRIORITY     	"priority"
#  define XML_CIB_ATTR_SOURCE       	"source"

#  define XML_NODE_JOIN_STATE    	"join"
#  define XML_NODE_EXPECTED     	"expected"
#  define XML_NODE_IN_CLUSTER        	"in_ccm"
#  define XML_NODE_IS_PEER    	"crmd"
#  define XML_NODE_IS_REMOTE    	"remote_node"
#  define XML_NODE_IS_FENCED		"node_fenced"
#  define XML_NODE_IS_MAINTENANCE   "node_in_maintenance"

#  define XML_CIB_ATTR_SHUTDOWN       	"shutdown"

/* Aside from being an old name for the executor, LRM is a misnomer here because
 * the controller and scheduler use these to track actions, which are not always
 * executor operations.
 */

// XML attribute that takes interval specification (user-facing configuration)
#  define XML_LRM_ATTR_INTERVAL		"interval"

// XML attribute that takes interval in milliseconds (daemon APIs)
// (identical value as above, but different constant allows clearer code intent)
#  define XML_LRM_ATTR_INTERVAL_MS  XML_LRM_ATTR_INTERVAL

#  define XML_LRM_ATTR_TASK		"operation"
#  define XML_LRM_ATTR_TASK_KEY		"operation_key"
#  define XML_LRM_ATTR_TARGET		"on_node"
#  define XML_LRM_ATTR_TARGET_UUID	"on_node_uuid"
/*! Actions to be executed on Pacemaker Remote nodes are routed through the
 *  controller on the cluster node hosting the remote connection. That cluster
 *  node is considered the router node for the action.
 */
#  define XML_LRM_ATTR_ROUTER_NODE  "router_node"
#  define XML_LRM_ATTR_RSCID		"rsc-id"
#  define XML_LRM_ATTR_OPSTATUS		"op-status"
#  define XML_LRM_ATTR_RC		"rc-code"
#  define XML_LRM_ATTR_CALLID		"call-id"
#  define XML_LRM_ATTR_OP_DIGEST	"op-digest"
#  define XML_LRM_ATTR_OP_RESTART	"op-force-restart"
#  define XML_LRM_ATTR_OP_SECURE	"op-secure-params"
#  define XML_LRM_ATTR_RESTART_DIGEST	"op-restart-digest"
#  define XML_LRM_ATTR_SECURE_DIGEST	"op-secure-digest"
#  define XML_LRM_ATTR_EXIT_REASON	"exit-reason"

#  define XML_RSC_OP_LAST_CHANGE        "last-rc-change"
#  define XML_RSC_OP_LAST_RUN           "last-run"  // deprecated since 2.0.3
#  define XML_RSC_OP_T_EXEC             "exec-time"
#  define XML_RSC_OP_T_QUEUE            "queue-time"

#  define XML_LRM_ATTR_MIGRATE_SOURCE	"migrate_source"
#  define XML_LRM_ATTR_MIGRATE_TARGET	"migrate_target"

#  define XML_TAG_GRAPH			"transition_graph"
#  define XML_GRAPH_TAG_RSC_OP		"rsc_op"
#  define XML_GRAPH_TAG_PSEUDO_EVENT	"pseudo_event"
#  define XML_GRAPH_TAG_CRM_EVENT	"crm_event"
#  define XML_GRAPH_TAG_DOWNED            "downed"
#  define XML_GRAPH_TAG_MAINTENANCE       "maintenance"

#  define XML_TAG_RULE			"rule"
#  define XML_RULE_ATTR_SCORE		"score"
#  define XML_RULE_ATTR_SCORE_ATTRIBUTE	"score-attribute"
#  define XML_RULE_ATTR_ROLE		"role"
#  define XML_RULE_ATTR_BOOLEAN_OP	"boolean-op"

#  define XML_TAG_EXPRESSION		"expression"
#  define XML_EXPR_ATTR_ATTRIBUTE	"attribute"
#  define XML_EXPR_ATTR_OPERATION	"operation"
#  define XML_EXPR_ATTR_VALUE		"value"
#  define XML_EXPR_ATTR_TYPE		"type"
#  define XML_EXPR_ATTR_VALUE_SOURCE	"value-source"

#  define XML_CONS_TAG_RSC_DEPEND	"rsc_colocation"
#  define XML_CONS_TAG_RSC_ORDER	"rsc_order"
#  define XML_CONS_TAG_RSC_LOCATION	"rsc_location"
#  define XML_CONS_TAG_RSC_TICKET	"rsc_ticket"
#  define XML_CONS_TAG_RSC_SET		"resource_set"
#  define XML_CONS_ATTR_SYMMETRICAL	"symmetrical"

#  define XML_LOCATION_ATTR_DISCOVERY	"resource-discovery"

#  define XML_COLOC_ATTR_SOURCE		"rsc"
#  define XML_COLOC_ATTR_SOURCE_ROLE	"rsc-role"
#  define XML_COLOC_ATTR_TARGET		"with-rsc"
#  define XML_COLOC_ATTR_TARGET_ROLE	"with-rsc-role"
#  define XML_COLOC_ATTR_NODE_ATTR	"node-attribute"
#  define XML_COLOC_ATTR_INFLUENCE          "influence"

//! \deprecated Deprecated since 2.1.5
#  define XML_COLOC_ATTR_SOURCE_INSTANCE	"rsc-instance"

//! \deprecated Deprecated since 2.1.5
#  define XML_COLOC_ATTR_TARGET_INSTANCE	"with-rsc-instance"

#  define XML_LOC_ATTR_SOURCE           "rsc"
#  define XML_LOC_ATTR_SOURCE_PATTERN   "rsc-pattern"

#  define XML_ORDER_ATTR_FIRST		"first"
#  define XML_ORDER_ATTR_THEN		"then"
#  define XML_ORDER_ATTR_FIRST_ACTION	"first-action"
#  define XML_ORDER_ATTR_THEN_ACTION	"then-action"
#  define XML_ORDER_ATTR_KIND		"kind"

//! \deprecated Deprecated since 2.1.5
#  define XML_ORDER_ATTR_FIRST_INSTANCE	"first-instance"

//! \deprecated Deprecated since 2.1.5
#  define XML_ORDER_ATTR_THEN_INSTANCE	"then-instance"

#  define XML_TICKET_ATTR_TICKET	"ticket"
#  define XML_TICKET_ATTR_LOSS_POLICY	"loss-policy"

#  define XML_NVPAIR_ATTR_NAME        	"name"
#  define XML_NVPAIR_ATTR_VALUE        	"value"

#  define XML_NODE_ATTR_RSC_DISCOVERY   "resource-discovery-enabled"

#  define XML_CONFIG_ATTR_DC_DEADTIME	"dc-deadtime"
#  define XML_CONFIG_ATTR_ELECTION_FAIL	"election-timeout"
#  define XML_CONFIG_ATTR_FORCE_QUIT	"shutdown-escalation"
#  define XML_CONFIG_ATTR_RECHECK	"cluster-recheck-interval"
#  define XML_CONFIG_ATTR_FENCE_REACTION	"fence-reaction"
#  define XML_CONFIG_ATTR_SHUTDOWN_LOCK         "shutdown-lock"
#  define XML_CONFIG_ATTR_SHUTDOWN_LOCK_LIMIT   "shutdown-lock-limit"
#  define XML_CONFIG_ATTR_PRIORITY_FENCING_DELAY "priority-fencing-delay"
#  define XML_CONFIG_ATTR_NODE_PENDING_TIMEOUT "node-pending-timeout"

#  define XML_ALERT_ATTR_PATH		"path"
#  define XML_ALERT_ATTR_TIMEOUT	"timeout"
#  define XML_ALERT_ATTR_TSTAMP_FORMAT	"timestamp-format"
#  define XML_ALERT_ATTR_REC_VALUE	"value"

#  define XML_CIB_TAG_GENERATION_TUPPLE	"generation_tuple"

#  define XML_ATTR_TRANSITION_MAGIC	"transition-magic"
#  define XML_ATTR_TRANSITION_KEY	"transition-key"

#  define XML_ATTR_TE_NOWAIT		"op_no_wait"
#  define XML_ATTR_TE_TARGET_RC		"op_target_rc"
#  define XML_TAG_TRANSIENT_NODEATTRS	"transient_attributes"

#  define XML_TAG_DIFF_ADDED		"diff-added"
#  define XML_TAG_DIFF_REMOVED		"diff-removed"

#  define XML_ACL_TAG_USER		"acl_target"
#  define XML_ACL_TAG_USERv1		"acl_user"
#  define XML_ACL_TAG_GROUP		"acl_group"
#  define XML_ACL_TAG_ROLE		"acl_role"
#  define XML_ACL_TAG_PERMISSION	"acl_permission"
#  define XML_ACL_TAG_ROLE_REF 		"role"
#  define XML_ACL_TAG_ROLE_REFv1	"role_ref"
#  define XML_ACL_ATTR_KIND		"kind"
#  define XML_ACL_TAG_READ		"read"
#  define XML_ACL_TAG_WRITE		"write"
#  define XML_ACL_TAG_DENY		"deny"
#  define XML_ACL_ATTR_REF		"reference"
#  define XML_ACL_ATTR_REFv1		"ref"
#  define XML_ACL_ATTR_TAG		"object-type"
#  define XML_ACL_ATTR_TAGv1		"tag"
#  define XML_ACL_ATTR_XPATH		"xpath"
#  define XML_ACL_ATTR_ATTRIBUTE	"attribute"

#  define XML_CIB_TAG_TICKETS		"tickets"
#  define XML_CIB_TAG_TICKET_STATE	"ticket_state"

#  define XML_CIB_TAG_TAGS   		"tags"
#  define XML_CIB_TAG_TAG   		"tag"
#  define XML_CIB_TAG_OBJ_REF 		"obj_ref"

#  define XML_TAG_FENCING_TOPOLOGY      "fencing-topology"
#  define XML_TAG_FENCING_LEVEL         "fencing-level"
#  define XML_ATTR_STONITH_INDEX        "index"
#  define XML_ATTR_STONITH_TARGET       "target"
#  define XML_ATTR_STONITH_TARGET_VALUE     "target-value"
#  define XML_ATTR_STONITH_TARGET_PATTERN   "target-pattern"
#  define XML_ATTR_STONITH_TARGET_ATTRIBUTE "target-attribute"
#  define XML_ATTR_STONITH_DEVICES      "devices"

#  define XML_TAG_DIFF                  "diff"
#  define XML_DIFF_VERSION              "version"
#  define XML_DIFF_VSOURCE              "source"
#  define XML_DIFF_VTARGET              "target"
#  define XML_DIFF_CHANGE               "change"
#  define XML_DIFF_LIST                 "change-list"
#  define XML_DIFF_ATTR                 "change-attr"
#  define XML_DIFF_RESULT               "change-result"
#  define XML_DIFF_OP                   "operation"
#  define XML_DIFF_PATH                 "path"
#  define XML_DIFF_POSITION             "position"

#  define ID(x) crm_element_value(x, XML_ATTR_ID)
#  define TYPE(x) crm_element_name(x)

#ifdef __cplusplus
}
#endif

#endif
