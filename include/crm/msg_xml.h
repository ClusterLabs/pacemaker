/*
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#ifndef XML_TAGS__H
#  define XML_TAGS__H

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
#  define F_CRM_ELECTION_ID		"election-id"
#  define F_CRM_ELECTION_AGE_S		"election-age-sec"
#  define F_CRM_ELECTION_AGE_US		"election-age-nano-sec"
#  define F_CRM_ELECTION_OWNER		"election-owner"
#  define F_CRM_TGRAPH			"crm-tgraph"
#  define F_CRM_TGRAPH_INPUT		"crm-tgraph-in"

#  define F_CRM_THROTTLE_MODE		"crm-limit-mode"
#  define F_CRM_THROTTLE_MAX		"crm-limit-max"

/*---- Common tags/attrs */
#  define XML_DIFF_MARKER		"__crm_diff_marker__"
#  define XML_ATTR_TAGNAME		F_XML_TAGNAME
#  define XML_TAG_CIB			"cib"
#  define XML_TAG_FAILED		"failed"

#  define XML_ATTR_CRM_VERSION		"crm_feature_set"
#  define XML_ATTR_DIGEST		"digest"
#  define XML_ATTR_VALIDATION		"validate-with"

#  define XML_ATTR_QUORUM_PANIC		"no-quorum-panic"
#  define XML_ATTR_HAVE_QUORUM		"have-quorum"
#  define XML_ATTR_EXPECTED_VOTES	"expected-quorum-votes"
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
#  define XML_ATTR_IDREF			"id-ref"
#  define XML_ATTR_ID_LONG		"long-id"
#  define XML_ATTR_TYPE			"type"
#  define XML_ATTR_FILTER_TYPE		"type-filter"
#  define XML_ATTR_FILTER_ID		"id-filter"
#  define XML_ATTR_FILTER_PRIORITY	"priority-filter"
#  define XML_ATTR_VERBOSE		"verbose"
#  define XML_ATTR_OP			"op"
#  define XML_ATTR_DC			"is_dc"
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
#  define XML_MSG_TAG			"crm_message"
#  define XML_MSG_TAG_DATA		"msg_data"
#  define XML_ATTR_REQUEST		"request"
#  define XML_ATTR_RESPONSE		"response"

#  define XML_ATTR_UNAME		"uname"
#  define XML_ATTR_UUID			"id"
#  define XML_ATTR_REFERENCE		"reference"

#  define XML_FAIL_TAG_RESOURCE		"failed_resource"

#  define XML_FAILRES_ATTR_RESID	"resource_id"
#  define XML_FAILRES_ATTR_REASON	"reason"
#  define XML_FAILRES_ATTR_RESSTATUS	"resource_status"

#  define XML_CRM_TAG_PING		"ping_response"
#  define XML_PING_ATTR_STATUS		"result"
#  define XML_PING_ATTR_SYSFROM		"crm_subsystem"

#  define XML_TAG_FRAGMENT		"cib_fragment"
#  define XML_ATTR_RESULT		"result"
#  define XML_ATTR_SECTION		"section"

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

#  define XML_CIB_TAG_STATE         	"node_state"
#  define XML_CIB_TAG_NODE          	"node"
#  define XML_CIB_TAG_DOMAIN          	"domain"
#  define XML_CIB_TAG_CONSTRAINT    	"constraint"
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
#  define XML_CIB_TAG_MASTER		"master"

#  define XML_CIB_TAG_RSC_TEMPLATE	"template"

#  define XML_RSC_ATTR_RESTART	  	"restart-type"
#  define XML_RSC_ATTR_ORDERED		"ordered"
#  define XML_RSC_ATTR_INTERLEAVE	"interleave"
#  define XML_RSC_ATTR_INCARNATION	"clone"
#  define XML_RSC_ATTR_INCARNATION_MAX	"clone-max"
#  define XML_RSC_ATTR_INCARNATION_NODEMAX	"clone-node-max"
#  define XML_RSC_ATTR_MASTER_MAX	"master-max"
#  define XML_RSC_ATTR_MASTER_NODEMAX	"master-node-max"
#  define XML_RSC_ATTR_STATE		"clone-state"
#  define XML_RSC_ATTR_MANAGED		"is-managed"
#  define XML_RSC_ATTR_TARGET_ROLE	"target-role"
#  define XML_RSC_ATTR_UNIQUE		"globally-unique"
#  define XML_RSC_ATTR_NOTIFY		"notify"
#  define XML_RSC_ATTR_STICKINESS	"resource-stickiness"
#  define XML_RSC_ATTR_FAIL_STICKINESS	"migration-threshold"
#  define XML_RSC_ATTR_FAIL_TIMEOUT	"failure-timeout"
#  define XML_RSC_ATTR_MULTIPLE		"multiple-active"
#  define XML_RSC_ATTR_PRIORITY		"priority"
#  define XML_RSC_ATTR_REQUIRES		"requires"
#  define XML_RSC_ATTR_PROVIDES		"provides"
#  define XML_RSC_ATTR_CONTAINER	"container"
#  define XML_RSC_ATTR_INTERNAL_RSC	"internal_rsc"
#  define XML_RSC_ATTR_MAINTENANCE	"maintenance"
#  define XML_RSC_ATTR_REMOTE_NODE  	"remote-node"

#  define XML_OP_ATTR_ON_FAIL		"on-fail"
#  define XML_OP_ATTR_START_DELAY	"start-delay"
#  define XML_OP_ATTR_ALLOW_MIGRATE	"allow-migrate"
#  define XML_OP_ATTR_DEPENDENT "dependent-on"
#  define XML_OP_ATTR_ORIGIN		"interval-origin"
#  define XML_OP_ATTR_PENDING		"record-pending"

#  define XML_CIB_TAG_LRM		"lrm"
#  define XML_LRM_TAG_RESOURCES     	"lrm_resources"
#  define XML_LRM_TAG_RESOURCE     	"lrm_resource"
#  define XML_LRM_TAG_AGENTS	     	"lrm_agents"
#  define XML_LRM_TAG_AGENT		"lrm_agent"
#  define XML_LRM_TAG_RSC_OP		"lrm_rsc_op"
#  define XML_AGENT_ATTR_CLASS		"class"
#  define XML_AGENT_ATTR_PROVIDER	"provider"
#  define XML_LRM_TAG_ATTRIBUTES	"attributes"

#  define XML_CIB_ATTR_REPLACE       	"replace"
#  define XML_CIB_ATTR_SOURCE       	"source"

#  define XML_CIB_ATTR_HEALTH       	"health"
#  define XML_CIB_ATTR_WEIGHT       	"weight"
#  define XML_CIB_ATTR_PRIORITY     	"priority"
#  define XML_CIB_ATTR_CLEAR        	"clear_on"
#  define XML_CIB_ATTR_SOURCE       	"source"

#  define XML_NODE_JOIN_STATE    	"join"
#  define XML_NODE_EXPECTED     	"expected"
#  define XML_NODE_IN_CLUSTER        	"in_ccm"
#  define XML_NODE_IS_PEER    	"crmd"
#  define XML_NODE_IS_REMOTE    	"remote_node"

#  define XML_CIB_ATTR_SHUTDOWN       	"shutdown"
#  define XML_CIB_ATTR_STONITH	    	"stonith"

#  define XML_LRM_ATTR_INTERVAL		"interval"
#  define XML_LRM_ATTR_TASK		"operation"
#  define XML_LRM_ATTR_TASK_KEY		"operation_key"
#  define XML_LRM_ATTR_TARGET		"on_node"
/*! used for remote nodes.
 *  For remote nodes the action is routed to the 'on_node'
 *  node location, and then from there if 'exec_on' is set
 *  the host will execute the action on the remote node
 *  it controls. */
#  define XML_LRM_ATTR_ROUTER_NODE  "router_node"
#  define XML_LRM_ATTR_TARGET_UUID	"on_node_uuid"
#  define XML_LRM_ATTR_RSCID		"rsc-id"
#  define XML_LRM_ATTR_OPSTATUS		"op-status"
#  define XML_LRM_ATTR_RC		"rc-code"
#  define XML_LRM_ATTR_CALLID		"call-id"
#  define XML_LRM_ATTR_OP_DIGEST	"op-digest"
#  define XML_LRM_ATTR_OP_RESTART	"op-force-restart"
#  define XML_LRM_ATTR_RESTART_DIGEST	"op-restart-digest"

#  define XML_RSC_OP_LAST_CHANGE        "last-rc-change"
#  define XML_RSC_OP_LAST_RUN           "last-run"
#  define XML_RSC_OP_T_EXEC             "exec-time"
#  define XML_RSC_OP_T_QUEUE            "queue-time"

#  define XML_LRM_ATTR_MIGRATE_SOURCE	"migrate_source"
#  define XML_LRM_ATTR_MIGRATE_TARGET	"migrate_target"

#  define XML_TAG_GRAPH			"transition_graph"
#  define XML_GRAPH_TAG_RSC_OP		"rsc_op"
#  define XML_GRAPH_TAG_PSEUDO_EVENT	"pseudo_event"
#  define XML_GRAPH_TAG_CRM_EVENT	"crm_event"

#  define XML_TAG_RULE			"rule"
#  define XML_RULE_ATTR_SCORE		"score"
#  define XML_RULE_ATTR_SCORE_ATTRIBUTE	"score-attribute"
#  define XML_RULE_ATTR_SCORE_MANGLED	"score-attribute-mangled"
#  define XML_RULE_ATTR_ROLE		"role"
#  define XML_RULE_ATTR_RESULT		"result"
#  define XML_RULE_ATTR_BOOLEAN_OP	"boolean-op"

#  define XML_TAG_EXPRESSION		"expression"
#  define XML_EXPR_ATTR_ATTRIBUTE	"attribute"
#  define XML_EXPR_ATTR_OPERATION	"operation"
#  define XML_EXPR_ATTR_VALUE		"value"
#  define XML_EXPR_ATTR_TYPE		"type"

#  define XML_CONS_TAG_RSC_DEPEND	"rsc_colocation"
#  define XML_CONS_TAG_RSC_ORDER	"rsc_order"
#  define XML_CONS_TAG_RSC_LOCATION	"rsc_location"
#  define XML_CONS_TAG_RSC_TICKET	"rsc_ticket"
#  define XML_CONS_TAG_RSC_SET		"resource_set"
#  define XML_CONS_ATTR_SYMMETRICAL	"symmetrical"

#  define XML_COLOC_ATTR_SOURCE		"rsc"
#  define XML_COLOC_ATTR_SOURCE_ROLE	"rsc-role"
#  define XML_COLOC_ATTR_TARGET		"with-rsc"
#  define XML_COLOC_ATTR_TARGET_ROLE	"with-rsc-role"
#  define XML_COLOC_ATTR_NODE_ATTR	"node-attribute"
#  define XML_COLOC_ATTR_SOURCE_INSTANCE	"rsc-instance"
#  define XML_COLOC_ATTR_TARGET_INSTANCE	"with-rsc-instance"

#  define XML_ORDER_ATTR_FIRST		"first"
#  define XML_ORDER_ATTR_THEN		"then"
#  define XML_ORDER_ATTR_FIRST_ACTION	"first-action"
#  define XML_ORDER_ATTR_THEN_ACTION	"then-action"
#  define XML_ORDER_ATTR_FIRST_INSTANCE	"first-instance"
#  define XML_ORDER_ATTR_THEN_INSTANCE	"then-instance"
#  define XML_ORDER_ATTR_KIND		"kind"

#  define XML_TICKET_ATTR_TICKET	"ticket"
#  define XML_TICKET_ATTR_LOSS_POLICY	"loss-policy"

#  define XML_NVPAIR_ATTR_NAME        	"name"
#  define XML_NVPAIR_ATTR_VALUE        	"value"

#  define XML_NODE_ATTR_STATE		"state"

#  define XML_CONFIG_ATTR_DC_DEADTIME	"dc-deadtime"
#  define XML_CONFIG_ATTR_ELECTION_FAIL	"election-timeout"
#  define XML_CONFIG_ATTR_FORCE_QUIT	"shutdown-escalation"
#  define XML_CONFIG_ATTR_RECHECK	"cluster-recheck-interval"

#  define XML_CIB_TAG_GENERATION_TUPPLE	"generation_tuple"

#  define XML_ATTR_TRANSITION_MAGIC	"transition-magic"
#  define XML_ATTR_TRANSITION_KEY	"transition-key"

#  define XML_ATTR_TE_NOWAIT		"op_no_wait"
#  define XML_ATTR_TE_TARGET_RC		"op_target_rc"
#  define XML_ATTR_TE_ALLOWFAIL		"op_allow_fail"
#  define XML_ATTR_LRM_PROBE		"lrm-is-probe"
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

#  include <crm/common/xml.h>

#  define ID(x) crm_element_value(x, XML_ATTR_ID)
#  define INSTANCE(x) crm_element_value(x, XML_CIB_ATTR_INSTANCE)
#  define TSTAMP(x) crm_element_value(x, XML_ATTR_TSTAMP)
#  define TYPE(x) crm_element_name(x)
#  define NAME(x) crm_element_value(x, XML_NVPAIR_ATTR_NAME)
#  define VALUE(x) crm_element_value(x, XML_NVPAIR_ATTR_VALUE)

#endif
