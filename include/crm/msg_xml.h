/*
 * Copyright 2004-2024 the Pacemaker project contributors
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
 * For consistency, new constants should start with "PCMK_", followed by:
 * * "XE" for XML element names
 * * "XA" for XML attribute names
 * * "OPT" for cluster option (property) names
 * * "META" for meta-attribute names
 * * "VALUE" for enumerated values for various options
 *
 * Old names that don't follow this policy should eventually be deprecated and
 * replaced with names that do.
 *
 * Symbols should be public if the user may specify them somewhere (especially
 * the CIB) or if they're part of a well-defined structure that a user may need
 * to parse. They should be internal if they're used only internally to
 * Pacemaker (such as daemon IPC/CPG message XML).
 *
 * Constants belong in the following locations:
 * * Public "XE" and "XA": msg_xml.h
 * * Internal "XE" and "XA": crm_internal.h
 * * Public "OPT", "META", and "VALUE": options.h
 * * Internal "OPT", "META", and "VALUE": options_internal.h
 *
 * For meta-attributes that can be specified as either XML attributes or nvpair
 * names, use "META" unless using both "XA" and "META" constants adds clarity.
 * An example is operation attributes, which can be specified either as
 * attributes of the PCMK_XE_OP element or as nvpairs in a meta-attribute set
 * beneath the PCMK_XE_OP element.
 */

/*
 * XML elements
 */

#define PCMK_XE_ACLS                        "acls"
#define PCMK_XE_ALERT                       "alert"
#define PCMK_XE_ALERTS                      "alerts"
#define PCMK_XE_ATTRIBUTE                   "attribute"
#define PCMK_XE_CIB                         "cib"
#define PCMK_XE_CONFIGURATION               "configuration"
#define PCMK_XE_CONSTRAINTS                 "constraints"
#define PCMK_XE_CONTENT                     "content"
#define PCMK_XE_CRM_CONFIG                  "crm_config"
#define PCMK_XE_DATE_EXPRESSION             "date_expression"
#define PCMK_XE_LONGDESC                    "longdesc"
#define PCMK_XE_NODES                       "nodes"
#define PCMK_XE_OP                          "op"
#define PCMK_XE_OP_DEFAULTS                 "op_defaults"
#define PCMK_XE_OPERATION                   "operation"
#define PCMK_XE_OP_EXPRESSION               "op_expression"
#define PCMK_XE_OPTION                      "option"
#define PCMK_XE_RECIPIENT                   "recipient"
#define PCMK_XE_RESOURCES                   "resources"
#define PCMK_XE_ROLE                        "role"
#define PCMK_XE_PARAMETER                   "parameter"
#define PCMK_XE_PARAMETERS                  "parameters"
#define PCMK_XE_RESOURCE_AGENT              "resource-agent"
#define PCMK_XE_RSC_DEFAULTS                "rsc_defaults"
#define PCMK_XE_RSC_EXPRESSION              "rsc_expression"
#define PCMK_XE_SELECT                      "select"
#define PCMK_XE_SELECT_ATTRIBUTES           "select_attributes"
#define PCMK_XE_SELECT_FENCING              "select_fencing"
#define PCMK_XE_SELECT_NODES                "select_nodes"
#define PCMK_XE_SELECT_RESOURCES            "select_resources"
#define PCMK_XE_SHORTDESC                   "shortdesc"
#define PCMK_XE_STATUS                      "status"
#define PCMK_XE_VERSION                     "version"


/*
 * XML attributes
 */

#define PCMK_XA_ADMIN_EPOCH                 "admin_epoch"
#define PCMK_XA_ATTRIBUTE                   "attribute"
#define PCMK_XA_BOOLEAN_OP                  "boolean-op"
#define PCMK_XA_CIB_LAST_WRITTEN            "cib-last-written"
#define PCMK_XA_CLASS                       "class"
#define PCMK_XA_CRM_DEBUG_ORIGIN            "crm-debug-origin"
#define PCMK_XA_CRM_FEATURE_SET             "crm_feature_set"
#define PCMK_XA_CRM_TIMESTAMP               "crm-timestamp"
#define PCMK_XA_DC_UUID                     "dc-uuid"
#define PCMK_XA_DEFAULT                     "default"
#define PCMK_XA_DESCRIPTION                 "description"
#define PCMK_XA_DEVICES                     "devices"
#define PCMK_XA_EPOCH                       "epoch"
#define PCMK_XA_EXEC_TIME                   "exec-time"
#define PCMK_XA_EXIT_REASON                 "exit-reason"
#define PCMK_XA_FIRST                       "first"
#define PCMK_XA_FIRST_ACTION                "first-action"
#define PCMK_XA_FORMAT                      "format"
#define PCMK_XA_HAVE_QUORUM                 "have-quorum"
#define PCMK_XA_ID                          "id"
#define PCMK_XA_ID_REF                      "id-ref"
#define PCMK_XA_INDEX                       "index"
#define PCMK_XA_INFLUENCE                   "influence"
#define PCMK_XA_KIND                        "kind"
#define PCMK_XA_LANG                        "lang"
#define PCMK_XA_LAST_RC_CHANGE              "last-rc-change"
#define PCMK_XA_LOSS_POLICY                 "loss-policy"
#define PCMK_XA_NAME                        "name"
#define PCMK_XA_NO_QUORUM_PANIC             "no-quorum-panic"
#define PCMK_XA_NODE_ATTRIBUTE              "node-attribute"
#define PCMK_XA_NUM_UPDATES                 "num_updates"
#define PCMK_XA_OBJECT_TYPE                 "object-type"
#define PCMK_XA_OP                          "op"
#define PCMK_XA_OPERATION                   "operation"
#define PCMK_XA_ORIGIN                      "origin"
#define PCMK_XA_PATH                        "path"
#define PCMK_XA_PROVIDER                    "provider"
#define PCMK_XA_QUEUE_TIME                  "queue-time"
#define PCMK_XA_REASON                      "reason"
#define PCMK_XA_REFERENCE                   "reference"
#define PCMK_XA_REQUEST                     "request"
#define PCMK_XA_RESOURCE_DISCOVERY          "resource-discovery"
#define PCMK_XA_RESULT                      "result"
#define PCMK_XA_ROLE                        "role"
#define PCMK_XA_RSC                         "rsc"
#define PCMK_XA_RSC_PATTERN                 "rsc-pattern"
#define PCMK_XA_RSC_ROLE                    "rsc-role"
#define PCMK_XA_SCORE                       "score"
#define PCMK_XA_SCORE_ATTRIBUTE             "score-attribute"
#define PCMK_XA_SYMMETRICAL                 "symmetrical"
#define PCMK_XA_TARGET                      "target"
#define PCMK_XA_TARGET_ATTRIBUTE            "target-attribute"
#define PCMK_XA_TARGET_PATTERN              "target-pattern"
#define PCMK_XA_TARGET_VALUE                "target-value"
#define PCMK_XA_TICKET                      "ticket"
#define PCMK_XA_THEN                        "then"
#define PCMK_XA_THEN_ACTION                 "then-action"
#define PCMK_XA_TYPE                        "type"
#define PCMK_XA_UNAME                       "uname"
#define PCMK_XA_UPDATE_CLIENT               "update-client"
#define PCMK_XA_UPDATE_ORIGIN               "update-origin"
#define PCMK_XA_UPDATE_USER                 "update-user"
#define PCMK_XA_VALIDATE_WITH               "validate-with"
#define PCMK_XA_VALUE                       "value"
#define PCMK_XA_VALUE_SOURCE                "value-source"
#define PCMK_XA_VERSION                     "version"
#define PCMK_XA_WITH_RSC                    "with-rsc"
#define PCMK_XA_WITH_RSC_ROLE               "with-rsc-role"
#define PCMK_XA_XPATH                       "xpath"


/*
 * Older constants that don't follow current naming
 */

#  ifndef T_CRM
#    define T_CRM     "crmd"
#  endif

#  ifndef T_ATTRD
#    define T_ATTRD     "attrd"
#  endif

#  define CIB_OPTIONS_FIRST "cib-bootstrap-options"

#  define F_CRM_DATA			"crm_xml"

/*---- Common tags/attrs */
#  define XML_DIFF_MARKER		"__crm_diff_marker__"
#  define XML_TAG_FAILED		"failed"

#  define XML_TAG_OPTIONS		"options"

/*---- top level tags/attrs */
#  define XML_PING_ATTR_PACEMAKERDSTATE_INIT "init"
#  define XML_PING_ATTR_PACEMAKERDSTATE_STARTINGDAEMONS "starting_daemons"
#  define XML_PING_ATTR_PACEMAKERDSTATE_WAITPING "wait_for_ping"
#  define XML_PING_ATTR_PACEMAKERDSTATE_RUNNING "running"
#  define XML_PING_ATTR_PACEMAKERDSTATE_SHUTTINGDOWN "shutting_down"
#  define XML_PING_ATTR_PACEMAKERDSTATE_SHUTDOWNCOMPLETE "shutdown_complete"
#  define XML_PING_ATTR_PACEMAKERDSTATE_REMOTE "remote"

#  define XML_FAIL_TAG_CIB		"failed_update"

/*---- CIB specific tags/attrs */
#  define XML_CIB_TAG_SECTION_ALL	"all"

#  define XML_CIB_TAG_NODE          	"node"
#  define XML_CIB_TAG_NVPAIR        	"nvpair"

#  define XML_CIB_TAG_PROPSET	   	"cluster_property_set"
#  define XML_TAG_ATTR_SETS	   	"instance_attributes"
#  define XML_TAG_META_SETS	   	"meta_attributes"
#  define XML_TAG_ATTRS			"attributes"
#  define XML_TAG_PARAM			"param"
#  define XML_TAG_UTILIZATION		"utilization"

#  define XML_TAG_RESOURCE_REF		"resource_ref"
#  define XML_CIB_TAG_RESOURCE	  	"primitive"
#  define XML_CIB_TAG_GROUP	  	"group"
#  define XML_CIB_TAG_INCARNATION	"clone"
#  define XML_CIB_TAG_CONTAINER		"bundle"

#  define XML_CIB_TAG_RSC_TEMPLATE	"template"

#  define XML_CIB_TAG_LRM		"lrm"
#  define XML_LRM_TAG_RESOURCES     	"lrm_resources"
#  define XML_LRM_TAG_RESOURCE     	"lrm_resource"
#  define XML_LRM_TAG_RSC_OP		"lrm_rsc_op"

#  define XML_NODE_IS_REMOTE    	"remote_node"
#  define XML_NODE_IS_FENCED		"node_fenced"
#  define XML_NODE_IS_MAINTENANCE   "node_in_maintenance"

#  define XML_CIB_ATTR_SHUTDOWN       	"shutdown"

#  define XML_TAG_GRAPH			"transition_graph"
#  define XML_GRAPH_TAG_RSC_OP		"rsc_op"
#  define XML_GRAPH_TAG_PSEUDO_EVENT	"pseudo_event"
#  define XML_GRAPH_TAG_CRM_EVENT	"crm_event"
#  define XML_GRAPH_TAG_DOWNED            "downed"
#  define XML_GRAPH_TAG_MAINTENANCE       "maintenance"

#  define XML_TAG_RULE			"rule"

#  define XML_TAG_EXPRESSION		"expression"

#  define XML_CONS_TAG_RSC_DEPEND	"rsc_colocation"
#  define XML_CONS_TAG_RSC_ORDER	"rsc_order"
#  define XML_CONS_TAG_RSC_LOCATION	"rsc_location"
#  define XML_CONS_TAG_RSC_TICKET	"rsc_ticket"
#  define XML_CONS_TAG_RSC_SET		"resource_set"

#  define XML_NODE_ATTR_RSC_DISCOVERY   "resource-discovery-enabled"

#  define XML_CIB_TAG_GENERATION_TUPPLE	"generation_tuple"

#  define XML_TAG_TRANSIENT_NODEATTRS	"transient_attributes"

#  define XML_ACL_TAG_USER		"acl_target"
#  define XML_ACL_TAG_USERv1		"acl_user"
#  define XML_ACL_TAG_GROUP		"acl_group"
#  define XML_ACL_TAG_ROLE		"acl_role"
#  define XML_ACL_TAG_PERMISSION	"acl_permission"
#  define XML_ACL_TAG_ROLE_REFv1	"role_ref"
#  define XML_ACL_TAG_READ		"read"
#  define XML_ACL_TAG_WRITE		"write"
#  define XML_ACL_TAG_DENY		"deny"

#  define XML_CIB_TAG_TICKETS		"tickets"
#  define XML_CIB_TAG_TICKET_STATE	"ticket_state"

#  define XML_CIB_TAG_TAGS   		"tags"
#  define XML_CIB_TAG_TAG   		"tag"
#  define XML_CIB_TAG_OBJ_REF 		"obj_ref"

#  define XML_TAG_FENCING_TOPOLOGY      "fencing-topology"
#  define XML_TAG_FENCING_LEVEL         "fencing-level"

#  define XML_TAG_DIFF                  "diff"
#  define XML_DIFF_VERSION              PCMK_XE_VERSION
#  define XML_DIFF_VSOURCE              "source"
#  define XML_DIFF_VTARGET              "target"
#  define XML_DIFF_CHANGE               "change"
#  define XML_DIFF_LIST                 "change-list"
#  define XML_DIFF_ATTR                 "change-attr"
#  define XML_DIFF_RESULT               "change-result"
#  define XML_DIFF_POSITION             "position"

#  define ID(x) crm_element_value(x, PCMK_XA_ID)

#ifdef __cplusplus
}
#endif

#endif
