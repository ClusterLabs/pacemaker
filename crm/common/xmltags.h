/* 
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#ifndef XML_TAGS__H
#define XML_TAGS__H

#define CRM_VERSION                "0.1"

//---- Common tags/attrs
#define XML_TAG_CIB                "cib"
#define XML_TAG_FAILED             "failed"

#define XML_ATTR_TIMEOUT           "timeout"
#define XML_ATTR_TSTAMP            "timestamp"
#define XML_ATTR_VERSION           "version"
#define XML_ATTR_DESC              "description"
#define XML_ATTR_ID                "id"
#define XML_ATTR_FILTER_TYPE       "type_filter"
#define XML_ATTR_FILTER_ID         "id_filter"
#define XML_ATTR_FILTER_PRIORITY   "priority_filter"
#define XML_ATTR_VERBOSE           "verbose"


//---- top level tags/attrs
#define XML_MSG_TAG                "crm_message"
#define XML_MSG_TAG_REQUEST        "request"
#define XML_MSG_TAG_RESPONSE       "response"

#define XML_MSG_ATTR_MSGTYPE       "message_type"
#define XML_MSG_ATTR_SYSFROM       "sys_from"
#define XML_MSG_ATTR_SYSTO         "sys_to"
#define XML_MSG_ATTR_HOSTFROM      "host_from"
#define XML_MSG_ATTR_HOSTTO        "host_to"
#define XML_MSG_ATTR_REFERENCE     "reference"


//---- request tags/attrs
#define XML_REQ_TAG_DC             "dc_request"
#define XML_REQ_TAG_CRM            "crmd_request"
#define XML_REQ_TAG_CIB            "cib_request"
#define XML_REQ_TAG_LRM            "lrm_request"
#define XML_REQ_TAG_PE             "pe_request"
#define XML_REQ_TAG_TE             "te_request"

#define XML_DC_ATTR_OP		   "dc_operation"
#define XML_CRM_ATTR_OP            "crmd_operation"
#define XML_LRM_ATTR_OP            "lrm_operation"
#define XML_PE_ATTR_OP             "pe_operation"
#define XML_TE_ATTR_OP             "te_operation"
#define XML_CIB_ATTR_OP            "cib_operation"
#define XML_CIB_ATTR_SECTION       "cib_section"

#define XML_LRM_ATTR_IDFILTER      "id_filter"
#define XML_LRM_ATTR_TYPEFILTER    "type_filter"


//---- response tags/attrs
#define XML_RESP_TAG_DC             "dc_response"
#define XML_RESP_TAG_CRM            "crmd_response"
#define XML_RESP_TAG_CIB            "cib_response"
#define XML_RESP_TAG_LRM            "lrm_response"
#define XML_RESP_TAG_PE             "pe_response"
#define XML_RESP_TAG_TE             "te_response"
#define XML_FAIL_TAG_RESOURCE       "failed_resource"

#define XML_FAILRES_ATTR_RESID      "resource_id"
#define XML_FAILRES_ATTR_REASON     "reason"
#define XML_FAILRES_ATTR_RESSTATUS  "resource_status"

#define XML_CRM_TAG_PING            "ping_response"
#define XML_PING_ATTR_STATUS        "ping_result"
#define XML_PING_ATTR_SYSFROM       "crm_subsystem"

#define XML_CIB_TAG_FRAGMENT        "cib_fragment"
#define XML_CIB_ATTR_RESULT         "cib_action_result"

#define XML_FAIL_TAG_CIB            "failed_update"

#define XML_FAILCIB_ATTR_ID         "id"
#define XML_FAILCIB_ATTR_OBJTYPE    "object_type"
#define XML_FAILCIB_ATTR_OP         "operation"
#define XML_FAILCIB_ATTR_REASON     "reason"

//---- CIB specific tags/attrs
#define XML_CIB_TAG_STATUS        "status"
#define XML_CIB_TAG_RESOURCES     "resources"
#define XML_CIB_TAG_NODES         "nodes"
#define XML_CIB_TAG_CONSTRAINTS   "constraints"

#define XML_CIB_TAG_STATE         "state"
#define XML_CIB_TAG_RESOURCE      "resource"
#define XML_CIB_TAG_NODE          "node"
#define XML_CIB_TAG_CONSTRAINT    "contraint"
#define XML_CIB_TAG_NVPAIR        "nv_pair"

#define XML_CIB_ATTR_HEALTH       "health"
#define XML_CIB_ATTR_WEIGHT       "weight"
#define XML_CIB_ATTR_PRIORITY     "priority"
#define XML_CIB_ATTR_RESTIMEOUT   "res_timeout"
#define XML_CIB_ATTR_MAXINSTANCE  "max_instances"
#define XML_CIB_ATTR_INSTANCE     "instance"
#define XML_CIB_ATTR_RESID        "res_id"
#define XML_CIB_ATTR_RESID1       "res_id_1"
#define XML_CIB_ATTR_RESID2       "res_id_2"
#define XML_CIB_ATTR_CLEAR        "clear_on"
#define XML_CIB_ATTR_SOURCE       "source"
#define XML_CIB_ATTR_CONTYPE      "constraint_type"
#define XML_CIB_ATTR_RESTYPE      "resource_type"
#define XML_CIB_ATTR_RESSTATUS    "resource_status"
#define XML_CIB_ATTR_NODEID       "node_id"
#define XML_CIB_ATTR_NODETYPE     "node_type"
#define XML_CIB_ATTR_NODESTATUS   "node_status"
#define XML_CIB_ATTR_VARTYPE      "var_type"
#define XML_CIB_ATTR_VARVALUE     "var_value"
#define XML_CIB_ATTR_NODEREF      "node_reference"
#define XML_CIB_ATTR_ACTION       "action"

#include <libxml/tree.h> 

#define ID(x) xmlGetProp(x, XML_ATTR_ID)
#define INSTANCE(x) xmlGetProp(x, XML_CIB_ATTR_INSTANCE)
#define TSTAMP(x) xmlGetProp(x, XML_ATTR_TSTAMP)
#define TYPE(x) x != NULL ? x->name : NULL 

#endif
