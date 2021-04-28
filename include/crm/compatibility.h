/*
 * Copyright 2004-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */
#ifndef CRM_COMPATIBILITY__H
#  define CRM_COMPATIBILITY__H

#ifdef __cplusplus
extern "C" {
#endif

/* This file allows external code that uses Pacemaker libraries to transition
 * more easily from old APIs to current ones. Any code that compiled with an
 * earlier API but not with the current API can include this file and have a
 * good chance of compiling again.
 *
 * Everything here is deprecated and will be removed at the next major Pacemaker
 * release (i.e. 3.0), so it should only be used during a transitionary period
 * while the external code is being updated to the current API.
 */

#include <crm/msg_xml.h>
#include <crm/pengine/pe_types.h> // enum pe_obj_types

/* Heartbeat-specific definitions. Support for heartbeat has been removed
 * entirely, so any code branches relying on these should be deleted.
 */
#define ACTIVESTATUS "active"
#define DEADSTATUS "dead"
#define PINGSTATUS "ping"
#define JOINSTATUS "join"
#define LEAVESTATUS "leave"
#define NORMALNODE "normal"
#define CRM_NODE_EVICTED "evicted"
#define CRM_LEGACY_CONFIG_DIR "/var/lib/heartbeat/crm"
#define HA_VARLIBHBDIR "/var/lib/heartbeat"
#define pcmk_cluster_heartbeat 0x0004

/* Corosync-version-1-specific definitions */

/* Support for corosync version 1 has been removed entirely, so any code
 * branches relying on these should be deleted.
 */
#define PCMK_SERVICE_ID 9
#define CRM_SERVICE PCMK_SERVICE_ID
#define XML_ATTR_EXPECTED_VOTES "expected-quorum-votes"
#define crm_class_members 1
#define crm_class_notify 2
#define crm_class_nodeid 3
#define crm_class_rmpeer 4
#define crm_class_quorum 5
#define pcmk_cluster_classic_ais 0x0010
#define pcmk_cluster_cman 0x0040
#define ais_fd_sync -1

// These are always true now
#define CS_USES_LIBQB 1
#define HAVE_CMAP 1
#define SUPPORT_CS_QUORUM 1
#define SUPPORT_AIS 1
#define AIS_COROSYNC 1

// These are always false now
#define HAVE_CONFDB 0
#define SUPPORT_CMAN 0
#define SUPPORT_PLUGIN 0
#define SUPPORT_STONITH_CONFIG 0
#define is_classic_ais_cluster() 0
#define is_cman_cluster() 0

// These have newer names
#define is_openais_cluster() is_corosync_cluster()
#if SUPPORT_COROSYNC
#define SUPPORT_CS
#endif

/* Isolation-specific definitions. Support for the resource isolation feature
 * has been removed * entirely, so any code branches relying on these should be
 * deleted.
 */
#define XML_RSC_ATTR_ISOLATION_INSTANCE "isolation-instance"
#define XML_RSC_ATTR_ISOLATION_WRAPPER "isolation-wrapper"
#define XML_RSC_ATTR_ISOLATION_HOST "isolation-host"
#define XML_RSC_ATTR_ISOLATION "isolation"

/* Schema-related definitions */

// This has been renamed
#define CRM_DTD_DIRECTORY CRM_SCHEMA_DIRECTORY

/* Exit-code-related definitions */

#define DAEMON_RESPAWN_STOP CRM_EX_FATAL
#define pcmk_err_panic      CRM_EX_PANIC

// Deprecated symbols that were removed
#define APPNAME_LEN         256
#define CRM_NODE_ACTIVE             CRM_NODE_MEMBER
#define CRM_OP_DIE          "die_no_respawn"
#define CRM_OP_RETRIVE_CIB  "retrieve_cib"
#define CRM_OP_HBEAT        "dc_beat"
#define CRM_OP_ABORT        "abort"
#define CRM_OP_DEBUG_UP     "debug_inc"
#define CRM_OP_DEBUG_DOWN   "debug_dec"
#define CRM_OP_EVENTCC      "event_cc"
#define CRM_OP_TEABORT      "te_abort"
#define CRM_OP_TEABORTED    "te_abort_confirmed"
#define CRM_OP_TE_HALT      "te_halt"
#define CRM_OP_TECOMPLETE   "te_complete"
#define CRM_OP_TETIMEOUT    "te_timeout"
#define CRM_OP_TRANSITION   "transition"
#define CRM_OP_NODES_PROBED "probe_nodes_complete"
#define DOT_ALL_FSA_INPUTS  1
#define DOT_FSA_ACTIONS     1
#define F_LRMD_CANCEL_CALLID        "lrmd_cancel_callid"
#define F_LRMD_RSC_METADATA         "lrmd_rsc_metadata_res"
#define F_LRMD_IPC_PROXY_NODE       "lrmd_ipc_proxy_node"
#define INSTANCE(x)                 crm_element_value(x, XML_CIB_ATTR_INSTANCE)
#define LOG_DEBUG_2  LOG_TRACE
#define LOG_DEBUG_3  LOG_TRACE
#define LOG_DEBUG_4  LOG_TRACE
#define LOG_DEBUG_5  LOG_TRACE
#define LOG_DEBUG_6  LOG_TRACE
#define LRMD_OP_RSC_CHK_REG         "lrmd_rsc_check_register"
#define MAX_IPC_FAIL                5
#define NAME(x)                     crm_element_value(x, XML_NVPAIR_ATTR_NAME)
#define MSG_LOG                     1
#define PE_OBJ_T_NATIVE             "native"
#define PE_OBJ_T_GROUP              "group"
#define PE_OBJ_T_INCARNATION        "clone"
#define PE_OBJ_T_MASTER             "master"
#define SERVICE_SCRIPT              "/sbin/service"
#define SOCKET_LEN                  1024
#define TSTAMP(x)                   crm_element_value(x, XML_ATTR_TSTAMP)
#define XML_ATTR_TAGNAME            F_XML_TAGNAME
#define XML_ATTR_FILTER_TYPE        "type-filter"
#define XML_ATTR_FILTER_ID          "id-filter"
#define XML_ATTR_FILTER_PRIORITY    "priority-filter"
#define XML_ATTR_DC                 "is_dc"
#define XML_MSG_TAG                 "crm_message"
#define XML_MSG_TAG_DATA            "msg_data"
#define XML_FAIL_TAG_RESOURCE       "failed_resource"
#define XML_FAILRES_ATTR_RESID      "resource_id"
#define XML_FAILRES_ATTR_REASON     "reason"
#define XML_FAILRES_ATTR_RESSTATUS  "resource_status"
#define XML_ATTR_RESULT             "result"
#define XML_ATTR_SECTION            "section"
#define XML_CIB_TAG_DOMAIN          "domain"
#define XML_CIB_TAG_CONSTRAINT      "constraint"
#define XML_RSC_ATTR_STATE          "clone-state"
#define XML_RSC_ATTR_PRIORITY       "priority"
#define XML_OP_ATTR_DEPENDENT       "dependent-on"
#define XML_LRM_TAG_AGENTS          "lrm_agents"
#define XML_LRM_TAG_AGENT           "lrm_agent"
#define XML_LRM_TAG_ATTRIBUTES      "attributes"
#define XML_CIB_ATTR_HEALTH         "health"
#define XML_CIB_ATTR_WEIGHT         "weight"
#define XML_CIB_ATTR_CLEAR          "clear_on"
#define XML_CIB_ATTR_STONITH        "stonith"
#define XML_CIB_ATTR_STANDBY        "standby"
#define XML_RULE_ATTR_SCORE_MANGLED "score-attribute-mangled"
#define XML_RULE_ATTR_RESULT        "result"
#define XML_NODE_ATTR_STATE         "state"
#define XML_ATTR_LRM_PROBE          "lrm-is-probe"
#define XML_ATTR_TE_ALLOWFAIL       "op_allow_fail"
#define VALUE(x)                    crm_element_value(x, XML_NVPAIR_ATTR_VALUE)
#define action_wrapper_s            pe_action_wrapper_s
#define add_cib_op_callback(cib, id, flag, data, fn) do {                \
        cib->cmds->register_callback(cib, id, 120, flag, data, #fn, fn); \
    } while(0)
#define cib_default_options = cib_none
#define crm_remote_baremetal              0x0004
#define crm_remote_container              0x0002
#define crm_element_value_const           crm_element_value
#define crm_element_value_const_int       crm_element_value_int
#define n_object_classes                  3
#define no_quorum_policy_e                pe_quorum_policy
#define node_s                            pe_node_s
#define node_shared_s                     pe_node_shared_s
#define pe_action_failure_is_fatal        0x00020
#define pe_rsc_munging                    0x00000800ULL
#define pe_rsc_try_reload                 0x00001000ULL
#define pe_rsc_shutdown                   0x00020000ULL
#define pe_rsc_migrating                  0x00400000ULL
#define pe_rsc_unexpectedly_running       0x02000000ULL
#define pe_rsc_have_unfencing             0x80000000ULL
#define resource_s                        pe_resource_s
#define ticket_s                          pe_ticket_s

#define node_score_infinity 1000000

/* Clone terminology definitions */

// These can no longer be used in a switch together
#define pe_master pe_clone

static inline enum pe_obj_types
get_resource_type(const char *name)
{
    if (safe_str_eq(name, XML_CIB_TAG_RESOURCE)) {
        return pe_native;

    } else if (safe_str_eq(name, XML_CIB_TAG_GROUP)) {
        return pe_group;

    } else if (safe_str_eq(name, XML_CIB_TAG_INCARNATION)
                || safe_str_eq(name, PCMK_XE_PROMOTABLE_LEGACY)) {
        return pe_clone;

    } else if (safe_str_eq(name, XML_CIB_TAG_CONTAINER)) {
        return pe_container;
    }

    return pe_unknown;
}

static inline const char *
get_resource_typename(enum pe_obj_types type)
{
    switch (type) {
        case pe_native:
            return XML_CIB_TAG_RESOURCE;
        case pe_group:
            return XML_CIB_TAG_GROUP;
        case pe_clone:
            return XML_CIB_TAG_INCARNATION;
        case pe_container:
            return XML_CIB_TAG_CONTAINER;
        case pe_unknown:
            return "unknown";
    }
    return "<unknown>";
}

#ifdef __cplusplus
}
#endif

#endif
