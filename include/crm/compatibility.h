/*
 * Copyright (C) 2012-2018 Andrew Beekhof <andrew@beekhof.net>
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */
#ifndef CRM_COMPATIBILITY__H
#  define CRM_COMPATIBILITY__H

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
static int ais_fd_sync = -1;

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

#endif
