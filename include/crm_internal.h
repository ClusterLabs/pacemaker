/*
 * Copyright 2006-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_INTERNAL__H
#define PCMK__CRM_INTERNAL__H

#ifndef PCMK__CONFIG_H
#define PCMK__CONFIG_H
#include <config.h>
#endif

#include <portability.h>

/* Our minimum glib dependency is 2.42. Define that as both the minimum and
 * maximum glib APIs that are allowed (i.e. APIs that were already deprecated
 * in 2.42, and APIs introduced after 2.42, cannot be used by Pacemaker code).
 */
#define GLIB_VERSION_MIN_REQUIRED GLIB_VERSION_2_42
#define GLIB_VERSION_MAX_ALLOWED GLIB_VERSION_2_42

#define G_LOG_DOMAIN "Pacemaker"

#include <glib.h>
#include <stdbool.h>
#include <libxml/tree.h>

/* Public API headers can guard including deprecated API headers with this
 * symbol, thus preventing internal code (which includes this header) from using
 * deprecated APIs, while still allowing external code to use them by default.
 */
#define PCMK_ALLOW_DEPRECATED 0

#include <crm/lrmd.h>
#include <crm/cluster/internal.h>
#include <crm/common/acl_internal.h>
#include <crm/common/action_relation_internal.h>
#include <crm/common/actions_internal.h>
#include <crm/common/alerts_internal.h>
#include <crm/common/attrs_internal.h>
#include <crm/common/bundles_internal.h>
#include <crm/common/cib_internal.h>
#include <crm/common/clone_internal.h>
#include <crm/common/cmdline_internal.h>
#include <crm/common/digest_internal.h>
#include <crm/common/failcounts_internal.h>
#include <crm/common/group_internal.h>
#include <crm/common/health_internal.h>
#include <crm/common/history_internal.h>
#include <crm/common/internal.h>
#include <crm/common/io_internal.h>
#include <crm/common/ipc_attrd_internal.h>
#include <crm/common/ipc_internal.h>
#include <crm/common/iso8601_internal.h>
#include <crm/common/lists_internal.h>
#include <crm/common/location_internal.h>
#include <crm/common/logging_internal.h>
#include <crm/common/messages_internal.h>
#include <crm/common/nodes_internal.h>
#include <crm/common/nvpair_internal.h>
#include <crm/common/options_internal.h>
#include <crm/common/output_internal.h>
#include <crm/common/primitive_internal.h>
#include <crm/common/remote_internal.h>
#include <crm/common/resources_internal.h>
#include <crm/common/results_internal.h>
#include <crm/common/roles_internal.h>
#include <crm/common/rules_internal.h>
#include <crm/common/scheduler_internal.h>
#include <crm/common/schemas_internal.h>
#include <crm/common/scores_internal.h>
#include <crm/common/servers_internal.h>
#include <crm/common/strings_internal.h>
#include <crm/common/tickets_internal.h>
#include <crm/common/tls_internal.h>
#include <crm/common/unittest_internal.h>
#include <crm/common/xml_internal.h>
#include <locale.h>
#include <gettext.h>

#ifdef __cplusplus
extern "C" {
#endif

#define N_(String) (String)

#ifdef ENABLE_NLS
#define _(String) gettext(String)
#else
#define _(String) (String)
#endif


/*
 * IPC service names that are only used internally
 */

#define PCMK__SERVER_BASED_RO		"cib_ro"
#define PCMK__SERVER_BASED_RW		"cib_rw"
#define PCMK__SERVER_BASED_SHM		"cib_shm"

/*
 * IPC commands that can be sent to Pacemaker daemons
 */

#define PCMK__ATTRD_CMD_PEER_REMOVE     "peer-remove"
#define PCMK__ATTRD_CMD_UPDATE          "update"
#define PCMK__ATTRD_CMD_UPDATE_BOTH     "update-both"
#define PCMK__ATTRD_CMD_UPDATE_DELAY    "update-delay"
#define PCMK__ATTRD_CMD_QUERY           "query"
#define PCMK__ATTRD_CMD_REFRESH         "refresh"
#define PCMK__ATTRD_CMD_SYNC_RESPONSE   "sync-response"
#define PCMK__ATTRD_CMD_CLEAR_FAILURE   "clear-failure"
#define PCMK__ATTRD_CMD_CONFIRM         "confirm"

#define PCMK__CONTROLD_CMD_NODES        "list-nodes"

#define ST__LEVEL_MIN 1
#define ST__LEVEL_MAX 9

#ifdef __cplusplus
}
#endif

#endif // CRM_INTERNAL__H
