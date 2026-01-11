/*
 * Copyright 2006-2026 the Pacemaker project contributors
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
#include <crm/common/internal.h>
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
