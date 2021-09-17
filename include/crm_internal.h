/*
 * Copyright 2006-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef CRM_INTERNAL__H
#  define CRM_INTERNAL__H

#  ifndef PCMK__CONFIG_H
#    define PCMK__CONFIG_H
#    include <config.h>
#  endif

#  include <portability.h>

/* Our minimum glib dependency is 2.42. Define that as both the minimum and
 * maximum glib APIs that are allowed (i.e. APIs that were already deprecated
 * in 2.42, and APIs introduced after 2.42, cannot be used by Pacemaker code).
 */
#define GLIB_VERSION_MIN_REQUIRED GLIB_VERSION_2_42
#define GLIB_VERSION_MAX_ALLOWED GLIB_VERSION_2_42

#  include <glib.h>
#  include <stdbool.h>
#  include <libxml/tree.h>

/* Public API headers can guard including deprecated API headers with this
 * symbol, thus preventing internal code (which includes this header) from using
 * deprecated APIs, while still allowing external code to use them by default.
 */
#define PCMK_ALLOW_DEPRECATED 0

#  include <crm/lrmd.h>
#  include <crm/common/logging.h>
#  include <crm/common/logging_internal.h>
#  include <crm/common/ipc_internal.h>
#  include <crm/common/options_internal.h>
#  include <crm/common/output_internal.h>
#  include <crm/common/xml_internal.h>
#  include <crm/common/internal.h>

#include <locale.h>
#include <libintl.h>
#define PACKAGE_NAME "pacemaker"
#define PACKAGE_LOCALEDIR "/usr/share/locale/"
#define _(x) gettext(x)

static inline gboolean is_zh_language(void)
{
    FILE *fp = NULL;
    char data[128] = {'0'};
    char *p = NULL;
    char* ret = NULL;
    fp = fopen("/etc/locale.conf", "r");
    if (fp == NULL){
        return false;
    }
    ret = fgets(data, sizeof(data), fp);
    if (ret == NULL){
        return false;
    }
    p = strstr(data, "zh_CN");
    if (p != NULL) {
    	return true;
    }
    fclose(fp);
    return false;
}

/*
 * XML attribute names used only by internal code
 */

#define PCMK__XA_ATTR_DAMPENING         "attr_dampening"
#define PCMK__XA_ATTR_FORCE             "attrd_is_force_write"
#define PCMK__XA_ATTR_INTERVAL          "attr_clear_interval"
#define PCMK__XA_ATTR_IS_PRIVATE        "attr_is_private"
#define PCMK__XA_ATTR_IS_REMOTE         "attr_is_remote"
#define PCMK__XA_ATTR_NAME              "attr_name"
#define PCMK__XA_ATTR_NODE_ID           "attr_host_id"
#define PCMK__XA_ATTR_NODE_NAME         "attr_host"
#define PCMK__XA_ATTR_OPERATION         "attr_clear_operation"
#define PCMK__XA_ATTR_PATTERN           "attr_regex"
#define PCMK__XA_ATTR_RESOURCE          "attr_resource"
#define PCMK__XA_ATTR_SECTION           "attr_section"
#define PCMK__XA_ATTR_SET               "attr_set"
#define PCMK__XA_ATTR_USER              "attr_user"
#define PCMK__XA_ATTR_UUID              "attr_key"
#define PCMK__XA_ATTR_VALUE             "attr_value"
#define PCMK__XA_ATTR_VERSION           "attr_version"
#define PCMK__XA_ATTR_WRITER            "attr_writer"
#define PCMK__XA_MODE                   "mode"
#define PCMK__XA_TASK                   "task"


/*
 * IPC service names that are only used internally
 */

#  define PCMK__SERVER_BASED_RO		"cib_ro"
#  define PCMK__SERVER_BASED_RW		"cib_rw"
#  define PCMK__SERVER_BASED_SHM		"cib_shm"

/*
 * IPC commands that can be sent to Pacemaker daemons
 */

#define PCMK__ATTRD_CMD_PEER_REMOVE     "peer-remove"
#define PCMK__ATTRD_CMD_UPDATE          "update"
#define PCMK__ATTRD_CMD_UPDATE_BOTH     "update-both"
#define PCMK__ATTRD_CMD_UPDATE_DELAY    "update-delay"
#define PCMK__ATTRD_CMD_QUERY           "query"
#define PCMK__ATTRD_CMD_REFRESH         "refresh"
#define PCMK__ATTRD_CMD_FLUSH           "flush"
#define PCMK__ATTRD_CMD_SYNC            "sync"
#define PCMK__ATTRD_CMD_SYNC_RESPONSE   "sync-response"
#define PCMK__ATTRD_CMD_CLEAR_FAILURE   "clear-failure"

#define PCMK__CONTROLD_CMD_NODES        "list-nodes"

/*
 * Environment variables used by Pacemaker
 */

#define PCMK__ENV_PHYSICAL_HOST         "physical_host"


#endif                          /* CRM_INTERNAL__H */
