/*
 * Copyright 2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_ACTIONS__H
#define PCMK__CRM_COMMON_ACTIONS__H

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * \file
 * \brief APIs related to actions
 * \ingroup core
 */

// Action names as strings
#define PCMK_ACTION_CANCEL              "cancel"
#define PCMK_ACTION_DELETE              "delete"
#define PCMK_ACTION_DEMOTE              "demote"
#define PCMK_ACTION_META_DATA           "meta-data"
#define PCMK_ACTION_MIGRATE_TO          "migrate_to"
#define PCMK_ACTION_MONITOR             "monitor"
#define PCMK_ACTION_NOTIFY              "notify"
#define PCMK_ACTION_PROMOTE             "promote"
#define PCMK_ACTION_RELOAD              "reload"
#define PCMK_ACTION_RELOAD_AGENT        "reload-agent"
#define PCMK_ACTION_START               "start"
#define PCMK_ACTION_STOP                "stop"
#define PCMK_ACTION_VALIDATE_ALL        "validate-all"

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_ACTIONS__H
