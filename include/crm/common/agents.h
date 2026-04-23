/*
 * Copyright 2017-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_AGENTS__H
#define PCMK__CRM_COMMON_AGENTS__H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief API related to resource agents
 * \ingroup core
 */

#include <stdint.h>       // uint32_t
#include <stdbool.h>

// Known (not necessarily supported) resource classes
#define PCMK_RESOURCE_CLASS_OCF     "ocf"
#define PCMK_RESOURCE_CLASS_SERVICE "service"
#define PCMK_RESOURCE_CLASS_LSB     "lsb"
#define PCMK_RESOURCE_CLASS_SYSTEMD "systemd"
#define PCMK_RESOURCE_CLASS_STONITH "stonith"
#define PCMK_RESOURCE_CLASS_ALERT   "alert"

/* Special stonith-class agent parameters interpreted directly by Pacemaker
 * (not including the pcmk_ACTION_{action,retries,timeout} parameters)
 */
#define PCMK_FENCING_ACTION_LIMIT       "pcmk_action_limit"
#define PCMK_FENCING_DELAY_BASE         "pcmk_delay_base"
#define PCMK_FENCING_DELAY_MAX          "pcmk_delay_max"
#define PCMK_FENCING_HOST_ARGUMENT      "pcmk_host_argument"
#define PCMK_FENCING_HOST_CHECK         "pcmk_host_check"
#define PCMK_FENCING_HOST_LIST          "pcmk_host_list"
#define PCMK_FENCING_HOST_MAP           "pcmk_host_map"
#define PCMK_FENCING_PROVIDES           "provides"

// OCF Resource Agent API standard version that this Pacemaker supports
#define PCMK_OCF_MAJOR_VERSION "1"
#define PCMK_OCF_MINOR_VERSION "1"
#define PCMK_OCF_VERSION       PCMK_OCF_MAJOR_VERSION "." PCMK_OCF_MINOR_VERSION

// Capabilities supported by a resource agent standard
enum pcmk_ra_caps {
    pcmk_ra_cap_none         = 0,

    //! Requires provider
    pcmk_ra_cap_provider     = (UINT32_C(1) << 0),

    //! Supports status instead of monitor
    pcmk_ra_cap_status       = (UINT32_C(1) << 1),

    //! Supports parameters
    pcmk_ra_cap_params       = (UINT32_C(1) << 2),

    //! Supports unique clones
    pcmk_ra_cap_unique       = (UINT32_C(1) << 3),

    //! Supports promotable clones
    pcmk_ra_cap_promotable   = (UINT32_C(1) << 4),

    //! Reads from standard input
    pcmk_ra_cap_stdin        = (UINT32_C(1) << 5),

    //! Supports pcmk_monitor_timeout, etc.
    pcmk_ra_cap_fence_params = (UINT32_C(1) << 6),

    //! Supports execution by crm_resource
    pcmk_ra_cap_cli_exec     = (UINT32_C(1) << 7),
};

uint32_t pcmk_get_ra_caps(const char *standard);
char *crm_generate_ra_key(const char *standard, const char *provider,
                          const char *type);
int crm_parse_agent_spec(const char *spec, char **standard, char **provider,
                         char **type);
bool pcmk_stonith_param(const char *param);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_AGENTS__H
