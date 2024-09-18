/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>
#include <stdint.h>         // uint64_t
#include <sys/types.h>

#include <crm/common/xml.h>
#include "crmcommon_private.h"

#define MIN_MSG_SIZE    12336    // sizeof(struct qb_ipc_connection_response)
#define MAX_MSG_SIZE    128*1024 // 128k default

/*!
 * \internal
 * \brief Choose an IPC buffer size in bytes
 *
 * \param[in] max  Use this value if environment/default is lower
 *
 * \return Maximum of max and value of PCMK_ipc_buffer (default 128KB)
 */
unsigned int
pcmk__ipc_buffer_size(unsigned int max)
{
    static long long env_value = 0LL; // Will be bounded to unsigned int

    if (env_value == 0LL) {
        const char *env_value_s = pcmk__env_option(PCMK__ENV_IPC_BUFFER);
        int rc = pcmk__scan_ll(env_value_s, &env_value, MAX_MSG_SIZE);

        if (rc != pcmk_rc_ok) {
            env_value = MAX_MSG_SIZE;
            max = QB_MAX(max, env_value);
            crm_warn("Using %u as IPC buffer size because '%s' is not "
                     "a valid value for PCMK_" PCMK__ENV_IPC_BUFFER ": %s",
                     max, env_value_s, pcmk_rc_str(rc));

        } else if (env_value <= 0LL) {
            env_value = MAX_MSG_SIZE;
            max = QB_MAX(max, env_value);
            crm_warn("Using %u as IPC buffer size because PCMK_"
                     PCMK__ENV_IPC_BUFFER " (%s) is not a positive integer",
                     max, env_value_s);

        } else if (env_value < MIN_MSG_SIZE) {
            env_value = MIN_MSG_SIZE;
            max = QB_MAX(max, env_value);
            crm_debug("Using %u as IPC buffer size because PCMK_"
                      PCMK__ENV_IPC_BUFFER " (%s) is too small",
                      max, env_value_s);

        } else if (env_value > UINT_MAX) {
            env_value = UINT_MAX;
            max = UINT_MAX;
            crm_debug("Using %u as IPC buffer size because PCMK_"
                      PCMK__ENV_IPC_BUFFER " (%s) is too big",
                      max, env_value_s);
        }
    }

    if (env_value > max) {
        const char *source = "PCMK_" PCMK__ENV_IPC_BUFFER;

        if (env_value == MAX_MSG_SIZE) {
            source = "default";
        }
        crm_debug("Using IPC buffer size %lld from %s (not %u)",
                  env_value, source, max);
        max = env_value;
    }
    return max;
}

/*!
 * \brief Return pacemaker's default IPC buffer size
 *
 * \return IPC buffer size in bytes
 */
unsigned int
crm_ipc_default_buffer_size(void)
{
    static unsigned int default_size = 0;

    if (default_size == 0) {
        default_size = pcmk__ipc_buffer_size(0);
    }
    return default_size;
}

/*!
 * \internal
 * \brief Check whether an IPC header is valid
 *
 * \param[in] header  IPC header to check
 *
 * \return true if IPC header has a supported version, false otherwise
 */
bool
pcmk__valid_ipc_header(const pcmk__ipc_header_t *header)
{
    if (header == NULL) {
        crm_err("IPC message without header");
        return false;

    } else if (header->version > PCMK__IPC_VERSION) {
        crm_err("Filtering incompatible v%d IPC message (only versions <= %d supported)",
                header->version, PCMK__IPC_VERSION);
        return false;
    }
    return true;
}

const char *
pcmk__client_type_str(uint64_t client_type)
{
    switch (client_type) {
        case pcmk__client_ipc:
            return "IPC";
        case pcmk__client_tcp:
            return "TCP";
#ifdef HAVE_GNUTLS_GNUTLS_H
        case pcmk__client_tls:
            return "TLS";
#endif
        default:
            return "unknown";
    }
}
