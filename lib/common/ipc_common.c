/*
 * Copyright 2004-2021 the Pacemaker project contributors
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

#include <crm/msg_xml.h>
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
    static unsigned int global_max = 0;

    if (global_max == 0) {
        long long global_ll;

        if ((pcmk__scan_ll(pcmk__env_option(PCMK__ENV_IPC_BUFFER), &global_ll,
                           0LL) != pcmk_rc_ok)
            || (global_ll <= 0)) {
            global_max = MAX_MSG_SIZE; // Default for unset or invalid

        } else if (global_ll < MIN_MSG_SIZE) {
            global_max = MIN_MSG_SIZE;

        } else if (global_ll > UINT_MAX) {
            global_max = UINT_MAX;

        } else {
            global_max = (unsigned int) global_ll;
        }
    }
    return QB_MAX(max, global_max);
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
