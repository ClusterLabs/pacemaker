/*
 * Copyright 2004-2025 the Pacemaker project contributors
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

/* The IPC buffer is always 128k.  If we are asked to send a message larger
 * than that size, it will be split into multiple messages that must be
 * reassembled on the other end.
 */
#define BUFFER_SIZE     (128*1024) // 128k

/*!
 * \brief Return pacemaker's IPC buffer size
 *
 * \return IPC buffer size in bytes
 */
unsigned int
crm_ipc_default_buffer_size(void)
{
    return BUFFER_SIZE;
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
        case pcmk__client_tls:
            return "TLS";
        default:
            return "unknown";
    }
}
