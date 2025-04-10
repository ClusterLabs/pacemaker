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

bool
pcmk__ipc_msg_is_multipart(void *data)
{
    pcmk__ipc_header_t *header = data;

    CRM_LOG_ASSERT(data != NULL);
    return pcmk_is_set(header->flags, crm_ipc_multipart);
}

bool
pcmk__ipc_msg_is_multipart_end(void *data)
{
    pcmk__ipc_header_t *header = data;

    CRM_LOG_ASSERT(data != NULL);
    return pcmk_is_set(header->flags, crm_ipc_multipart_end);
}

uint16_t
pcmk__ipc_multipart_id(void *data)
{
    pcmk__ipc_header_t *header = data;

    CRM_LOG_ASSERT(data != NULL);
    return header->part_id;
}

/*!
 * \internal
 * \brief Add more data to a partial IPC message
 *
 * This function can be called repeatedly to build up a complete IPC message
 * from smaller parts.  It does this by inspecting flags on the message.
 * Most of the time, IPC messages will be small enough where this function
 * won't get called more than once, but more complex clusters can end up with
 * very large IPC messages that don't fit in a single buffer.
 *
 * Important return values:
 *
 * - EBADMSG - Something was wrong with the data.
 * - pcmk_rc_ipc_more - \p data was a chunk of a partial message and there is
 *                      more to come.  The caller should not process the message
 *                      yet and should continue reading from the IPC connection.
 * - pcmk_rc_ok - We have the complete message.  The caller should process
 *                it and free the buffer to prepare for the next message.
 *
 * \param[in,out] c     The client to add this data to
 * \param[in]     data  The received IPC message or message portion.  The
 *                      caller is responsible for freeing this.
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__ipc_msg_append(GByteArray **buffer, void *data)
{
    pcmk__ipc_header_t *header = (pcmk__ipc_header_t *) data;
    const guint8 *payload = (guint8 *) data + sizeof(pcmk__ipc_header_t);
    int rc = pcmk_rc_ok;

    if (!pcmk__valid_ipc_header(header)) {
        return EBADMSG;
    }

    if (pcmk__ipc_msg_is_multipart_end(data)) {
        /* This is the end of a multipart IPC message.  Add the payload of the
         * received data (so, don't include the header) to the partial buffer.
         * Remember that this needs to include the NULL terminating character.
         */
        g_byte_array_append(*buffer, payload, header->size);

    } else if (pcmk__ipc_msg_is_multipart(data)) {
        if (pcmk__ipc_multipart_id(data) == 0) {
            /* This is the first part of a multipart IPC message.  Initialize
             * the buffer with the entire message, including its header.  Do
             * not include the NULL terminating character.
             */
            *buffer = g_byte_array_new();

            /* Clear any multipart flags from the header of the incoming part
             * so they'll be clear in the fully reassembled message.  This
             * message is passed to pcmk__client_data2xml, which will extract
             * the header flags and return them.  Those flags can then be used
             * when constructing a reply, including ACKs.  We don't want these
             * specific incoming flags to influence the reply.
             */
            pcmk__clear_ipc_flags(header->flags, "server",
                                  crm_ipc_multipart | crm_ipc_multipart_end);

            g_byte_array_append(*buffer, data,
                                sizeof(pcmk__ipc_header_t) + header->size - 1);

        } else {
            /* This is some intermediate part of a multipart message.  Add
             * the payload of the received data (so, don't include the header)
             * to the partial buffer and return.  Do not include the NULL
             * terminating character.
             */
            g_byte_array_append(*buffer, payload, header->size - 1);
        }

        rc = pcmk_rc_ipc_more;

    } else {
        /* This is a standalone IPC message.  For simplicity in the caller,
         * copy the entire message over into a byte array so it can be handled
         * the same as a multipart message.
         */
        *buffer = g_byte_array_new();
        g_byte_array_append(*buffer, data,
                            sizeof(pcmk__ipc_header_t) + header->size);
    }

    return rc;
}
