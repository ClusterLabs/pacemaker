/*
 * Copyright 2004-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <errno.h>
#include <sys/types.h>
#include <stdint.h>

#include <crm/cluster.h>
#include <crm/msg_xml.h>
#include <crm/common/acl_internal.h>
#include <crm/common/ipc_internal.h>
#include <crm/common/logging.h>
#include <crm/common/results.h>
#include <crm/common/strings_internal.h>
#include <crm/common/util.h>

#include "pacemaker-attrd.h"

#define attrd_send_ack(client, id, flags) \
    pcmk__ipc_send_ack((client), (id), (flags), "ack", ATTRD_PROTOCOL_VERSION, CRM_EX_INDETERMINATE)

static qb_ipcs_service_t *ipcs = NULL;

/*!
 * \internal
 * \brief Accept a new client IPC connection
 *
 * \param[in] c    New connection
 * \param[in] uid  Client user id
 * \param[in] gid  Client group id
 *
 * \return pcmk_ok on success, -errno otherwise
 */
static int32_t
attrd_ipc_accept(qb_ipcs_connection_t *c, uid_t uid, gid_t gid)
{
    crm_trace("New client connection %p", c);
    if (attrd_shutting_down()) {
        crm_info("Ignoring new connection from pid %d during shutdown",
                 pcmk__client_pid(c));
        return -EPERM;
    }

    if (pcmk__new_client(c, uid, gid) == NULL) {
        return -EIO;
    }
    return pcmk_ok;
}

/*!
 * \internal
 * \brief Destroy a client IPC connection
 *
 * \param[in] c  Connection to destroy
 *
 * \return FALSE (i.e. do not re-run this callback)
 */
static int32_t
attrd_ipc_closed(qb_ipcs_connection_t *c)
{
    pcmk__client_t *client = pcmk__find_client(c);

    if (client == NULL) {
        crm_trace("Ignoring request to clean up unknown connection %p", c);
    } else {
        crm_trace("Cleaning up closed client connection %p", c);
        pcmk__free_client(client);
    }
    return FALSE;
}

/*!
 * \internal
 * \brief Destroy a client IPC connection
 *
 * \param[in] c  Connection to destroy
 *
 * \note We handle a destroyed connection the same as a closed one,
 *       but we need a separate handler because the return type is different.
 */
static void
attrd_ipc_destroy(qb_ipcs_connection_t *c)
{
    crm_trace("Destroying client connection %p", c);
    attrd_ipc_closed(c);
}

static int32_t
attrd_ipc_dispatch(qb_ipcs_connection_t * c, void *data, size_t size)
{
    uint32_t id = 0;
    uint32_t flags = 0;
    pcmk__client_t *client = pcmk__find_client(c);
    xmlNode *xml = NULL;
    const char *op;

    // Sanity-check, and parse XML from IPC data
    CRM_CHECK((c != NULL) && (client != NULL), return 0);
    if (data == NULL) {
        crm_debug("No IPC data from PID %d", pcmk__client_pid(c));
        return 0;
    }
    xml = pcmk__client_data2xml(client, data, &id, &flags);
    if (xml == NULL) {
        crm_debug("Unrecognizable IPC data from PID %d", pcmk__client_pid(c));
        return 0;
    }

    CRM_ASSERT(client->user != NULL);
    pcmk__update_acl_user(xml, PCMK__XA_ATTR_USER, client->user);

    op = crm_element_value(xml, PCMK__XA_TASK);

    if (client->name == NULL) {
        const char *value = crm_element_value(xml, F_ORIG);
        client->name = crm_strdup_printf("%s.%d", value?value:"unknown", client->pid);
    }

    if (pcmk__str_eq(op, PCMK__ATTRD_CMD_PEER_REMOVE, pcmk__str_casei)) {
        attrd_send_ack(client, id, flags);
        attrd_client_peer_remove(client, xml);

    } else if (pcmk__str_eq(op, PCMK__ATTRD_CMD_CLEAR_FAILURE, pcmk__str_casei)) {
        attrd_send_ack(client, id, flags);
        attrd_client_clear_failure(xml);

    } else if (pcmk__str_eq(op, PCMK__ATTRD_CMD_UPDATE, pcmk__str_casei)) {
        attrd_send_ack(client, id, flags);
        attrd_client_update(xml);

    } else if (pcmk__str_eq(op, PCMK__ATTRD_CMD_UPDATE_BOTH, pcmk__str_casei)) {
        attrd_send_ack(client, id, flags);
        attrd_client_update(xml);

    } else if (pcmk__str_eq(op, PCMK__ATTRD_CMD_UPDATE_DELAY, pcmk__str_casei)) {
        attrd_send_ack(client, id, flags);
        attrd_client_update(xml);

    } else if (pcmk__str_eq(op, PCMK__ATTRD_CMD_REFRESH, pcmk__str_casei)) {
        attrd_send_ack(client, id, flags);
        attrd_client_refresh();

    } else if (pcmk__str_eq(op, PCMK__ATTRD_CMD_QUERY, pcmk__str_casei)) {
        /* queries will get reply, so no ack is necessary */
        attrd_client_query(client, id, flags, xml);

    } else {
        crm_info("Ignoring request from client %s with unknown operation %s",
                 pcmk__client_name(client), op);
    }

    free_xml(xml);
    return 0;
}

static struct qb_ipcs_service_handlers ipc_callbacks = {
    .connection_accept = attrd_ipc_accept,
    .connection_created = NULL,
    .msg_process = attrd_ipc_dispatch,
    .connection_closed = attrd_ipc_closed,
    .connection_destroyed = attrd_ipc_destroy
};

void
attrd_ipc_fini(void)
{
    if (ipcs != NULL) {
        pcmk__drop_all_clients(ipcs);
        qb_ipcs_destroy(ipcs);
        ipcs = NULL;
    }
}

/*!
 * \internal
 * \brief Set up attrd IPC communication
 */
void
attrd_init_ipc(void)
{
    pcmk__serve_attrd_ipc(&ipcs, &ipc_callbacks);
}
