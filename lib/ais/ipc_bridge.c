/*
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <string.h>

#include <crm_internal.h>
#include <crm/crm.h>
#include <crm/common/ipc.h>
#include <glib/ghash.h>

#include <crm/ais.h>

int num_clients = 0;
GHashTable *ipc_client_list = NULL;
gboolean ais_shutdown_flag = FALSE;

typedef struct ais_client_s {
    char *id;
    char *name;
    char *callback_id;

    const char *channel_name;

    IPC_Channel *channel;
    GCHSource *source;
    unsigned long num_calls;
} ais_client_t;

static void
ais_ipc_connection_destroy(gpointer user_data)
{
    ais_client_t *ais_client = user_data;

    if (ais_client == NULL) {
        return;
    }

    if (ais_client->source != NULL) {
        crm_trace("Deleting %s (%p) from mainloop", ais_client->name, ais_client->source);
        G_main_del_IPC_Channel(ais_client->source);
        ais_client->source = NULL;
    }

    crm_trace("Destroying %s (%p)", ais_client->name, user_data);
    num_clients--;
    crm_debug("Num unfree'd clients: %d", num_clients);
    crm_free(ais_client->name);
    crm_free(ais_client->callback_id);
    crm_free(ais_client->id);
    crm_free(ais_client);
    crm_trace("Freed the cib client");

    return;
}

static gboolean
ais_process_disconnect(IPC_Channel * channel, ais_client_t * ais_client)
{
    if (channel == NULL) {
        CRM_LOG_ASSERT(ais_client == NULL);

    } else if (ais_client == NULL) {
        crm_err("No client");

    } else {
        CRM_LOG_ASSERT(channel->ch_status != IPC_CONNECT);
        crm_trace("Cleaning up after client disconnect: %s/%s/%s",
                  crm_str(ais_client->name), ais_client->channel_name, ais_client->id);

        if (ais_client->id != NULL) {
            if (!g_hash_table_remove(ipc_client_list, ais_client->id)) {
                crm_err("Client %s not found in the hashtable", ais_client->name);
            }
        }
    }

    if (ais_shutdown_flag && g_hash_table_size(ipc_client_list) == 0) {
        crm_info("All clients disconnected...");
        exit(0);
    }

    return FALSE;
}

static gboolean
ais_ipc_callback(IPC_Channel * channel, gpointer user_data)
{
    int lpc = 0;
    xmlNode *op_request = NULL;
    gboolean keep_channel = TRUE;
    ais_client_t *ais_client = user_data;

    if (ais_client == NULL) {
        crm_err("Receieved call from unknown source. Discarding.");
        return FALSE;
    }

    if (ais_client->name == NULL) {
        ais_client->name = crm_itoa(channel->farside_pid);
    }
    if (ais_client->id == NULL) {
        ais_client->id = crm_strdup(ais_client->name);
        g_hash_table_insert(ipc_client_list, ais_client->id, ais_client);
    }

    crm_err("Callback for %s on %s channel", ais_client->id, ais_client->channel_name);

    while (IPC_ISRCONN(channel)) {
        if (channel->ops->is_message_pending(channel) == 0) {
            break;
        }

        op_request = msgfromIPC_noauth(channel);
        if (op_request == NULL) {
            perror("Receive failure:");
            break;
        }

        lpc++;
        crm_assert_failed = FALSE;

        ha_msg_add(op_request, "client-id", ais_client->id);
        ha_msg_add(op_request, "client-name", ais_client->name);
        crm_log_xml_err("Client[inbound]", op_request);

/* 		cib_common_callback_worker( */
/* 			op_request, cib_client, force_synchronous, privileged); */

        crm_msg_del(op_request);

        if (channel->ch_status == IPC_CONNECT) {
            break;
        }
    }

    crm_trace("Processed %d messages", lpc);

    if (channel->ch_status != IPC_CONNECT) {
        crm_trace("Client disconnected");
        keep_channel = ais_process_disconnect(channel, ais_client);
    }

    return keep_channel;
}

gboolean
ais_client_connect(IPC_Channel * channel, gpointer user_data)
{
    const char *channel_name = user_data;
    ais_client_t *new_client = NULL;

    crm_trace("Connecting channel");

    if (channel == NULL) {
        crm_err("Channel was NULL");

    } else if (channel->ch_status != IPC_CONNECT) {
        crm_err("Channel was disconnected");

    } else if (channel_name == NULL) {
        crm_err("user_data must contain channel name");

    } else if (ais_shutdown_flag) {
        crm_info("Ignoring new client [%d] during shutdown", channel->farside_pid);

    } else {
        crm_malloc0(new_client, sizeof(ais_client_t));
        num_clients++;
        new_client->channel = channel;
        new_client->channel_name = channel_name;

        crm_trace("Created channel %p for channel %s", new_client, new_client->channel_name);

        channel->ops->set_recv_qlen(channel, 500);
        channel->ops->set_send_qlen(channel, 500);

        new_client->source =
            G_main_add_IPC_Channel(G_PRIORITY_DEFAULT, channel, FALSE, ais_ipc_callback, new_client,
                                   ais_ipc_connection_destroy);

        crm_trace("Channel %s connected for client %s", new_client->channel_name, new_client->id);
    }

    if (new_client == NULL) {
        return FALSE;
    }
    return TRUE;
}
