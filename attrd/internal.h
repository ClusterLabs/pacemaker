/*
 * Copyright (C) 2013-2017 Andrew Beekhof <andrew@beekhof.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <attrd_common.h>

typedef struct attribute_s {
    char *uuid; /* TODO: Remove if at all possible */
    char *id;
    char *set;
    GHashTable *values;
    int update;
    int timeout_ms;

    /* TODO: refactor these three as a bitmask */
    bool changed; /* whether attribute value has changed since last write */
    bool unknown_peer_uuids; /* whether we know we're missing a peer uuid */
    gboolean is_private; /* whether to keep this attribute out of the CIB */

    mainloop_timer_t *timer;

    char *user;

} attribute_t;

typedef struct attribute_value_s {
        uint32_t nodeid;
        gboolean is_remote;
        char *nodename;
        char *current;
        char *requested;
} attribute_value_t;

crm_cluster_t *attrd_cluster;
GHashTable *attributes;
election_t *writer;

#define attrd_send_ack(client, id, flags) \
    crm_ipcs_send_ack((client), (id), (flags), "ack", __FUNCTION__, __LINE__)

void write_attributes(bool all);
void attrd_broadcast_protocol(void);
void attrd_peer_message(crm_node_t *client, xmlNode *msg);
void attrd_client_peer_remove(const char *client_name, xmlNode *xml);
void attrd_client_clear_failure(xmlNode *xml);
void attrd_client_update(xmlNode *xml);
void attrd_client_refresh(void);
void attrd_client_query(crm_client_t *client, uint32_t id, uint32_t flags, xmlNode *query);

void free_attribute(gpointer data);

gboolean attrd_election_cb(gpointer user_data);
void attrd_peer_change_cb(enum crm_status_type type, crm_node_t *peer, const void *data);
