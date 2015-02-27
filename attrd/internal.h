/*
 * Copyright (C) 2013 Andrew Beekhof <andrew@beekhof.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

cib_t *the_cib;
GMainLoop *mloop;
bool shutting_down;
crm_cluster_t *attrd_cluster;
GHashTable *attributes;
election_t *writer;
int attrd_error;

void write_attributes(bool all, bool peer_discovered);
void attrd_peer_message(crm_node_t *client, xmlNode *msg);
void attrd_client_message(crm_client_t *client, xmlNode *msg);
void free_attribute(gpointer data);

gboolean attrd_election_cb(gpointer user_data);
void attrd_peer_change_cb(enum crm_status_type type, crm_node_t *peer, const void *data);
