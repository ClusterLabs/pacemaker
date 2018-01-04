/*
 * Copyright (C) 2013 Andrew Beekhof <andrew@beekhof.net>
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
#ifndef PE_REMOTE__H
#  define PE_REMOTE__H

gboolean xml_contains_remote_node(xmlNode *xml);
gboolean is_baremetal_remote_node(node_t *node);
gboolean is_container_remote_node(node_t *node);
gboolean is_remote_node(node_t *node);
gboolean is_rsc_baremetal_remote_node(resource_t *rsc, pe_working_set_t * data_set);
resource_t * rsc_contains_remote_node(pe_working_set_t * data_set, resource_t *rsc);
void pe_foreach_guest_node(const pe_working_set_t *data_set, const node_t *host,
                           void (*helper)(const node_t*, void*), void *user_data);
xmlNode *pe_create_remote_xml(xmlNode *parent, const char *uname,
                              const char *container_id, const char *migrateable,
                              const char *is_managed, const char *start_timeout,
                              const char *server, const char *port);

#endif
