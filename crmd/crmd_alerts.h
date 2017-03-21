/*
 * Copyright (C) 2015 Andrew Beekhof <andrew@beekhof.net>
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
#ifndef CRMD_ALERTS_H
#  define CRMD_ALERTS_H

#  include <crm/crm.h>
#  include <crm/cluster.h>
#  include <crm/stonith-ng.h>

void crmd_enable_notifications(const char *script, const char *target);
void crmd_notify_node_event(crm_node_t *node);
void crmd_notify_fencing_op(stonith_event_t *e);
void crmd_notify_resource_op(const char *node, lrmd_event_data_t *op);
void crmd_drain_alerts(GMainContext *ctx);
void parse_notifications(xmlNode *notifications);

#endif
