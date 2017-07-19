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

#ifndef LRMD_ALERT_INTERNAL_H
#define LRMD_ALERT_INTERNAL_H

#include <glib.h>
#include <crm/lrmd.h>

int lrmd_send_attribute_alert(GList *alert_list,
                              lrmd_t *(*lrmd_connect_func)(void),
                              const char *node, uint32_t nodeid,
                              const char *attr_name, const char *attr_value);
int lrmd_send_node_alert(GList *alert_list, lrmd_t *(*lrmd_connect_func)(void),
                         const char *node, uint32_t nodeid, const char *state);
int lrmd_send_fencing_alert(GList *alert_list,
                            lrmd_t *(*lrmd_connect_func)(void),
                            const char *target, const char *task,
                            const char *desc, int op_rc);
int lrmd_send_resource_alert(GList *alert_list,
                             lrmd_t *(*lrmd_connect_func)(void),
                             const char *node, lrmd_event_data_t *op);

#endif
