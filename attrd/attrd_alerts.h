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

#ifndef ATTRD_ALERT__H
#  define ATTRD_ALERT__H

#  include <crm/crm.h>
#  include <crm/cluster.h>
#  include <crm/common/alerts_internal.h>

extern cib_t *the_cib;
extern lrmd_t *the_lrmd;
extern crm_trigger_t *attrd_config_read;

lrmd_t * attrd_lrmd_connect(void);
void attrd_lrmd_disconnect(void);
gboolean attrd_read_options(gpointer user_data);
void attrd_cib_updated_cb(const char *event, xmlNode * msg);
void attrd_enable_alerts(const char *script, const char *target);
int lrmd_send_attribute_alert(GList *alert_list,
                              lrmd_t *(*lrmd_connect_func)(void),
                              const char *node, uint32_t nodeid,
                              const char *attr_name, const char *attr_value);
#if HAVE_ATOMIC_ATTRD
void set_alert_attribute_value(GHashTable *t, attribute_value_t *v);
void send_alert_attributes_value(attribute_t *a, GHashTable *t);
#endif
#endif

