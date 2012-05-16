/* 
 * Copyright (C) 2011 Andrew Beekhof <andrew@beekhof.net>
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
#ifndef STONITH_NG_INTERNAL__H
#  define STONITH_NG_INTERNAL__H

#  include <crm/common/ipc.h>
#  include <crm/common/xml.h>
#  include <clplumbing/proctrack.h>

typedef struct async_command_s {

    int id;
    int stdout;
    int options;
    int timeout;

    char *op;
    char *origin;
    char *client;
    char *remote;

    char *victim;
    char *action;
    char *device;

    GListPtr device_list;
    GListPtr device_next;

    void (*done)(GPid pid, gint status, gpointer user_data);
    guint timer_sigterm;
    guint timer_sigkill;

} async_command_t;

extern int run_stonith_agent(const char *agent, const char *action, const char *victim,
                             GHashTable * dev_hash, GHashTable * port_map, int *agent_result,
                             char **output, async_command_t * track);

extern gboolean is_redhat_agent(const char *agent);

xmlNode *create_level_registration_xml(const char *node, int level,
                                       stonith_key_value_t * device_list);

xmlNode *create_device_registration_xml(const char *id, const char *namespace, const char *agent,
                                        stonith_key_value_t * params);

#endif
