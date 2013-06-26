/* 
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
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
#ifndef TE_CALLBACKS__H
#  define TE_CALLBACKS__H

extern void cib_fencing_updated(xmlNode * msg, int call_id, int rc,
                                xmlNode * output, void *user_data);

extern void cib_action_updated(xmlNode * msg, int call_id, int rc,
                               xmlNode * output, void *user_data);

extern gboolean global_timer_callback(gpointer data);
extern gboolean action_timer_callback(gpointer data);

extern gboolean te_graph_trigger(gpointer user_data);

extern void te_update_diff(const char *event, xmlNode * msg);

extern void tengine_stonith_callback(stonith_t * stonith, stonith_callback_data_t * data);

#endif
