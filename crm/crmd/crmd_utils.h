/* $Id: crmd_utils.h,v 1.1 2004/06/01 12:25:15 andrew Exp $ */
/* 
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#ifndef CRMD_UTILS__H
#define CRMD_UTILS__H

#include <libxml/tree.h>
#include <crm/crm.h>

extern long long toggle_bit   (long long  action_list, long long action);
extern long long clear_bit    (long long  action_list, long long action);
extern long long set_bit      (long long  action_list, long long action);

extern void toggle_bit_inplace(long long *action_list, long long action);
extern void clear_bit_inplace (long long *action_list, long long action);
extern void set_bit_inplace   (long long *action_list, long long action);

extern gboolean is_set(long long action_list, long long action);

extern gboolean startTimer(fsa_timer_t *timer);
extern gboolean stopTimer(fsa_timer_t *timer);
extern gboolean timer_popped(gpointer data);

extern void cleanup_subsystem(struct crm_subsystem_s *the_subsystem);

extern xmlNodePtr create_node_state(const char *node,
				    const char *ccm_state,
				    const char *crmd_state,
				    const char *join_state);

extern enum crmd_fsa_input invoke_local_cib(xmlNodePtr msg_options,
					    xmlNodePtr msg_data,
					    const char *operation);

#endif
