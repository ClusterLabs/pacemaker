/* $Id: crmd_utils.h,v 1.10 2004/12/05 16:35:09 andrew Exp $ */
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

#define CLIENT_EXIT_WAIT 30

extern enum crmd_fsa_input update_local_cib(
	xmlNodePtr msg_data, gboolean callbacks);


extern long long toggle_bit   (long long  action_list, long long action);
extern long long clear_bit    (long long  action_list, long long action);
extern long long set_bit      (long long  action_list, long long action);

#define set_bit_inplace(word, bit)    word = set_bit(word, bit)
#define clear_bit_inplace(word, bit)  word = clear_bit(word, bit)
#define toggle_bit_inplace(word, bit) word = toggle_bit(word, bit)

extern gboolean is_set(long long action_list, long long action);
extern gboolean is_set_any(long long action_list, long long action);

extern gboolean stopTimer (fsa_timer_t *timer);
extern gboolean startTimer(fsa_timer_t *timer);
extern gboolean timer_popped(gpointer data);

extern void cleanup_subsystem(struct crm_subsystem_s *the_subsystem);

extern xmlNodePtr create_node_state(
	const char *uuid, const char *uname,
	const char *ha_state, const char *ccm_state,
	const char *crmd_state, const char *join_state, const char *exp_state);

extern void create_node_entry(
	const char *uuid, const char *uname, const char *type);

extern void set_uuid(xmlNodePtr node, const char *attr, const char *uname);

extern gboolean stop_subsystem (struct crm_subsystem_s *centry);
extern gboolean start_subsystem(struct crm_subsystem_s *centry);

extern lrm_op_t *copy_lrm_op(const lrm_op_t *op);
extern lrm_rsc_t *copy_lrm_rsc(const lrm_rsc_t *rsc);
extern struct crmd_ccm_data_s *copy_ccm_data(
	const struct crmd_ccm_data_s *ccm_input);
extern oc_ev_membership_t *copy_ccm_oc_data(const oc_ev_membership_t *oc_in) ;

extern void fsa_dump_actions(long long action, const char *text);

#endif
