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
#ifndef CRMD_UTILS__H
#  define CRMD_UTILS__H

#  include <crm/crm.h>
#  include <crm/common/xml.h>
#  include <crm/cib/internal.h> /* For CIB_OP_MODIFY */

#  define CLIENT_EXIT_WAIT 30
#  define FAKE_TE_ID	"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

extern void process_client_disconnect(crmd_client_t * curr_client);

#  define fsa_cib_update(section, data, options, call_id, user_name)	\
	if(fsa_cib_conn != NULL) {					\
	    call_id = fsa_cib_conn->cmds->delegated_variant_op(		\
		fsa_cib_conn, CIB_OP_MODIFY, NULL, section, data,	\
		NULL, options, user_name);				\
									\
	} else {							\
		crm_err("No CIB connection available");			\
	}

#  define fsa_cib_anon_update(section, data, options)			\
	if(fsa_cib_conn != NULL) {					\
	    fsa_cib_conn->cmds->modify(					\
		fsa_cib_conn, section, data, options);			\
									\
	} else {							\
		crm_err("No CIB connection available");			\
	}

extern gboolean fsa_has_quorum;
extern int last_peer_update;

extern gboolean crm_timer_stop(fsa_timer_t * timer);
extern gboolean crm_timer_start(fsa_timer_t * timer);
extern gboolean crm_timer_popped(gpointer data);
extern gboolean is_timer_started(fsa_timer_t *timer);

extern xmlNode *create_node_state(const char *uname, const char *in_cluster,
                                  const char *is_peer, const char *join_state,
                                  const char *exp_state, gboolean clear_shutdown, const char *src);

extern gboolean stop_subsystem(struct crm_subsystem_s *centry, gboolean force_quit);
extern gboolean start_subsystem(struct crm_subsystem_s *centry);

extern void fsa_dump_actions(long long action, const char *text);
extern void fsa_dump_inputs(int log_level, const char *text, long long input_register);

extern gboolean update_dc(xmlNode * msg);
extern void erase_node_from_join(const char *node);
extern void populate_cib_nodes(gboolean with_client_status);
extern void crm_update_quorum(gboolean quorum, gboolean force_update);
extern void erase_status_tag(const char *uname, const char *tag, int options);
extern void update_attrd(const char *host, const char *name, const char *value,
                         const char *user_name);

extern const char *get_timer_desc(fsa_timer_t * timer);
gboolean too_many_st_failures(void);

#  define start_transition(state) do {					\
	switch(state) {							\
	    case S_TRANSITION_ENGINE:					\
		register_fsa_action(A_TE_CANCEL);			\
		break;							\
	    case S_POLICY_ENGINE:					\
	    case S_IDLE:						\
		register_fsa_input(C_FSA_INTERNAL, I_PE_CALC, NULL);	\
		break;							\
	    default:							\
		crm_debug("NOT starting a new transition in state %s",	\
			  fsa_state2string(fsa_state));			\
		break;							\
	}								\
    } while(0)

#endif
