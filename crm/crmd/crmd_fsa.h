/* $Id: crmd_fsa.h,v 1.19 2004/05/28 07:55:28 andrew Exp $ */
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
#ifndef XML_CRM_FSA__H
#define XML_CRM_FSA__H

#include <fsa_defines.h>
#include <ocf/oc_event.h>
#include <clplumbing/ipc.h>
#include <hb_api.h>
#include <libxml/tree.h>
#include <lrm/lrm_api.h>
#include <crm/crm.h>

struct ccm_data 
{
		const oc_ev_membership_t *oc;
		oc_ed_t *event;
};


struct oc_node_list_s
{
		int members_size;
		GHashTable *members; // contents: oc_node_t *

		int new_members_size;
		GHashTable *new_members; // contents: oc_node_t *

		int dead_members_size;
		GHashTable *dead_members; // contents: oc_node_t *
};

/* copy from struct client_child in heartbeat.h
 *
 * Plus a couple of other things
 */
typedef struct oc_node_list_s oc_node_list_t;
struct crm_subsystem_s {
		pid_t	pid;		/* Process id of child process */
		int	respawn;	/* Respawn it if it dies? */
		int	respawncount;	/* Last time we respawned this command */
		int	shortrcount;	/* How many times has it respawned too fast? */
		const char*	command;	/* What command to run? */
		const char*	path;		/* Path (argv[0])? */
/* extras */
		const char*	name;
		IPC_Channel	*ipc;	/* How can we communicate with it */
		long long	flag;	/*  */
};

typedef struct fsa_timer_s fsa_timer_t;
struct fsa_timer_s 
{
		guint	source_id;	/* timer source id */
		uint	period_ms;	/* timer period */
		enum crmd_fsa_input fsa_input;
		gboolean (*callback)(gpointer data);
};



extern enum crmd_fsa_state s_crmd_fsa(enum crmd_fsa_cause cause,
				      enum crmd_fsa_input initial_input,
				      void *data);

extern long long clear_flags(long long actions,
			     enum crmd_fsa_cause cause,
enum crmd_fsa_state cur_state,
			     enum crmd_fsa_input cur_input);
/* Utilities */
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
extern gboolean do_dc_heartbeat(gpointer data);


/* Global FSA stuff */
extern enum crmd_fsa_state fsa_state;
extern oc_node_list_t *fsa_membership_copy;
extern ll_cluster_t   *fsa_cluster_conn;
extern ll_lrm_t       *fsa_lrm_conn;
extern long long       fsa_input_register;
extern const char     *fsa_our_uname;
extern char	      *fsa_pe_ref; // the last invocation of the PE
extern const char     *fsa_our_dc;

extern fsa_timer_t *election_trigger;		/*  */
extern fsa_timer_t *election_timeout;		/*  */
extern fsa_timer_t *shutdown_escalation_timmer;	/*  */
extern fsa_timer_t *dc_heartbeat;
extern fsa_timer_t *integration_timer;

extern struct crm_subsystem_s *cib_subsystem;
extern struct crm_subsystem_s *te_subsystem;
extern struct crm_subsystem_s *pe_subsystem;

extern void cleanup_subsystem(struct crm_subsystem_s *the_subsystem);
extern enum crmd_fsa_input send_cib_status_update(xmlNodePtr update);
extern xmlNodePtr create_node_state(const char *node, const char *state,
				    const char *exp_state, xmlNodePtr lrm_data);
extern xmlNodePtr do_update_cib_nodes(xmlNodePtr updates);

#define AM_I_DC is_set(fsa_input_register, R_THE_DC)
#define AM_I_OPERATIONAL (is_set(fsa_input_register, R_STARTING)==FALSE)

#include <fsa_proto.h>

#endif
