/* $Id: master.c,v 1.1 2005/09/12 11:04:22 andrew Exp $ */
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

#include <portability.h>

#include <pengine.h>
#include <pe_utils.h>
#include <crm/msg_xml.h>

extern void clone_create_notifications(
	resource_t *rsc, action_t *action, action_t *action_complete,
	pe_working_set_t *data_set);

typedef struct clone_variant_data_s
{
		resource_t *self;

		int clone_max;
		int clone_max_node;

		int active_clones;
		int max_nodes;

		gboolean interleave;
		gboolean ordered;

		gboolean notify_confirm;
		
		GListPtr child_list; /* resource_t* */
		
} clone_variant_data_t;

#define NO_MASTER_PREFS 0

#define get_clone_variant_data(data, rsc)				\
	CRM_ASSERT(rsc->variant == pe_master);				\
	data = (clone_variant_data_t *)rsc->variant_opaque;

void master_unpack(resource_t *rsc, pe_working_set_t *data_set)
{
	add_hash_param(rsc->parameters, "stateful", XML_BOOLEAN_TRUE);
	clone_unpack(rsc, data_set);
}

static void
child_promoting_constraints(
	clone_variant_data_t *clone_data, enum pe_ordering type,
	resource_t *child, resource_t *last, pe_working_set_t *data_set)
{
/* 	if(clone_data->ordered */
/* 	   || clone_data->self->restart_type == pe_restart_restart) { */
/* 		type = pe_ordering_manditory; */
/* 	} */
	if(child == NULL) {
		if(clone_data->ordered && last != NULL) {
			crm_debug_4("Ordered version (last node)");
			/* last child promote before promoted started */
			custom_action_order(
				last, promote_key(last), NULL,
				clone_data->self, promoted_key(clone_data->self), NULL,
				type, data_set);
		}
		
	} else if(clone_data->ordered) {
		crm_debug_4("Ordered version");
		if(last == NULL) {
			/* global promote before first child promote */
			last = clone_data->self;

		} /* else: child/child relative promote */

		order_start_start(last, child, type);
		custom_action_order(
			last, promote_key(last), NULL,
			child, promote_key(child), NULL,
			type, data_set);

	} else {
		crm_debug_4("Un-ordered version");
		
		/* child promote before global promoted */
		custom_action_order(
			child, promote_key(child), NULL,
			clone_data->self, promoted_key(clone_data->self), NULL,
			type, data_set);
                
		/* global promote before child promote */
		custom_action_order(
			clone_data->self, promote_key(clone_data->self), NULL,
			child, promote_key(child), NULL,
			type, data_set);

	}
}

static void
child_demoting_constraints(
	clone_variant_data_t *clone_data, enum pe_ordering type,
	resource_t *child, resource_t *last, pe_working_set_t *data_set)
{
/* 	if(clone_data->ordered */
/* 	   || clone_data->self->restart_type == pe_restart_restart) { */
/* 		type = pe_ordering_manditory; */
/* 	} */
	
	if(child == NULL) {
		if(clone_data->ordered && last != NULL) {
			crm_debug_4("Ordered version (last node)");
			/* global demote before first child demote */
			custom_action_order(
				clone_data->self, demote_key(clone_data->self), NULL,
				last, demote_key(last), NULL,
				pe_ordering_manditory, data_set);
		}
		
	} else if(clone_data->ordered && last != NULL) {
		crm_debug_4("Ordered version");

		/* child/child relative demote */
		custom_action_order(child, demote_key(child), NULL,
				    last, demote_key(last), NULL,
				    type, data_set);

	} else if(clone_data->ordered) {
		crm_debug_4("Ordered version (1st node)");
		/* first child stop before global stopped */
		custom_action_order(
			child, demote_key(child), NULL,
			clone_data->self, demoted_key(clone_data->self), NULL,
			type, data_set);

	} else {
		crm_debug_4("Un-ordered version");

		/* child demote before global demoted */
		custom_action_order(
			child, demote_key(child), NULL,
			clone_data->self, demoted_key(clone_data->self), NULL,
			type, data_set);
                        
		/* global demote before child demote */
		custom_action_order(
			clone_data->self, demote_key(clone_data->self), NULL,
			child, demote_key(child), NULL,
			type, data_set);
	}
}


static void
master_update_pseudo_status(
	resource_t *child, gboolean *demoting, gboolean *promoting) 
{
	CRM_ASSERT(demoting != NULL);
	CRM_ASSERT(promoting != NULL);

	slist_iter(
		action, action_t, child->actions, lpc,

		if(*promoting && *demoting) {
			return;

		} else if(action->optional) {
			continue;

		} else if(safe_str_eq(CRMD_ACTION_DEMOTE, action->task)) {
			*demoting = TRUE;

		} else if(safe_str_eq(CRMD_ACTION_PROMOTE, action->task)) {
			*promoting = TRUE;
		}
		);

}

void master_create_actions(resource_t *rsc, pe_working_set_t *data_set)
{
	int len = 0;
	node_t *chosen = NULL;
	char *attr_name = NULL;
	const char *attr_value = NULL;
	
	action_t *action = NULL;
	action_t *action_complete = NULL;
	gboolean any_promoting = FALSE;
	gboolean any_demoting = FALSE;
	resource_t *last_promote_rsc = NULL;
	resource_t *last_demote_rsc = NULL;
	const char *master_max_s =
		get_rsc_param(rsc, XML_RSC_ATTR_MASTER_MAX);
	const char *master_node_max_s =
		get_rsc_param(rsc, XML_RSC_ATTR_MASTER_NODEMAX);

	int promoted = 0;
	int max_nodes = 0;
	int master_max = crm_atoi(master_max_s, "1");
	int master_node_max = crm_atoi(master_node_max_s, "1");
	
	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, rsc);

	/* how many can we have? */
	if(master_max >  clone_data->max_nodes * clone_data->clone_max_node) {
		master_max = clone_data->max_nodes * clone_data->clone_max_node;
		crm_info("Limited to %d masters (potential slaves)",master_max);
	}
	if(master_max >  max_nodes * master_node_max) {
		master_max = clone_data->max_nodes * master_node_max;
		crm_info("Limited to %d masters (available nodes)", master_max);
	}
	
	/*
	 * assign priority
	 */

	slist_iter(
		child_rsc, resource_t, clone_data->child_list, lpc,

		CRM_DEV_ASSERT(child_rsc->color != NULL);
		chosen = child_rsc->color->details->chosen_node;
		
		switch(child_rsc->next_role) {
			case RSC_ROLE_STARTED:
				if(NO_MASTER_PREFS) {
					child_rsc->priority =
						clone_data->clone_max - lpc;
					break;
				}
				
				child_rsc->priority = -1;

				CRM_DEV_ASSERT(chosen != NULL);

				len = 8 + strlen(child_rsc->id);
				crm_malloc0(attr_name, len);
				sprintf(attr_name, "master-%s", child_rsc->id);
				
				attr_value = g_hash_table_lookup(
					chosen->details->attrs, attr_name);

				crm_err("%s=%s for %s", attr_name,
					crm_str(attr_value),
					chosen->details->uname);
				
				if(attr_value != NULL) {
					child_rsc->priority = char2score(
						attr_value);
				}
				crm_free(attr_name);
				break;
			case RSC_ROLE_SLAVE:
				child_rsc->priority = -1;
				break;
			case RSC_ROLE_STOPPED:
				child_rsc->priority = -2;
				break;
			default:
				CRM_DEV_ASSERT(FALSE/* unhandled */);
		}
		);

	/* sort based on the new "promote" priority */
	clone_data->child_list = g_list_sort(
		clone_data->child_list, sort_rsc_priority);

	/* mark the first N as masters */
	slist_iter(
		child_rsc, resource_t, clone_data->child_list, lpc,
		switch(child_rsc->next_role) {
			case RSC_ROLE_STARTED:
				if(child_rsc->priority > 0 && master_max > lpc){
					crm_info("Promoting %s", child_rsc->id);
					child_rsc->next_role = RSC_ROLE_MASTER;
					promoted++;
					
				} else {
					crm_info("Demoting %s", child_rsc->id);
					child_rsc->next_role = RSC_ROLE_SLAVE;
				}
				break;
				
			case RSC_ROLE_SLAVE:
				if(child_rsc->priority < 0 ||master_max <= lpc){
					pe_warn("Cannot promote %s (slave)",
						child_rsc->id);
					lpc--;
				}
				break;

			case RSC_ROLE_STOPPED:
				if(child_rsc->priority < 0 ||master_max <= lpc){
					pe_warn("Cannot promote %s (stopping)",
						child_rsc->id);
					lpc--;
				}
				break;
			default:
				CRM_DEV_ASSERT(FALSE/* unhandled */);
		}
		);
	crm_info("Promoted %d (of %d) slaves to master", promoted, master_max);
	
	/* create actions as normal */
	clone_create_actions(rsc, data_set);

	slist_iter(
		child_rsc, resource_t, clone_data->child_list, lpc,
		gboolean child_promoting = FALSE;
		gboolean child_demoting = FALSE;

		master_update_pseudo_status(
			child_rsc, &child_demoting, &child_promoting);

		any_demoting = any_demoting || child_demoting;
		any_promoting = any_promoting || child_promoting;
		);
	
	/* promote */
	action = promote_action(clone_data->self, NULL, !any_promoting);
	action_complete = custom_action(
		clone_data->self, promoted_key(rsc),
		CRMD_ACTION_PROMOTED, NULL, !any_promoting, data_set);

	action->pseudo = TRUE;
	action_complete->pseudo = TRUE;
	
	child_promoting_constraints(clone_data, pe_ordering_optional, 
				   NULL, last_promote_rsc, data_set);

	clone_create_notifications(rsc, action, action_complete, data_set);	


	/* demote */
	action = demote_action(clone_data->self, NULL, !any_demoting);
	action_complete = custom_action(
		clone_data->self, demoted_key(rsc),
		CRMD_ACTION_DEMOTED, NULL, !any_demoting, data_set);

	action->pseudo = TRUE;
	action_complete->pseudo = TRUE;
	
	child_demoting_constraints(clone_data, pe_ordering_optional,
				   NULL, last_demote_rsc, data_set);

	clone_create_notifications(rsc, action, action_complete, data_set);	
}

void
master_internal_constraints(resource_t *rsc, pe_working_set_t *data_set)
{
	resource_t *last_rsc = NULL;	
	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, rsc);

	clone_internal_constraints(rsc, data_set);
	
	/* global demoted before start */
	custom_action_order(
		clone_data->self, demoted_key(clone_data->self), NULL,
		clone_data->self, start_key(clone_data->self), NULL,
		pe_ordering_optional, data_set);

	/* global started before promote */
	custom_action_order(
		clone_data->self, started_key(clone_data->self), NULL,
		clone_data->self, promote_key(clone_data->self), NULL,
		pe_ordering_optional, data_set);

	/* global demoted before stop */
	custom_action_order(
		clone_data->self, demoted_key(clone_data->self), NULL,
		clone_data->self, stop_key(clone_data->self), NULL,
		pe_ordering_optional, data_set);

	/* global demote before demoted */
	custom_action_order(
		clone_data->self, demote_key(clone_data->self), NULL,
		clone_data->self, demoted_key(clone_data->self), NULL,
		pe_ordering_optional, data_set);
	
	slist_iter(
		child_rsc, resource_t, clone_data->child_list, lpc,

		/* child demote before promote */
		custom_action_order(
			child_rsc, demote_key(child_rsc), NULL,
			child_rsc, promote_key(child_rsc), NULL,
			pe_ordering_restart, data_set);
		
		child_promoting_constraints(clone_data, pe_ordering_optional,
					    child_rsc, last_rsc, data_set);

		child_demoting_constraints(clone_data, pe_ordering_optional,
					   child_rsc, last_rsc, data_set);

		last_rsc = child_rsc;
		
		);
	
}

