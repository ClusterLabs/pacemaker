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

#include <sys/param.h>
#include <crm/crm.h>
#include <crmd_fsa.h>

#include <sys/types.h>
#include <sys/wait.h>

#include <unistd.h>			/* for access */
#include <heartbeat.h>
#include <clplumbing/cl_signal.h>

#include <errno.h>

#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>

#include <crmd.h>
#include <crmd_messages.h>
#include <crmd_callbacks.h>
#include <crmd_lrm.h>

#include <lrm/raexec.h>

#include <crm/dmalloc_wrapper.h>

char *make_stop_id(const char *rsc, int call_id);
void ghash_print_pending(gpointer key, gpointer value, gpointer user_data);

gboolean stop_all_resources(void);
gboolean resource_stopped(gpointer key, gpointer value, gpointer user_data);

gboolean build_operation_update(
	crm_data_t *rsc_list, lrm_op_t *op, const char *src, int lpc);

gboolean build_active_RAs(crm_data_t *rsc_list);
gboolean is_rsc_active(const char *rsc_id);

void do_update_resource(lrm_op_t *op);
gboolean process_lrm_event(lrm_op_t *op);

enum crmd_fsa_input do_lrm_rsc_op(
	lrm_rsc_t *rsc, char *rid, const char *operation,
	crm_data_t *msg, HA_Message *request);

enum crmd_fsa_input do_fake_lrm_op(gpointer data);

void stop_recurring_action(
	gpointer key, gpointer value, gpointer user_data);

gboolean remove_recurring_action(
	gpointer key, gpointer value, gpointer user_data);

lrm_op_t *construct_op(
	crm_data_t *rsc_op, const char *rsc_id, const char *operation);

void send_direct_ack(const char *to_host, const char *to_sys,
		     lrm_op_t* op, const char *rsc_id);

void free_recurring_op(gpointer value);


GHashTable *monitors = NULL;
GHashTable *resources = NULL;
GHashTable *resources_confirmed = NULL;
GHashTable *shutdown_ops = NULL;

int num_lrm_register_fails = 0;
int max_lrm_register_fails = 30;

enum crmd_rscstate {
	crmd_rscstate_NULL,
	crmd_rscstate_START,
	crmd_rscstate_START_PENDING,
	crmd_rscstate_START_OK,	
	crmd_rscstate_START_FAIL,	
	crmd_rscstate_STOP,
	crmd_rscstate_STOP_PENDING,
	crmd_rscstate_STOP_OK,	
	crmd_rscstate_STOP_FAIL,		
	crmd_rscstate_MON,
	crmd_rscstate_MON_PENDING,
	crmd_rscstate_MON_OK,
	crmd_rscstate_MON_FAIL,		
	crmd_rscstate_GENERIC_PENDING,
	crmd_rscstate_GENERIC_OK,
	crmd_rscstate_GENERIC_FAIL	
};


const char *crmd_rscstate2string(enum crmd_rscstate state);

const char *
crmd_rscstate2string(enum crmd_rscstate state) 
{
	switch(state) {
		case crmd_rscstate_NULL:
			return NULL;
			
		case crmd_rscstate_START:
			return CRMD_ACTION_START;
			
		case crmd_rscstate_START_PENDING:
			return CRMD_ACTION_START_PENDING;
			
		case crmd_rscstate_START_OK:
			return CRMD_ACTION_STARTED;
			
		case crmd_rscstate_START_FAIL:
			return CRMD_ACTION_START_FAIL;
			
		case crmd_rscstate_STOP:
			return CRMD_ACTION_STOP;
			
		case crmd_rscstate_STOP_PENDING:
			return CRMD_ACTION_STOP_PENDING;
			
		case crmd_rscstate_STOP_OK:
			return CRMD_ACTION_STOPPED;
			
		case crmd_rscstate_STOP_FAIL:
			return CRMD_ACTION_STOP_FAIL;
			
		case crmd_rscstate_MON:
			return CRMD_ACTION_MON;
			
		case crmd_rscstate_MON_PENDING:
			return CRMD_ACTION_MON_PENDING;
			
		case crmd_rscstate_MON_OK:
			return CRMD_ACTION_MON_OK;
			
		case crmd_rscstate_MON_FAIL:
			return CRMD_ACTION_MON_FAIL;
			
		case crmd_rscstate_GENERIC_PENDING:
			return CRMD_ACTION_GENERIC_PENDING;
			
		case crmd_rscstate_GENERIC_OK:
			return CRMD_ACTION_GENERIC_OK;
			
		case crmd_rscstate_GENERIC_FAIL:
			return CRMD_ACTION_GENERIC_FAIL;
			
	}
	return "<unknown>";
}

GCHSource *lrm_source = NULL;

/*	 A_LRM_CONNECT	*/
enum crmd_fsa_input
do_lrm_control(long long action,
	       enum crmd_fsa_cause cause,
	       enum crmd_fsa_state cur_state,
	       enum crmd_fsa_input current_input,
	       fsa_data_t *msg_data)
{
	int ret = HA_OK;

	if(action & A_LRM_DISCONNECT) {
		if(lrm_source) {
			crm_debug("Removing LRM connection from MainLoop");
			if(G_main_del_IPC_Channel(lrm_source) == FALSE) {
				crm_err("Could not remove LRM connection"
					" from MainLoop");
			}
			lrm_source = NULL;			
		}
		if(fsa_lrm_conn) {
			fsa_lrm_conn->lrm_ops->signoff(fsa_lrm_conn);
			crm_info("Disconnected from the LRM");
			clear_bit_inplace(fsa_input_register, R_LRM_CONNECTED);
			fsa_lrm_conn = NULL;
		}
		/* TODO: Clean up the hashtable */
	}

	if(action & A_LRM_CONNECT) {
	
		ret = HA_OK;
		
		monitors = g_hash_table_new_full(
			g_str_hash, g_str_equal,
			g_hash_destroy_str, free_recurring_op);

		resources = g_hash_table_new_full(
			g_str_hash, g_str_equal,
			g_hash_destroy_str, g_hash_destroy_str);
		
		resources_confirmed = g_hash_table_new_full(
			g_str_hash, g_str_equal,
			g_hash_destroy_str, g_hash_destroy_str);
		
		shutdown_ops = g_hash_table_new_full(
			g_str_hash, g_str_equal,
			g_hash_destroy_str, g_hash_destroy_str);
		
		fsa_lrm_conn = ll_lrm_new(XML_CIB_TAG_LRM);	
		if(NULL == fsa_lrm_conn) {
			register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);
			ret = HA_FAIL;
		}

		if(ret == HA_OK) {
			crm_debug("Connecting to the LRM");
			ret = fsa_lrm_conn->lrm_ops->signon(
				fsa_lrm_conn, CRM_SYSTEM_CRMD);
		}
		
		if(ret != HA_OK) {
			if(++num_lrm_register_fails < max_lrm_register_fails) {
				crm_warn("Failed to sign on to the LRM %d"
					 " (%d max) times",
					 num_lrm_register_fails,
					 max_lrm_register_fails);
				
				crm_timer_start(wait_timer);
				crmd_fsa_stall(NULL);
				return I_NULL;
			}
		}

		if(ret == HA_OK) {
			crm_debug_4("LRM: set_lrm_callback...");
			ret = fsa_lrm_conn->lrm_ops->set_lrm_callback(
				fsa_lrm_conn, lrm_op_callback);
			if(ret != HA_OK) {
				crm_err("Failed to set LRM callbacks");
			}
		}
		
		if(ret != HA_OK) {
			crm_err("Failed to sign on to the LRM %d"
				" (max) times", num_lrm_register_fails);
			register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);
			return I_NULL;
		}

		/* TODO: create a destroy handler that causes
		 * some recovery to happen
		 */
		lrm_source = G_main_add_IPC_Channel(
			G_PRIORITY_LOW,
			fsa_lrm_conn->lrm_ops->ipcchan(fsa_lrm_conn),
			FALSE, lrm_dispatch, fsa_lrm_conn,
			default_ipc_connection_destroy);

		set_bit_inplace(fsa_input_register, R_LRM_CONNECTED);
		crm_debug("LRM connection established");
		
	}	

	if(action & ~(A_LRM_CONNECT|A_LRM_DISCONNECT)) {
		crm_err("Unexpected action %s in %s",
		       fsa_action2string(action), __FUNCTION__);
	}
		
	
	return I_NULL;
}

gboolean
stop_all_resources(void)
{
	GListPtr lrm_list = NULL;

	crm_info("Making sure all active resources are stopped before exit");
	
	if(fsa_lrm_conn == NULL) {
		return TRUE;

	} else if(is_set(fsa_input_register, R_SENT_RSC_STOP)) {
		crm_debug("Already sent stop operation");
		return TRUE;
	}

	lrm_list = fsa_lrm_conn->lrm_ops->get_all_rscs(fsa_lrm_conn);
	slist_iter(
		rsc_id, char, lrm_list, lpc,

		if(is_rsc_active(rsc_id)) {
			crm_err("Resource %s was active at shutdown."
				"  You may ignore this error if it is unmanaged.",
				rsc_id);
/* 			do_lrm_rsc_op(NULL, rsc_id, CRMD_ACTION_STOP, NULL, NULL); */
		}
		);

	set_bit_inplace(fsa_input_register, R_SENT_RSC_STOP);
	
	if(g_hash_table_size(shutdown_ops) == 0) {
		register_fsa_input(C_FSA_INTERNAL, I_TERMINATE, NULL);

	} else {
		crm_info("Waiting for %d pending stop operations "
			 " to complete before exiting",
			 g_hash_table_size(shutdown_ops));
	}

	return TRUE;
}

gboolean
build_operation_update(
	crm_data_t *xml_rsc, lrm_op_t *op, const char *src, int lpc)
{
	char *fail_state = NULL;
	const char *state = NULL;
	crm_data_t *xml_op = NULL;
	char *op_id = NULL;
	const char *caller_version = NULL;	

	CRM_DEV_ASSERT(op != NULL);
	if(crm_assert_failed) {
		return FALSE;
	}

	crm_debug_2("%s: Updating resouce %s after %s %s op",
		 src, op->rsc_id, op_status2text(op->op_status), op->op_type);

	if(op->op_status == LRM_OP_CANCELLED) {
		crm_debug_3("Ignoring cancelled op");
		return TRUE;
	}

	if(AM_I_DC) {
		caller_version = CRM_FEATURE_SET;

	} else if(fsa_our_dc_version != NULL) {
		caller_version = fsa_our_dc_version;

	} else {
		/* there is a small risk in formerly mixed clusters that
		 *   it will be sub-optimal.
		 * however with our upgrade policy, the update we send
		 *   should still be completely supported anyway
		 */
		caller_version = g_hash_table_lookup(
			op->params, XML_ATTR_CRM_VERSION);
		crm_warn("Falling back to operation originator version: %s",
			 caller_version);
	}
	crm_debug_3("DC version: %s", caller_version);
	
	if(safe_str_eq(op->op_type, CRMD_ACTION_NOTIFY)) {
		const char *n_type = g_hash_table_lookup(
			op->params, "notify_type");
		const char *n_task = g_hash_table_lookup(
			op->params, "notify_operation");
		CRM_DEV_ASSERT(n_type != NULL);
		CRM_DEV_ASSERT(n_task != NULL);
		op_id = generate_notify_key(op->rsc_id, n_type, n_task);

		/* these are not yet allowed to fail */
		op->op_status = LRM_OP_DONE;
		op->rc = 0;
		
	} else {
		op_id = generate_op_key(op->rsc_id, op->op_type, op->interval);
	}

	/* Handle recurring ops - infer last op_status */
	if(op->op_status == LRM_OP_PENDING && op->interval > 0) {
		if(op->rc == 0) {
			crm_debug("Mapping pending operation to DONE");
			op->op_status = LRM_OP_DONE;
		} else {
			crm_debug("Mapping pending operation to ERROR");
			op->op_status = LRM_OP_ERROR;
		}
	}

	xml_op = find_entity(xml_rsc, XML_LRM_TAG_RSC_OP, op_id);
	if(xml_op != NULL) {
		const char *old_status_s = crm_element_value(
			xml_op, XML_LRM_ATTR_OPSTATUS);
		int old_status = crm_parse_int(old_status_s, "-2");
		int log_level = LOG_ERR;

		if(old_status_s == NULL) {
			crm_err("No value for "XML_LRM_ATTR_OPSTATUS);
			
		} else if(old_status == op->op_status) {
			/* safe to mask */
			log_level = LOG_WARNING;
			
		} else if(old_status == LRM_OP_PENDING){
			/* ??safe to mask?? */
/* 			log_level = LOG_WARNING; */
		}
 		crm_log_maybe(log_level,
			      "Duplicate %s operations in get_cur_state()",
			      op_id);
 		crm_log_maybe(log_level+2,
			      "New entry: %s %s (call=%d, status=%s)",
			      op_id, op->user_data, op->call_id,
			      op_status2text(op->op_status));
		crm_log_xml(log_level+2, "Existing entry", xml_op);
		crm_free(op_id);
		return FALSE;
		
	} else {
		xml_op = create_xml_node(xml_rsc, XML_LRM_TAG_RSC_OP);
	}
	crm_xml_add(xml_op, XML_ATTR_ID, op_id);
	crm_free(op_id);

	crm_xml_add(xml_op,  XML_LRM_ATTR_TASK,   op->op_type);
	crm_xml_add(xml_op,  XML_ATTR_ORIGIN, src);
	
	if(op->user_data == NULL) {
		op->user_data = generate_transition_key(-1, fsa_our_uname);
	}
	
#if CRM_DEPRECATED_SINCE_2_0_3
	if(compare_version("1.0.3", caller_version) > 0) {
		CRM_CHECK(FALSE, ; );
		fail_state = generate_transition_magic_v202(
			op->user_data, op->op_status);
	} else {
		fail_state = generate_transition_magic(
			op->user_data, op->op_status, op->rc);
	}
#else
	fail_state = generate_transition_magic(
		op->user_data, op->op_status, op->rc);
#endif
	
	crm_xml_add(xml_op, XML_ATTR_TRANSITION_KEY, op->user_data);
	crm_xml_add(xml_op, XML_ATTR_TRANSITION_MAGIC, fail_state);
	crm_free(fail_state);	
	
	switch(op->op_status) {
		case LRM_OP_PENDING:
			break;
		case LRM_OP_CANCELLED:
			crm_err("What to do here");
			break;
		case LRM_OP_ERROR:
		case LRM_OP_TIMEOUT:
		case LRM_OP_NOTSUPPORTED:
			crm_debug("Resource action %s/%s %s: %d",
				  op->rsc_id, op->op_type,
				  op_status2text(op->op_status), op->rc);
			break;
		case LRM_OP_DONE:
			if(safe_str_eq(CRMD_ACTION_START, op->op_type)) {
				state = CRMD_ACTION_STARTED;

			} else if(safe_str_eq(CRMD_ACTION_STOP, op->op_type)) {
				state = CRMD_ACTION_STOPPED;
				
			} else if(safe_str_eq(CRMD_ACTION_MON, op->op_type)) {
				state = CRMD_ACTION_STARTED;
		
			} else {
				crm_warn("Using status \"%s\" for op \"%s\""
					 "... this is still in the experimental stage.",
					 CRMD_ACTION_GENERIC_OK, op->op_type);
				state = CRMD_ACTION_GENERIC_OK;
			}	
			break;
	}
	
	crm_xml_add_int(xml_op,  XML_LRM_ATTR_CALLID, op->call_id);

	/* set these on 'xml_rsc' too to make life easy for the PE */
	crm_xml_add_int(xml_op, XML_LRM_ATTR_RC, op->rc);
	crm_xml_add_int(xml_op, XML_LRM_ATTR_OPSTATUS, op->op_status);
	crm_xml_add_int(xml_op, XML_LRM_ATTR_INTERVAL, op->interval);

	if(safe_str_neq(op->op_type, CRMD_ACTION_STOP)) {
		/* this will enable us to later determin that the
		 *   resource's parameters have changed and we should force
		 *   a restart
		 * however it will come at the cost of a potentially much
		 *   larger CIB
		 */
		char *digest = NULL;
		crm_data_t *args_xml = NULL;
		crm_data_t *args_parent = NULL;
#if CRM_DEPRECATED_SINCE_2_0_4
		if(compare_version("1.0.5", caller_version) > 0) {
			args_parent = xml_op;
		}
#endif
		args_xml = create_xml_node(args_parent, XML_TAG_PARAMS);
		g_hash_table_foreach(op->params, hash2field, args_xml);
		filter_action_parameters(args_xml);
		digest = calculate_xml_digest(args_xml, TRUE);
		crm_xml_add(xml_op, XML_LRM_ATTR_OP_DIGEST, digest);
		if(args_parent == NULL) {
			free_xml(args_xml);
		}
	}
	
	return TRUE;
}

gboolean
is_rsc_active(const char *rsc_id) 
{
	GList *op_list  = NULL;
	gboolean active = FALSE;
	lrm_rsc_t *the_rsc = NULL;
	state_flag_t cur_state = 0;
	int max_call_id = -1;
	
	if(fsa_lrm_conn == NULL) {
		return FALSE;
	}

	the_rsc = fsa_lrm_conn->lrm_ops->get_rsc(fsa_lrm_conn, rsc_id);

	crm_debug_2("Processing lrm_rsc_t entry %s", rsc_id);
	
	if(the_rsc == NULL) {
		crm_err("NULL resource returned from the LRM");
		return FALSE;
	}
	
	op_list = the_rsc->ops->get_cur_state(the_rsc, &cur_state);
	
	crm_debug_3("\tcurrent state:%s",cur_state==LRM_RSC_IDLE?"Idle":"Busy");
	
	slist_iter(
		op, lrm_op_t, op_list, llpc,
		
		crm_debug("Processing op %s_%d (%d) for %s (status=%d, rc=%d)", 
			  op->op_type, op->interval, op->call_id, the_rsc->id,
			  op->op_status, op->rc);
		
		CRM_ASSERT(max_call_id <= op->call_id);			
		if(safe_str_eq(op->op_type, CRMD_ACTION_STOP)) {
			active = FALSE;
			
		} else if(op->rc == EXECRA_NOT_RUNNING) {
			active = FALSE;

		} else {
			active = TRUE;
		}
		
		max_call_id = op->call_id;
		lrm_free_op(op);
		);

	g_list_free(op_list);
	lrm_free_rsc(the_rsc);

	return active;
}


gboolean
build_active_RAs(crm_data_t *rsc_list)
{
	GList *op_list  = NULL;
	GList *lrm_list = NULL;
	gboolean found_op = FALSE;
	state_flag_t cur_state = 0;
	
	if(fsa_lrm_conn == NULL) {
		return FALSE;
	}

	lrm_list = fsa_lrm_conn->lrm_ops->get_all_rscs(fsa_lrm_conn);

	slist_iter(
		rid, char, lrm_list, lpc,

		lrm_rsc_t *the_rsc =
			fsa_lrm_conn->lrm_ops->get_rsc(fsa_lrm_conn, rid);

		crm_data_t *xml_rsc = create_xml_node(
			rsc_list, XML_LRM_TAG_RESOURCE);

		int max_call_id = -1;
		
		crm_debug("Processing lrm_rsc_t entry %s", rid);
		
		if(the_rsc == NULL) {
			crm_err("NULL resource returned from the LRM");
			continue;
		}

		crm_xml_add(xml_rsc, XML_ATTR_ID, the_rsc->id);
		crm_xml_add(xml_rsc, XML_ATTR_TYPE, the_rsc->type);
		crm_xml_add(xml_rsc, XML_AGENT_ATTR_CLASS, the_rsc->class);
		crm_xml_add(xml_rsc, XML_AGENT_ATTR_PROVIDER,the_rsc->provider);

		op_list = the_rsc->ops->get_cur_state(the_rsc, &cur_state);

		crm_debug_2("\tcurrent state:%s",
			    cur_state==LRM_RSC_IDLE?"Idle":"Busy");

		slist_iter(
			op, lrm_op_t, op_list, llpc,

			crm_debug_2("Processing op %s for %s (status=%d, rc=%d)", 
				    op->op_type, the_rsc->id, op->op_status, op->rc);

			if(max_call_id < op->call_id) {
				build_operation_update(
					xml_rsc, op, __FUNCTION__, llpc);

			} else if(max_call_id > op->call_id) {
				crm_err("Bad call_id in list=%d. Previous call_id=%d",
					op->call_id, max_call_id);

			} else {
				crm_warn("lrm->get_cur_state() returned"
					 " duplicate entries for call_id=%d",
					 op->call_id);
			}
			max_call_id = op->call_id;
			found_op = TRUE;
			lrm_free_op(op);
			);
		if(found_op == FALSE && g_list_length(op_list) != 0) {
			crm_err("Could not properly determin last op"
				" for %s from %d entries", the_rsc->id,
				g_list_length(op_list));
		}

		g_list_free(op_list);
		lrm_free_rsc(the_rsc);
		);

	g_list_free(lrm_list);

	return TRUE;
}

crm_data_t*
do_lrm_query(gboolean is_replace)
{
	gboolean shut_down = FALSE;
	crm_data_t *xml_result= NULL;
	crm_data_t *xml_state = NULL;
	crm_data_t *xml_data  = NULL;
	crm_data_t *rsc_list  = NULL;
	const char *exp_state = CRMD_JOINSTATE_MEMBER;

	if(is_set(fsa_input_register, R_SHUTDOWN)) {
		exp_state = CRMD_STATE_INACTIVE;
		shut_down = TRUE;
	}
	
	xml_state = create_node_state(
		fsa_our_uname, ACTIVESTATUS, XML_BOOLEAN_TRUE,
		ONLINESTATUS, CRMD_JOINSTATE_MEMBER, exp_state,
		!shut_down, __FUNCTION__);

	xml_data  = create_xml_node(xml_state, XML_CIB_TAG_LRM);
	crm_xml_add(xml_data, XML_ATTR_ID, fsa_our_uuid);
	rsc_list  = create_xml_node(xml_data, XML_LRM_TAG_RESOURCES);

	/* Build a list of active (not always running) resources */
	build_active_RAs(rsc_list);

	if(is_replace) {
		crm_xml_add(xml_state, XML_CIB_ATTR_REPLACE, XML_CIB_TAG_LRM);
	}

	xml_result = create_cib_fragment(xml_state, XML_CIB_TAG_STATUS);

	crm_log_xml_debug_3(xml_state, "Current state of the LRM");
	
	return xml_result;
}

struct recurring_op_s 
{
		char *rsc_id;
		int   call_id;
};


static void
cancel_monitor(lrm_rsc_t *rsc, const char *key)
{
	struct recurring_op_s *existing_op = NULL;

	if(rsc == NULL) {	
		crm_err("No resource to cancel and operation for");
		return;
		
	} else if(key == NULL) {
		crm_err("No operation to cancel");
		return;
	}
	
	existing_op = g_hash_table_lookup(monitors, key);
	if(existing_op != NULL) {
		crm_debug("Cancelling previous invocation of %s (%d)",
			  key, existing_op->call_id);
		/* cancel it so we can then restart it without conflict */
		if(rsc->ops->cancel_op(rsc, existing_op->call_id) != HA_OK) {
			crm_info("Couldn't cancel %s (%d)",
				 key, existing_op->call_id);
		} else {
			g_hash_table_remove(monitors, key);
		}

	} else {
		crm_debug("No previous invocation of %s", key);
	}
}

/*
static gboolean
is_active(const char *rsc_id) 
{
	char *stop_id = NULL;
	const char *last_op = NULL;
	gboolean is_active = TRUE;	

	last_op = g_hash_table_lookup(resources, rsc_id);
	stop_id = generate_op_key(rsc_id, CRMD_ACTION_STOP, 0);
			
	if(safe_str_eq(last_op, stop_id)) {
		is_active = FALSE;
	}

	crm_free(stop_id);
	return is_active;
}
*/

/*	 A_LRM_INVOKE	*/
enum crmd_fsa_input
do_lrm_invoke(long long action,
	      enum crmd_fsa_cause cause,
	      enum crmd_fsa_state cur_state,
	      enum crmd_fsa_input current_input,
	      fsa_data_t *msg_data)
{
	const char *crm_op = NULL;
	const char *from_sys = NULL;
	const char *from_host = NULL;
	const char *operation = NULL;
	enum crmd_fsa_input next_input = I_NULL;
	ha_msg_input_t *input = fsa_typed_data(fsa_dt_ha_msg);

	crm_op    = cl_get_string(input->msg, F_CRM_TASK);
	from_sys  = cl_get_string(input->msg, F_CRM_SYS_FROM);
	if(safe_str_neq(from_sys, CRM_SYSTEM_TENGINE)) {
		from_host = cl_get_string(input->msg, F_CRM_HOST_FROM);
	}
	
	crm_debug_2("LRM command from: %s", from_sys);
	
	if(safe_str_eq(crm_op, CRM_OP_LRM_DELETE)) {
		operation = CRMD_ACTION_DELETE;

	} else if(safe_str_eq(operation, CRM_OP_LRM_REFRESH)) {
		crm_op = CRM_OP_LRM_REFRESH;

	} else if(input->xml != NULL) {
		operation = crm_element_value(input->xml, XML_LRM_ATTR_TASK);
	}

	if(crm_op != NULL && safe_str_eq(crm_op, CRM_OP_LRM_REFRESH)) {
		enum cib_errors rc = cib_ok;
		crm_data_t *fragment = do_lrm_query(TRUE);
		crm_info("Forcing a local LRM refresh");

		fsa_cib_update(XML_CIB_TAG_STATUS, fragment,
			       cib_quorum_override, rc);
		free_xml(fragment);
		
	} else if(crm_op != NULL && safe_str_eq(crm_op, CRM_OP_LRM_QUERY)) {
		crm_data_t *data = do_lrm_query(FALSE);
		HA_Message *reply = create_reply(input->msg, data);

		if(relay_message(reply, TRUE) == FALSE) {
			crm_err("Unable to route reply");
			crm_log_message(LOG_ERR, reply);
			crm_msg_del(reply);
		}
		free_xml(data);

	} else if(safe_str_eq(operation, CRM_OP_PROBED)
		  || safe_str_eq(crm_op, CRM_OP_REPROBE)) {
		const char *probed = XML_BOOLEAN_TRUE;
		if(safe_str_eq(crm_op, CRM_OP_REPROBE)) {
			probed = XML_BOOLEAN_FALSE;
		}
		
		update_attr(fsa_cib_conn, cib_none, XML_CIB_TAG_STATUS,
			    fsa_our_uuid, NULL, NULL, CRM_OP_PROBED, probed);

	} else if(operation != NULL) {
		char rid[64];
		lrm_rsc_t *rsc = NULL;
		const char *id_from_cib = NULL;
		crm_data_t *xml_rsc = find_xml_node(
			input->xml, XML_CIB_TAG_RESOURCE, TRUE);

		CRM_DEV_ASSERT(xml_rsc != NULL);
		if(crm_assert_failed) {
			crm_log_xml_err(input->xml, "Bad resource");
			return I_NULL;
		}
		
		id_from_cib = crm_element_value(xml_rsc, XML_ATTR_ID);
		CRM_DEV_ASSERT(id_from_cib != NULL);
		if(crm_assert_failed) {
			crm_err("No value for %s in %s",
				XML_ATTR_ID, crm_element_name(xml_rsc));
			crm_log_xml_err(input->xml, "Bad command");
			return I_NULL;
		}
		
		/* only the first 16 chars are used by the LRM */
		strncpy(rid, id_from_cib, 64);
		rid[63] = 0;

		crm_debug_2("Retrieving %s from the LRM.", rid);
		rsc = fsa_lrm_conn->lrm_ops->get_rsc(fsa_lrm_conn, rid);

		if(safe_str_eq(operation, CRMD_ACTION_CANCEL)) {
			lrm_op_t* op = NULL;
			crm_data_t *params = NULL;
			const char *op_key = NULL;
			const char *op_task = NULL;

			crm_log_xml_debug(input->xml, "CancelOp");

			op_key  = crm_element_value(xml_rsc, "operation_key");
			params  = find_xml_node(input->xml, XML_TAG_ATTRS,TRUE);
			
			if(params != NULL) {
				op_task = crm_element_value(
					params, XML_LRM_ATTR_TASK);
#if CRM_DEPRECATED_SINCE_2_0_4
				if(op_task == NULL) {
					op_task = crm_element_value(params, "task");
				}
#endif
			}
			CRM_CHECK(params != NULL
				  && op_task != NULL
				  && op_key != NULL,
				  return I_NULL);

			op = construct_op(input->xml, id_from_cib, op_task);
			
			CRM_ASSERT(op != NULL);
			if(op_key == NULL) {
				crm_err("No operation to cancel");
				crm_log_message(LOG_ERR, input->msg);
				
			} else if(rsc != NULL) {
				cancel_monitor(rsc, op_key);
			}
			
			op->op_status = LRM_OP_DONE;
			op->rc = EXECRA_OK;
			send_direct_ack(from_host, from_sys, op, id_from_cib);
			free_lrm_op(op);			
			
		} else if(safe_str_eq(operation, CRMD_ACTION_DELETE)) {
			int rc = HA_OK;
			lrm_op_t* op = NULL;

			op = construct_op(input->xml, id_from_cib, operation);
			CRM_ASSERT(op != NULL);
			op->op_status = LRM_OP_DONE;
			op->rc = EXECRA_OK;

			if(rsc == NULL) {
				crm_debug("Resource %s was already removed",
					 id_from_cib);

			} else {
				crm_info("Removing resource %s from the LRM",
					 rsc->id);
				rc = fsa_lrm_conn->lrm_ops->delete_rsc(
					fsa_lrm_conn, rid);
				if(rc != HA_OK) {
					crm_err("Failed to remove resource %s",
						rid);
					op->op_status = LRM_OP_ERROR;
					op->rc = EXECRA_UNKNOWN_ERROR;
				}
			}

			send_direct_ack(from_host, from_sys, op, id_from_cib);
			free_lrm_op(op);			
			
		} else {
			next_input = do_lrm_rsc_op(
				rsc, rid, operation, input->xml, input->msg);
		}
		lrm_free_rsc(rsc);
		
	} else {
		crm_err("Operation was neither a lrm_query, nor a rsc op.  %s",
			crm_str(crm_op));
		register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);
	}

	return next_input;
}

lrm_op_t *
construct_op(crm_data_t *rsc_op, const char *rsc_id, const char *operation)
{
	lrm_op_t *op = NULL;
	const char *transition = NULL;
	CRM_DEV_ASSERT(rsc_id != NULL);

	crm_malloc0(op, sizeof(lrm_op_t));
	op->op_type   = crm_strdup(operation);
	op->op_status = LRM_OP_PENDING;
	op->rc = -1;
	op->rsc_id = crm_strdup(rsc_id);
	op->interval = 0;
	op->timeout  = 0;
	op->start_delay = 0;
	op->app_name = crm_strdup(CRM_SYSTEM_CRMD);

	if(rsc_op == NULL) {
		CRM_DEV_ASSERT(safe_str_eq(CRMD_ACTION_STOP, operation));
		op->user_data = NULL;
		op->user_data_len = 0;
		/* the stop_all_resources() case
		 * by definition there is no DC (or they'd be shutting
		 *   us down).
		 * So we should put our version here.
		 */
		op->params = g_hash_table_new_full(
			g_str_hash, g_str_equal,
			g_hash_destroy_str, g_hash_destroy_str);
		
		g_hash_table_insert(op->params,
				    crm_strdup(XML_ATTR_CRM_VERSION),
				    crm_strdup(CRM_FEATURE_SET));

		crm_debug_2("Constructed %s op for %s", operation, rsc_id);
		return op;
	}

	op->params = xml2list(rsc_op);
#if CRM_DEPRECATED_SINCE_2_0_3
	if(g_hash_table_lookup(op->params, XML_ATTR_CRM_VERSION) == NULL) {
		g_hash_table_destroy(op->params);
		op->params = xml2list_202(rsc_op);
	}
#endif
		
	if(op->params == NULL) {
		CRM_DEV_ASSERT(safe_str_eq(CRMD_ACTION_STOP, operation));
	}
	
	op->interval = crm_parse_int(
		g_hash_table_lookup(op->params, "interval"),    "0");
	op->timeout  = crm_parse_int(
		g_hash_table_lookup(op->params, "timeout"),     "0");
	op->start_delay = crm_parse_int(
		g_hash_table_lookup(op->params, "start_delay"), "0");

	/* sanity */
	if(op->interval < 0) {
		op->interval = 0;
		g_hash_table_replace(
			op->params, crm_strdup("interval"), crm_strdup("0"));
	}
	if(op->timeout < 0) {
		op->timeout = 0;
		g_hash_table_replace(
			op->params, crm_strdup("timeout"), crm_strdup("0"));
	}
	if(op->start_delay < 0) {
		op->start_delay = 0;
		g_hash_table_replace(
			op->params, crm_strdup("start_delay"), crm_strdup("0"));
	}

	transition = crm_element_value(rsc_op, XML_ATTR_TRANSITION_KEY);
	CRM_CHECK(transition != NULL, return op);
	
	op->user_data = crm_strdup(transition);
	op->user_data_len = 1+strlen(op->user_data);

	if(safe_str_eq(operation, CRMD_ACTION_START)
	   || safe_str_eq(operation, CRMD_ACTION_STOP)) {
		char *interval_s = g_hash_table_lookup(op->params, "interval");
 		CRM_CHECK(op->interval == 0, return NULL);
 		CRM_CHECK(interval_s == NULL, return NULL);
	}

	crm_debug_2("Constructed %s op for %s: interval=%d",
		    operation, rsc_id, op->interval);	
	
	return op;
}

void
send_direct_ack(const char *to_host, const char *to_sys,
		lrm_op_t* op, const char *rsc_id)
{
	HA_Message *reply = NULL;
	crm_data_t *update, *iter;
	crm_data_t *fragment;
	
	CRM_DEV_ASSERT(op != NULL);
	if(crm_assert_failed) {
		return;
	}
	if(op->rsc_id == NULL) {
		CRM_DEV_ASSERT(rsc_id != NULL);
		op->rsc_id = crm_strdup(rsc_id);
	}
	if(to_sys == NULL) {
		to_sys = CRM_SYSTEM_TENGINE;
	}
	crm_info("ACK'ing resource op: %s for %s", op->op_type, op->rsc_id);
	
	update = create_node_state(
		fsa_our_uname, NULL, NULL, NULL, NULL, NULL, FALSE, __FUNCTION__);

	iter = create_xml_node(update, XML_CIB_TAG_LRM);
	crm_xml_add(iter, XML_ATTR_ID, fsa_our_uuid);
	iter = create_xml_node(iter,   XML_LRM_TAG_RESOURCES);
	iter = create_xml_node(iter,   XML_LRM_TAG_RESOURCE);

	crm_xml_add(iter, XML_ATTR_ID, op->rsc_id);

	build_operation_update(iter, op, __FUNCTION__, 0);	
	fragment = create_cib_fragment(update, XML_CIB_TAG_STATUS);

	reply = create_request(CRM_OP_INVOKE_LRM, fragment, to_host,
			       to_sys, CRM_SYSTEM_LRMD, NULL);

	crm_debug("Sending ACK: %s", cl_get_string(reply, XML_ATTR_REFERENCE));

	crm_log_xml_debug_2(update, "ACK Update");
	crm_log_message_adv(LOG_DEBUG_3, "ACK Reply", reply);
	
	if(relay_message(reply, TRUE) == FALSE) {
		crm_log_message_adv(LOG_ERR, "Unable to route reply", reply);
		crm_msg_del(reply);
	}
	free_xml(fragment);
	free_xml(update);
}

enum crmd_fsa_input
do_lrm_rsc_op(lrm_rsc_t *rsc, char *rid, const char *operation,
	      crm_data_t *msg, HA_Message *request)
{
	int call_id  = 0;
	char *op_id  = NULL;
	lrm_op_t* op = NULL;

	const char *type = NULL;
	const char *class = NULL;
	const char *provider = NULL;
	const char *transition = NULL;
	
	GHashTable *params   = NULL;
	fsa_data_t *msg_data = NULL;

	CRM_DEV_ASSERT(rid != NULL);
	
	if(rsc != NULL) {
		class = rsc->class;
		type = rsc->type;

	} else if(msg != NULL) {
		crm_data_t *xml_rsc = find_xml_node(
			msg, XML_CIB_TAG_RESOURCE, TRUE);

		class = crm_element_value(xml_rsc, XML_AGENT_ATTR_CLASS);
		CRM_DEV_ASSERT(class != NULL);
		if(crm_assert_failed) { return I_NULL; }
		
		type = crm_element_value(xml_rsc, XML_ATTR_TYPE);
		CRM_DEV_ASSERT(type != NULL);
		if(crm_assert_failed) { return I_NULL; }

		provider = crm_element_value(xml_rsc, XML_AGENT_ATTR_PROVIDER);
	}
	
	if(msg != NULL) {
		transition = crm_element_value(msg, XML_ATTR_TRANSITION_KEY);
		if(transition == NULL) {
			crm_err("Missing transition");
			crm_log_message(LOG_ERR, msg);
		}
	}

	if(rsc == NULL) {
		/* check if its already there */
		rsc = fsa_lrm_conn->lrm_ops->get_rsc(fsa_lrm_conn, rid);
	}

	if(rsc == NULL) {
		/* add it to the list */
		crm_debug("adding rsc %s before operation", rid);
		if(msg != NULL) {
			params = xml2list(msg);
#if CRM_DEPRECATED_SINCE_2_0_3
			if(g_hash_table_lookup(
				   params, XML_ATTR_CRM_VERSION) == NULL) {
				g_hash_table_destroy(params);
				params = xml2list_202(msg);
			}
#endif
		}
		fsa_lrm_conn->lrm_ops->add_rsc(
			fsa_lrm_conn, rid, class, type, provider, params);
		
		rsc = fsa_lrm_conn->lrm_ops->get_rsc(fsa_lrm_conn, rid);
		g_hash_table_destroy(params);
	}
	
	if(rsc == NULL) {
		crm_err("Could not add resource %s to LRM", rid);
		register_fsa_error(C_FSA_INTERNAL, I_FAIL, NULL);
		return I_NULL;
	}

	/* stop the monitor before stopping the resource */
	if(safe_str_eq(operation, CRMD_ACTION_STOP)) {
		g_hash_table_foreach(monitors, stop_recurring_action, rsc);
		g_hash_table_foreach_remove(
			monitors, remove_recurring_action, rsc);
	}
	
	/* now do the op */
	op = construct_op(msg, rsc->id, operation);
	crm_info("Performing op %s on %s (interval=%dms, key=%s)",
		 operation, rid, op->interval, transition);

	if((AM_I_DC == FALSE && fsa_state != S_NOT_DC)
	   || (AM_I_DC && fsa_state != S_TRANSITION_ENGINE)) {
		if(safe_str_neq(operation, CRMD_ACTION_STOP)) {
			crm_info("Discarding attempt to perform action %s on %s"
				 " in state %s", operation, rid,
				 fsa_state2string(fsa_state));
			op->rc = 99;
			op->op_status = LRM_OP_ERROR;
			send_direct_ack(NULL, NULL, op, rsc->id);
			free_lrm_op(op);
			crm_free(op_id);
			return I_NULL;
		}
	}

	op_id = generate_op_key(rsc->id, op->op_type, op->interval);

	if(op->interval > 0) {
		cancel_monitor(rsc, op_id);
		op->target_rc = CHANGED;

	} else {
		op->target_rc = EVERYTIME;
	}

	g_hash_table_replace(resources,crm_strdup(rsc->id), crm_strdup(op_id));

	call_id = rsc->ops->perform_op(rsc, op);

	if(call_id <= 0) {
		crm_err("Operation %s on %s failed: %d",operation,rid,call_id);
		register_fsa_error(C_FSA_INTERNAL, I_FAIL, NULL);

	} else if(op->interval > 0) {
		struct recurring_op_s *op = NULL;
		crm_malloc0(op, sizeof(struct recurring_op_s));
		crm_debug_2("Adding recurring %s op for %s (%d)",
			    op_id, rsc->id, call_id);
		
		op->call_id = call_id;
		op->rsc_id  = crm_strdup(rsc->id);
		g_hash_table_insert(monitors, op_id, op);
		op_id = NULL;
		
	} else {
		/* record all non-recurring operations so we can wait
		 * for them to complete during shutdown
		 */
		char *call_id_s = make_stop_id(rsc->id, call_id);
		g_hash_table_replace(
			shutdown_ops, call_id_s, crm_strdup(rsc->id));
		crm_debug_2("Recording pending op: %s/%s %s",
			    rsc->id, operation, call_id_s);
	}

	crm_free(op_id);
	free_lrm_op(op);		
	return I_NULL;
}

void
stop_recurring_action(gpointer key, gpointer value, gpointer user_data)
{
	lrm_rsc_t *rsc = user_data;
	struct recurring_op_s *op = (struct recurring_op_s*)value;
	
	if(safe_str_eq(op->rsc_id, rsc->id)) {
		if(op->call_id > 0) {
			crm_debug("Stopping recurring op %d for %s (%s)",
				  op->call_id, rsc->id, (char*)key);
			rsc->ops->cancel_op(rsc, op->call_id);
			
		} else {
			crm_err("Invalid call_id %d for %s",
				op->call_id, rsc->id);
			/* TODO: we probably need to look up the LRM to find it */
		}
	}
}

gboolean
remove_recurring_action(gpointer key, gpointer value, gpointer user_data)
{
	lrm_rsc_t *rsc = user_data;
	struct recurring_op_s *op = (struct recurring_op_s*)value;
	if(safe_str_eq(op->rsc_id, rsc->id)) {
		return TRUE;
	}
	return FALSE;
}

void
free_recurring_op(gpointer value)
{
	struct recurring_op_s *op = (struct recurring_op_s*)value;
	crm_free(op->rsc_id);
	crm_free(op);
}


void
free_lrm_op(lrm_op_t *op) 
{
	g_hash_table_destroy(op->params);
	crm_free(op->user_data);
	crm_free(op->output);
	crm_free(op->rsc_id);
	crm_free(op->op_type);
	crm_free(op->app_name);
	crm_free(op);	
}


static void dup_attr(gpointer key, gpointer value, gpointer user_data)
{
	g_hash_table_replace(user_data, crm_strdup(key), crm_strdup(value));
}

lrm_op_t *
copy_lrm_op(const lrm_op_t *op)
{
	lrm_op_t *op_copy = NULL;

	CRM_DEV_ASSERT(op != NULL);
	if(crm_assert_failed) {
		return NULL;
	}
	CRM_ASSERT(op->rsc_id != NULL);

	crm_malloc0(op_copy, sizeof(lrm_op_t));

	op_copy->op_type = crm_strdup(op->op_type);
 	/* input fields */
	op_copy->params = g_hash_table_new_full(
		g_str_hash, g_str_equal,
		g_hash_destroy_str, g_hash_destroy_str);
	
	if(op->params != NULL) {
		g_hash_table_foreach(op->params, dup_attr, op_copy->params);
	}
	op_copy->timeout   = op->timeout;
	op_copy->interval  = op->interval; 
	op_copy->target_rc = op->target_rc; 

	/* in the CRM, this is always a string */
	if(op->user_data != NULL) {
		op_copy->user_data = crm_strdup(op->user_data); 
	}
	
	/* output fields */
	op_copy->op_status = op->op_status; 
	op_copy->rc        = op->rc; 
	op_copy->call_id   = op->call_id; 
	op_copy->output    = NULL;
	op_copy->rsc_id    = crm_strdup(op->rsc_id);
	if(op->app_name != NULL) {
		op_copy->app_name  = crm_strdup(op->app_name);
	}
	if(op->output != NULL) {
		op_copy->output = crm_strdup(op->output);
	}
	
	return op_copy;
}


lrm_rsc_t *
copy_lrm_rsc(const lrm_rsc_t *rsc)
{
	lrm_rsc_t *rsc_copy = NULL;

	if(rsc == NULL) {
		return NULL;
	}
	
	crm_malloc0(rsc_copy, sizeof(lrm_rsc_t));

	rsc_copy->id       = crm_strdup(rsc->id);
	rsc_copy->type     = crm_strdup(rsc->type);
	rsc_copy->class    = NULL;
	rsc_copy->provider = NULL;

	if(rsc->class != NULL) {
		rsc_copy->class    = crm_strdup(rsc->class);
	}
	if(rsc->provider != NULL) {
		rsc_copy->provider = crm_strdup(rsc->provider);
	}
/* 	GHashTable* 	params; */
	rsc_copy->params = NULL;
	rsc_copy->ops    = NULL;

	return rsc_copy;
}

static void
cib_rsc_callback(const HA_Message *msg, int call_id, int rc,
		 crm_data_t *output, void *user_data)
{
	if(rc != cib_ok) {
		crm_err("Resource update %d failed: %s",
			call_id, cib_error2string(rc));	
	} else {
		crm_debug("Resource update %d complete", call_id);	
	}
}


void
do_update_resource(lrm_op_t* op)
{
/*
  <status>
    <nodes_status id=uname>
      <lrm>
        <lrm_resources>
          <lrm_resource id=...>
          </...>
*/
	int rc = cib_ok;
	crm_data_t *update, *iter;
	
	CRM_CHECK(op != NULL, return);

	update = create_node_state(
		fsa_our_uname, NULL, NULL, NULL, NULL, NULL, FALSE, __FUNCTION__);

	iter = create_xml_node(update, XML_CIB_TAG_LRM);
	crm_xml_add(iter, XML_ATTR_ID, fsa_our_uuid);
	iter = create_xml_node(iter,   XML_LRM_TAG_RESOURCES);
	iter = create_xml_node(iter,   XML_LRM_TAG_RESOURCE);

	crm_xml_add(iter, XML_ATTR_ID, op->rsc_id);
	if(op->interval == 0) {
		lrm_rsc_t *rsc = NULL;
		crm_debug_2("Updating %s resource definitions after %s op",
			    op->rsc_id, op->op_type);
		
		rsc = fsa_lrm_conn->lrm_ops->get_rsc(fsa_lrm_conn, op->rsc_id);

		crm_xml_add(iter, XML_ATTR_TYPE, rsc->type);
		crm_xml_add(iter, XML_AGENT_ATTR_CLASS, rsc->class);
		crm_xml_add(iter, XML_AGENT_ATTR_PROVIDER,rsc->provider);
		
		lrm_free_rsc(rsc);
	}
	
	build_operation_update(iter, op, __FUNCTION__, 0);

	/* make it an asyncronous call and be done with it
	 *
	 * Best case:
	 *   the resource state will be discovered during
	 *   the next signup or election.
	 *
	 * Bad case:
	 *   we are shutting down and there is no DC at the time,
	 *   but then why were we shutting down then anyway?
	 *   (probably because of an internal error)
	 *
	 * Worst case:
	 *   we get shot for having resources "running" when the really weren't
	 *
	 * the alternative however means blocking here for too long, which
	 * isnt acceptable
	 */
	fsa_cib_update(XML_CIB_TAG_STATUS, update, cib_quorum_override, rc);
			
	if(rc > 0) {
		/* the return code is a call number, not an error code */
		crm_debug("Sent resource state update message: %d", rc);
		add_cib_op_callback(rc, FALSE, NULL, cib_rsc_callback);
		
	} else {
		crm_err("Resource state update failed: %s",
			cib_error2string(rc));	
		CRM_DEV_ASSERT(rc == cib_ok);
	}
	
	free_xml(update);
}

enum crmd_fsa_input
do_lrm_event(long long action,
	     enum crmd_fsa_cause cause,
	     enum crmd_fsa_state cur_state,
	     enum crmd_fsa_input cur_input,
	     fsa_data_t *msg_data)
{
	lrm_op_t *op = NULL;
	
	CRM_CHECK(msg_data->fsa_cause == C_LRM_OP_CALLBACK, return I_NULL);

	op = fsa_typed_data(fsa_dt_lrm);
	process_lrm_event(op);

	return I_NULL;
}


gboolean
process_lrm_event(lrm_op_t *op)
{
	const char *last_op = NULL;
	const char *probe_s = NULL;
	gboolean is_probe = FALSE;
	int log_rsc_err = LOG_WARNING;
	
	CRM_CHECK(op != NULL, return I_NULL);
	CRM_CHECK(op->rsc_id != NULL, return I_NULL);

	probe_s = g_hash_table_lookup(op->params, XML_ATTR_LRM_PROBE);
	is_probe = crm_is_true(probe_s);

	switch(op->op_status) {
		case LRM_OP_PENDING:
			/* this really shouldnt happen */
			crm_err("LRM operation (%d) %s_%d on %s %s: %s",
				op->call_id, op->op_type,
				op->interval,
				crm_str(op->rsc_id),
				op_status2text(op->op_status),
				execra_code2string(op->rc));
			break;
		case LRM_OP_ERROR:
			if(is_probe) {
				log_rsc_err = LOG_INFO;
			}
			crm_log_maybe(log_rsc_err,
				      "LRM operation (%d) %s_%d on %s %s: (%d) %s",
				      op->call_id, op->op_type,
				      op->interval,
				      crm_str(op->rsc_id),
				      op_status2text(op->op_status),
				      op->rc, execra_code2string(op->rc));
			if(op->output != NULL) {
				crm_debug("Result: %s", op->output);
			}
			break;
		case LRM_OP_CANCELLED:
			crm_warn("LRM operation (%d) %s_%d on %s %s",
				 op->call_id, op->op_type,
				 op->interval,
				 crm_str(op->rsc_id),
				 op_status2text(op->op_status));
			return I_NULL;
			break;
		case LRM_OP_TIMEOUT:
			last_op = g_hash_table_lookup(
				resources_confirmed, crm_strdup(op->rsc_id));

			if(safe_str_eq(last_op, CRMD_ACTION_STOP)
			   && safe_str_eq(op->op_type, CRMD_ACTION_MON)) {
				crm_err("LRM sent a timed out %s operation"
					" _after_ a confirmed stop",
					op->op_type);
				return I_NULL;
			}

			crm_err("LRM operation (%d) %s_%d on %s %s",
				op->call_id, op->op_type,
				op->interval,
				crm_str(op->rsc_id),
				op_status2text(op->op_status));
			break;
		case LRM_OP_NOTSUPPORTED:
			crm_err("LRM operation (%d) %s_%d on %s %s",
				op->call_id, op->op_type,
				op->interval,
				crm_str(op->rsc_id),
				op_status2text(op->op_status));
			break;
		case LRM_OP_DONE:
			crm_info("LRM operation (%d) %s_%d on %s %s",
				 op->call_id, op->op_type,
				 op->interval,
				 crm_str(op->rsc_id),
				 op_status2text(op->op_status));
			break;
	}
	g_hash_table_replace(resources_confirmed,
			     crm_strdup(op->rsc_id), crm_strdup(op->op_type));

	do_update_resource(op);

	if(g_hash_table_size(shutdown_ops) > 0) {
		char *op_id = make_stop_id(op->rsc_id, op->call_id);
		if(g_hash_table_remove(shutdown_ops, op_id)) {
			crm_debug_2("Op %d (%s %s) confirmed",
				  op->call_id, op->op_type, op->rsc_id);

		} else if(op->interval == 0) {
			crm_err("Op %d (%s %s) not matched: %s",
				op->call_id, op->op_type, op->rsc_id, op_id);
		}
		crm_free(op_id);
	}
	
	if(is_set(fsa_input_register, R_SENT_RSC_STOP)) {
		if(g_hash_table_size(shutdown_ops) == 0) {
			register_fsa_input(C_FSA_INTERNAL, I_TERMINATE, NULL);
			
		} else {
			crm_info("Still waiting for %d pending stop operations"
				 " to complete before exiting",
				 g_hash_table_size(shutdown_ops));
			g_hash_table_foreach(
				shutdown_ops, ghash_print_pending, NULL);
		}
	}
	
	return TRUE;
}

char *
make_stop_id(const char *rsc, int call_id)
{
	char *op_id = NULL;
	crm_malloc0(op_id, strlen(rsc) + 34);
	if(op_id != NULL) {
		snprintf(op_id, strlen(rsc) + 34, "%s:%d", rsc, call_id);
	}
	return op_id;
}

void
ghash_print_pending(gpointer key, gpointer value, gpointer user_data) 
{
	const char *uname = key;
	crm_debug("Pending action: %s", uname);
}

gboolean
resource_stopped(gpointer key, gpointer value, gpointer user_data)
{
	const char *this_rsc = value;
	const char *target_rsc = user_data;
	if(safe_str_eq(this_rsc, target_rsc)) {
		return TRUE;
	}
	return FALSE;
}
