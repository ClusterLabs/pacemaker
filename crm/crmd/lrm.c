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

void do_update_resource(lrm_op_t *op);

enum crmd_fsa_input do_lrm_rsc_op(
	lrm_rsc_t *rsc, char *rid, const char *operation,
	crm_data_t *msg, HA_Message *request);

enum crmd_fsa_input do_fake_lrm_op(gpointer data);

void stop_recurring_action(
	gpointer key, gpointer value, gpointer user_data);

gboolean remove_recurring_action(
	gpointer key, gpointer value, gpointer user_data);

void free_recurring_op(gpointer value);

void nack_rsc_op(lrm_op_t* op, HA_Message *msg);

GHashTable *xml2list(crm_data_t *parent);
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
		if(fsa_lrm_conn) {
			fsa_lrm_conn->lrm_ops->signoff(fsa_lrm_conn);
		}
		/* TODO: Clean up the hashtable */
	}

	if(action & A_LRM_CONNECT) {
	
		crm_debug_4("LRM: connect...");
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
			crm_debug_4("LRM: sigon...");
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
		G_main_add_IPC_Channel(G_PRIORITY_LOW,
			      fsa_lrm_conn->lrm_ops->ipcchan(fsa_lrm_conn),
			      FALSE,
			      lrm_dispatch,
			      fsa_lrm_conn,
			      default_ipc_connection_destroy);

		set_bit_inplace(fsa_input_register, R_LRM_CONNECTED);
		
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

	crm_info("Makeing sure all active resources are stopped before exit");
	
	if(fsa_lrm_conn == NULL) {
		return TRUE;

	} else if(is_set(fsa_input_register, R_SENT_RSC_STOP)) {
		crm_debug("Already sent stop operation");
		return TRUE;
	}

	lrm_list = fsa_lrm_conn->lrm_ops->get_all_rscs(fsa_lrm_conn);
	slist_iter(
		rsc_id, char, lrm_list, lpc,

		const char *last_op = g_hash_table_lookup(resources, rsc_id);
		if(safe_str_neq(last_op, CRMD_ACTION_STOP)) {
			crm_warn("Resource %s was active at shutdown", rsc_id);
			do_lrm_rsc_op(NULL, rsc_id, CRMD_ACTION_STOP, NULL, NULL);
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
	int len = 0;
	char *tmp = NULL;
	char *fail_state = NULL;
	const char *state = NULL;
	crm_data_t *xml_op = NULL;
	char *op_id = NULL;

	CRM_DEV_ASSERT(op != NULL);
	if(crm_assert_failed) {
		return FALSE;
	}

	crm_debug("%s: Updating resouce %s after %s %s op",
		 src, op->rsc_id, op_status2text(op->op_status), op->op_type);

	if(op->op_status == LRM_OP_CANCELLED) {
		crm_debug("Ignoring cancelled op");
		return TRUE;
	}
	
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
		int old_status = crm_atoi(old_status_s, "-2");
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
 		crm_log_maybe(log_level-2,
			      "New entry: %s %s (call=%d, status=%s)",
			      op_id, op->user_data, op->call_id,
			      op_status2text(op->op_status));
		crm_log_xml(log_level-2, "Existing entry", xml_op);
		crm_free(op_id);
		return FALSE;
		
	} else {
		xml_op = create_xml_node(xml_rsc, XML_LRM_TAG_RSC_OP);
	}
	crm_xml_add(xml_op, XML_ATTR_ID, op_id);
	crm_free(op_id);

	crm_xml_add(xml_rsc, XML_LRM_ATTR_LASTOP, op->op_type);
	crm_xml_add(xml_op,  XML_LRM_ATTR_TASK,   op->op_type);
	crm_xml_add(xml_op,  "origin", src);
	
	if(op->user_data == NULL) {
		op->user_data = generate_transition_key(-1, fsa_our_uname);
	}
	fail_state = generate_transition_magic(op->user_data, op->op_status);
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
			crm_debug("Resource action %s/%s failed: %d",
				  op->rsc_id, op->op_type, op->op_status);
			len = strlen(op->op_type);
			len += strlen("_failed_");
			crm_malloc0(fail_state, sizeof(char)*len);
			if(fail_state != NULL) {
				sprintf(fail_state, "%s_failed", op->op_type);
			}
			crm_xml_add(xml_op, XML_LRM_ATTR_RSCSTATE, fail_state);
			crm_xml_add(xml_rsc, XML_LRM_ATTR_RSCSTATE, fail_state);
			crm_free(fail_state);			
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

			crm_xml_add(xml_op, XML_LRM_ATTR_RSCSTATE, state);
			crm_xml_add(xml_rsc, XML_LRM_ATTR_RSCSTATE, state);
			break;
	}
	
	tmp = crm_itoa(op->call_id);
	crm_xml_add(xml_op,  XML_LRM_ATTR_CALLID, tmp);
	crm_free(tmp);

	/* set these on 'xml_rsc' too to make life easy for the TE */
	tmp = crm_itoa(op->rc);
	crm_xml_add(xml_op, XML_LRM_ATTR_RC, tmp);
	crm_xml_add(xml_rsc, XML_LRM_ATTR_RC, tmp);
	crm_free(tmp);

	tmp = crm_itoa(op->op_status);
	crm_xml_add(xml_op, XML_LRM_ATTR_OPSTATUS, tmp);
	crm_xml_add(xml_rsc, XML_LRM_ATTR_OPSTATUS, tmp);
	crm_free(tmp);

	set_node_tstamp(xml_op);
	
	return TRUE;
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
				build_operation_update(xml_rsc, op, __FUNCTION__, llpc);

			} else if(max_call_id > op->call_id) {
				crm_err("Bad call_id in list=%d. Previous call_id=%d",
					op->call_id, max_call_id);

			} else {
				crm_debug("Skipping duplicate entry for call_id=%d",
					op->call_id);
			}
			max_call_id = op->call_id;
			found_op = TRUE;
			
			);
		if(found_op == FALSE) {
			crm_err("Could not properly determin last op"
				" for %s from %d entries", the_rsc->id,
				g_list_length(op_list));
		}

		g_list_free(op_list);
		);

	g_list_free(lrm_list);

	return TRUE;
}

crm_data_t*
do_lrm_query(gboolean is_replace)
{
	crm_data_t *xml_result= NULL;
	crm_data_t *xml_state = NULL;
	crm_data_t *xml_data  = NULL;
	crm_data_t *rsc_list  = NULL;
	const char *exp_state = CRMD_STATE_ACTIVE;

	if(is_set(fsa_input_register, R_SHUTDOWN)) {
		exp_state = CRMD_STATE_INACTIVE;
	}
	
	xml_state = create_node_state(
		fsa_our_uname, fsa_our_uname,
		ACTIVESTATUS, XML_BOOLEAN_TRUE, ONLINESTATUS,
		CRMD_JOINSTATE_MEMBER, exp_state, __FUNCTION__);

	xml_data  = create_xml_node(xml_state, XML_CIB_TAG_LRM);
	rsc_list  = create_xml_node(xml_data, XML_LRM_TAG_RESOURCES);

	/* Build a list of active (not always running) resources */
	build_active_RAs(rsc_list);

	if(is_replace) {
		crm_xml_add(xml_state, XML_CIB_ATTR_REPLACE, XML_CIB_TAG_LRM);
	}

	xml_result = create_cib_fragment(xml_state, NULL);

	crm_log_xml_debug_3(xml_state, "Current state of the LRM");
	
	return xml_result;
}

/*	 A_LRM_INVOKE	*/
enum crmd_fsa_input
do_lrm_invoke(long long action,
	      enum crmd_fsa_cause cause,
	      enum crmd_fsa_state cur_state,
	      enum crmd_fsa_input current_input,
	      fsa_data_t *msg_data)
{
	const char *crm_op = NULL;
	const char *operation = NULL;
	enum crmd_fsa_input next_input = I_NULL;
	ha_msg_input_t *input = fsa_typed_data(fsa_dt_ha_msg);
		
	crm_op = cl_get_string(input->msg, F_CRM_TASK);
	operation = crm_element_value(input->xml, XML_LRM_ATTR_TASK);
	
	if(crm_op != NULL && safe_str_eq(crm_op, "lrm_query")) {
		crm_data_t *data = do_lrm_query(FALSE);
		HA_Message *reply = create_reply(input->msg, data);

		if(relay_message(reply, TRUE) == FALSE) {
			crm_err("Unable to route reply");
			crm_log_message(LOG_ERR, reply);
			crm_msg_del(reply);
		}
		free_xml(data);

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
			crm_err("No value for %s in %s.",
				XML_ATTR_ID, crm_element_name(xml_rsc));
			crm_log_xml_err(input->xml, "Bad command");
			return I_NULL;
		}
		
		/* only the first 16 chars are used by the LRM */
		strncpy(rid, id_from_cib, 64);
		rid[63] = 0;
		
		rsc = fsa_lrm_conn->lrm_ops->get_rsc(fsa_lrm_conn, rid);
		next_input = do_lrm_rsc_op(rsc, rid, operation, input->xml, input->msg);
		
	} else {
		crm_err("Operation was neither a lrm_query, nor a rsc op.  %s",
			crm_str(crm_op));
		register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);
	}

	return next_input;
}

struct recurring_op_s 
{
		char *rsc_id;
		int   call_id;
};

void
nack_rsc_op(lrm_op_t* op, HA_Message *msg)
{
	HA_Message *reply = NULL;
	crm_data_t *update, *iter;
	crm_data_t *fragment;

	CRM_DEV_ASSERT(op != NULL);
	if(crm_assert_failed) {
		return;
	}
	CRM_DEV_ASSERT(msg != NULL);
	if(crm_assert_failed) {
		return;
	}

	crm_err("NACK'ing resource op");
	
	update = create_xml_node(NULL, XML_CIB_TAG_STATE);
	set_uuid(fsa_cluster_conn, update, XML_ATTR_UUID, fsa_our_uname);
	crm_xml_add(update,  XML_ATTR_UNAME, fsa_our_uname);

	iter = create_xml_node(update, XML_CIB_TAG_LRM);
	iter = create_xml_node(iter,   XML_LRM_TAG_RESOURCES);
	iter = create_xml_node(iter,   XML_LRM_TAG_RESOURCE);

	crm_xml_add(iter, XML_ATTR_ID, op->rsc_id);

	op->rc = 99;
	op->op_status = LRM_OP_ERROR;
	build_operation_update(iter, op, __FUNCTION__, 0);
	fragment = create_cib_fragment(update, NULL);

	reply = create_reply(msg, fragment);
	crm_log_xml_info(update, "NACK Update");
	crm_log_message_adv(LOG_INFO, "NACK'd msg", msg);
	crm_log_message_adv(LOG_INFO, "NACK Reply", reply);
	
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
		crm_debug_2("adding rsc %s before operation", rid);
		if(msg != NULL) {
			params = xml2list(msg);

		} else {
			CRM_DEV_ASSERT(safe_str_eq(CRMD_ACTION_STOP, operation));
		}
		fsa_lrm_conn->lrm_ops->add_rsc(
			fsa_lrm_conn, rid, class, type, provider, params);
		
		rsc = fsa_lrm_conn->lrm_ops->get_rsc(fsa_lrm_conn, rid);
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
	crm_info("Performing op %s on %s", operation, rid);
	crm_malloc0(op, sizeof(lrm_op_t));
	op->op_type   = crm_strdup(operation);
	op->op_status = LRM_OP_PENDING;
	op->user_data = NULL;
	op->user_data_len = 0;
	
	if(transition != NULL) {
		op->user_data = crm_strdup(transition);
		op->user_data_len = 1+strlen(op->user_data);
	} else {
		CRM_DEV_ASSERT(safe_str_eq(CRMD_ACTION_STOP, operation));
	}
	

	if(params == NULL) {
		if(msg != NULL) {
			params = xml2list(msg);
		} else {
			CRM_DEV_ASSERT(safe_str_eq(
					       CRMD_ACTION_STOP, operation));
		}
	}

	op->params = params;
	op->interval = crm_get_msec(g_hash_table_lookup(op->params,"interval"));
	op->timeout  = crm_get_msec(g_hash_table_lookup(op->params, "timeout"));
	op->start_delay = crm_get_msec(
		g_hash_table_lookup(op->params,"start_delay"));

	/* sanity */
	if(op->interval < 0) {
		op->interval = 0;
	}
	if(op->timeout < 0) {
		op->timeout = 0;
	}
	if(op->start_delay < 0) {
		op->start_delay = 0;
	}
	if(g_hash_table_lookup(op->params, "timeout") != NULL) {
		char *timeout_ms = crm_itoa(op->timeout);
		g_hash_table_replace(
			op->params, crm_strdup("timeout"), timeout_ms);
	}
	if(g_hash_table_lookup(op->params, "interval") != NULL) {
		char *interval_ms = crm_itoa(op->interval);
		g_hash_table_replace(
			op->params, crm_strdup("interval"), interval_ms);
	}
	if(g_hash_table_lookup(op->params, "start_delay") != NULL) {
		char *delay_ms = crm_itoa(op->start_delay);
		g_hash_table_replace(
			op->params, crm_strdup("start_delay"), delay_ms);
	}

	if(safe_str_eq(operation, CRMD_ACTION_START)
	   || safe_str_eq(operation, CRMD_ACTION_STOP)) {
		char *tmp = g_hash_table_lookup(op->params, "interval");
/* 		CRM_DEV_ASSERT(op->interval == 0); */
/* 		CRM_DEV_ASSERT(tmp == NULL); */
		if(op->interval != 0) {
			crm_err("Interval for %s oepration was not 0",
				operation);
		}
		if(tmp != NULL) {
			crm_warn("An interval (%s) was specified for a"
				 " %s operation", tmp, operation);
		}
		

	}
	
	if(safe_str_neq(operation, CRMD_ACTION_STOP)) {
		if((AM_I_DC == FALSE && fsa_state != S_NOT_DC)
		   || (AM_I_DC && fsa_state != S_TRANSITION_ENGINE)) {
			crm_info("Discarding attempt to perform action %s on %s"
				 " in state %s", operation, rid,
				 fsa_state2string(fsa_state));
			op->rsc_id = crm_strdup(rsc->id);
			nack_rsc_op(op, request);
			free_lrm_op(op);
			crm_free(op_id);
			return I_NULL;
		}
	}
	
	if(op->interval > 0) {
		struct recurring_op_s *existing_op = NULL;

		op_id = generate_op_key(rsc->id, op->op_type, op->interval);
		existing_op = g_hash_table_lookup(monitors, op_id);
		if(existing_op != NULL) {
			crm_debug("Cancelling previous invocation of"
				  " %s on %s (%d)",
				  crm_str(op_id), rsc->id,existing_op->call_id);
			/*cancel it so we can then restart it without conflict*/
			rsc->ops->cancel_op(rsc, existing_op->call_id);
			g_hash_table_remove(monitors, op_id);
		}
	}

	op->app_name = crm_strdup(CRM_SYSTEM_CRMD);
	
	if(safe_str_eq(operation, CRMD_ACTION_MON)) {
		op->target_rc = CHANGED;

	} else {
		op->target_rc = EVERYTIME;
	}

	if(safe_str_eq(CRMD_ACTION_MON, operation)) {
		const char *last_op = g_hash_table_lookup(resources, rsc->id);
		if(safe_str_eq(last_op, CRMD_ACTION_STOP)) {
			crm_warn("Attempting to schedule %s after a stop.",
				 op_id);
			free_lrm_op(op);
			crm_free(op_id);
			return I_NULL;			
		}
	}	

	g_hash_table_replace(
		resources, crm_strdup(rsc->id), crm_strdup(operation));

	call_id = rsc->ops->perform_op(rsc, op);

	if(call_id <= 0) {
		crm_err("Operation %s on %s failed: %d",
			operation, rid, call_id);
		register_fsa_error(C_FSA_INTERNAL, I_FAIL, NULL);

	} else if(op->interval > 0) {
		struct recurring_op_s *op = NULL;
		crm_malloc0(op, sizeof(struct recurring_op_s));
		crm_debug("Adding recurring %s op for %s (%d)",
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
		crm_debug("Recording pending op: %s", call_id_s);
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

void
do_update_resource(lrm_op_t* op)
{
/*
  <status>
  <nodes_status id=uname>
  <lrm>
  <lrm_resources>
  <lrm_resource id=>
  </...>
*/
	crm_data_t *update, *iter;
	crm_data_t *fragment;
	int rc = cib_ok;

	CRM_DEV_ASSERT(op != NULL);
	if(crm_assert_failed) {
		return;
	}

	update = create_xml_node(NULL, XML_CIB_TAG_STATE);
	set_uuid(fsa_cluster_conn, update, XML_ATTR_UUID, fsa_our_uname);
	crm_xml_add(update,  XML_ATTR_UNAME, fsa_our_uname);

	iter = create_xml_node(update, XML_CIB_TAG_LRM);
	iter = create_xml_node(iter,   XML_LRM_TAG_RESOURCES);
	iter = create_xml_node(iter,   XML_LRM_TAG_RESOURCE);

	crm_xml_add(iter, XML_ATTR_ID, op->rsc_id);

	build_operation_update(iter, op, __FUNCTION__, 0);
	fragment = create_cib_fragment(update, NULL);

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
	rc = fsa_cib_conn->cmds->modify(
		fsa_cib_conn, XML_CIB_TAG_STATUS, fragment, NULL,
		cib_quorum_override);
			
	if(rc > 0) {
		/* the return code is a call number, not an error code */
		crm_debug_3("Sent resource state update message: %d", rc);
		
	} else {
		crm_err("Resource state update failed: %s",
			cib_error2string(rc));	
		CRM_DEV_ASSERT(rc == cib_ok);
	}
	
	free_xml(fragment);
	free_xml(update);
}

enum crmd_fsa_input
do_lrm_event(long long action,
	     enum crmd_fsa_cause cause,
	     enum crmd_fsa_state cur_state,
	     enum crmd_fsa_input cur_input,
	     fsa_data_t *msg_data)
{
	lrm_op_t* op = NULL;
	const char *last_op = NULL;
	
	if(msg_data->fsa_cause != C_LRM_OP_CALLBACK) {
		register_fsa_error(C_FSA_INTERNAL, I_FAIL, NULL);
		return I_NULL;
	}

	op = fsa_typed_data(fsa_dt_lrm);
	
	CRM_DEV_ASSERT(op != NULL);
	CRM_DEV_ASSERT(op != NULL && op->rsc_id != NULL);

	if(crm_assert_failed) {
		return I_NULL;
	}

	if(op->op_status == LRM_OP_DONE && op->rc != EXECRA_OK) {
		crm_warn("Mapping operation %d status with a rc=%d"
			 " to status %d",
			 op->op_status, op->rc, LRM_OP_ERROR);
		op->op_status = LRM_OP_ERROR;
	}

	switch(op->op_status) {
		case LRM_OP_PENDING:
			/* this really shouldnt happen */
			crm_err("LRM operation (%d) %s on %s %s: %s",
				op->call_id, op->op_type,
				crm_str(op->rsc_id),
				op_status2text(op->op_status),
				execra_code2string(op->rc));
			break;
		case LRM_OP_ERROR:
			crm_err("LRM operation (%d) %s on %s %s: %s",
				op->call_id, op->op_type,
				crm_str(op->rsc_id),
				op_status2text(op->op_status),
				execra_code2string(op->rc));
			crm_debug("Result: %s", op->output);
			break;
		case LRM_OP_CANCELLED:
			crm_warn("LRM operation (%d) %s on %s %s",
				 op->call_id, op->op_type,
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

			crm_err("LRM operation (%d) %s on %s %s",
				op->call_id, op->op_type,
				crm_str(op->rsc_id),
				op_status2text(op->op_status));
			break;
		case LRM_OP_NOTSUPPORTED:
			crm_err("LRM operation (%d) %s on %s %s",
				op->call_id, op->op_type,
				crm_str(op->rsc_id),
				op_status2text(op->op_status));
			break;
		case LRM_OP_DONE:
			crm_debug("LRM operation (%d) %s on %s %s",
				  op->call_id, op->op_type,
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
			crm_debug("Op %d (%s %s) confirmed",
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
			crm_debug("Still waiting for %d pending stop operations"
				  " to complete before exiting",
				  g_hash_table_size(shutdown_ops));
			g_hash_table_foreach(
				shutdown_ops, ghash_print_pending, NULL);
		}
	}
	
	return I_NULL;
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
