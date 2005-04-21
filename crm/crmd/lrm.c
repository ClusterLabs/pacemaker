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
#include <sys/param.h>
#include <crm/crm.h>
#include <crmd_fsa.h>

#include <sys/types.h>
#include <sys/wait.h>

#include <unistd.h>			/* for access */
#include <clplumbing/cl_signal.h>

#include <errno.h>

#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>

#include <crmd.h>
#include <crmd_messages.h>
#include <crmd_callbacks.h>

#include <lrm/raexec.h>

#include <crm/dmalloc_wrapper.h>

gboolean stop_all_resources(void);

gboolean build_operation_update(
	crm_data_t *rsc_list, lrm_rsc_t *rsc, lrm_op_t *op,
	const char *src, int lpc);

gboolean build_suppported_RAs(
	crm_data_t *metadata_list, crm_data_t *xml_agent_list);

gboolean build_active_RAs(crm_data_t *rsc_list);

void do_update_resource(lrm_rsc_t *rsc, lrm_op_t *op);

enum crmd_fsa_input do_lrm_rsc_op(
	lrm_rsc_t *rsc, char *rid, const char *operation, crm_data_t *msg);

enum crmd_fsa_input do_fake_lrm_op(gpointer data);

void stop_recurring_action(
	gpointer key, gpointer value, gpointer user_data);

gboolean remove_recurring_action(
	gpointer key, gpointer value, gpointer user_data);

void free_recurring_op(gpointer value);

GHashTable *xml2list(crm_data_t *parent);
GHashTable *monitors = NULL;
GHashTable *resources = NULL;
int num_lrm_register_fails = 0;
int max_lrm_register_fails = 30;

const char *rsc_path[] = 
{
/* 	XML_GRAPH_TAG_RSC_OP, */
	XML_CIB_TAG_RESOURCE,
	"instance_attributes",
	"rsc_parameters"
};

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

void free_lrm_op(lrm_op_t *op);

const char *crmd_rscstate2string(enum crmd_rscstate state);

const char *
crmd_rscstate2string(enum crmd_rscstate state) 
{
	switch(state) {
		case crmd_rscstate_NULL:
			return NULL;
			
		case crmd_rscstate_START:
			return CRMD_RSCSTATE_START;
			
		case crmd_rscstate_START_PENDING:
			return CRMD_RSCSTATE_START_PENDING;
			
		case crmd_rscstate_START_OK:
			return CRMD_RSCSTATE_START_OK;
			
		case crmd_rscstate_START_FAIL:
			return CRMD_RSCSTATE_START_FAIL;
			
		case crmd_rscstate_STOP:
			return CRMD_RSCSTATE_STOP;
			
		case crmd_rscstate_STOP_PENDING:
			return CRMD_RSCSTATE_STOP_PENDING;
			
		case crmd_rscstate_STOP_OK:
			return CRMD_RSCSTATE_STOP_OK;
			
		case crmd_rscstate_STOP_FAIL:
			return CRMD_RSCSTATE_STOP_FAIL;
			
		case crmd_rscstate_MON:
			return CRMD_RSCSTATE_MON;
			
		case crmd_rscstate_MON_PENDING:
			return CRMD_RSCSTATE_MON_PENDING;
			
		case crmd_rscstate_MON_OK:
			return CRMD_RSCSTATE_MON_OK;
			
		case crmd_rscstate_MON_FAIL:
			return CRMD_RSCSTATE_MON_FAIL;
			
		case crmd_rscstate_GENERIC_PENDING:
			return CRMD_RSCSTATE_GENERIC_PENDING;
			
		case crmd_rscstate_GENERIC_OK:
			return CRMD_RSCSTATE_GENERIC_OK;
			
		case crmd_rscstate_GENERIC_FAIL:
			return CRMD_RSCSTATE_GENERIC_FAIL;
			
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
	
		crm_trace("LRM: connect...");
		ret = HA_OK;
		
		monitors = g_hash_table_new_full(
			g_str_hash, g_str_equal,
			g_hash_destroy_str, free_recurring_op);

		resources = g_hash_table_new_full(
			g_str_hash, g_str_equal,
			g_hash_destroy_str, g_hash_destroy_str);
		
		fsa_lrm_conn = ll_lrm_new(XML_CIB_TAG_LRM);	
		if(NULL == fsa_lrm_conn) {
			register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);
			ret = HA_FAIL;
		}

		if(ret == HA_OK) {
			crm_trace("LRM: sigon...");
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
				crmd_fsa_stall();
				return I_NULL;
			}
		}

		if(ret == HA_OK) {
			crm_trace("LRM: set_lrm_callback...");
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
		G_main_add_fd(G_PRIORITY_LOW,
			      fsa_lrm_conn->lrm_ops->inputfd(fsa_lrm_conn),
			      FALSE,
			      lrm_dispatch, fsa_lrm_conn,
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
build_suppported_RAs(crm_data_t *metadata_list, crm_data_t *xml_agent_list)
{
	GList *types            = NULL;
	GList *classes          = NULL;
	const char *version     = NULL;
	crm_data_t *xml_agent    = NULL;
	
/* 	return TRUE; */
	
	if(fsa_lrm_conn == NULL) {
		return FALSE;
	}
	
	classes = fsa_lrm_conn->lrm_ops->get_rsc_class_supported(fsa_lrm_conn);

	slist_iter(
		class, char, classes, lpc,

		types = fsa_lrm_conn->lrm_ops->get_rsc_type_supported(
			fsa_lrm_conn, class);

		slist_iter(
			type, char, types, llpc,
			
			version = "1";

			xml_agent = create_xml_node(
				xml_agent_list, XML_LRM_TAG_AGENT);
			
			set_xml_property_copy(
				xml_agent, XML_AGENT_ATTR_CLASS, class);
			set_xml_property_copy(xml_agent, XML_ATTR_TYPE, type);

			set_xml_property_copy(
				xml_agent, XML_ATTR_VERSION, version);

			)
		g_list_free(types);
		);

	g_list_free(classes);

	return TRUE;
}


gboolean
stop_all_resources(void)
{
	GList *op_list  = NULL;
	GList *lrm_list = NULL;
	state_flag_t cur_state = 0;
	const char *this_op    = NULL;
	
	if(fsa_lrm_conn == NULL) {
		return TRUE;
	}

	lrm_list = fsa_lrm_conn->lrm_ops->get_all_rscs(fsa_lrm_conn);

	slist_iter(
		rid, char, lrm_list, lpc,

		lrm_rsc_t *the_rsc =
			fsa_lrm_conn->lrm_ops->get_rsc(fsa_lrm_conn, rid);

		crm_info("Processing lrm_rsc_t entry %s", rid);
		
		if(the_rsc == NULL) {
			crm_err("NULL resource returned from the LRM");
			continue;
		}

		op_list = the_rsc->ops->get_cur_state(the_rsc, &cur_state);

		crm_verbose("\tcurrent state:%s",
			    cur_state==LRM_RSC_IDLE?"Idle":"Busy");

		slist_iter(
			op, lrm_op_t, op_list, llpc,

			this_op = op->op_type;
			crm_debug("Processing op %s for %s (status=%d, rc=%d)",
				  op->op_type, the_rsc->id,
				  op->op_status, op->rc);
			
			if(safe_str_neq(this_op, CRMD_RSCSTATE_STOP)){
				do_lrm_rsc_op(the_rsc, the_rsc->id,
					      CRMD_RSCSTATE_STOP, NULL);
			}
			break;
			);
		);
	return TRUE;
}

gboolean
build_operation_update(
	crm_data_t *xml_rsc, lrm_rsc_t *rsc, lrm_op_t *op,
	const char *src, int lpc)
{
	int len = 0;
	char *tmp = NULL;
	char *fail_state = NULL;
	crm_data_t *xml_op = NULL;

	if(op == NULL || rsc == NULL) {
		crm_err("Either resouce or op was not specified");
		return FALSE;
	}

	crm_info("Updating resouce %s after op %s", rsc->id, op->op_type);
	
	xml_op = create_xml_node(xml_rsc, XML_LRM_TAG_RSC_OP);
	
	if(op->interval <= 0
	   ||safe_str_eq(op->op_type, CRMD_RSCSTATE_START)
	   || safe_str_eq(op->op_type, CRMD_RSCSTATE_STOP)) {
		set_xml_property_copy(xml_op, XML_ATTR_ID, op->op_type);

	} else {
		char *op_id = NULL;
		len = 34 + strlen(op->op_type);
		crm_malloc(op_id, sizeof(char)*len);
		if(op_id != NULL) {
			sprintf(op_id, "%s_%d", op->op_type, op->interval);
		}
		set_xml_property_copy(xml_op, XML_ATTR_ID, op_id);
		crm_free(op_id);
	}

	set_xml_property_copy(xml_op, XML_LRM_ATTR_TASK, op->op_type);
	set_xml_property_copy(xml_op, "origin", src);

	if(lpc == 0) {
		set_xml_property_copy(xml_rsc, XML_LRM_ATTR_LASTOP,op->op_type);
	}

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
				  rsc->id, op->op_type, op->op_status);
			len = strlen(op->op_type);
			len += strlen("_failed_");
			crm_malloc(fail_state, sizeof(char)*len);
			if(fail_state != NULL) {
				sprintf(fail_state, "%s_failed", op->op_type);
			}
			set_xml_property_copy(
				xml_op, XML_LRM_ATTR_RSCSTATE, fail_state);
			if(lpc == 0) {
				set_xml_property_copy(
					xml_rsc, XML_LRM_ATTR_RSCSTATE,
					fail_state);
			}
			crm_free(fail_state);
			break;
		case LRM_OP_DONE:
			set_xml_property_copy(
				xml_op, XML_LRM_ATTR_RSCSTATE,
				op->user_data);
			if(lpc == 0) {
				set_xml_property_copy(
					xml_rsc, XML_LRM_ATTR_RSCSTATE,
					op->user_data);
			}
			break;
	}

	/* set these on 'xml_rsc' too to make life easy for the TE */
	tmp = crm_itoa(op->rc);
	set_xml_property_copy(xml_op, XML_LRM_ATTR_RC, tmp);
	if(lpc == 0) {
		set_xml_property_copy(xml_rsc, XML_LRM_ATTR_RC, tmp);
	}
	crm_free(tmp);

	tmp = crm_itoa(op->op_status);
	set_xml_property_copy(xml_op, XML_LRM_ATTR_OPSTATUS, tmp);
	if(lpc == 0) {
		set_xml_property_copy(xml_rsc, XML_LRM_ATTR_OPSTATUS, tmp);
	}
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

		crm_info("Processing lrm_rsc_t entry %s", rid);
		
		if(the_rsc == NULL) {
			crm_err("NULL resource returned from the LRM");
			continue;
		}

		set_xml_property_copy(xml_rsc, XML_ATTR_ID, the_rsc->id);

		op_list = the_rsc->ops->get_cur_state(the_rsc, &cur_state);

		crm_verbose("\tcurrent state:%s",
			    cur_state==LRM_RSC_IDLE?"Idle":"Busy");

		slist_iter(
			op, lrm_op_t, op_list, llpc,

			crm_info("Processing op %s for %s (status=%d, rc=%d)", 
				 op->op_type, the_rsc->id, op->op_status, op->rc);
			build_operation_update(
				xml_rsc, the_rsc, op, __FUNCTION__, llpc);

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
	crm_data_t *xml_state = create_xml_node(NULL, XML_CIB_TAG_STATE);
	crm_data_t *xml_data  = create_xml_node(xml_state, XML_CIB_TAG_LRM);
	crm_data_t *rsc_list  = create_xml_node(xml_data,XML_LRM_TAG_RESOURCES);

	/* Build a list of active (not always running) resources */
	build_active_RAs(rsc_list);

	if(is_replace) {
		set_xml_property_copy(
			xml_state, XML_CIB_ATTR_REPLACE, XML_CIB_TAG_LRM);
	}

	set_uuid(fsa_cluster_conn, xml_state, XML_ATTR_UUID, fsa_our_uname);
	set_xml_property_copy(xml_state, XML_ATTR_UNAME, fsa_our_uname);
	xml_result = create_cib_fragment(xml_state, NULL);

	crm_xml_devel(xml_state, "Current state of the LRM");
	
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
		
	operation = get_xml_attr_nested(
		input->xml, rsc_path, DIMOF(rsc_path) -3,
		XML_LRM_ATTR_TASK, FALSE);
	
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
		const char *id_from_cib = NULL;
		lrm_rsc_t *rsc = NULL;

		if(AM_I_DC == FALSE && cur_state != S_NOT_DC) {
			crm_err("Ignoring LRM operation while in state %s",
				fsa_state2string(cur_state));
		}
		
		id_from_cib = get_xml_attr_nested(
			input->xml, rsc_path, DIMOF(rsc_path) -2,
			XML_ATTR_ID, TRUE);

		if(id_from_cib == NULL) {
			crm_err("No value for %s in message at level %d.",
				XML_ATTR_ID, DIMOF(rsc_path) -2);
			return I_NULL;
		}
		
		/* only the first 16 chars are used by the LRM */
		strncpy(rid, id_from_cib, 64);
		rid[63] = 0;
		
		rsc = fsa_lrm_conn->lrm_ops->get_rsc(fsa_lrm_conn, rid);
		next_input = do_lrm_rsc_op(rsc, rid, operation, input->xml);
		
	} else {
		crm_err("Operation was neither a lrm_query, nor a rsc op.  %s",
			crm_str(crm_op));
		next_input = I_ERROR;
	}

	return next_input;
}

struct recurring_op_s 
{
		char *rsc_id;
		int   call_id;
};

enum crmd_fsa_input
do_lrm_rsc_op(
	lrm_rsc_t *rsc, char *rid, const char *operation, crm_data_t *msg)
{
	lrm_op_t* op        = NULL;
	int call_id         = 0;
	fsa_data_t *msg_data = NULL;
	char *op_id = NULL;

	const char *type = NULL;
	const char *class = NULL;
	const char *provider = NULL;

	GHashTable *params = NULL;
	
	if(rsc != NULL) {
		class = rsc->class;
		type = rsc->type;
		
	} else if(msg != NULL) {
		class = get_xml_attr_nested(
			msg, rsc_path, DIMOF(rsc_path) -2,
			XML_AGENT_ATTR_CLASS, TRUE);
		
		type = get_xml_attr_nested(
			msg, rsc_path, DIMOF(rsc_path) -2,
			XML_ATTR_TYPE, TRUE);

		provider = get_xml_attr_nested(
			msg, rsc_path, DIMOF(rsc_path) -2,
			XML_AGENT_ATTR_PROVIDER, FALSE);
	}
	
	if(rsc == NULL) {
		/* check if its already there */
		CRM_DEV_ASSERT(rid != NULL);
		rsc = fsa_lrm_conn->lrm_ops->get_rsc(fsa_lrm_conn, rid);
	}

	if(rsc == NULL) {
		/* add it to the list */
		crm_verbose("adding rsc %s before operation", rid);
		if(msg != NULL) {
			params = xml2list(msg);

		} else {
			CRM_DEV_ASSERT(safe_str_eq(CRMD_RSCSTATE_STOP, operation));
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
	if(safe_str_eq(operation, CRMD_RSCSTATE_STOP)) {
		g_hash_table_foreach(monitors, stop_recurring_action, rsc);
		g_hash_table_foreach_remove(
			monitors, remove_recurring_action, rsc);
	}
	
	/* now do the op */
	crm_info("Performing op %s on %s", operation, rid);
	crm_malloc(op, sizeof(lrm_op_t));
	op->op_type   = crm_strdup(operation);
	op->op_status = LRM_OP_PENDING;
	op->user_data = NULL;
	
	if(params == NULL) {
		if(msg != NULL) {
			params = xml2list(msg);
		} else {
			CRM_DEV_ASSERT(safe_str_eq(
					       CRMD_RSCSTATE_STOP, operation));
		}
	}

	op->params = params;
	op->interval = crm_get_msec(g_hash_table_lookup(op->params,"interval"));
	op->timeout  = crm_get_msec(g_hash_table_lookup(op->params, "timeout"));

	/* sanity */
	if(op->interval < 0) {
		op->interval = 0;
	}
	if(op->timeout < 0) {
		op->timeout = 0;
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

	if(op->interval > 0) {
		int len;
		struct recurring_op_s *existing_op = NULL;

		len = 34 + strlen(op->op_type);
		crm_malloc(op_id, sizeof(char)*len);
		if(op_id != NULL) {
			sprintf(op_id, "%s_%d", op->op_type, op->interval);
		}
		existing_op = g_hash_table_lookup(monitors, op_id);
		if(existing_op != NULL) {
			crm_debug("Operation %s on %s has already been invoked",
				  op_id, rsc->id);
			/*cancel it so we can then restart it without conflict*/
			rsc->ops->cancel_op(rsc, existing_op->call_id);
			g_hash_table_remove(monitors, op_id);
		}
	}

	op->app_name = crm_strdup(CRM_SYSTEM_CRMD);
	
	if(safe_str_eq(operation, CRMD_RSCSTATE_MON)) {
		op->target_rc = CHANGED;

	} else {
		op->target_rc = EVERYTIME;
	}

	if(safe_str_eq(CRMD_RSCSTATE_START, operation)) {
		op->user_data = crm_strdup(CRMD_RSCSTATE_START_OK);

	} else if(safe_str_eq(CRMD_RSCSTATE_STOP, operation)) {
		op->user_data = crm_strdup(CRMD_RSCSTATE_STOP_OK);
		
	} else if(safe_str_eq(CRMD_RSCSTATE_MON, operation)) {
		op->user_data = crm_strdup(CRMD_RSCSTATE_MON_OK);
		const char *last_op = g_hash_table_lookup(resources, rsc->id);
		if(safe_str_eq(last_op, CRMD_RSCSTATE_STOP)) {
			crm_err("Attempting to schedule %s for _after_ a stop.", op_id);
			free_lrm_op(op);
			crm_free(op_id);
			return I_NULL;			
		}
		
	} else {
		crm_warn("Using status \"%s\" for op \"%s\""
			 "... this is still in the experimental stage.",
			 CRMD_RSCSTATE_GENERIC_OK, operation);
		op->user_data = crm_strdup(CRMD_RSCSTATE_GENERIC_OK);
	}	

	g_hash_table_replace(
		resources, crm_strdup(rsc->id), crm_strdup(operation));

	op->user_data_len = 1+strlen(op->user_data);
	call_id = rsc->ops->perform_op(rsc, op);

	if(call_id <= 0) {
		crm_err("Operation %s on %s failed: %d",
			operation, rid, call_id);
		register_fsa_error(C_FSA_INTERNAL, I_FAIL, NULL);

	} else if(call_id > 0 && op->interval > 0) {
		struct recurring_op_s *op = NULL;
		crm_malloc(op, sizeof(struct recurring_op_s));
		crm_debug("Adding recurring %s op for %s", operation, rsc->id);

		op->call_id = call_id;
		op->rsc_id  = crm_strdup(rsc->id);
		g_hash_table_insert(monitors, op_id, op);
		op_id = NULL;
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
	crm_free(op->op_type);
	crm_free(op->app_name);
	crm_free(op);	
}


GHashTable *
xml2list(crm_data_t *parent)
{
	crm_data_t *nvpair_list = NULL;
	GHashTable *nvpair_hash = g_hash_table_new_full(
		g_str_hash, g_str_equal,
		g_hash_destroy_str, g_hash_destroy_str);

	CRM_DEV_ASSERT(parent != NULL);
	if(parent != NULL) {
		nvpair_list = find_xml_node(parent, XML_TAG_ATTRS, FALSE);
		if(nvpair_list == NULL) {
			crm_debug("No attributes in %s",
				  crm_element_name(parent));
			crm_xml_verbose(parent,"No attributes for resource op");
		}
	}
	
	xml_child_iter(
		nvpair_list, node_iter, XML_CIB_TAG_NVPAIR,
		
		const char *key   = crm_element_value(
			node_iter, XML_NVPAIR_ATTR_NAME);
		const char *value = crm_element_value(
			node_iter, XML_NVPAIR_ATTR_VALUE);
		
		crm_verbose("Added %s=%s", key, value);
		
		g_hash_table_insert(
			nvpair_hash, crm_strdup(key), crm_strdup(value));
		);
	
	return nvpair_hash;
}


void
do_update_resource(lrm_rsc_t *rsc, lrm_op_t* op)
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

	if(op == NULL || rsc == NULL) {
		crm_err("Either resouce or op was not specified");
		return;
	}

	update = create_xml_node(NULL, XML_CIB_TAG_STATE);
	set_uuid(fsa_cluster_conn, update, XML_ATTR_UUID, fsa_our_uname);
	set_xml_property_copy(update,  XML_ATTR_UNAME, fsa_our_uname);

	iter = create_xml_node(update, XML_CIB_TAG_LRM);
	iter = create_xml_node(iter,   XML_LRM_TAG_RESOURCES);
	iter = create_xml_node(iter,   XML_LRM_TAG_RESOURCE);

	set_xml_property_copy(iter, XML_ATTR_ID, rsc->id);

	build_operation_update(iter, rsc, op, __FUNCTION__, 0);
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
		crm_devel("Sent resource state update message: %d", rc);
		
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
	lrm_rsc_t* rsc = NULL;
	const char *last_op = NULL;
	
	if(msg_data->fsa_cause != C_LRM_OP_CALLBACK) {
		register_fsa_error(C_FSA_INTERNAL, I_FAIL, NULL);
		return I_NULL;
	}

	op = fsa_typed_data(fsa_dt_lrm);
	
	CRM_DEV_ASSERT(op != NULL);
	CRM_DEV_ASSERT(op != NULL && op->rsc != NULL);

	if(op == NULL || op->rsc == NULL) {
		return I_NULL;
	}

	rsc = op->rsc;

	if(op->op_status == LRM_OP_DONE && op->rc != EXECRA_OK) {
		crm_warn("Mapping operation %d status with a rc=%d"
			 " to status %d",
			 op->op_status, op->rc, LRM_OP_ERROR);
		op->op_status = LRM_OP_ERROR;
	}

	switch(op->op_status) {
		case LRM_OP_PENDING:
			/* this really shouldnt happen */
			crm_err("LRM operation %s on %s::%s(%s):%s %s: %s",
				op->op_type,
				crm_str(rsc->class),
				crm_str(rsc->type),
				crm_str(rsc->provider),
				crm_str(rsc->id),
				op_status2text(op->op_status),
				execra_code2string(op->rc));
			break;
		case LRM_OP_ERROR:
			crm_err("LRM operation %s on %s::%s(%s):%s %s: %s",
				op->op_type,
				crm_str(rsc->class),
				crm_str(rsc->type),
				crm_str(rsc->provider),
				crm_str(rsc->id),
				op_status2text(op->op_status),
				execra_code2string(op->rc));
			crm_debug("Result: %s", op->output);
			break;
		case LRM_OP_CANCELLED:
			crm_warn("LRM operation %s on %s::%s(%s):%s %s",
				 op->op_type,
				 crm_str(rsc->class),
				 crm_str(rsc->type),
				 crm_str(rsc->provider),
				 crm_str(rsc->id),
				 op_status2text(op->op_status));
			return I_NULL;
			break;
		case LRM_OP_TIMEOUT:
			last_op = g_hash_table_lookup(
				resources, crm_strdup(rsc->id));

			if(safe_str_eq(last_op, CRMD_RSCSTATE_STOP)
			   && safe_str_eq(op->op_type, CRMD_RSCSTATE_MON)) {
				crm_err("LRM sent a timed out %s operation _after_ it was cancelled",
					op->op_type);
				return I_NULL;
			}

			crm_err("LRM operation %s on %s::%s(%s):%s %s",
				op->op_type,
				crm_str(rsc->class),
				crm_str(rsc->type),
				crm_str(rsc->provider),
				crm_str(rsc->id),
				op_status2text(op->op_status));
			break;
		case LRM_OP_NOTSUPPORTED:
			crm_err("LRM operation %s on %s::%s(%s):%s %s",
				op->op_type,
				crm_str(rsc->class),
				crm_str(rsc->type),
				crm_str(rsc->provider),
				crm_str(rsc->id),
				op_status2text(op->op_status));
			break;
		case LRM_OP_DONE:
			crm_debug("LRM operation %s on %s::%s(%s):%s %s",
				  op->op_type,
				  crm_str(rsc->class),
				  crm_str(rsc->type),
				  crm_str(rsc->provider),
				  crm_str(rsc->id),
				  op_status2text(op->op_status));
			break;
		case LRM_OP_PENDING:
			crm_debug("LRM operation %s on %s::%s(%s):%s: not executed yet",
				 op->op_type,
				 crm_str(rsc->class),
				 crm_str(rsc->type),
				 crm_str(rsc->provider),
				 crm_str(rsc->id));
			break;
	}
	do_update_resource(rsc, op);
	return I_NULL;
}
