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
#include <crm/crm.h>
#include <crmd_fsa.h>

#include <sys/types.h>
#include <sys/wait.h>

#include <unistd.h>			// for access
#include <clplumbing/cl_signal.h>

#include <errno.h>

#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>

#include <crmd.h>
#include <crmd_messages.h>
#include <crmd_callbacks.h>

#include <crm/dmalloc_wrapper.h>

xmlNodePtr do_lrm_query(gboolean);

gboolean build_suppported_RAs(xmlNodePtr xml_agent_list);

gboolean build_active_RAs(xmlNodePtr rsc_list);

void do_update_resource(
	lrm_rsc_t *rsc, int status, int rc, const char *op_type);

enum crmd_fsa_input do_lrm_rsc_op(
	lrm_rsc_t *rsc, rsc_id_t rid, const char *operation, xmlNodePtr msg);

enum crmd_fsa_input do_lrm_monitor(lrm_rsc_t *rsc);

enum crmd_fsa_input do_fake_lrm_op(gpointer data);

GHashTable *xml2list(xmlNodePtr parent, const char **attr_path, int depth);

const char *rsc_path[] = 
{
	"msg_data",
	"rsc_op",
	"resource",
	"instance_attributes",
	"parameters"
};


/*	 A_LRM_CONNECT	*/
enum crmd_fsa_input
do_lrm_control(long long action,
	       enum crmd_fsa_cause cause,
	       enum crmd_fsa_state cur_state,
	       enum crmd_fsa_input current_input,
	       void *data)
{
	enum crmd_fsa_input failed = I_NULL;//I_FAIL;
	int ret = HA_OK;

	if(action & A_LRM_DISCONNECT) {
		fsa_lrm_conn->lrm_ops->signoff(fsa_lrm_conn);
	}

	if(action & A_LRM_CONNECT) {
	
		crm_trace("LRM: connect...");
		fsa_lrm_conn = ll_lrm_new(XML_CIB_TAG_LRM);	
		if(NULL == fsa_lrm_conn) {
			return failed;
		}
		
		crm_trace("LRM: sigon...");
		ret = fsa_lrm_conn->lrm_ops->signon(fsa_lrm_conn,
						    CRM_SYSTEM_CRMD);
		
		if(ret != HA_OK) {
			crm_err("Failed to sign on to the LRM");
			return failed;
		}
		
		crm_trace("LRM: set_lrm_callback...");
		ret = fsa_lrm_conn->lrm_ops->set_lrm_callback(
			fsa_lrm_conn, lrm_op_callback, lrm_monitor_callback);
		
		if(ret != HA_OK) {
			crm_err("Failed to set LRM callbacks");
			return failed;
		}

		/* TODO: create a destroy handler that causes
		 * some recovery to happen
		 */
		G_main_add_fd(G_PRIORITY_LOW,
			      fsa_lrm_conn->lrm_ops->inputfd(fsa_lrm_conn),
			      FALSE,
			      lrm_dispatch, fsa_lrm_conn,
			      default_ipc_input_destroy);
	}	

	if(action & ~(A_LRM_CONNECT|A_LRM_DISCONNECT)) {
		crm_err("Unexpected action %s in %s",
		       fsa_action2string(action), __FUNCTION__);
	}
		
	
	return I_NULL;
}

gboolean
build_suppported_RAs(xmlNodePtr xml_agent_list)
{
	int lpc = 0, llpc = 0;
	GList *types    = NULL;
	GList *classes  = NULL;
	xmlNodePtr xml_agent = NULL;

	classes = fsa_lrm_conn->lrm_ops->get_rsc_class_supported(fsa_lrm_conn);

	slist_iter(
		class, char, classes, lpc,

		types = fsa_lrm_conn->lrm_ops->get_rsc_type_supported(
			fsa_lrm_conn, class);

		slist_iter(
			type, char, types, llpc,
			
			xml_agent = create_xml_node(
				xml_agent_list, "lrm_agent");
			
			set_xml_property_copy(xml_agent, "class",       class);
			set_xml_property_copy(xml_agent, XML_ATTR_TYPE, type);

			/* we dont have this yet */
			set_xml_property_copy(xml_agent, "version",     "1");

			)
		g_list_free(types);
		);

	g_list_free(classes);

	return TRUE;
}


gboolean
build_active_RAs(xmlNodePtr rsc_list)
{
	int lpc = 0, llpc = 0;

	GList *op_list  = NULL;
	GList *lrm_list = NULL;

	state_flag_t cur_state = 0;
	const char *this_op    = NULL;
	gboolean found = FALSE;
	
	lrm_list = fsa_lrm_conn->lrm_ops->get_all_rscs(fsa_lrm_conn);

	slist_iter(
		the_rsc, lrm_rsc_t, lrm_list, lpc,

/* 		GHashTable* 	params; */
		
		xmlNodePtr xml_rsc = create_xml_node(rsc_list, "rsc_state");
		const char *status_text = "<unknown>";
		
		set_xml_property_copy(xml_rsc, XML_ATTR_ID, the_rsc->id);
		set_xml_property_copy(xml_rsc, "type",      the_rsc->type);
		set_xml_property_copy(xml_rsc, "class",     the_rsc->class);
		set_xml_property_copy(xml_rsc, "node_id",   fsa_our_uname);
		
		op_list = the_rsc->ops->get_cur_state(the_rsc, &cur_state);

		crm_verbose("\tcurrent state:%s\n",
			    cur_state==LRM_RSC_IDLE?"Idle":"Busy");

		slist_iter(
			op, lrm_op_t, op_list, llpc,

			this_op = op->op_type;

			if(found == FALSE && safe_str_neq(this_op, "status")){
				switch(op->status) {
					case LRM_OP_DONE:
						status_text = "done";
						break;
					case LRM_OP_CANCELLED:
						status_text = "cancelled";
						break;
					case LRM_OP_TIMEOUT:
						status_text = "timeout";
						break;
					case LRM_OP_NOTSUPPORTED:
						status_text = "not suported";
						break;
					case LRM_OP_ERROR:
						status_text = "error";
						break;
				}
			}

			if(found) {
				set_xml_property_copy(
					xml_rsc, "rsc_op", this_op);

				/* we only want the last one */
				break;
			}
			)

		set_xml_property_copy(xml_rsc, "op_result", status_text);
		
		g_list_free(op_list);
		);

	g_list_free(lrm_list);

	return TRUE;
}

xmlNodePtr
do_lrm_query(gboolean is_replace)
{
	xmlNodePtr xml_result= NULL;
	xmlNodePtr xml_state = create_xml_node(NULL, XML_CIB_TAG_STATE);
	xmlNodePtr xml_data  = create_xml_node(xml_state, XML_CIB_TAG_LRM);
	xmlNodePtr rsc_list  = create_xml_node(xml_data,XML_LRM_TAG_RESOURCES);
	xmlNodePtr xml_agent_list = create_xml_node(xml_data, "lrm_agents");

	/* Build a list of supported agents */
	build_suppported_RAs(xml_agent_list);
	
	/* Build a list of active (not always running) resources */
	build_active_RAs(rsc_list);

	if(is_replace) {
		set_xml_property_copy(xml_data, "replace", XML_CIB_TAG_LRM);
	}
	
	set_xml_property_copy(xml_state, XML_ATTR_ID, fsa_our_uname);
	xml_result = create_cib_fragment(xml_state, NULL);
	
	return xml_result;
}

/*	A_UPDATE_NODESTATUS */
enum crmd_fsa_input
do_update_node_status(long long action,
		      enum crmd_fsa_cause cause,
		      enum crmd_fsa_state cur_state,
		      enum crmd_fsa_input current_input,
		      void *data)
{
	xmlNodePtr update = NULL,
		fragment = NULL,
		tmp1 = NULL;
		fragment = NULL;
	if(action & A_UPDATE_NODESTATUS) {

#ifndef USE_FAKE_LRM
		update = do_lrm_query(TRUE);
#else
		tmp1 = create_xml_node(NULL, XML_CIB_TAG_STATE);
		set_xml_property_copy(tmp1, XML_ATTR_ID, fsa_our_uname);
		update = create_cib_fragment(tmp1, NULL);
#endif
		/* this only happens locally.  the updates are pushed out
		 * as part of the join process
		 */
		store_request(NULL, update, CRM_OP_UPDATE, CRM_SYSTEM_DC);
		free_xml(update);

		return I_NULL;
	}

	return I_ERROR;
}


/*	 A_LRM_INVOKE	*/
enum crmd_fsa_input
do_lrm_invoke(long long action,
	      enum crmd_fsa_cause cause,
	      enum crmd_fsa_state cur_state,
	      enum crmd_fsa_input current_input,
	      void *data)
{
	enum crmd_fsa_input next_input = I_NULL;
	xmlNodePtr msg;
	const char *operation = NULL;
	rsc_id_t rid;
	const char *id_from_cib = NULL;
	const char *crm_op = NULL;
	lrm_rsc_t *rsc = NULL;

#ifdef USE_FAKE_LRM
	return do_fake_lrm_op(data);
#endif
	
	crm_err("Action %s (%.16llx) only kind of supported\n",
	       fsa_action2string(action), action);


	msg = (xmlNodePtr)data;
		
	operation = get_xml_attr_nested(
		msg, rsc_path, DIMOF(rsc_path) -3, XML_ATTR_OP, TRUE);
	
	
	id_from_cib = get_xml_attr_nested(
		msg, rsc_path, DIMOF(rsc_path) -2, XML_ATTR_ID, TRUE);
	
	// only the first 16 chars are used by the LRM
	strncpy(rid, id_from_cib, 16);
	
	crm_op = get_xml_attr(msg, XML_TAG_OPTIONS, XML_ATTR_OP, TRUE);
	
	rsc = fsa_lrm_conn->lrm_ops->get_rsc(fsa_lrm_conn, rid);
	
	if(crm_op != NULL && strcmp(crm_op, "lrm_query") == 0) {
		xmlNodePtr data, reply;

		data = do_lrm_query(FALSE);
		reply = create_reply(msg, data);

		relay_message(reply, TRUE);

		free_xml(data);
		free_xml(reply);

	} else if(operation != NULL && strcmp(operation, "monitor") == 0) {
		next_input = do_lrm_monitor(rsc);
		
	} else if(operation != NULL) {
		next_input = do_lrm_rsc_op(rsc, rid, operation, msg);
		
	} else {
		next_input = I_ERROR;
	}

	return next_input;
}


enum crmd_fsa_input
do_lrm_rsc_op(
	lrm_rsc_t *rsc, rsc_id_t rid, const char *operation, xmlNodePtr msg)
{
	lrm_op_t* op = NULL;

	if(rsc == NULL) {
		// add it to the list
		crm_verbose("adding rsc %s before operation", rid);
		fsa_lrm_conn->lrm_ops->add_rsc(
			fsa_lrm_conn, rid,
			get_xml_attr_nested(
				msg, rsc_path, DIMOF(rsc_path) -2,
				"class", TRUE),
			get_xml_attr_nested(
				msg, rsc_path, DIMOF(rsc_path) -2,
				XML_ATTR_TYPE, TRUE),
			NULL);
		
		rsc = fsa_lrm_conn->lrm_ops->get_rsc(
			fsa_lrm_conn, rid);
	}
	
	if(rsc == NULL) {
		crm_err("Could not add resource to LRM");
		return I_FAIL;
	}
	
	// now do the op
	crm_verbose("performing op %s...", operation);
	op = g_new(lrm_op_t, 1);
	op->op_type = operation;
	op->params = xml2list(msg, rsc_path, DIMOF(rsc_path));
	op->timeout = 0;
	op->user_data = rsc;
	rsc->ops->perform_op(rsc, op);

	return I_NULL;
}

enum crmd_fsa_input
do_lrm_monitor(lrm_rsc_t *rsc)
{
	lrm_mon_t* mon = NULL;

	if(rsc == NULL) {
		crm_err("Could not find resource to monitor");
		return I_FAIL;
	}
	
	mon = g_new(lrm_mon_t, 1);
	mon->op_type = "status";
	mon->params = NULL;
	mon->timeout = 0;
	mon->user_data = rsc;
	mon->mode = LRM_MONITOR_SET;
	mon->interval = 2;
	mon->target = 1;
	rsc->ops->set_monitor(rsc, mon);

	return I_NULL;
}


GHashTable *
xml2list(xmlNodePtr parent, const char**attr_path, int depth)
{
	xmlNodePtr node_iter = NULL;

	GHashTable   *nvpair_hash =
		g_hash_table_new(&g_str_hash, &g_str_equal);

	xmlNodePtr nvpair_list =
		find_xml_node_nested(parent, attr_path, depth);
	
	if(nvpair_list != NULL){
		node_iter = nvpair_list->children;
		while(node_iter != NULL) {
			
			const char *key   = xmlGetProp(
				node_iter, XML_NVPAIR_ATTR_NAME);
			const char *value = xmlGetProp(
				node_iter, XML_NVPAIR_ATTR_VALUE);
			
			crm_verbose("Added %s=%s", key, value);
			
			g_hash_table_insert (nvpair_hash,
					     crm_strdup(key),
					     crm_strdup(value));
			
			node_iter = node_iter->next;
		}
	}
	
	return nvpair_hash;
}


void
do_update_resource(lrm_rsc_t *rsc, int status, int rc, const char *op_type)
{
/*
  <status>
  <nodes_status id=uname>
  <lrm>
  <lrm_resources>
  <lrm_resource id=>
  </...>
*/
	xmlNodePtr update, iter;
	char *tmp = NULL;
	xmlNodePtr fragment, tmp1;
	
	
	update = create_xml_node(NULL, "node_state");
	set_xml_property_copy(update,  XML_ATTR_ID, fsa_our_uname);
	iter = create_xml_node(update, XML_CIB_TAG_LRM);
	iter = create_xml_node(iter,   XML_LRM_TAG_RESOURCES);
	iter = create_xml_node(iter,   "lrm_resource");
	
	set_xml_property_copy(iter, XML_ATTR_ID, rsc->id);
	set_xml_property_copy(iter, XML_LRM_ATTR_LASTOP, op_type);
	
	tmp = crm_itoa(status);
	set_xml_property_copy(iter, XML_LRM_ATTR_OPSTATE, tmp);
	crm_free(tmp);
	
	tmp = crm_itoa(rc);
	set_xml_property_copy(iter, XML_LRM_ATTR_OPCODE, tmp);
	crm_free(tmp);

	set_xml_property_copy(iter, XML_LRM_ATTR_TARGET, fsa_our_uname);
	
	tmp1 = create_xml_node(NULL, XML_CIB_TAG_STATE);
	set_xml_property_copy(tmp1, XML_ATTR_ID, fsa_our_uname);
	add_node_copy(tmp1, update);

	fragment = create_cib_fragment(tmp1, NULL);

	send_request(NULL, fragment, CRM_OP_UPDATE,
		     fsa_our_dc, CRM_SYSTEM_DCIB, NULL);
	
	free_xml(fragment);
	free_xml(update);
	free_xml(tmp1);
}

enum crmd_fsa_input
do_lrm_event(long long action,
	     enum crmd_fsa_cause cause,
	     enum crmd_fsa_state cur_state,
	     enum crmd_fsa_input cur_input,
	     void *data)
{
	
	if(cause == C_LRM_MONITOR_CALLBACK) {
		lrm_mon_t* monitor = (lrm_mon_t*)data;
		lrm_rsc_t* rsc = monitor->rsc;
		

		switch(monitor->status) {
			case LRM_OP_DONE:
				crm_trace("An LRM monitor operation passed");
				return I_NULL;
				break;

			case LRM_OP_CANCELLED:
			case LRM_OP_TIMEOUT:
			case LRM_OP_NOTSUPPORTED:
			case LRM_OP_ERROR:
				crm_err("An LRM monitor operation failed"
					" or was aborted");

				do_update_resource(rsc,
						   monitor->status,
						   monitor->rc,
						   monitor->op_type);

				break;
		}	

	} else if(cause == C_LRM_OP_CALLBACK) {
		lrm_op_t* op = (lrm_op_t*)data;
		lrm_rsc_t* rsc = op->rsc;

		switch(op->status) {
			case LRM_OP_CANCELLED:
			case LRM_OP_TIMEOUT:
			case LRM_OP_NOTSUPPORTED:
			case LRM_OP_ERROR:
				crm_err("An LRM operation failed"
					" or was aborted");
				// keep going
			case LRM_OP_DONE:

				do_update_resource(rsc,
						   op->status,
						   op->rc,
						   op->op_type);

				break;
		}
		
	} else {

		return I_FAIL;
	}
	
	return I_NULL;
}

enum crmd_fsa_input
do_fake_lrm_op(gpointer data)
{
	xmlNodePtr msg          = NULL;
	const char *crm_op      = NULL;
	const char *operation   = NULL;
	const char *id_from_cib = NULL;
	long int op_code = 0;
	const char *op_status = NULL;
	xmlNodePtr update = NULL;
	xmlNodePtr state = NULL;
	xmlNodePtr iter = NULL;
	char *op_code_s = NULL;

	
	if(data == NULL) {
		return I_ERROR;
	}
	
	msg = (xmlNodePtr)data;
	
	operation = get_xml_attr_nested(
		msg, rsc_path, DIMOF(rsc_path) -3, XML_LRM_ATTR_TASK, TRUE);
	
	id_from_cib = get_xml_attr_nested(
		msg, rsc_path, DIMOF(rsc_path) -2, XML_ATTR_ID, TRUE);
	
	crm_op = get_xml_attr(msg, XML_TAG_OPTIONS, XML_ATTR_OP, TRUE);

	if(safe_str_eq(crm_op, "rsc_op")) {

		state = create_xml_node(NULL, XML_CIB_TAG_STATE);
		iter = create_xml_node(state, XML_CIB_TAG_LRM);

		crm_verbose("performing op %s...", operation);

		// so we can identify where to do the update
		set_xml_property_copy(state, XML_ATTR_ID, fsa_our_uname);

		iter = create_xml_node(iter, XML_LRM_TAG_RESOURCES);
		iter = create_xml_node(iter, "lrm_resource");

		set_xml_property_copy(iter, XML_ATTR_ID, id_from_cib);
		set_xml_property_copy(iter, XML_LRM_ATTR_LASTOP, operation);


#if 0
		/* introduce a 10% chance of an action failing */
		op_code = random();
#endif
		if((op_code % 10) == 1) {
			op_code = 1;
		} else {
			op_code = 0;
		}
		op_code_s = crm_itoa(op_code);

		if(op_code) {
			// fail
			if(safe_str_eq(operation, "start")){
				op_status = "stopped";
			} else {
				op_status = "started";
			}
		} else {
			// pass
			if(safe_str_eq(operation, "start")){
				op_status = "started";
			} else {
				op_status = "stopped";
			}
		}
		
		set_xml_property_copy(iter, XML_LRM_ATTR_OPSTATE,op_status);
		set_xml_property_copy(iter, XML_LRM_ATTR_OPCODE, op_code_s);
		set_xml_property_copy(
			iter, XML_LRM_ATTR_TARGET, fsa_our_uname);

		crm_free(op_code_s);
		
		update = create_cib_fragment(state, NULL);
		
		send_request(NULL, update, CRM_OP_UPDATE,
			     fsa_our_dc, CRM_SYSTEM_DCIB, NULL);
	}
	
	return I_NULL;
}
