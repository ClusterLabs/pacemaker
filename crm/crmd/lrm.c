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
#include <clplumbing/realtime.h>
#include <sys/types.h>	// for calls to open
#include <sys/stat.h>	// for calls to open
#include <fcntl.h>	// for calls to open
#include <pwd.h>	// for getpwuid
#include <grp.h>	// for initgroups

#include <sys/time.h>	// for getrlimit
#include <sys/resource.h>// for getrlimit

#include <crm/common/crmutils.h>
#include <crm/common/ipcutils.h>
#include <crm/common/msgutils.h>

#include <crm/msg_xml.h>
#include <crm/common/xmlutils.h>


#include <crm/cib.h>

#include <crmd.h>
#include <crmd_messages.h>
#include <string.h>
#include <errno.h>

#include <crm/dmalloc_wrapper.h>

xmlNodePtr do_lrm_query(void);

GHashTable *xml2list(xmlNodePtr parent, const char **attr_path, int depth);

gboolean lrm_dispatch(int fd, gpointer user_data);

void do_update_resource(lrm_rsc_t *rsc,
			int status,
			int rc,
			const char *op_type);

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
	FNIN();

	if(action & A_LRM_DISCONNECT) {
		fsa_lrm_conn->lrm_ops->signoff(fsa_lrm_conn);
	}

	if(action & A_LRM_CONNECT) {
	
		CRM_NOTE("LRM: connect...");
		fsa_lrm_conn = ll_lrm_new(XML_CIB_TAG_LRM);	
		if(NULL == fsa_lrm_conn) {
			return failed;
		}
		
		CRM_NOTE("LRM: sigon...");
		ret = fsa_lrm_conn->lrm_ops->signon(fsa_lrm_conn,
						    CRM_SYSTEM_CRMD);
		
		if(ret != HA_OK) {
			cl_log(LOG_ERR, "Failed to sign on to the LRM");
			return failed;
		}
		
		CRM_NOTE("LRM: set_lrm_callback...");
		ret = fsa_lrm_conn->lrm_ops->set_lrm_callback(
			fsa_lrm_conn, lrm_op_callback, lrm_monitor_callback);
		
		if(ret != HA_OK) {
			cl_log(LOG_ERR, "Failed to set LRM callbacks");
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
		cl_log(LOG_ERR, "Unexpected action %s in %s",
		       fsa_action2string(action), __FUNCTION__);
	}
		
	
	FNRET(I_NULL);
}

gboolean lrm_dispatch(int fd, gpointer user_data)
{
	ll_lrm_t *lrm = (ll_lrm_t*)user_data;
	lrm->lrm_ops->rcvmsg(lrm, FALSE);
	return TRUE;
}

xmlNodePtr
do_lrm_query(void)
{
	GList* lrm_list = NULL;
	GList* element = NULL;
	GList* op_list = NULL;
	xmlNodePtr agent = NULL;
	xmlNodePtr data = create_xml_node(NULL, XML_CIB_TAG_LRM);
	xmlNodePtr agent_list = create_xml_node(data, "lrm_agents");
	xmlNodePtr rsc_list;
	char *rsc_type = NULL;
	state_flag_t cur_state = 0;
	const char *this_op = NULL;
	GList* node = NULL;
	
	lrm_list = fsa_lrm_conn->lrm_ops->get_ra_supported(fsa_lrm_conn);
	if (NULL != lrm_list) {
		GList* element = g_list_first(lrm_list);
		while (NULL != element) {
			rsc_type = (char*)element->data;
			
			agent =
				create_xml_node(agent_list, "lrm_agent");
			
			set_xml_property_copy(agent, "class",   rsc_type);

			/* we dont have these yet */
			set_xml_property_copy(agent, XML_ATTR_TYPE,    NULL);
			set_xml_property_copy(agent, "version", NULL);
			
			element = g_list_next(element);
		}
	}
	
	g_list_free(lrm_list);
	lrm_list = fsa_lrm_conn->lrm_ops->get_all_rscs(fsa_lrm_conn);

	rsc_list = create_xml_node(data, XML_LRM_TAG_RESOURCES);

	if (NULL != lrm_list) {
		element = g_list_first(lrm_list);
	}
	
	while (NULL != element) {
		lrm_rsc_t *the_rsc = (lrm_rsc_t*)element->data;
		
/* 				const char*	ra_type; */
/* 				GHashTable* 	params; */
		
		xmlNodePtr xml_rsc = create_xml_node(rsc_list, "rsc_state");
		
		set_xml_property_copy(xml_rsc, XML_ATTR_ID,     the_rsc->id);
		set_xml_property_copy(xml_rsc, "rsc_id", the_rsc->name);
		set_xml_property_copy(xml_rsc, "node_id",fsa_our_uname);
		
		op_list = the_rsc->ops->get_cur_state(the_rsc,
						      &cur_state);
		CRM_DEBUG("\tcurrent state:%s\n",
			  cur_state==LRM_RSC_IDLE?"Idle":"Busy");
		
		node = g_list_first(op_list);
		
		while(NULL != node){
			lrm_op_t* op = (lrm_op_t*)node->data;
			this_op = op->op_type;
			if(this_op == NULL
			   || strcmp(this_op, "status") != 0){
				
				const char *status_text = "<unknown>";
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
				
				
				set_xml_property_copy(xml_rsc,
						      "op_result",
						      status_text);
				
				set_xml_property_copy(xml_rsc,
						      "rsc_op",
						      this_op);
				
				// we only want the last one
				break;
			}
			
			node = g_list_next(node);
		}
		
		element = g_list_next(element);
	}

	if (NULL != lrm_list) {
		g_list_free(lrm_list);
	}
	
	return data;
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
	xmlNodePtr fragment, tmp1;
	xmlNodePtr msg;
	const char *rsc_path[] = 
		{
			"msg_data",
			"rsc_op",
			"resource",
			"instance_attributes",
			"parameters"
		};
	const char *operation = NULL;
	rsc_id_t rid;
	const char *id_from_cib = NULL;
	const char *crm_op = NULL;
	lrm_rsc_t *rsc = NULL;
	lrm_mon_t* mon = NULL;
	lrm_op_t* op = NULL;
	
	FNIN();

	if(action & A_UPDATE_NODESTATUS) {

		xmlNodePtr data = NULL;
#ifndef USE_FAKE_LRM
		data = do_lrm_query();
#endif
		set_xml_property_copy(data, "replace", XML_CIB_TAG_LRM);

		tmp1 = create_xml_node(NULL, XML_CIB_TAG_STATE);
		set_xml_property_copy(tmp1, XML_ATTR_ID, fsa_our_uname);

		fragment = create_cib_fragment(tmp1, NULL);
		add_node_copy(tmp1, data);

		/* this only happens locally.  the updates are pushed out
		 * as part of the join process
		 */
		store_request(NULL, fragment, CRM_OP_UPDATE, CRM_SYSTEM_DC);

		free_xml(fragment);
		free_xml(tmp1);
		free_xml(data);

		FNRET(next_input);
	}

#ifdef USE_FAKE_LRM
	if(data == NULL) {
		FNRET(I_ERROR);
	}
	
	msg = (xmlNodePtr)data;
	
	operation = get_xml_attr_nested(msg, rsc_path, DIMOF(rsc_path) -3,
					XML_LRM_ATTR_TASK, TRUE);
	
	id_from_cib = get_xml_attr_nested(msg, rsc_path, DIMOF(rsc_path) -2,
					  XML_ATTR_ID, TRUE);
	
	crm_op = get_xml_attr(msg, XML_TAG_OPTIONS, XML_ATTR_OP, TRUE);

	if(safe_str_eq(crm_op, "rsc_op")) {

		const char *op_status = NULL;
		xmlNodePtr update = NULL;
		xmlNodePtr state = create_xml_node(NULL, XML_CIB_TAG_STATE);
		xmlNodePtr iter = create_xml_node(state, XML_CIB_TAG_LRM);

		CRM_DEBUG("performing op %s...", operation);

		// so we can identify where to do the update
		set_xml_property_copy(state, XML_ATTR_ID, fsa_our_uname);

		iter = create_xml_node(iter, XML_LRM_TAG_RESOURCES);
		iter = create_xml_node(iter, "lrm_resource");

		set_xml_property_copy(iter, XML_ATTR_ID, id_from_cib);
		set_xml_property_copy(iter, XML_LRM_ATTR_LASTOP, operation);

		long int op_code = 0;

#if 0
		/* introduce a 10% chance of an action failing */
		op_code = random();
#endif
		if((op_code % 10) == 1) {
			op_code = 1;
		} else {
			op_code = 0;
		}
		char *op_code_s = crm_itoa(op_code);

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
		set_xml_property_copy(iter, XML_LRM_ATTR_TARGET, fsa_our_uname);

		crm_free(op_code_s);
		
		update = create_cib_fragment(state, NULL);
		
		send_request(NULL, update, CRM_OP_UPDATE,
			     fsa_our_dc, CRM_SYSTEM_DCIB, NULL);
	}
	
	FNRET(I_NULL);
#endif

	
	cl_log(LOG_WARNING, "Action %s (%.16llx) only kind of supported\n",
	       fsa_action2string(action), action);


	msg = (xmlNodePtr)data;
		
	operation = get_xml_attr_nested(msg, rsc_path, DIMOF(rsc_path) -3,
					XML_ATTR_OP, TRUE);
	
	
	id_from_cib = get_xml_attr_nested(msg, rsc_path, DIMOF(rsc_path) -2,
					  XML_ATTR_ID, TRUE);
	
	// only the first 16 chars are used by the LRM
	strncpy(rid, id_from_cib, 16);
	
	
	crm_op = get_xml_attr(msg, XML_TAG_OPTIONS, XML_ATTR_OP, TRUE);
	
	rsc = fsa_lrm_conn->lrm_ops->get_rsc(fsa_lrm_conn, rid);
	
	if(crm_op != NULL && strcmp(crm_op, "lrm_query") == 0) {

		xmlNodePtr data, tmp1, tmp2, reply;

		tmp1 = create_xml_node(NULL, XML_CIB_TAG_STATE);
		set_xml_property_copy(tmp1, XML_ATTR_ID, fsa_our_uname);
		
		data = create_cib_fragment(tmp1, NULL);

		tmp2 = do_lrm_query();
		add_node_copy(tmp1, tmp2);

		reply = create_reply(msg, data);

		relay_message(reply, TRUE);

		free_xml(data);
		free_xml(reply);
		free_xml(tmp2);
		free_xml(tmp1);

	} else if(operation != NULL && strcmp(operation, "monitor") == 0) {
		if(rsc == NULL) {
			cl_log(LOG_ERR, "Could not find resource to monitor");
			FNRET(I_FAIL);
		}
		
		mon = g_new(lrm_mon_t, 1);
		mon->op_type = "status";
		mon->params = NULL;
		mon->timeout = 0;
		mon->user_data = rsc;
		mon->mode = LRM_MONITOR_SET;
		mon->interval = 2;
		mon->target = 1;
		rsc->ops->set_monitor(rsc,mon);
		mon = g_new(lrm_mon_t, 1);

	} else if(operation != NULL) {
		if(rsc == NULL) {
			// add it to the list
			CRM_DEBUG("adding rsc %s before operation", rid);
			fsa_lrm_conn->lrm_ops->add_rsc(
				fsa_lrm_conn, rid,
				get_xml_attr_nested(msg, 
						    rsc_path,
						    DIMOF(rsc_path) -2,
						    "class", TRUE),
				get_xml_attr_nested(msg, 
						    rsc_path,
						    DIMOF(rsc_path) -2,
						    XML_ATTR_TYPE, TRUE),
				NULL);
			
			rsc = fsa_lrm_conn->lrm_ops->get_rsc(
				fsa_lrm_conn, rid);
		}

		if(rsc == NULL) {
			cl_log(LOG_ERR, "Could not add resource to LRM");
			FNRET(I_FAIL);
		}
		
		// now do the op
		CRM_DEBUG("performing op %s...", operation);
		op = g_new(lrm_op_t, 1);
		op->op_type = operation;
		op->params = xml2list(msg, rsc_path, DIMOF(rsc_path));
		op->timeout = 0;
		op->user_data = rsc;
		rsc->ops->perform_op(rsc, op);
	}

	FNRET(next_input);
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
			
			CRM_DEBUG("Added %s=%s", key, value);
			
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
	set_xml_property_copy(update, XML_ATTR_ID, fsa_our_uname);
	iter = create_xml_node(update, XML_CIB_TAG_LRM);
	iter = create_xml_node(iter, XML_LRM_TAG_RESOURCES);
	iter = create_xml_node(iter, "lrm_resource");
	
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
	FNIN();
	if(cause == C_LRM_MONITOR_CALLBACK) {
		lrm_mon_t* monitor = (lrm_mon_t*)data;
		lrm_rsc_t* rsc = monitor->rsc;
		

		switch(monitor->status) {
			case LRM_OP_DONE:
				CRM_NOTE("An LRM monitor operation passed");
				FNRET(I_NULL);
				break;

			case LRM_OP_CANCELLED:
			case LRM_OP_TIMEOUT:
			case LRM_OP_NOTSUPPORTED:
			case LRM_OP_ERROR:
				cl_log(LOG_ERR,
				       "An LRM monitor operation failed"
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
				cl_log(LOG_ERR,
				       "An LRM operation failed"
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

		FNRET(I_FAIL);
	}
	
	FNRET(I_NULL);
}
