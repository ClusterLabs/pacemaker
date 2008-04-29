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
#include <crm_internal.h>
#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/msg.h>
#include <clplumbing/cl_misc.h>

#include <lrm/lrm_api.h>

#include <glib.h>

#include <heartbeat.h> /* for ONLINESTATUS */

#include <crm/pengine/status.h>
#include <utils.h>
#include <crm/pengine/rules.h>
#include <unpack.h>

gboolean
unpack_config(xmlNode *config, pe_working_set_t *data_set)
{
	const char *name = NULL;
	const char *value = NULL;
	GHashTable *config_hash = g_hash_table_new_full(
		g_str_hash,g_str_equal, g_hash_destroy_str,g_hash_destroy_str);

	data_set->config_hash = config_hash;

	unpack_instance_attributes(
		config, XML_CIB_TAG_PROPSET, NULL, config_hash,
		CIB_OPTIONS_FIRST, data_set->now);

#if CRM_DEPRECATED_SINCE_2_0_1
	xml_child_iter_filter(
		config, a_child, XML_CIB_TAG_NVPAIR,

		name = crm_element_value(a_child, XML_NVPAIR_ATTR_NAME);

		value = crm_element_value(a_child, XML_NVPAIR_ATTR_VALUE);
		if(g_hash_table_lookup(config_hash, name) == NULL) {
			g_hash_table_insert(
				config_hash,crm_strdup(name),crm_strdup(value));
		}
		crm_config_err("Creating <nvpair id=%s name=%s/> directly"
			      "beneath <crm_config> has been depreciated since"
			      " 2.0.1", ID(a_child), name);
		);
#else
	xml_child_iter_filter(
		config, a_child, XML_CIB_TAG_NVPAIR,

		name = crm_element_value(a_child, XML_NVPAIR_ATTR_NAME);
		crm_config_err("Creating <nvpair id=%s name=%s/> directly"
			      "beneath <crm_config> has been depreciated since"
			      " 2.0.1 and is now disabled", ID(a_child), name);
		);
#endif
	verify_pe_options(data_set->config_hash);
	
	value = pe_pref(data_set->config_hash, "default-action-timeout");
	data_set->transition_idle_timeout = crm_strdup(value);
	crm_debug("Default action timeout: %s", data_set->transition_idle_timeout);

	value = pe_pref(data_set->config_hash, "default-resource-stickiness");
	data_set->default_resource_stickiness = char2score(value);
	crm_debug("Default stickiness: %d",
		 data_set->default_resource_stickiness);

	value = pe_pref(data_set->config_hash, "stop-all-resources");
	data_set->stop_everything = crm_is_true(value);
	crm_debug("Stop all active resources: %s",
		  data_set->stop_everything?"true":"false");
	
	value = pe_pref(data_set->config_hash, "default-migration-threshold");
	data_set->default_migration_threshold = char2score(value);
	crm_debug("Default migration threshold: %d",
		 data_set->default_migration_threshold);
	
	value = pe_pref(data_set->config_hash, "stonith-enabled");
	cl_str_to_boolean(value, &data_set->stonith_enabled);
	crm_debug("STONITH of failed nodes is %s",
		 data_set->stonith_enabled?"enabled":"disabled");	

	data_set->stonith_action = pe_pref(data_set->config_hash, "stonith-action");
	crm_debug_2("STONITH will %s nodes", data_set->stonith_action);	
	
	value = pe_pref(data_set->config_hash, "symmetric-cluster");
	cl_str_to_boolean(value, &data_set->symmetric_cluster);
	if(data_set->symmetric_cluster) {
		crm_debug("Cluster is symmetric"
			 " - resources can run anywhere by default");
	}

	value = pe_pref(data_set->config_hash, "no-quorum-policy");
	if(safe_str_eq(value, "ignore")) {
		data_set->no_quorum_policy = no_quorum_ignore;
		
	} else if(safe_str_eq(value, "freeze")) {
		data_set->no_quorum_policy = no_quorum_freeze;

	} else {
		data_set->no_quorum_policy = no_quorum_stop;
	}
	
	switch (data_set->no_quorum_policy) {
		case no_quorum_freeze:
			crm_debug("On loss of CCM Quorum: Freeze resources");
			break;
		case no_quorum_stop:
			crm_debug("On loss of CCM Quorum: Stop ALL resources");
			break;
		case no_quorum_ignore:
			crm_notice("On loss of CCM Quorum: Ignore");
			break;
	}

	value = pe_pref(data_set->config_hash, "stop-orphan-resources");
	cl_str_to_boolean(value, &data_set->stop_rsc_orphans);
	crm_debug_2("Orphan resources are %s",
		    data_set->stop_rsc_orphans?"stopped":"ignored");	
	
	value = pe_pref(data_set->config_hash, "stop-orphan-actions");
	cl_str_to_boolean(value, &data_set->stop_action_orphans);
	crm_debug_2("Orphan resource actions are %s",
		    data_set->stop_action_orphans?"stopped":"ignored");	

	value = pe_pref(data_set->config_hash, "remove-after-stop");
	cl_str_to_boolean(value, &data_set->remove_after_stop);
	crm_debug_2("Stopped resources are removed from the status section: %s",
		    data_set->remove_after_stop?"true":"false");	
	
	value = pe_pref(data_set->config_hash, "is-managed-default");
	cl_str_to_boolean(value, &data_set->is_managed_default);
	crm_debug_2("By default resources are %smanaged",
		    data_set->is_managed_default?"":"not ");

	value = pe_pref(data_set->config_hash, "start-failure-is-fatal");
	cl_str_to_boolean(value, &data_set->start_failure_fatal);
	crm_debug_2("Start failures are %s",
		    data_set->start_failure_fatal?"always fatal":"handled by failcount");
	
	return TRUE;
}

gboolean
unpack_nodes(xmlNode * xml_nodes, pe_working_set_t *data_set)
{
	node_t *new_node   = NULL;
	const char *id     = NULL;
	const char *uname  = NULL;
	const char *type   = NULL;
	gboolean unseen_are_unclean = TRUE;
	const char *blind_faith = pe_pref(
		data_set->config_hash, "startup-fencing");
	
	if(crm_is_true(blind_faith) == FALSE) {
		unseen_are_unclean = FALSE;
		crm_warn("Blind faith: not fencing unseen nodes");
	}

	xml_child_iter_filter(
		xml_nodes, xml_obj, XML_CIB_TAG_NODE,

		new_node = NULL;

		id     = crm_element_value(xml_obj, XML_ATTR_ID);
		uname  = crm_element_value(xml_obj, XML_ATTR_UNAME);
		type   = crm_element_value(xml_obj, XML_ATTR_TYPE);
		crm_debug_3("Processing node %s/%s", uname, id);

		if(id == NULL) {
			crm_config_err("Must specify id tag in <node>");
			continue;
		}
		if(type == NULL) {
			crm_config_err("Must specify type tag in <node>");
			continue;
		}
		if(pe_find_node(data_set->nodes, uname) != NULL) {
		    crm_config_warn("Detected multiple node entries with uname=%s"
				    " - this is rarely intended", uname);
		}

		crm_malloc0(new_node, sizeof(node_t));
		if(new_node == NULL) {
			return FALSE;
		}
		
		new_node->weight = 0;
		new_node->fixed  = FALSE;
		crm_malloc0(new_node->details,
			   sizeof(struct node_shared_s));

		if(new_node->details == NULL) {
			crm_free(new_node);
			return FALSE;
		}

		crm_debug_3("Creaing node for entry %s/%s", uname, id);
		new_node->details->id		= id;
		new_node->details->uname	= uname;
		new_node->details->type		= node_ping;
		new_node->details->online	= FALSE;
		new_node->details->shutdown	= FALSE;
		new_node->details->running_rsc	= NULL;
		new_node->details->attrs        = g_hash_table_new_full(
			g_str_hash, g_str_equal,
			g_hash_destroy_str, g_hash_destroy_str);
		
/* 		if(data_set->have_quorum == FALSE */
/* 		   && data_set->no_quorum_policy == no_quorum_stop) { */
/* 			/\* start shutting resources down *\/ */
/* 			new_node->weight = -INFINITY; */
/* 		} */
		
		if(data_set->stonith_enabled == FALSE || unseen_are_unclean == FALSE) {
			/* blind faith... */
			new_node->details->unclean = FALSE; 

		} else {
			/* all nodes are unclean until we've seen their
			 * status entry
			 */
			new_node->details->unclean = TRUE;
		}
		
		if(type == NULL
		   || safe_str_eq(type, "member")
		   || safe_str_eq(type, NORMALNODE)) {
			new_node->details->type = node_member;
		}

		add_node_attrs(xml_obj, new_node, data_set);

		if(crm_is_true(g_hash_table_lookup(
				       new_node->details->attrs, "standby"))) {
			crm_info("Node %s is in standby-mode",
				 new_node->details->uname);
			new_node->weight = -INFINITY;
			new_node->details->standby = TRUE;
		}
		
		data_set->nodes = g_list_append(data_set->nodes, new_node);    
		crm_debug_3("Done with node %s",
			    crm_element_value(xml_obj, XML_ATTR_UNAME));
		);
  
	return TRUE;
}

gboolean 
unpack_resources(xmlNode * xml_resources, pe_working_set_t *data_set)
{
	xml_child_iter(
		xml_resources, xml_obj, 

		resource_t *new_rsc = NULL;
		crm_debug_3("Begining unpack... %s",
			    xml_obj?crm_element_name(xml_obj):"<none>");
		if(common_unpack(xml_obj, &new_rsc, NULL, data_set)) {
			data_set->resources = g_list_append(
				data_set->resources, new_rsc);
			
			print_resource(LOG_DEBUG_3, "Added", new_rsc, FALSE);

		} else {
			crm_config_err("Failed unpacking %s %s",
				      crm_element_name(xml_obj),
				      crm_element_value(xml_obj, XML_ATTR_ID));
			if(new_rsc != NULL && new_rsc->fns != NULL) {
				new_rsc->fns->free(new_rsc);
			}
		}
		);
	
	data_set->resources = g_list_sort(
		data_set->resources, sort_rsc_priority);

	return TRUE;
}


/* remove nodes that are down, stopping */
/* create +ve rsc_to_node constraints between resources and the nodes they are running on */
/* anything else? */
gboolean
unpack_status(xmlNode * status, pe_working_set_t *data_set)
{
	const char *id    = NULL;
	const char *uname = NULL;

	xmlNode * lrm_rsc    = NULL;
	xmlNode * attrs      = NULL;
	node_t    *this_node  = NULL;
	
	crm_debug_3("Begining unpack");
	xml_child_iter_filter(
		status, node_state, XML_CIB_TAG_STATE,

		id         = crm_element_value(node_state, XML_ATTR_ID);
		uname = crm_element_value(node_state,    XML_ATTR_UNAME);
		attrs = find_xml_node(
			node_state, XML_TAG_TRANSIENT_NODEATTRS, FALSE);

		lrm_rsc = find_xml_node(node_state, XML_CIB_TAG_LRM, FALSE);
		lrm_rsc = find_xml_node(lrm_rsc, XML_LRM_TAG_RESOURCES, FALSE);

		crm_debug_3("Processing node %s", uname);
		this_node = pe_find_node_id(data_set->nodes, id);

		if(uname == NULL) {
			/* error */
			continue;

		} else if(this_node == NULL) {
			crm_config_warn("Node %s in status section no longer exists",
				       uname);
			continue;
		}

		/* Mark the node as provisionally clean
		 * - at least we have seen it in the current cluster's lifetime
		 */
		this_node->details->unclean = FALSE;
		
		crm_debug_3("Adding runtime node attrs");
		add_node_attrs(attrs, this_node, data_set);

		crm_debug_3("determining node state");
		determine_online_status(node_state, this_node, data_set);

		if(this_node->details->online || data_set->stonith_enabled) {
			/* offline nodes run no resources...
			 * unless stonith is enabled in which case we need to
			 *   make sure rsc start events happen after the stonith
			 */
			crm_debug_3("Processing lrm resource entries");
			unpack_lrm_resources(this_node, lrm_rsc, data_set);
		}
		);

	return TRUE;
	
}

static gboolean
determine_online_status_no_fencing(xmlNode * node_state, node_t *this_node)
{
	gboolean online = FALSE;
	const char *join_state = crm_element_value(node_state, XML_CIB_ATTR_JOINSTATE);
	const char *crm_state  = crm_element_value(node_state, XML_CIB_ATTR_CRMDSTATE);
	const char *ccm_state  = crm_element_value(node_state, XML_CIB_ATTR_INCCM);
	const char *ha_state   = crm_element_value(node_state, XML_CIB_ATTR_HASTATE);
	const char *exp_state  = crm_element_value(node_state, XML_CIB_ATTR_EXPSTATE);

	if(ha_state == NULL) {
		ha_state = DEADSTATUS;
	}
	
	if(!crm_is_true(ccm_state) || safe_str_eq(ha_state, DEADSTATUS)){
		crm_debug_2("Node is down: ha_state=%s, ccm_state=%s",
			    crm_str(ha_state), crm_str(ccm_state));
		
	} else if(!crm_is_true(ccm_state)
		  || safe_str_eq(ha_state, DEADSTATUS)) {

	} else if(safe_str_eq(crm_state, ONLINESTATUS)) {
		if(safe_str_eq(join_state, CRMD_JOINSTATE_MEMBER)) {
			online = TRUE;
		} else {
			crm_debug("Node is not ready to run resources: %s", join_state);
		}
		
	} else if(this_node->details->expected_up == FALSE) {
		crm_debug_2("CRMd is down: ha_state=%s, ccm_state=%s",
			    crm_str(ha_state), crm_str(ccm_state));
		crm_debug_2("\tcrm_state=%s, join_state=%s, expected=%s",
			    crm_str(crm_state), crm_str(join_state),
			    crm_str(exp_state));
		
	} else {
		/* mark it unclean */
		this_node->details->unclean = TRUE;
		
		crm_warn("Node %s is partially & un-expectedly down",
			 this_node->details->uname);
		crm_info("\tha_state=%s, ccm_state=%s,"
			 " crm_state=%s, join_state=%s, expected=%s",
			 crm_str(ha_state), crm_str(ccm_state),
			 crm_str(crm_state), crm_str(join_state),
			 crm_str(exp_state));
	}
	return online;
}

static gboolean
determine_online_status_fencing(xmlNode * node_state, node_t *this_node)
{
	gboolean online = FALSE;
	const char *join_state = crm_element_value(node_state, XML_CIB_ATTR_JOINSTATE);
	const char *crm_state  = crm_element_value(node_state, XML_CIB_ATTR_CRMDSTATE);
	const char *ccm_state  = crm_element_value(node_state, XML_CIB_ATTR_INCCM);
	const char *ha_state   = crm_element_value(node_state, XML_CIB_ATTR_HASTATE);
	const char *exp_state  = crm_element_value(node_state, XML_CIB_ATTR_EXPSTATE);

	if(ha_state == NULL) {
		ha_state = DEADSTATUS;
	}

	if(crm_is_true(ccm_state)
	   && safe_str_eq(ha_state, ACTIVESTATUS)
	   && safe_str_eq(crm_state, ONLINESTATUS)) {
		online = TRUE;
		if(safe_str_neq(join_state, CRMD_JOINSTATE_MEMBER)) {
			crm_info("Node %s is not ready to run resources",
				 this_node->details->uname);
			this_node->details->standby = TRUE;
		}
		
	} else if(crm_is_true(ccm_state) == FALSE
 		  && safe_str_eq(ha_state, DEADSTATUS)
		  && safe_str_eq(crm_state, OFFLINESTATUS)
		  && this_node->details->expected_up == FALSE) {
		crm_debug("Node %s is down: join_state=%s, expected=%s",
			  this_node->details->uname,
			  crm_str(join_state), crm_str(exp_state));
		
	} else if(this_node->details->expected_up) {
		/* mark it unclean */
		this_node->details->unclean = TRUE;
		
		crm_warn("Node %s (%s) is un-expectedly down",
			 this_node->details->uname, this_node->details->id);
		crm_info("\tha_state=%s, ccm_state=%s,"
			 " crm_state=%s, join_state=%s, expected=%s",
			 crm_str(ha_state), crm_str(ccm_state),
			 crm_str(crm_state), crm_str(join_state),
			 crm_str(exp_state));

	} else {
		crm_info("Node %s is comming up", this_node->details->uname);
		crm_debug("\tha_state=%s, ccm_state=%s,"
			  " crm_state=%s, join_state=%s, expected=%s",
			  crm_str(ha_state), crm_str(ccm_state),
			  crm_str(crm_state), crm_str(join_state),
			  crm_str(exp_state));

	}
	return online;
}

gboolean
determine_online_status(
	xmlNode * node_state, node_t *this_node, pe_working_set_t *data_set)
{
	gboolean online = FALSE;
	const char *shutdown  = crm_element_value(node_state, XML_CIB_ATTR_SHUTDOWN);
	const char *exp_state = crm_element_value(node_state, XML_CIB_ATTR_EXPSTATE);
	
	if(this_node == NULL) {
		crm_config_err("No node to check");
		return online;
	}

	shutdown = crm_element_value(node_state, XML_CIB_ATTR_SHUTDOWN);
	
	this_node->details->expected_up = FALSE;
	if(safe_str_eq(exp_state, CRMD_JOINSTATE_MEMBER)) {
		this_node->details->expected_up = TRUE;
	}

	this_node->details->shutdown = FALSE;
	if(shutdown != NULL && safe_str_neq("0", shutdown)) {
		this_node->details->shutdown = TRUE;
		this_node->details->expected_up = FALSE;
	}

	if(data_set->stonith_enabled == FALSE) {
		online = determine_online_status_no_fencing(
			node_state, this_node);
		
	} else {
		online = determine_online_status_fencing(
			node_state, this_node);
	}
	
	if(online) {
		this_node->details->online = TRUE;

	} else {
		/* remove node from contention */
		this_node->fixed = TRUE;
		this_node->weight = -INFINITY;
	}

	if(online && this_node->details->shutdown) {
		/* dont run resources here */
		this_node->fixed = TRUE;
		this_node->weight = -INFINITY;
	}	

	if(this_node->details->unclean) {
		pe_proc_warn("Node %s is unclean", this_node->details->uname);

	} else if(this_node->details->online) {
		crm_info("Node %s is %s", this_node->details->uname,
			 this_node->details->shutdown?"shutting down":
			 this_node->details->standby?"standby":"online");

	} else {
		crm_debug_2("Node %s is offline", this_node->details->uname);
	}
	
	

	return online;
}

#define set_char(x) last_rsc_id[lpc] = x; complete = TRUE;

static char *
increment_clone(char *last_rsc_id)
{
	int lpc = 0;
	int len = 0;
	char *tmp = NULL;
	gboolean complete = FALSE;

	CRM_CHECK(last_rsc_id != NULL, return NULL);
	if(last_rsc_id != NULL) {
		len = strlen(last_rsc_id);
	}
	
	lpc = len-1;
	while(complete == FALSE && lpc > 0) {
		switch (last_rsc_id[lpc]) {
			case 0:
				lpc--;
				break;
			case '0':
				set_char('1');
				break;
			case '1':
				set_char('2');
				break;
			case '2':
				set_char('3');
				break;
			case '3':
				set_char('4');
				break;
			case '4':
				set_char('5');
				break;
			case '5':
				set_char('6');
				break;
			case '6':
				set_char('7');
				break;
			case '7':
				set_char('8');
				break;
			case '8':
				set_char('9');
				break;
			case '9':
				last_rsc_id[lpc] = '0';
				lpc--;
				break;
			case ':':
				tmp = last_rsc_id;
				crm_malloc0(last_rsc_id, len + 2);
				memcpy(last_rsc_id, tmp, len);
				last_rsc_id[++lpc] = '1';
				last_rsc_id[len] = '0';
				last_rsc_id[len+1] = 0;
				complete = TRUE;
				crm_free(tmp);
				break;
			default:
				crm_err("Unexpected char: %c (%d)",
					last_rsc_id[lpc], lpc);
				break;
		}
	}
	return last_rsc_id;
}

static resource_t *
create_fake_resource(const char *rsc_id, xmlNode *rsc_entry, pe_working_set_t *data_set) 
{
	resource_t *rsc = NULL;
	xmlNode *xml_rsc  = create_xml_node(NULL, XML_CIB_TAG_RESOURCE);
	copy_in_properties(xml_rsc, rsc_entry);
	crm_xml_add(xml_rsc, XML_ATTR_ID, rsc_id);
	crm_log_xml_info(xml_rsc, "Orphan resource");
	
	common_unpack(xml_rsc, &rsc, NULL, data_set);
	set_bit(rsc->flags, pe_rsc_orphan);
	
	data_set->resources = g_list_append(data_set->resources, rsc);
	return rsc;
}

static resource_t *
unpack_find_resource(
	pe_working_set_t *data_set, node_t *node, const char *rsc_id, xmlNode *rsc_entry)
{
	resource_t *rsc = NULL;
	gboolean is_duped_clone = FALSE;
	char *alt_rsc_id = crm_strdup(rsc_id);
	
	while(rsc == NULL) {
		crm_debug_3("looking for: %s", alt_rsc_id);
		rsc = pe_find_resource(data_set->resources, alt_rsc_id);
		/* no match */
		if(rsc == NULL) {
			crm_debug_2("%s not found: %d", alt_rsc_id, is_duped_clone);
			if(is_duped_clone) {
				/* create one */
				rsc = create_fake_resource(alt_rsc_id, rsc_entry, data_set);
				crm_info("Making sure orphan %s/%s is stopped on %s",
					 rsc_id, rsc->id, node->details->uname);
				resource_location(rsc, NULL, -INFINITY, "__orphan_clone_dont_run__", data_set);
			}
			break;
			
			/* not running anywhere else */
		} else if(rsc->running_on == NULL) {
			crm_debug_3("not active yet");
			break;
			
			/* always unique */
		} else if(is_set(rsc->flags, pe_rsc_unique)) {
			crm_debug_3("unique");
			break;
			
			/* running somewhere already but we dont care
			 *   find another clone instead
			 */
		} else {
			crm_debug_3("find another one");
			rsc = NULL;
			is_duped_clone = TRUE;
			alt_rsc_id = increment_clone(alt_rsc_id);
		}
	}
	crm_free(alt_rsc_id);
	if(rsc != NULL) {
		crm_free(rsc->clone_name);
		rsc->clone_name = NULL;
		if(is_duped_clone) {
			crm_info("Internally renamed %s on %s to %s",
				 rsc_id, node->details->uname, rsc->id);
			rsc->clone_name = crm_strdup(rsc_id);
		}
	}
	
	
	return rsc;
}

static resource_t *
process_orphan_resource(xmlNode *rsc_entry, node_t *node, pe_working_set_t *data_set) 
{
	resource_t *rsc = NULL;
	const char *rsc_id   = crm_element_value(rsc_entry, XML_ATTR_ID);
	
	crm_log_xml_info(rsc_entry, "Orphan resource");
	crm_config_warn("Nothing known about resource %s running on %s",
		       rsc_id, node->details->uname);
	rsc = create_fake_resource(rsc_id, rsc_entry, data_set);
	
	if(data_set->stop_rsc_orphans == FALSE) {
	    clear_bit(rsc->flags, pe_rsc_managed);
		
	} else {
		crm_info("Making sure orphan %s is stopped", rsc_id);
		
		print_resource(LOG_DEBUG_3, "Added orphan", rsc, FALSE);
			
		CRM_CHECK(rsc != NULL, return NULL);
		resource_location(rsc, NULL, -INFINITY, "__orphan_dont_run__", data_set);
	}
	return rsc;
}

static void
process_rsc_state(resource_t *rsc, node_t *node,
		  enum action_fail_response on_fail,
		  xmlNode *migrate_op,
		  pe_working_set_t *data_set) 
{
	if(on_fail == action_migrate_failure) {
		node_t *from = NULL;
		const char *uuid = NULL;
		uuid = crm_element_value(migrate_op, CRMD_ACTION_MIGRATED);
		from = pe_find_node_id(data_set->nodes, uuid);
		process_rsc_state(rsc, from, action_fail_recover,NULL,data_set);
		on_fail = action_fail_recover;
	}
	
	crm_debug_2("Resource %s is %s on %s",
		    rsc->id, role2text(rsc->role),
		    node->details->uname);

	/* process current state */
	if(rsc->role != RSC_ROLE_UNKNOWN) { 
		rsc->known_on = g_list_append(rsc->known_on, node);
	}

	if(rsc->role != RSC_ROLE_STOPPED
		&& rsc->role != RSC_ROLE_UNKNOWN) { 
		if(on_fail != action_fail_ignore) {
		    set_bit(rsc->flags, pe_rsc_failed);
		    crm_debug_2("Force stop");
		}

		native_add_running(rsc, node, data_set);

		if(is_set(rsc->flags, pe_rsc_managed) && rsc->stickiness != 0) {
			resource_location(rsc, node, rsc->stickiness,
					  "stickiness", data_set);
			crm_debug_2("Resource %s: preferring current location"
				    " (node=%s, weight=%d)", rsc->id,
				    node->details->uname, rsc->stickiness);
		}
	
		if(on_fail == action_fail_ignore) {
			/* nothing to do */
		} else if(node->details->unclean) {
			stop_action(rsc, node, FALSE);

		} else if(on_fail == action_fail_fence) {
			/* treat it as if it is still running
			 * but also mark the node as unclean
			 */
			node->details->unclean = TRUE;
			stop_action(rsc, node, FALSE);
				
		} else if(on_fail == action_fail_block) {
			/* is_managed == FALSE will prevent any
			 * actions being sent for the resource
			 */
		    clear_bit(rsc->flags, pe_rsc_managed);
				
		} else if(on_fail == action_fail_migrate) {
			stop_action(rsc, node, FALSE);

			/* make sure it comes up somewhere else
			 * or not at all
			 */
			resource_location(rsc, node, -INFINITY,
					  "__action_migration_auto__",data_set);

		} else {
			stop_action(rsc, node, FALSE);
		}
			
	} else if(rsc->clone_name) {
		crm_debug_2("Resetting clone_name %s for %s (stopped)",
			    rsc->clone_name, rsc->id);
		crm_free(rsc->clone_name);
		rsc->clone_name = NULL;

	} else {
		char *key = stop_key(rsc);
		GListPtr possible_matches = find_actions(rsc->actions, key, node);
		slist_iter(stop, action_t, possible_matches, lpc,
			   stop->optional = TRUE;
			);
		crm_free(key);
	}
}

/* create active recurring operations as optional */ 
static void
process_recurring(node_t *node, resource_t *rsc,
		  int start_index, int stop_index,
		  GListPtr sorted_op_list, pe_working_set_t *data_set)
{
	const char *task = NULL;
	const char *status = NULL;
	
	crm_debug_3("%s: Start index %d, stop index = %d",
		    rsc->id, start_index, stop_index);
	slist_iter(rsc_op, xmlNode, sorted_op_list, lpc,
		   int interval = 0;
		   char *key = NULL;
		   const char *id = ID(rsc_op);
		   const char *interval_s = NULL;
		   if(node->details->online == FALSE) {
			   crm_debug_4("Skipping %s/%s: node is offline",
				       rsc->id, node->details->uname);
			   break;
			   
		   } else if(start_index < stop_index) {
			   crm_debug_4("Skipping %s/%s: not active",
				       rsc->id, node->details->uname);
			   break;
			   
		   } else if(lpc <= start_index) {
			   crm_debug_4("Skipping %s/%s: old",
				       id, node->details->uname);
			   continue;
		   }
		   	
		   interval_s = crm_element_value(rsc_op,XML_LRM_ATTR_INTERVAL);
		   interval = crm_parse_int(interval_s, "0");
		   if(interval == 0) {
			   crm_debug_4("Skipping %s/%s: non-recurring",
				       id, node->details->uname);
			   continue;
		   }
		   
		   status = crm_element_value(rsc_op, XML_LRM_ATTR_OPSTATUS);
		   if(safe_str_eq(status, "-1")) {
			   crm_debug_4("Skipping %s/%s: status",
				       id, node->details->uname);
			   continue;
		   }
		   task = crm_element_value(rsc_op, XML_LRM_ATTR_TASK);
		   /* create the action */
		   key = generate_op_key(rsc->id, task, interval);
		   crm_debug_3("Creating %s/%s", key, node->details->uname);
		   custom_action(rsc, key, task, node, TRUE, TRUE, data_set);
		);
}

void
calculate_active_ops(GListPtr sorted_op_list, int *start_index, int *stop_index) 
{
	const char *task = NULL;
	const char *status = NULL;

	*stop_index = -1;
	*start_index = -1;
	
	slist_iter(
		rsc_op, xmlNode, sorted_op_list, lpc,

		task = crm_element_value(rsc_op, XML_LRM_ATTR_TASK);
		status = crm_element_value(rsc_op, XML_LRM_ATTR_OPSTATUS);

		if(safe_str_eq(task, CRMD_ACTION_STOP)
		   && safe_str_eq(status, "0")) {
			*stop_index = lpc;
			
		} else if(safe_str_eq(task, CRMD_ACTION_START)) {
			*start_index = lpc;
			
		} else if(*start_index <= *stop_index
			  && safe_str_eq(task, CRMD_ACTION_STATUS)) {
			const char *rc = crm_element_value(rsc_op, XML_LRM_ATTR_RC);
			if(safe_str_eq(rc, "0") || safe_str_eq(rc, "8")) {
				*start_index = lpc;
			}
		}
		);
}

static void
unpack_lrm_rsc_state(
	node_t *node, xmlNode * rsc_entry, pe_working_set_t *data_set)
{	
	int stop_index = -1;
	int start_index = -1;
	int max_call_id = -1;

	const char *task = NULL;
	const char *value = NULL;
	const char *rsc_id  = crm_element_value(rsc_entry, XML_ATTR_ID);

	resource_t *rsc = NULL;
	GListPtr op_list = NULL;
	GListPtr sorted_op_list = NULL;

	xmlNode *migrate_op = NULL;
	
	enum action_fail_response on_fail = FALSE;
	enum rsc_role_e saved_role = RSC_ROLE_UNKNOWN;
	
	crm_debug_3("[%s] Processing %s on %s",
		    crm_element_name(rsc_entry), rsc_id, node->details->uname);

	/* extract operations */
	op_list = NULL;
	sorted_op_list = NULL;
		
	xml_child_iter_filter(
		rsc_entry, rsc_op, XML_LRM_TAG_RSC_OP,
		op_list = g_list_append(op_list, rsc_op);
		);

	if(op_list == NULL) {
		/* if there are no operations, there is nothing to do */
		return;
	}

	/* find the resource */
	rsc = unpack_find_resource(data_set, node, rsc_id, rsc_entry);
	if(rsc == NULL) {
		rsc = process_orphan_resource(rsc_entry, node, data_set);
	} 
	CRM_ASSERT(rsc != NULL);
	
	/* process operations */
	max_call_id = -1;

	saved_role = rsc->role;
	on_fail = action_fail_ignore;
	rsc->role = RSC_ROLE_UNKNOWN;
	sorted_op_list = g_list_sort(op_list, sort_op_by_callid);
	
	slist_iter(
		rsc_op, xmlNode, sorted_op_list, lpc,

		task = crm_element_value(rsc_op, XML_LRM_ATTR_TASK);
		if(safe_str_eq(task, CRMD_ACTION_MIGRATED)) {
			migrate_op = rsc_op;
		}
		
		unpack_rsc_op(rsc, node, rsc_op,
			      &max_call_id, &on_fail, data_set);
		);

	/* create active recurring operations as optional */ 
	calculate_active_ops(sorted_op_list, &start_index, &stop_index);
	process_recurring(node, rsc, start_index, stop_index,
			  sorted_op_list, data_set);
	
	/* no need to free the contents */
	g_list_free(sorted_op_list);
	
	process_rsc_state(rsc, node, on_fail, migrate_op, data_set);

	value = g_hash_table_lookup(rsc->meta, XML_RSC_ATTR_TARGET_ROLE);
	if(value != NULL && safe_str_neq("default", value)) {
		enum rsc_role_e req_role = text2role(value);
		if(req_role != RSC_ROLE_UNKNOWN && req_role != rsc->next_role){
			if(rsc->next_role != RSC_ROLE_UNKNOWN) {
				crm_debug("%s: Overwriting calculated next role %s"
					  " with requested next role %s",
					  rsc->id, role2text(rsc->next_role),
					  role2text(req_role));
			}
			rsc->next_role = req_role;
		}
	}
		
	if(saved_role > rsc->role) {
		rsc->role = saved_role;
	}
}

gboolean
unpack_lrm_resources(node_t *node, xmlNode * lrm_rsc_list, pe_working_set_t *data_set)
{
	CRM_CHECK(node != NULL, return FALSE);

	crm_debug_3("Unpacking resources on %s", node->details->uname);

	slist_iter(
	    rsc, resource_t, data_set->resources, lpc,
	    common_apply_stickiness(rsc, node, data_set);
	    );
	
	xml_child_iter_filter(
		lrm_rsc_list, rsc_entry, XML_LRM_TAG_RESOURCE,
		unpack_lrm_rsc_state(node, rsc_entry, data_set);
		);
	
	return TRUE;
}



gboolean
unpack_rsc_op(resource_t *rsc, node_t *node, xmlNode *xml_op,
	      int *max_call_id, enum action_fail_response *on_fail,
	      pe_working_set_t *data_set) 
{    
	const char *id          = NULL;
	const char *task        = NULL;
 	const char *task_id     = NULL;
 	const char *actual_rc   = NULL;
/* 	const char *target_rc   = NULL;	 */
	const char *task_status = NULL;
	const char *interval_s  = NULL;
	const char *op_digest   = NULL;
	const char *op_version  = NULL;

	int interval = 0;
	int task_id_i = -1;
	int task_status_i = -2;
	int actual_rc_i = 0;
	
	action_t *action = NULL;
	node_t *effective_node = NULL;

	gboolean is_probe = FALSE;
	gboolean is_stop_action = FALSE;

	
	CRM_CHECK(rsc    != NULL, return FALSE);
	CRM_CHECK(node   != NULL, return FALSE);
	CRM_CHECK(xml_op != NULL, return FALSE);

	id	    = ID(xml_op);
	task        = crm_element_value(xml_op, XML_LRM_ATTR_TASK);
 	task_id     = crm_element_value(xml_op, XML_LRM_ATTR_CALLID);
	task_status = crm_element_value(xml_op, XML_LRM_ATTR_OPSTATUS);
	op_digest   = crm_element_value(xml_op, XML_LRM_ATTR_OP_DIGEST);
	op_version  = crm_element_value(xml_op, XML_ATTR_CRM_VERSION);

	CRM_CHECK(id != NULL, return FALSE);
	CRM_CHECK(task != NULL, return FALSE);
	CRM_CHECK(task_status != NULL, return FALSE);

	task_status_i = crm_parse_int(task_status, NULL);

	CRM_CHECK(task_status_i <= LRM_OP_ERROR, return FALSE);
	CRM_CHECK(task_status_i >= LRM_OP_PENDING, return FALSE);

	if(safe_str_eq(task, CRMD_ACTION_NOTIFY)) {
		/* safe to ignore these */
		return TRUE;
	}

	crm_debug_2("Unpacking task %s/%s (call_id=%s, status=%s) on %s (role=%s)",
		    id, task, task_id, task_status, node->details->uname,
		    role2text(rsc->role));

	interval_s = crm_element_value(xml_op, XML_LRM_ATTR_INTERVAL);
	interval = crm_parse_int(interval_s, "0");
	
	if(interval == 0 && safe_str_eq(task, CRMD_ACTION_STATUS)) {
		is_probe = TRUE;
	}
	
	if(safe_str_eq(task, CRMD_ACTION_STOP)) {
		is_stop_action = TRUE;
	}
	
	if(task_status_i != LRM_OP_PENDING) {
		task_id_i = crm_parse_int(task_id, "-1");

		CRM_CHECK(task_id != NULL, return FALSE);
		CRM_CHECK(task_id_i >= 0, return FALSE);
		CRM_CHECK(task_id_i > *max_call_id, return FALSE);
	}

	if(*max_call_id < task_id_i) {
		*max_call_id = task_id_i;
	}
	
	if(node->details->unclean) {
		crm_debug_2("Node %s (where %s is running) is unclean."
			  " Further action depends on the value of %s",
			  node->details->uname, rsc->id, XML_RSC_ATTR_STOPFAIL);
	}

	actual_rc = crm_element_value(xml_op, XML_LRM_ATTR_RC);
	CRM_CHECK(actual_rc != NULL, return FALSE);	
	actual_rc_i = crm_parse_int(actual_rc, NULL);

	if(task_status_i == LRM_OP_NOTSUPPORTED) {
	    actual_rc_i = EXECRA_UNIMPLEMENT_FEATURE;
	}
	
	switch(actual_rc_i) {
	    case EXECRA_NOT_RUNNING:
		if(is_probe) {
			/* treat these like stops */
			is_stop_action = TRUE;
		}
		if(is_stop_action) {
			task_status_i = LRM_OP_DONE;
 		} else {
			task_status_i = LRM_OP_ERROR;
		}
		break;
		
	    case EXECRA_RUNNING_MASTER:
		if(is_probe
		   || (rsc->role == RSC_ROLE_MASTER
		       && safe_str_eq(task, CRMD_ACTION_STATUS))) {
			task_status_i = LRM_OP_DONE;

		} else {
			task_status_i = LRM_OP_ERROR;
			if(rsc->role != RSC_ROLE_MASTER) {
			    /* this wil happen normally if the PE is invoked after
			     * a resource is demoted and re-promoted but before the
			     * 'master' monitor has been re-initiated
			     *
			     * The monitor will occur before the promote and appear
			     * to be an error (the error status is be cleared by a
			     * successful demote)
			     */
			    crm_warn("%s reported %s in master mode on %s",
					id, rsc->id,
					node->details->uname);
			}
		}
		rsc->role = RSC_ROLE_MASTER;
		break;
		
	    case EXECRA_FAILED_MASTER:
		rsc->role = RSC_ROLE_MASTER;
		task_status_i = LRM_OP_ERROR;
		break;

	    case EXECRA_UNIMPLEMENT_FEATURE:
		if(interval > 0) {
		    task_status_i = LRM_OP_ERROR;
		    break;
		}
		/* else: fall through */
	    case EXECRA_INSUFFICIENT_PRIV:
	    case EXECRA_NOT_INSTALLED:
		effective_node = node;
		/* fall through */
	    case EXECRA_NOT_CONFIGURED:
	    case EXECRA_INVALID_PARAM:
		crm_err("Hard error: %s failed with rc=%d.", id, actual_rc_i);
		if(effective_node) {
		    crm_err("  Preventing %s from re-starting on %s",
			    rsc->id, effective_node->details->uname);
		} else {
		    crm_err("  Preventing %s from re-starting anywhere in the cluster",
			    rsc->id);
		}

		resource_location(rsc, effective_node, -INFINITY, "hard-error", data_set);
		if(is_probe) {
			/* treat these like stops */
			is_stop_action = TRUE;
			task_status_i = LRM_OP_DONE;
			actual_rc_i = EXECRA_NOT_RUNNING;
			
 		} else {
			task_status_i = LRM_OP_ERROR;
		}
		break;

	    case EXECRA_OK:
		if(interval > 0 && rsc->role == RSC_ROLE_MASTER) {
		    /* catch status ops that return 0 instead of 8 while they
		     *   are supposed to be in master mode
		     */
		    task_status_i = LRM_OP_ERROR;
		}
		break;
		
	    default:
		if(task_status_i == LRM_OP_DONE) {
		    crm_info("Remapping %s (rc=%d) on %s to an ERROR",
			     id, actual_rc_i, node->details->uname);
		    task_status_i = LRM_OP_ERROR;
		}
	}
	
	if(task_status_i == LRM_OP_ERROR
	   || task_status_i == LRM_OP_TIMEOUT
	   || task_status_i == LRM_OP_NOTSUPPORTED) {
		action = custom_action(rsc, crm_strdup(id), task, NULL,
				       TRUE, FALSE, data_set);
		if(action->on_fail == action_fail_ignore) {
		    crm_warn("Remapping %s (rc=%d) on %s to DONE",
			     id, actual_rc_i, node->details->uname);
			task_status_i = LRM_OP_DONE;
		}
	}
	
	switch(task_status_i) {
		case LRM_OP_PENDING:
			if(safe_str_eq(task, CRMD_ACTION_START)) {
				set_bit(rsc->flags, pe_rsc_start_pending);
				rsc->role = RSC_ROLE_STARTED;
				
			} else if(safe_str_eq(task, CRMD_ACTION_PROMOTE)) {
				rsc->role = RSC_ROLE_MASTER;
			}
			break;
		
		case LRM_OP_DONE:
			crm_debug_3("%s/%s completed on %s",
				    rsc->id, task, node->details->uname);

			if(is_stop_action) {
				rsc->role = RSC_ROLE_STOPPED;

				/* clear any previous failure actions */
				*on_fail = action_fail_ignore;
				rsc->next_role = RSC_ROLE_UNKNOWN;
				
			} else if(safe_str_eq(task, CRMD_ACTION_PROMOTE)) {
				rsc->role = RSC_ROLE_MASTER;

			} else if(safe_str_eq(task, CRMD_ACTION_DEMOTE)) {
				rsc->role = RSC_ROLE_SLAVE;
				
			} else if(rsc->role < RSC_ROLE_STARTED) {
				crm_debug_3("%s active on %s",
					    rsc->id, node->details->uname);
				rsc->role = RSC_ROLE_STARTED;
			}
			break;

		case LRM_OP_ERROR:
		case LRM_OP_TIMEOUT:
		case LRM_OP_NOTSUPPORTED:
			crm_warn("Processing failed op %s on %s: %s",
				 id, node->details->uname,
				 op_status2text(task_status_i));
			crm_xml_add(xml_op, XML_ATTR_UNAME, node->details->uname);
			add_node_copy(data_set->failed, xml_op);

			if(*on_fail < action->on_fail) {
				*on_fail = action->on_fail;
			}

			if(is_stop_action) {
			    resource_location(
				rsc, node, -INFINITY, "__stop_fail__", data_set);
			    
			} else if((data_set->start_failure_fatal
				   || compare_version("2.0", op_version) > 0)
				  && safe_str_eq(task, CRMD_ACTION_START)) {
			    crm_warn("Compatability handling for failed op %s on %s",
				     id, node->details->uname);
			    resource_location(
				rsc, node, -INFINITY, "__legacy_start__", data_set);
			}

			if(safe_str_eq(task, CRMD_ACTION_PROMOTE)) {
				rsc->role = RSC_ROLE_MASTER;

			} else if(safe_str_eq(task, CRMD_ACTION_DEMOTE)) {
			    /*
			     * staying in role=master ends up putting the PE/TE into a loop
			     * setting role=slave is not dangerous because no master will be
			     * promoted until the failed resource has been fully stopped
			     */
			    crm_warn("Forcing %s to stop after a failed demote action", rsc->id);
			    rsc->next_role = RSC_ROLE_STOPPED;
			    rsc->role = RSC_ROLE_SLAVE;
				
			} else if(rsc->role < RSC_ROLE_STARTED) {
				rsc->role = RSC_ROLE_STARTED;
			}

			crm_debug_2("Resource %s: role=%s, unclean=%s, on_fail=%s, fail_role=%s",
				    rsc->id, role2text(rsc->role),
				    node->details->unclean?"true":"false",
				    fail2text(action->on_fail),
				    role2text(action->fail_role));

			if(action->fail_role != RSC_ROLE_STARTED
			   && rsc->next_role < action->fail_role) {
				rsc->next_role = action->fail_role;
			}

			if(action->fail_role == RSC_ROLE_STOPPED) {
				crm_err("Making sure %s doesn't come up again", rsc->id);
				/* make sure it doesnt come up again */
				pe_free_shallow_adv(rsc->allowed_nodes, TRUE);
				rsc->allowed_nodes = node_list_dup(
					data_set->nodes, FALSE, FALSE);
				slist_iter(
					node, node_t, rsc->allowed_nodes, lpc,
					node->weight = -INFINITY;
					);
			}
			
			pe_free_action(action);
			action = NULL;
			break;
		case LRM_OP_CANCELLED:
			/* do nothing?? */
			pe_err("Dont know what to do for cancelled ops yet");
			break;
	}

	crm_debug_3("Resource %s after %s: role=%s",
		    rsc->id, task, role2text(rsc->role));

	pe_free_action(action);
	
	return TRUE;
}

gboolean
add_node_attrs(xmlNode *xml_obj, node_t *node, pe_working_set_t *data_set)
{
 	g_hash_table_insert(node->details->attrs,
			    crm_strdup("#"XML_ATTR_UNAME),
			    crm_strdup(node->details->uname));
 	g_hash_table_insert(node->details->attrs,
			    crm_strdup("#"XML_ATTR_ID),
			    crm_strdup(node->details->id));
	if(safe_str_eq(node->details->id, data_set->dc_uuid)) {
		data_set->dc_node = node;
		node->details->is_dc = TRUE;
		g_hash_table_insert(node->details->attrs,
				    crm_strdup("#"XML_ATTR_DC),
				    crm_strdup(XML_BOOLEAN_TRUE));
	} else {
		g_hash_table_insert(node->details->attrs,
				    crm_strdup("#"XML_ATTR_DC),
				    crm_strdup(XML_BOOLEAN_FALSE));
	}
	
	unpack_instance_attributes(
		xml_obj, XML_TAG_ATTR_SETS, NULL,
		node->details->attrs, NULL, data_set->now);

	return TRUE;
}

static GListPtr
extract_operations(const char *node, const char *rsc, xmlNode *rsc_entry, gboolean active_filter)
{	
    int stop_index = -1;
    int start_index = -1;
    
    GListPtr op_list = NULL;
    GListPtr sorted_op_list = NULL;

    /* extract operations */
    op_list = NULL;
    sorted_op_list = NULL;
    
    xml_child_iter_filter(
	rsc_entry, rsc_op, XML_LRM_TAG_RSC_OP,
	crm_xml_add(rsc_op, "resource", rsc);
	crm_xml_add(rsc_op, XML_ATTR_UNAME, node);
	op_list = g_list_append(op_list, rsc_op);
	);
    
    if(op_list == NULL) {
	/* if there are no operations, there is nothing to do */
	return NULL;
    }
    
    sorted_op_list = g_list_sort(op_list, sort_op_by_callid);
    
    /* create active recurring operations as optional */ 
    if(active_filter == FALSE) {
	return sorted_op_list;
    }
    
    op_list = NULL;
    
    calculate_active_ops(sorted_op_list, &start_index, &stop_index);	
    slist_iter(rsc_op, xmlNode, sorted_op_list, lpc,
	       if(start_index < stop_index) {
		   crm_debug_4("Skipping %s: not active", ID(rsc_entry));
		   break;
		   
	       } else if(lpc < start_index) {
		   crm_debug_4("Skipping %s: old", ID(rsc_op));
		   continue;
	       }
	       op_list = g_list_append(op_list, rsc_op);
	);
    
    g_list_free(sorted_op_list);
    return op_list;
}

GListPtr find_operations(
    const char *rsc, const char *node, gboolean active_filter, pe_working_set_t *data_set) 
{
    GListPtr output = NULL;
    GListPtr intermediate = NULL;

    xmlNode *tmp = NULL;
    xmlNode *status = find_xml_node(data_set->input, XML_CIB_TAG_STATUS, TRUE);

    const char *uname = NULL;
    node_t *this_node = NULL;
    
    xml_child_iter_filter(
	status, node_state, XML_CIB_TAG_STATE,
	
	uname = crm_element_value(node_state, XML_ATTR_UNAME);
	if(node != NULL && safe_str_neq(uname, node)) {
	    continue;
	}

	this_node = pe_find_node(data_set->nodes, uname);
	CRM_CHECK(this_node != NULL, continue);
	
	determine_online_status(node_state, this_node, data_set);
	
	if(this_node->details->online || data_set->stonith_enabled) {
	    /* offline nodes run no resources...
	     * unless stonith is enabled in which case we need to
	     *   make sure rsc start events happen after the stonith
	     */
	    tmp = find_xml_node(node_state, XML_CIB_TAG_LRM, FALSE);
	    tmp = find_xml_node(tmp, XML_LRM_TAG_RESOURCES, FALSE);

	    xml_child_iter_filter(
		tmp, lrm_rsc, XML_LRM_TAG_RESOURCE,
		const char *rsc_id  = crm_element_value(lrm_rsc, XML_ATTR_ID);
		if(rsc != NULL && safe_str_neq(rsc_id, rsc)) {
		    continue;
		}

		intermediate = extract_operations(uname, rsc_id, lrm_rsc, active_filter);
		output = g_list_concat(output, intermediate);
		);
	}
	);

    return output;
}
