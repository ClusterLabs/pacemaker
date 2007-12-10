
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

#include <sys/param.h>

#include <crm/crm.h>

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>

#include <heartbeat.h>
#include <hb_api.h>
#include <clplumbing/uids.h>
#include <clplumbing/Gmain_timeout.h>

#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/ctrl.h>
#include <crm/common/ipc.h>

#include <crm/cib.h>
#include <crm/pengine/rules.h>
#include <crm/pengine/status.h>

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif
void usage(const char *cmd, int exit_status);

gboolean do_force = FALSE;
gboolean BE_QUIET = FALSE;
const char *attr_set_type = XML_TAG_ATTR_SETS;
char *host_id = NULL;
const char *rsc_id = NULL;
const char *host_uname = NULL;
const char *prop_name = NULL;
const char *prop_value = NULL;
const char *rsc_type = NULL;
const char *prop_id = NULL;
const char *prop_set = NULL;
char *migrate_lifetime = NULL;
char rsc_cmd = 'L';
char *our_pid = NULL;
IPC_Channel *crmd_channel = NULL;
char *xml_file = NULL;
int cib_options = cib_sync_call;

#define OPTARGS	"V?LRQxDCPp:WMUr:H:v:t:p:g:d:i:s:G:S:fX:lmu:F"
#define CMD_ERR(fmt, args...) do {		\
	crm_warn(fmt, ##args);			\
	fprintf(stderr, fmt, ##args);		\
    } while(0)

static int
do_find_resource(const char *rsc, pe_working_set_t *data_set)
{
	int found = 0;
	resource_t *the_rsc = pe_find_resource(data_set->resources, rsc);

	if(the_rsc == NULL) {
		return cib_NOTEXISTS;
	}

	slist_iter(node, node_t, the_rsc->running_on, lpc,
		   crm_debug_3("resource %s is running on: %s",
			       rsc, node->details->uname);
		   if(BE_QUIET) {
			   fprintf(stdout, "%s\n", node->details->uname);
		   } else {
			   fprintf(stdout, "resource %s is running on: %s\n",
				   rsc, node->details->uname);
		   }
		   
		   found++;
		);
	
	if(BE_QUIET == FALSE && found == 0) {
		fprintf(stderr, "resource %s is NOT running\n", rsc);
	}
	
	return 0;
}

static void
print_raw_rsc(resource_t *rsc, int level) 
{
	int lpc = 0;
	GListPtr children = NULL;
	for(; lpc < level; lpc++) {
		printf("  ");
	}
	printf(" * %s\n", rsc->id);
	children = rsc->fns->children(rsc);
	slist_iter(child, resource_t, children, lpc,
		   print_raw_rsc(child, level+1);
		);
}


static int
do_find_resource_list(pe_working_set_t *data_set, gboolean raw)
{
	int found = 0;
	
	slist_iter(
		rsc, resource_t, data_set->resources, lpc,
		if(raw) {
			found++;
			print_raw_rsc(rsc, 0);
			continue;
			
		} else if(is_set(rsc->flags, pe_rsc_orphan)
			  && rsc->fns->active(rsc, TRUE) == FALSE) {
			continue;
		}
		rsc->fns->print(
			rsc, NULL, pe_print_printf|pe_print_rsconly, stdout);
		found++;
		);

	if(found == 0) {
		printf("NO resources configured\n");
		return cib_NOTEXISTS;
	}

	return 0;
}

static int
dump_resource(const char *rsc, pe_working_set_t *data_set)
{
	char *rsc_xml = NULL;
	resource_t *the_rsc = pe_find_resource(data_set->resources, rsc);

	if(the_rsc == NULL) {
		return cib_NOTEXISTS;
	}
	the_rsc->fns->print(the_rsc, NULL, pe_print_printf, stdout);

	rsc_xml = dump_xml_formatted(the_rsc->xml);

	fprintf(stdout, "raw xml:\n%s", rsc_xml);
	
	crm_free(rsc_xml);
	
	return 0;
}

static int
dump_resource_attr(
	const char *rsc, const char *attr, pe_working_set_t *data_set)
{
	node_t *current = NULL;
	resource_t *the_rsc = pe_find_resource(data_set->resources, rsc);
	const char *value = NULL;

	if(the_rsc == NULL) {
		return cib_NOTEXISTS;
	}

	if(g_list_length(the_rsc->running_on) == 1) {
		current = the_rsc->running_on->data;

	} else if(g_list_length(the_rsc->running_on) > 1) {
		CMD_ERR("%s is active on more than one node,"
			" returning the default value for %s\n",
			the_rsc->id, crm_str(value));
	} 
	
	unpack_instance_attributes(
		the_rsc->xml, attr_set_type, current?current->details->attrs:NULL,
		the_rsc->parameters, NULL, data_set->now);

	if(the_rsc->parameters != NULL) {
		crm_debug("Looking up %s in %s", attr, the_rsc->id);
		value = g_hash_table_lookup(the_rsc->parameters, attr);
	}
	if(value != NULL) {
		fprintf(stdout, "%s\n", value);
		return 0;
	}
	return cib_NOTEXISTS;
}

static int
set_resource_attr(const char *rsc_id, const char *attr_set, const char *attr_id,
		  const char *attr_name, const char *attr_value,
		  cib_t *cib, pe_working_set_t *data_set)
{
	int rc = cib_ok;
	int matches = 0;
	
	char *local_attr_id = NULL;
	char *local_attr_set = NULL;
	
	crm_data_t *xml_top = NULL;
	crm_data_t *xml_obj = NULL;
	crm_data_t *nv_children = NULL;
	crm_data_t *set_children = NULL;

	resource_t *rsc = pe_find_resource(data_set->resources, rsc_id);

	if(rsc == NULL) {
		return cib_NOTEXISTS;
	}

	/* filter by set and type */
	matches = find_xml_children(
		&set_children, rsc->xml, 
		attr_set_type, XML_ATTR_ID, attr_set, FALSE);
	crm_log_xml_debug(set_children, "search by set:");

	crm_debug("%d objects matching tag=%s id=%s",
		  matches, attr_set_type, attr_set?attr_set:"<any>");
	
	if(matches == 0) {
		/* nothing more to search */
		crm_debug("No objects matching tag=%s id=%s",
			  attr_set_type, attr_set?attr_set:"<any>");
		
	} else if(attr_id == NULL) {
		matches = find_xml_children(
			&nv_children, set_children,
			XML_CIB_TAG_NVPAIR, XML_NVPAIR_ATTR_NAME, attr_name, FALSE);
		crm_log_xml_debug(nv_children, "search by name:");

	} else {
		matches = find_xml_children(
			&nv_children, set_children,
			XML_CIB_TAG_NVPAIR, XML_ATTR_ID, attr_id, FALSE);
		crm_log_xml_debug(nv_children, "search by id:");
	}
	
	
	if(matches > 1) {
		CMD_ERR("Multiple attributes match name=%s for the resource %s:\n",
			attr_name, rsc->id);

		if(set_children == NULL) {
			free_xml(set_children);
			set_children = NULL;
			find_xml_children(
				&set_children, rsc->xml, 
				attr_set_type, NULL, NULL, FALSE);
			xml_child_iter(
				set_children, set,
				free_xml(nv_children);
				nv_children = NULL;
				find_xml_children(
					&nv_children, set,
					XML_CIB_TAG_NVPAIR, XML_NVPAIR_ATTR_NAME, attr_name, FALSE);
				xml_child_iter(
					nv_children, child,
					fprintf(stderr,"  Set: %s,\tValue: %s,\tID: %s\n",
						ID(set),
						crm_element_value(child, XML_NVPAIR_ATTR_VALUE),
						ID(child));
					);
				);
			
		} else {
			xml_child_iter(
				nv_children, child,
				fprintf(stderr,"  ID: %s, Value: %s\n", ID(child),
					crm_element_value(child, XML_NVPAIR_ATTR_VALUE));
				);
		}
		
		if(BE_QUIET == FALSE) {
			CMD_ERR("\nThe following text can be suppressed with the -Q option:\n");
			if(attr_set == NULL) {
				CMD_ERR("  * To choose an existing entry to change, please supply one of the set names above using the -s option.\n");
			} else {
				CMD_ERR("  * To choose an existing entry to change, please supply one of the IDs above using the -i option.\n");			
			}
			CMD_ERR("  * To create a new value with a default ID, please supply a different set name using the -s option.\n");
			
			CMD_ERR("You can also use --query-xml to display the complete resource definition.\n");
		}
		
		return cib_unknown;
		
	} else if(matches == 0) {
		if(attr_set == NULL) {
			if(safe_str_eq(attr_set_type, XML_TAG_META_SETS)) {
				local_attr_set = crm_concat(rsc->id, "meta-options", '-');
			} else {
				local_attr_set = crm_strdup(rsc->id);
			}
			attr_set = local_attr_set;
		}
		if(attr_id == NULL) {
			local_attr_id = crm_concat(attr_set, attr_name, '-');
			attr_id = local_attr_id;
		}
		
		xml_top = create_xml_node(NULL, crm_element_name(rsc->xml));
		crm_xml_add(xml_top, XML_ATTR_ID, rsc->id);
		
		xml_obj = create_xml_node(xml_top, attr_set_type);
		crm_xml_add(xml_obj, XML_ATTR_ID, attr_set);
		
		xml_obj = create_xml_node(xml_obj, XML_TAG_ATTRS);
		xml_obj = create_xml_node(xml_obj, XML_CIB_TAG_NVPAIR);

	} else {
		if(attr_id == NULL) {
			/* extract it */
			xml_child_iter(nv_children, child, attr_id = ID(child));
		}
		xml_obj = create_xml_node(NULL, XML_CIB_TAG_NVPAIR);
		xml_top = xml_obj;
	}
		
	crm_xml_add(xml_obj, XML_ATTR_ID, attr_id);
	crm_xml_add(xml_obj, XML_NVPAIR_ATTR_NAME, attr_name);
	crm_xml_add(xml_obj, XML_NVPAIR_ATTR_VALUE, attr_value);
	
	crm_log_xml_debug(xml_top, "Update");
	
	rc = cib->cmds->modify(cib, XML_CIB_TAG_RESOURCES, xml_top, NULL,
			       cib_options);

	free_xml(xml_top);
	crm_free(local_attr_id);
	crm_free(local_attr_set);
	return rc;
}

static int
delete_resource_attr(
	const char *rsc_id, const char *attr_set, const char *attr_id,
	const char *attr_name, cib_t *cib, pe_working_set_t *data_set)
{
	crm_data_t *xml_obj = NULL;
	crm_data_t *xml_match = NULL;

	int rc = cib_ok;
	char *local_attr_id = NULL;
	resource_t *rsc = pe_find_resource(data_set->resources, rsc_id);

	if(rsc == NULL) {
		return cib_NOTEXISTS;
	}

 	rc = find_attr_details(
	    rsc->xml, NULL, attr_set, attr_id, attr_name, &xml_match, TRUE);

	if(rc == cib_NOTEXISTS) {
	    return cib_ok;
	}
	
	if(rc != cib_ok) {
	    return rc;
	}
	
	if(attr_id == NULL) {
		local_attr_id = crm_element_value_copy(xml_match, XML_ATTR_ID);
		attr_id = local_attr_id;
	}

	xml_obj = create_xml_node(NULL, XML_CIB_TAG_NVPAIR);
	crm_xml_add(xml_obj, XML_ATTR_ID, attr_id);
	crm_xml_add(xml_obj, XML_NVPAIR_ATTR_NAME, attr_name);
	
	crm_log_xml_debug(xml_obj, "Delete");
	
	rc = cib->cmds->delete(cib, XML_CIB_TAG_RESOURCES, xml_obj, NULL,
			       cib_options);

	free_xml(xml_obj);
	free_xml(xml_match);
	crm_free(local_attr_id);
	return rc;
}

static int
dump_resource_prop(
	const char *rsc, const char *attr, pe_working_set_t *data_set)
{
	const char *value = NULL;
	resource_t *the_rsc = pe_find_resource(data_set->resources, rsc);

	if(the_rsc == NULL) {
		return cib_NOTEXISTS;
	}

	value = crm_element_value(the_rsc->xml, attr);

	if(value != NULL) {
		fprintf(stdout, "%s\n", value);
		return 0;
	}
	return cib_NOTEXISTS;
}

static void
resource_ipc_connection_destroy(gpointer user_data)
{
	crm_info("Connection to CRMd was terminated");
	exit(1);
}

static gboolean
crmd_msg_callback(IPC_Channel * server, void *private_data)
{
	int lpc = 0;
	IPC_Message *msg = NULL;
	ha_msg_input_t *new_input = NULL;
	gboolean hack_return_good = TRUE;

	while (server->ch_status != IPC_DISCONNECT
	       && server->ops->is_message_pending(server) == TRUE) {
		if(new_input != NULL) {
			delete_ha_msg_input(new_input);
			new_input = NULL;
		}
		
		if (server->ops->recv(server, &msg) != IPC_OK) {
			perror("Receive failure:");
			return !hack_return_good;
		}

		if (msg == NULL) {
			crm_debug_4("No message this time");
			continue;
		}

		lpc++;
		new_input = new_ipc_msg_input(msg);
		crm_log_message(LOG_MSG, new_input->msg);
		msg->msg_done(msg);
		
		if (validate_crm_message(
			    new_input->msg, crm_system_name, our_pid,
			    XML_ATTR_RESPONSE) == FALSE) {
			crm_info("Message was not a CRM response. Discarding.");
		}
		delete_ha_msg_input(new_input);
		new_input = NULL;		
	}

	if (server->ch_status == IPC_DISCONNECT) {
		crm_debug_2("admin_msg_callback: received HUP");
		return !hack_return_good;
	}

	return hack_return_good;
}

static int
send_lrm_rsc_op(IPC_Channel *crmd_channel, const char *op,
		const char *host_uname, const char *rsc_id,
		gboolean only_failed, pe_working_set_t *data_set)
{
	char *key = NULL;
	int rc = cib_send_failed;
	HA_Message *cmd = NULL;
	crm_data_t *xml_rsc = NULL;
	const char *value = NULL;
	HA_Message *params = NULL;
	crm_data_t *msg_data = NULL;
	resource_t *rsc = pe_find_resource(data_set->resources, rsc_id);

	if(rsc == NULL) {
		CMD_ERR("Resource %s not found\n", rsc_id);
		return cib_NOTEXISTS;

	} else if(rsc->variant != pe_native) {
		CMD_ERR("We can only process primitive resources, not %s\n", rsc_id);
		return cib_invalid_argument;

	} else if(host_uname == NULL) {
		CMD_ERR("Please supply a hostname with -H\n");
		return cib_invalid_argument;
	}
	
	key = crm_concat("0:0:crm-resource", our_pid, '-');
	
	msg_data = create_xml_node(NULL, XML_GRAPH_TAG_RSC_OP);
	crm_xml_add(msg_data, XML_ATTR_TRANSITION_KEY, key);
	
	xml_rsc = create_xml_node(msg_data, XML_CIB_TAG_RESOURCE);
	crm_xml_add(xml_rsc, XML_ATTR_ID, rsc->id);
	crm_xml_add(xml_rsc, XML_ATTR_ID_LONG, rsc->long_name);

	value = crm_element_value(rsc->xml, XML_ATTR_TYPE);
	crm_xml_add(xml_rsc, XML_ATTR_TYPE, value);
	if(value == NULL) {
		CMD_ERR("%s has no type!  Aborting...\n", rsc_id);
		return cib_NOTEXISTS;
	}

	value = crm_element_value(rsc->xml, XML_AGENT_ATTR_CLASS);
	crm_xml_add(xml_rsc, XML_AGENT_ATTR_CLASS, value);
	if(value == NULL) {
		CMD_ERR("%s has no class!  Aborting...\n", rsc_id);
		return cib_NOTEXISTS;
	}

	value = crm_element_value(rsc->xml, XML_AGENT_ATTR_PROVIDER);
	crm_xml_add(xml_rsc, XML_AGENT_ATTR_PROVIDER, value);

	params = create_xml_node(msg_data, XML_TAG_ATTRS);
	crm_xml_add(params, XML_ATTR_CRM_VERSION, CRM_FEATURE_SET);
	crm_xml_add(params, CRM_META"_"XML_LRM_ATTR_INTERVAL, "60000"); /* 1 minute */
	
	cmd = create_request(op, msg_data, host_uname,
			     CRM_SYSTEM_CRMD, crm_system_name, our_pid);

/* 	crm_log_xml_warn(cmd, "send_lrm_rsc_op"); */	
	free_xml(msg_data);
	crm_free(key);

	if(send_ipc_message(crmd_channel, cmd)) {
	    rc = 0;
	    sleep(1); /* dont exit striaght away, give the crmd time
		       * to process our request
		       */
	} else {
	    CMD_ERR("Could not send %s op to the crmd", op);
	}
	
	crm_msg_del(cmd);
	return rc;
}


static int
delete_lrm_rsc(IPC_Channel *crmd_channel, const char *host_uname,
	       const char *rsc_id, pe_working_set_t *data_set)
{
	return send_lrm_rsc_op(crmd_channel, CRM_OP_LRM_DELETE, host_uname, rsc_id, TRUE, data_set); 
}

static int
fail_lrm_rsc(IPC_Channel *crmd_channel, const char *host_uname,
	     const char *rsc_id, pe_working_set_t *data_set)
{
    crm_warn("Failing: %s", rsc_id);
    return send_lrm_rsc_op(crmd_channel, CRM_OP_LRM_FAIL, host_uname, rsc_id, FALSE, data_set); 
}

static int
refresh_lrm(IPC_Channel *crmd_channel, const char *host_uname)  
{
	HA_Message *cmd = NULL;
	int rc = cib_send_failed;
	
	cmd = create_request(CRM_OP_LRM_REFRESH, NULL, host_uname,
			     CRM_SYSTEM_CRMD, crm_system_name, our_pid);
	
	if(send_ipc_message(crmd_channel, cmd)) {
		rc = 0;
	}
	crm_msg_del(cmd);
	return rc;
}

static int
migrate_resource(
	const char *rsc_id,
	const char *existing_node, const char *preferred_node,
	cib_t *	cib_conn) 
{
	char *later_s = NULL;
	enum cib_errors rc = cib_ok;
	char *id = NULL;
	crm_data_t *cib = NULL;
	crm_data_t *rule = NULL;
	crm_data_t *expr = NULL;
	crm_data_t *constraints = NULL;
	crm_data_t *fragment = NULL;
	crm_data_t *lifetime = NULL;
	
	crm_data_t *can_run = NULL;
	crm_data_t *dont_run = NULL;

	fragment = create_cib_fragment(NULL, NULL);
	cib = fragment;

	CRM_DEV_ASSERT(safe_str_eq(crm_element_name(cib), XML_TAG_CIB));
	constraints = get_object_root(XML_CIB_TAG_CONSTRAINTS, cib);
	
	id = crm_concat("cli-prefer", rsc_id, '-');
	can_run = create_xml_node(NULL, XML_CONS_TAG_RSC_LOCATION);
	crm_xml_add(can_run, XML_ATTR_ID, id);
	crm_free(id);

	id = crm_concat("cli-standby", rsc_id, '-');
	dont_run = create_xml_node(NULL, XML_CONS_TAG_RSC_LOCATION);
	crm_xml_add(dont_run, XML_ATTR_ID, id);
	crm_free(id);

	if(migrate_lifetime) {
		char *life = crm_strdup(migrate_lifetime);
		char *life_mutable = life;
		
		ha_time_t *now = NULL;
		ha_time_t *later = NULL;
		ha_time_t *duration = parse_time_duration(&life_mutable);
		
		if(duration == NULL) {
			CMD_ERR("Invalid duration specified: %s\n",
				migrate_lifetime);
			CMD_ERR("Please refer to"
				" http://en.wikipedia.org/wiki/ISO_8601#Duration"
				" for examples of valid durations\n");
			crm_free(life);
			return cib_invalid_argument;
		}
		now = new_ha_date(TRUE);
		later = add_time(now, duration);
		log_date(LOG_INFO, "now     ", now, ha_log_date|ha_log_time);
		log_date(LOG_INFO, "later   ", later, ha_log_date|ha_log_time);
		log_date(LOG_INFO, "duration", duration, ha_log_date|ha_log_time|ha_log_local);
		later_s = date_to_string(later, ha_log_date|ha_log_time);
		printf("Migration will take effect until: %s\n", later_s);

		free_ha_date(duration);
		free_ha_date(later);
		free_ha_date(now);
		crm_free(life);
	}
	
	if(existing_node == NULL) {
		crm_log_xml_notice(can_run, "Deleting");
		rc = cib_conn->cmds->delete(cib_conn, XML_CIB_TAG_CONSTRAINTS,
					    dont_run, NULL, cib_options);
		if(rc == cib_NOTEXISTS) {
			rc = cib_ok;

		} else if(rc != cib_ok) {
			goto bail;
		}

	} else {
		if(BE_QUIET == FALSE) {
			fprintf(stderr,
				"WARNING: Creating rsc_location constraint '%s'"
				" with a score of -INFINITY for resource %s"
				" on %s.\n",
				ID(dont_run), rsc_id, existing_node);
			CMD_ERR("\tThis will prevent %s from running"
				" on %s until the constraint is removed using"
				" the 'crm_resource -U' command or manually"
				" with cibadmin\n", rsc_id, existing_node);
			CMD_ERR("\tThis will be the case even if %s is"
				" the last node in the cluster\n", existing_node);
			CMD_ERR("\tThis messgae can be disabled with -Q\n");
		}
		
		crm_xml_add(dont_run, "rsc", rsc_id);

		if(later_s) {
			lifetime = create_xml_node(dont_run, "lifetime");

			rule = create_xml_node(lifetime, XML_TAG_RULE);
			id = crm_concat("cli-standby-lifetime", rsc_id, '-');
			crm_xml_add(rule, XML_ATTR_ID, id);
			crm_free(id);

			expr = create_xml_node(rule, "date_expression");
			id = crm_concat("cli-standby-lifetime-end",rsc_id,'-');
			crm_xml_add(expr, XML_ATTR_ID, id);
			crm_free(id);			

			crm_xml_add(expr, "operation", "lt");
			crm_xml_add(expr, "end", later_s);
		}
		
		rule = create_xml_node(dont_run, XML_TAG_RULE);
		expr = create_xml_node(rule, XML_TAG_EXPRESSION);
		id = crm_concat("cli-standby-rule", rsc_id, '-');
		crm_xml_add(rule, XML_ATTR_ID, id);
		crm_free(id);
		
		crm_xml_add(rule, XML_RULE_ATTR_SCORE, MINUS_INFINITY_S);
		
		id = crm_concat("cli-standby-expr", rsc_id, '-');
		crm_xml_add(expr, XML_ATTR_ID, id);
		crm_free(id);
		
		crm_xml_add(expr, XML_EXPR_ATTR_ATTRIBUTE, "#uname");
		crm_xml_add(expr, XML_EXPR_ATTR_OPERATION, "eq");
		crm_xml_add(expr, XML_EXPR_ATTR_VALUE, existing_node);
		crm_xml_add(expr, XML_EXPR_ATTR_TYPE, "string");
		
		add_node_copy(constraints, dont_run);
	}
	
	if(preferred_node == NULL) {
		crm_log_xml_notice(can_run, "Deleting");
		rc = cib_conn->cmds->delete(cib_conn, XML_CIB_TAG_CONSTRAINTS,
					    can_run, NULL, cib_options);
		if(rc == cib_NOTEXISTS) {
			rc = cib_ok;

		} else if(rc != cib_ok) {
			goto bail;
		}

	} else {
		crm_xml_add(can_run, "rsc", rsc_id);

		if(later_s) {
			lifetime = create_xml_node(can_run, "lifetime");

			rule = create_xml_node(lifetime, XML_TAG_RULE);
			id = crm_concat("cli-prefer-lifetime", rsc_id, '-');
			crm_xml_add(rule, XML_ATTR_ID, id);
			crm_free(id);

			expr = create_xml_node(rule, "date_expression");
			id = crm_concat("cli-prefer-lifetime-end", rsc_id, '-');
			crm_xml_add(expr, XML_ATTR_ID, id);
			crm_free(id);			

			crm_xml_add(expr, "operation", "lt");
			crm_xml_add(expr, "end", later_s);
		}

		rule = create_xml_node(can_run, XML_TAG_RULE);
		expr = create_xml_node(rule, XML_TAG_EXPRESSION);
		id = crm_concat("cli-prefer-rule", rsc_id, '-');
		crm_xml_add(rule, XML_ATTR_ID, id);
		crm_free(id);

		crm_xml_add(rule, XML_RULE_ATTR_SCORE, INFINITY_S);
	
		id = crm_concat("cli-prefer-expr", rsc_id, '-');
		crm_xml_add(expr, XML_ATTR_ID, id);
		crm_free(id);

		crm_xml_add(expr, XML_EXPR_ATTR_ATTRIBUTE, "#uname");
		crm_xml_add(expr, XML_EXPR_ATTR_OPERATION, "eq");
		crm_xml_add(expr, XML_EXPR_ATTR_VALUE, preferred_node);
		crm_xml_add(expr, XML_EXPR_ATTR_TYPE, "string");
		
		add_node_copy(constraints, can_run);
	}

	if(preferred_node != NULL || existing_node != NULL) {
		crm_log_xml_notice(fragment, "CLI Update");
		rc = cib_conn->cmds->update(cib_conn, XML_CIB_TAG_CONSTRAINTS,
					    fragment, NULL, cib_options);
	}

  bail:
	free_xml(fragment);
	free_xml(dont_run);
	free_xml(can_run);
	crm_free(later_s);
	return rc;
}


int
main(int argc, char **argv)
{
	pe_working_set_t data_set;
	crm_data_t *cib_xml_copy = NULL;

	cib_t *	cib_conn = NULL;
	enum cib_errors rc = cib_ok;
	
	int argerr = 0;
	int flag;

#ifdef HAVE_GETOPT_H
	int option_index = 0;
	static struct option long_options[] = {
		/* Top-level Options */
		{"verbose",    0, 0, 'V'},
		{"help",       0, 0, '?'},
		{"quiet",      0, 0, 'Q'},
		{"list",       0, 0, 'L'},
		{"list-raw",   0, 0, 'l'},
		{"refresh",    0, 0, 'R'},
		{"reprobe",    0, 0, 'P'},
		{"query-xml",  0, 0, 'x'},
		{"delete",     0, 0, 'D'},
		{"cleanup",    0, 0, 'C'},
		{"locate",     0, 0, 'W'},
		{"migrate",    0, 0, 'M'},
		{"un-migrate", 0, 0, 'U'},
		{"resource",   1, 0, 'r'},
		{"host-uname", 1, 0, 'H'},
		{"lifetime",   1, 0, 'u'},
		{"fail",       0, 0, 'F'},
		{"force",      0, 0, 'f'},
		{"meta",       0, 0, 'm'},

		{"set-parameter",   1, 0, 'p'},
		{"get-parameter",   1, 0, 'g'},
		{"delete-parameter",1, 0, 'd'},
		{"property-value",  1, 0, 'v'},
		{"get-property",    1, 0, 'G'},
		{"set-property",    1, 0, 'S'},
		{"resource-type",   1, 0, 't'},

		{"xml-file", 0, 0, 'X'},		
		
		{0, 0, 0, 0}
	};
#endif

	crm_log_init(basename(argv[0]), LOG_ERR, FALSE, FALSE, argc, argv);
	if(argc < 2) {
		usage(crm_system_name, LSB_EXIT_EINVAL);
	}

	while (1) {
#ifdef HAVE_GETOPT_H
		flag = getopt_long(argc, argv, OPTARGS,
				   long_options, &option_index);
#else
		flag = getopt(argc, argv, OPTARGS);
#endif
		if (flag == -1)
			break;

		switch(flag) {
			case 'V':
				cl_log_enable_stderr(TRUE);
				alter_debug(DEBUG_INC);
				break;
			case '?':
				usage(crm_system_name, LSB_EXIT_OK);
				break;
			case 'X':
				xml_file = crm_strdup(optarg);
				break;
			case 'Q':
				BE_QUIET = TRUE;
				break;
			case 'm':
				attr_set_type = XML_TAG_META_SETS;
				break;
				
			case 'L':
			case 'l':
			case 'R':
			case 'x':
			case 'D':
			case 'F':
			case 'C':
			case 'P':
			case 'W':
			case 'M':
			case 'U':
				rsc_cmd = flag;
				break;
				
			case 'u':
				migrate_lifetime = crm_strdup(optarg);
				break;
				
			case 'p':
				crm_debug_2("Option %c => %s", flag, optarg);
				prop_name = optarg;
				rsc_cmd = flag;
				break;

			case 'g':
				crm_debug_2("Option %c => %s", flag, optarg);
				prop_name = optarg;
				rsc_cmd = flag;
				break;

			case 'd':
				crm_debug_2("Option %c => %s", flag, optarg);
				prop_name = optarg;
				rsc_cmd = flag;
				break;

			case 'S':
				crm_debug_2("Option %c => %s", flag, optarg);
				prop_name = optarg;
				rsc_cmd = flag;
				break;

			case 'G':
				crm_debug_2("Option %c => %s", flag, optarg);
				prop_name = optarg;
				rsc_cmd = flag;
				break;
				
			case 'f':
				do_force = TRUE;
				break;
			case 'i':
				crm_debug_2("Option %c => %s", flag, optarg);
				prop_id = optarg;
				break;
			case 's':
				crm_debug_2("Option %c => %s", flag, optarg);
				prop_set = optarg;
				break;
			case 'r':
				crm_debug_2("Option %c => %s", flag, optarg);
				rsc_id = optarg;
				break;

			case 'v':
				crm_debug_2("Option %c => %s", flag, optarg);
				prop_value = optarg;
				break;

			case 't':
				crm_debug_2("Option %c => %s", flag, optarg);
				rsc_type = optarg;
				break;

			case 'H':
				crm_debug_2("Option %c => %s", flag, optarg);
				host_uname = optarg;
				break;
				
			default:
				CMD_ERR("Argument code 0%o (%c) is not (?yet?) supported\n", flag, flag);
				++argerr;
				break;
		}
	}

	if (optind < argc) {
		CMD_ERR("non-option ARGV-elements: ");
		while (optind < argc) {
			CMD_ERR("%s ", argv[optind++]);
		}
		CMD_ERR("\n");
	}

	if (optind > argc) {
		++argerr;
	}

	if (argerr) {
		usage(crm_system_name, LSB_EXIT_GENERIC);
	}

	crm_malloc0(our_pid, 11);
	if(our_pid != NULL) {
		snprintf(our_pid, 10, "%d", getpid());
		our_pid[10] = '\0';
	}

	if(do_force) {
		crm_debug("Forcing...");
		cib_options |= cib_scope_local|cib_quorum_override;
	}

	if(rsc_cmd == 'L'
	   || rsc_cmd == 'W'
	   || rsc_cmd == 'D'
	   || rsc_cmd == 'x'
	   || rsc_cmd == 'M'
	   || rsc_cmd == 'U'
	   || rsc_cmd == 'C' 
	   || rsc_cmd == 'F' 
	   || rsc_cmd == 'p'
	   || rsc_cmd == 'd'
	   || rsc_cmd == 'g'
	   || rsc_cmd == 'G'
	   || rsc_cmd == 'S'
	   || rsc_cmd == 'l') {
		resource_t *rsc = NULL;
		if(xml_file != NULL) {
			FILE *xml_strm = fopen(xml_file, "r");
			if(strstr(xml_file, ".bz2") != NULL) {
				cib_xml_copy = file2xml(xml_strm, TRUE);
			} else {
				cib_xml_copy = file2xml(xml_strm, FALSE);
			}
			if(xml_strm != NULL) {
				fclose(xml_strm);
			}

		} else {
			cib_conn = cib_new();
			rc = cib_conn->cmds->signon(
				cib_conn, crm_system_name, cib_command_synchronous);
			if(rc != cib_ok) {
				CMD_ERR("Error signing on to the CIB service: %s\n",
					cib_error2string(rc));
				return rc;
			}

			cib_xml_copy = get_cib_copy(cib_conn);
		}
		
		set_working_set_defaults(&data_set);
		data_set.input = cib_xml_copy;
		data_set.now = new_ha_date(TRUE);

		cluster_status(&data_set);
		rsc = pe_find_resource(data_set.resources, rsc_id);
		if(rsc != NULL) {
			rsc_id = rsc->id;

		} else {
			rc = cib_NOTEXISTS;
		}
	}

	if(rsc_cmd == 'R'
	   || rsc_cmd == 'C'
	   || rsc_cmd == 'F'
	   || rsc_cmd == 'P') {
		GCHSource *src = NULL;
		src = init_client_ipc_comms(CRM_SYSTEM_CRMD, crmd_msg_callback,
				      NULL, &crmd_channel);

		if(src == NULL) {
			CMD_ERR("Error signing on to the CRMd service\n");
			return 1;
		}
		
		send_hello_message(
			crmd_channel, our_pid, crm_system_name, "0", "1");

		set_IPC_Channel_dnotify(src, resource_ipc_connection_destroy);
	}

	crm_warn("here i am - 3");
	if(rsc_cmd == 'L') {
		rc = cib_ok;
		do_find_resource_list(&data_set, FALSE);
		
	} else if(rsc_cmd == 'l') {
		rc = cib_ok;
		do_find_resource_list(&data_set, TRUE);
		
	} else if(rsc_cmd == 'C') {
		rc = delete_lrm_rsc(crmd_channel, host_uname, rsc_id, &data_set);
		
	} else if(rsc_cmd == 'F') {
		rc = fail_lrm_rsc(crmd_channel, host_uname, rsc_id, &data_set);
		
	} else if(rc == cib_NOTEXISTS) {
		CMD_ERR("Resource %s not found: %s\n",
			crm_str(rsc_id), cib_error2string(rc));
		
	} else if(rsc_cmd == 'W') {
		if(rsc_id == NULL) {
			CMD_ERR("Must supply a resource id with -r\n");
			return cib_NOTEXISTS;
		} 
		rc = do_find_resource(rsc_id, &data_set);
		
	} else if(rsc_cmd == 'x') {
		if(rsc_id == NULL) {
			CMD_ERR("Must supply a resource id with -r\n");
			return cib_NOTEXISTS;
		} 
		rc = dump_resource(rsc_id, &data_set);

	} else if(rsc_cmd == 'U') {
		if(rsc_id == NULL) {
			CMD_ERR("Must supply a resource id with -r\n");
			return cib_NOTEXISTS;
		} 
		rc = migrate_resource(rsc_id, NULL, NULL, cib_conn);

	} else if(rsc_cmd == 'M') {
		node_t *dest = NULL;
		node_t *current = NULL;
		const char *current_uname = NULL;
		resource_t *rsc = pe_find_resource(data_set.resources, rsc_id);
		if(rsc != NULL && rsc->running_on != NULL) {
			current = rsc->running_on->data;
			if(current != NULL) {
				current_uname = current->details->uname;
			}
		}

		if(host_uname != NULL) {
			dest = pe_find_node(data_set.nodes, host_uname);
		}
		
		if(rsc == NULL) {
			CMD_ERR("Resource %s not migrated:"
				" not found\n", rsc_id);

		} else if(rsc->variant == pe_native
			  && g_list_length(rsc->running_on) > 1) {
			CMD_ERR("Resource %s not migrated:"
				" active on multiple nodes\n", rsc_id);
			
		} else if(host_uname != NULL && dest == NULL) {
			CMD_ERR("Error performing operation: "
				"%s is not a known node\n", host_uname);

		} else if(host_uname != NULL
			  && safe_str_eq(current_uname, host_uname)) {
			CMD_ERR("Error performing operation: "
				"%s is already active on %s\n",
				rsc_id, host_uname);

		} else if(current_uname != NULL
			  && (do_force || host_uname == NULL)) {
			rc = migrate_resource(rsc_id, current_uname,
					      host_uname, cib_conn);

			
		} else if(host_uname != NULL) {
			rc = migrate_resource(
				rsc_id, NULL, host_uname, cib_conn);

		} else {
			CMD_ERR("Resource %s not migrated: "
				"not-active and no prefered location"
				" specified.\n", rsc_id);
		}
		
	} else if(rsc_cmd == 'G') {
		if(rsc_id == NULL) {
			CMD_ERR("Must supply a resource id with -r\n");
			return cib_NOTEXISTS;
		} 
		rc = dump_resource_prop(rsc_id, prop_name, &data_set);

	} else if(rsc_cmd == 'S') {
		crm_data_t *msg_data = NULL;
		if(prop_value == NULL || strlen(prop_value) == 0) {
			CMD_ERR("You need to supply a value with the -v option\n");
			return CIBRES_MISSING_FIELD;

		} else if(cib_conn == NULL) {
			return cib_connection;
		}

		if(rsc_id == NULL) {
			CMD_ERR("Must supply a resource id with -r\n");
			return cib_NOTEXISTS;
		} 
		CRM_DEV_ASSERT(rsc_type != NULL);
		CRM_DEV_ASSERT(prop_name != NULL);
		CRM_DEV_ASSERT(prop_value != NULL);

		msg_data = create_xml_node(NULL, rsc_type);
		crm_xml_add(msg_data, XML_ATTR_ID, rsc_id);
		crm_xml_add(msg_data, prop_name, prop_value);
		
		rc = cib_conn->cmds->modify(cib_conn, XML_CIB_TAG_RESOURCES,
					    msg_data, NULL, cib_options);
		free_xml(msg_data);

	} else if(rsc_cmd == 'g') {
		if(rsc_id == NULL) {
			CMD_ERR("Must supply a resource id with -r\n");
			return cib_NOTEXISTS;
		} 
		rc = dump_resource_attr(rsc_id, prop_name, &data_set);

	} else if(rsc_cmd == 'p') {
		if(rsc_id == NULL) {
			CMD_ERR("Must supply a resource id with -r\n");
			return cib_NOTEXISTS;
		} 
		if(prop_value == NULL || strlen(prop_value) == 0) {
			CMD_ERR("You need to supply a value with the -v option\n");
			return CIBRES_MISSING_FIELD;
		}
		rc = set_resource_attr(rsc_id, prop_set, prop_id, prop_name,
				       prop_value, cib_conn, &data_set);

	} else if(rsc_cmd == 'd') {
		if(rsc_id == NULL) {
			CMD_ERR("Must supply a resource id with -r\n");
			return cib_NOTEXISTS;
		} 
		rc = delete_resource_attr(rsc_id, prop_id, prop_set, prop_name,
					  cib_conn, &data_set);

	} else if(rsc_cmd == 'P') {
		HA_Message *cmd = NULL;
		
		cmd = create_request(CRM_OP_REPROBE, NULL, host_uname,
				     CRM_SYSTEM_CRMD, crm_system_name, our_pid);
		send_ipc_message(crmd_channel, cmd);
		crm_msg_del(cmd);

	} else if(rsc_cmd == 'R') {
		refresh_lrm(crmd_channel, host_uname);

	} else if(rsc_cmd == 'D') {
		crm_data_t *msg_data = NULL;
		
		if(rsc_id == NULL) {
			CMD_ERR("Must supply a resource id with -r\n");
			return cib_NOTEXISTS;
		} 
		if(rsc_type == NULL) {
			CMD_ERR("You need to specify a resource type with -t");
			return cib_NOTEXISTS;

		} else if(cib_conn == NULL) {
			return cib_connection;
		}

		msg_data = create_xml_node(NULL, rsc_type);
		crm_xml_add(msg_data, XML_ATTR_ID, rsc_id);

		rc = cib_conn->cmds->delete(cib_conn, XML_CIB_TAG_RESOURCES,
					    msg_data, NULL, cib_options);
		free_xml(msg_data);

	} else {
		CMD_ERR("Unknown command: %c\n", rsc_cmd);
	}

	if(cib_conn != NULL) {
		cleanup_calculations(&data_set);
		cib_conn->cmds->signoff(cib_conn);
	}
	if(rc == cib_no_quorum) {
		CMD_ERR("Error performing operation: %s\n",
			cib_error2string(rc));
		CMD_ERR("Try using -f\n");

	} else if(rc != cib_ok) {
		CMD_ERR("Error performing operation: %s\n",
			cib_error2string(rc));
	}
	
	return rc;
}

void
usage(const char *cmd, int exit_status)
{
	FILE *stream;

	stream = exit_status ? stderr : stdout;
	fprintf(stream, "usage: %s [-?VS] -(L|Q|W|D|C|P|p) [options]\n", cmd);

	fprintf(stream, "\t--%s (-%c)\t: this help message\n", "help", '?');
	fprintf(stream, "\t--%s (-%c)\t: "
		"turn on debug info. additional instances increase verbosity\n",
		"verbose", 'V');
	fprintf(stream, "\t--%s (-%c)\t: Print only the value on stdout (for use with -W)\n",
		"quiet", 'Q');

	fprintf(stream, "\nCommands\n");
	fprintf(stream, "\t--%s (-%c)\t: List all resources\n", "list", 'L');
	fprintf(stream, "\t--%s (-%c)\t: Query a resource\n"
		"\t\t\t  Requires: -r\n", "query-xml", 'x');
	fprintf(stream, "\t--%s (-%c)\t: Locate a resource\n"
		"\t\t\t  Requires: -r\n", "locate", 'W');
	fprintf(stream, "\t--%s (-%c)\t: Migrate a resource from it current"
		" location.  Use -H to specify a destination\n"
		"\t\tIf -H is not specified, we will force the resource to move by"
		" creating a rule for the current location and a score of -INFINITY\n"
		"\t\tNOTE: This will prevent the resource from running on this"
		" node until the constraint is removed with -U\n"
		"\t\t\t  Requires: -r, Optional: -H, -f, --lifetime\n", "migrate", 'M');
	fprintf(stream, "\t--%s (-%c)\t: Remove all constraints created by -M\n"
		"\t\t\t  Requires: -r\n", "un-migrate", 'U');
	fprintf(stream, "\t--%s (-%c)\t: Delete a resource from the CIB\n"
		"\t\t\t  Requires: -r, -t\n", "delete", 'D');
	fprintf(stream, "\t--%s (-%c)\t: Delete a resource from the LRM\n"
		"\t\t\t  Requires: -r.  Optional: -H\n", "cleanup", 'C');
	fprintf(stream, "\t--%s (-%c)\t: Recheck for resources started outside of the CRM\n"
		"\t\t\t  Optional: -H\n", "reprobe", 'P');
	fprintf(stream, "\t--%s (-%c)\t: Refresh the CIB from the LRM\n"
		"\t\t\t  Optional: -H\n", "refresh", 'R');
	fprintf(stream, "\t--%s (-%c) <string>\t: "
		"Set the named parameter for a resource\n"
		"\t\t\t  Requires: -r, -v.  Optional: -i, -s, --meta\n", "set-parameter", 'p');
	fprintf(stream, "\t--%s (-%c) <string>\t: "
		"Get the named parameter for a resource\n"
		"\t\t\t  Requires: -r.  Optional: -i, -s, --meta\n", "get-parameter", 'g');
	fprintf(stream, "\t--%s (-%c) <string>: "
		"Delete the named parameter for a resource\n"
		"\t\t\t  Requires: -r.  Optional: -i, --meta\n", "delete-parameter", 'd');
	fprintf(stream, "\nOptions\n");
	fprintf(stream, "\t--%s (-%c) <string>\t: Resource ID\n", "resource", 'r');
	fprintf(stream, "\t--%s (-%c) <string>\t: "
		"Resource type (primitive, clone, group, ...)\n",
		"resource-type", 't');

	fprintf(stream, "\t--%s (-%c) <string>\t: "
		"Property value\n", "property-value", 'v');
	fprintf(stream, "\t--%s (-%c) <string>\t: "
		"Host name\n", "host-uname", 'H');
	fprintf(stream, "\t--%s\t: Modify a resource's configuration option rather than one which is passed to the resource agent script."
		"\n\t\tFor use with -p, -g, -d\n", "meta");
	fprintf(stream, "\t--%s (-%c) <string>\t: "
		"Lifespan of migration constraints\n", "lifetime", 'u');
	fprintf(stream, "\t--%s (-%c)\t: "
		"Force the resource to move by creating a rule for the"
		" current location and a score of -INFINITY\n"
		"\t\tThis should be used if the resource's stickiness and"
		" constraint scores total more than INFINITY (Currently 100,000)\n"
		"\t\tNOTE: This will prevent the resource from running on this"
		" node until the constraint is removed with -U or the --lifetime duration expires\n",
		"force", 'f');
	fprintf(stream, "\t-%c <string>\t: (Advanced Use Only) ID of the instance_attributes object to change\n", 's');
	fprintf(stream, "\t-%c <string>\t: (Advanced Use Only) ID of the nvpair object to change/delete\n", 'i');
	fflush(stream);

	exit(exit_status);
}
