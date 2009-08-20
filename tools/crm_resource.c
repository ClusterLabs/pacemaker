
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

#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/ipc.h>

#include <crm/cib.h>
#include <crm/pengine/rules.h>
#include <crm/pengine/status.h>

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
char *move_lifetime = NULL;
char rsc_cmd = 'L';
char *our_pid = NULL;
IPC_Channel *crmd_channel = NULL;
char *xml_file = NULL;
int cib_options = cib_sync_call;

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

#define cons_string(x) x?x:"NA"
static void
print_cts_constraints(pe_working_set_t *data_set) 
{
    xmlNode *lifetime = NULL;
    xmlNode * cib_constraints = get_object_root(XML_CIB_TAG_CONSTRAINTS, data_set->input);
    xml_child_iter(cib_constraints, xml_obj, 

		   const char *id = crm_element_value(xml_obj, XML_ATTR_ID);
		   if(id == NULL) {
		       continue;
		   }
		   
		   lifetime = first_named_child(xml_obj, "lifetime");
		   
		   if(test_ruleset(lifetime, NULL, data_set->now) == FALSE) {
		       continue;
		   }
		   
		   if(safe_str_eq(XML_CONS_TAG_RSC_DEPEND, crm_element_name(xml_obj))) {
		       printf("Constraint %s %s %s %s %s %s %s\n",
			      crm_element_name(xml_obj),
			      cons_string(crm_element_value(xml_obj, XML_ATTR_ID)),
			      cons_string(crm_element_value(xml_obj, XML_COLOC_ATTR_SOURCE)),
			      cons_string(crm_element_value(xml_obj, XML_COLOC_ATTR_TARGET)),
			      cons_string(crm_element_value(xml_obj, XML_RULE_ATTR_SCORE)),
			      cons_string(crm_element_value(xml_obj, XML_COLOC_ATTR_SOURCE_ROLE)),
			      cons_string(crm_element_value(xml_obj, XML_COLOC_ATTR_TARGET_ROLE)));
		       
		   } else if(safe_str_eq(XML_CONS_TAG_RSC_LOCATION, crm_element_name(xml_obj))) {
		       /* unpack_rsc_location(xml_obj, data_set); */
		   }
	);
}

static void
print_cts_rsc(resource_t *rsc) 
{
    const char *host = NULL;
    gboolean needs_quorum = TRUE;
    const char *rtype = crm_element_value(rsc->xml, XML_ATTR_TYPE);
    const char *rprov = crm_element_value(rsc->xml, XML_AGENT_ATTR_PROVIDER);
    const char *rclass = crm_element_value(rsc->xml, XML_AGENT_ATTR_CLASS);

    if(safe_str_eq(rclass, "stonith")) {
	needs_quorum = FALSE;

    } else {
	xml_child_iter_filter(rsc->ops_xml, op, "op",
			  const char *name = crm_element_value(op, "name");
			  if(safe_str_neq(name, CRMD_ACTION_START)) {
			      const char *value = crm_element_value(op, "requires");
			      if(safe_str_eq(value, "nothing")) {
				  needs_quorum = FALSE;
			      }
			      break;
			  }
	);
    }

    if(rsc->running_on != NULL && g_list_length(rsc->running_on) == 1) {
	node_t *tmp = rsc->running_on->data;
	host = tmp->details->uname;
    }

    printf("Resource: %s %s %s %s %s %s %s %s %d %lld 0x%.16llx\n",
	   crm_element_name(rsc->xml), rsc->id,
	   rsc->clone_name?rsc->clone_name:rsc->id, rsc->parent?rsc->parent->id:"NA",
	   rprov?rprov:"NA", rclass, rtype, host?host:"NA", needs_quorum, rsc->flags, rsc->flags);

    slist_iter(child, resource_t, rsc->children, lpc,
	       print_cts_rsc(child);
	);
}


static void
print_raw_rsc(resource_t *rsc) 
{
	GListPtr children = rsc->children;

	if(children == NULL) {
	    printf("%s\n", rsc->id);
	}
	
	slist_iter(child, resource_t, children, lpc,
		   print_raw_rsc(child);
		);
}


static int
do_find_resource_list(pe_working_set_t *data_set, gboolean raw)
{
	int found = 0;
	
	slist_iter(
		rsc, resource_t, data_set->resources, lpc,
		if(is_set(rsc->flags, pe_rsc_orphan)
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


static resource_t *find_rsc_or_clone(const char *rsc, pe_working_set_t *data_set) 
{
    resource_t *the_rsc = pe_find_resource(data_set->resources, rsc);
    if(the_rsc == NULL) {
	char *as_clone = crm_concat(rsc, "0", ':');
	the_rsc = pe_find_resource(data_set->resources, as_clone);
	crm_free(as_clone);
    }
    return the_rsc;
}

static int
dump_resource(const char *rsc, pe_working_set_t *data_set)
{
	char *rsc_xml = NULL;
	resource_t *the_rsc = find_rsc_or_clone(rsc, data_set);

	if(the_rsc == NULL) {
		return cib_NOTEXISTS;
	}
	the_rsc->fns->print(the_rsc, NULL, pe_print_printf, stdout);

	rsc_xml = dump_xml_formatted(the_rsc->xml);

	fprintf(stdout, "raw xml:\n%s\n", rsc_xml);
	
	crm_free(rsc_xml);
	
	return 0;
}

static int
dump_resource_attr(
	const char *rsc, const char *attr, pe_working_set_t *data_set)
{
	int rc = cib_NOTEXISTS;
	node_t *current = NULL;
	GHashTable *params = NULL;
	resource_t *the_rsc = find_rsc_or_clone(rsc, data_set);
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

	params = g_hash_table_new_full(
		g_str_hash, g_str_equal,
		g_hash_destroy_str, g_hash_destroy_str);

	if(safe_str_eq(attr_set_type, XML_TAG_ATTR_SETS)) {
	    get_rsc_attributes(params, the_rsc, current, data_set);
	} else {
	    get_meta_attributes(params, the_rsc, current, data_set);
	}
	
	crm_debug("Looking up %s in %s", attr, the_rsc->id);
	value = g_hash_table_lookup(params, attr);
	if(value != NULL) {
		fprintf(stdout, "%s\n", value);
		rc = 0;
	}

	g_hash_table_destroy(params);
	return rc;
}

static int find_resource_attr(
    cib_t *the_cib, const char *attr, const char *rsc, const char *set_type, const char *set_name,
    const char *attr_id, const char *attr_name, char **value)
{
    int offset = 0;
    static int xpath_max = 1024;
    enum cib_errors rc = cib_ok;
    xmlNode *xml_search = NULL;

    char *xpath_string = NULL;

    CRM_ASSERT(value != NULL);
    *value = NULL;
    
    crm_malloc0(xpath_string, xpath_max);
    offset += snprintf(xpath_string + offset, xpath_max - offset, "%s", get_object_path("resources"));

    offset += snprintf(xpath_string + offset, xpath_max - offset, "//*[@id=\"%s\"]", rsc);

    if(set_type) {
	offset += snprintf(xpath_string + offset, xpath_max - offset, "//%s", set_type);
	if(set_name) {
	    offset += snprintf(xpath_string + offset, xpath_max - offset, "[@id=\"%s\"]", set_name);
	}
    }
    
    offset += snprintf(xpath_string + offset, xpath_max - offset, "//nvpair[");
    if(attr_id) {
	offset += snprintf(xpath_string + offset, xpath_max - offset, "@id=\"%s\"", attr_id);
    }
    
    if(attr_name) {
	if(attr_id) {
	    offset += snprintf(xpath_string + offset, xpath_max - offset, " and ");
	}
	offset += snprintf(xpath_string + offset, xpath_max - offset, "@name=\"%s\"", attr_name);
    }   
    offset += snprintf(xpath_string + offset, xpath_max - offset, "]");

    rc = the_cib->cmds->query(
	the_cib, xpath_string, &xml_search, cib_sync_call|cib_scope_local|cib_xpath);
	
    if(rc != cib_ok) {
	return rc;
    }

    crm_log_xml_debug(xml_search, "Match");
    if(xml_has_children(xml_search)) {
	rc = cib_missing_data;
	printf("Multiple attributes match name=%s\n", attr_name);
	
	xml_child_iter(xml_search, child,
		       printf("  Value: %s \t(id=%s)\n", 
			      crm_element_value(child, XML_NVPAIR_ATTR_VALUE), ID(child));
	    );

    } else {
	const char *tmp = crm_element_value(xml_search, attr);
	if(tmp) {
	    *value = crm_strdup(tmp);
	}
    }

    free_xml(xml_search);
    return rc;
}

static int
set_resource_attr(const char *rsc_id, const char *attr_set, const char *attr_id,
		  const char *attr_name, const char *attr_value,
		  cib_t *cib, pe_working_set_t *data_set)
{
	int rc = cib_ok;
	
	char *local_attr_id = NULL;
	char *local_attr_set = NULL;
	
	xmlNode *xml_top = NULL;
	xmlNode *xml_obj = NULL;

	gboolean use_attributes_tag = FALSE;
	resource_t *rsc = find_rsc_or_clone(rsc_id, data_set);

	if(rsc == NULL) {
		return cib_NOTEXISTS;
	}

	if(safe_str_eq(attr_set_type, XML_TAG_ATTR_SETS)) {
	    rc = find_resource_attr(
		cib, XML_ATTR_ID, rsc_id, XML_TAG_META_SETS, attr_set, attr_id, attr_name, &local_attr_id);
	    if(rc == cib_ok) {
		printf("WARNING: There is already a meta attribute called %s (id=%s)\n", attr_name, local_attr_id);
	    }
	}
 	rc = find_resource_attr(
	    cib, XML_ATTR_ID, rsc_id, attr_set_type, attr_set, attr_id, attr_name, &local_attr_id);

	if(rc == cib_ok) {
	    crm_debug("Found a match for name=%s: id=%s", attr_name, local_attr_id);
	    attr_id = local_attr_id;

	} else if(rc != cib_NOTEXISTS) {
	    return rc;

	} else {
	    const char *value = NULL;
	    xmlNode *cib_top = NULL;
	    const char *tag = crm_element_name(rsc->xml);

	    rc = cib->cmds->query(cib, "/cib", &cib_top, cib_sync_call|cib_scope_local|cib_xpath|cib_no_children);
	    value = crm_element_value(cib_top, "ignore_dtd");
	    if(value != NULL) {
		use_attributes_tag = TRUE;
		
	    } else {
		value = crm_element_value(cib_top, XML_ATTR_VALIDATION);
		if(value && strstr(value, "-0.6")) {
		    use_attributes_tag = TRUE;
		}
	    }
	    free_xml(cib_top);

	    if(attr_set == NULL) {
		local_attr_set = crm_concat(rsc_id, attr_set_type, '-');
		attr_set = local_attr_set;
	    }
	    if(attr_id == NULL) {
		local_attr_id = crm_concat(attr_set, attr_name, '-');
		attr_id = local_attr_id;
	    }

	    if(use_attributes_tag && safe_str_eq(tag, XML_CIB_TAG_MASTER)) {
		tag = "master_slave"; /* use the old name */
	    }
	    
	    xml_top = create_xml_node(NULL, tag);
	    crm_xml_add(xml_top, XML_ATTR_ID, rsc_id);
	    
	    xml_obj = create_xml_node(xml_top, attr_set_type);
	    crm_xml_add(xml_obj, XML_ATTR_ID, attr_set);

	    if(use_attributes_tag) {
		xml_obj = create_xml_node(xml_obj, XML_TAG_ATTRS);
	    }
	}
		
	xml_obj = create_xml_node(xml_obj, XML_CIB_TAG_NVPAIR);
	if(xml_top == NULL) {
	    xml_top = xml_obj;
	}
	
	crm_xml_add(xml_obj, XML_ATTR_ID, attr_id);
	crm_xml_add(xml_obj, XML_NVPAIR_ATTR_NAME, attr_name);
	crm_xml_add(xml_obj, XML_NVPAIR_ATTR_VALUE, attr_value);
	
	crm_log_xml_debug(xml_top, "Update");
	
	rc = cib->cmds->modify(cib, XML_CIB_TAG_RESOURCES, xml_top, cib_options);
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
	xmlNode *xml_obj = NULL;

	int rc = cib_ok;
	char *local_attr_id = NULL;
	resource_t *rsc = find_rsc_or_clone(rsc_id, data_set);

	if(rsc == NULL) {
		return cib_NOTEXISTS;
	}

 	rc = find_resource_attr(
	    cib, XML_ATTR_ID, rsc_id, attr_set_type, attr_set, attr_id, attr_name, &local_attr_id);

	if(rc == cib_NOTEXISTS) {
	    return cib_ok;

	} else if(rc != cib_ok) {
	    return rc;
	}
	
	if(attr_id == NULL) {
		attr_id = local_attr_id;
	}

	xml_obj = create_xml_node(NULL, XML_CIB_TAG_NVPAIR);
	crm_xml_add(xml_obj, XML_ATTR_ID, attr_id);
	crm_xml_add(xml_obj, XML_NVPAIR_ATTR_NAME, attr_name);
	
	crm_log_xml_debug(xml_obj, "Delete");
	
	rc = cib->cmds->delete(cib, XML_CIB_TAG_RESOURCES, xml_obj, cib_options);

	if(rc == cib_ok) {
	    printf("Deleted %s option: id=%s%s%s%s%s\n", rsc_id, local_attr_id,
		   attr_set?" set=":"", attr_set?attr_set:"",
		   attr_name?" name=":"", attr_name?attr_name:"");
	}

	free_xml(xml_obj);
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
	gboolean hack_return_good = TRUE;

	while (server->ch_status != IPC_DISCONNECT
	       && server->ops->is_message_pending(server) == TRUE) {
		if (server->ops->recv(server, &msg) != IPC_OK) {
			perror("Receive failure:");
			return !hack_return_good;
		}

		if (msg == NULL) {
			crm_debug_4("No message this time");
			continue;
		}

		lpc++;
		msg->msg_done(msg);		
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
	xmlNode *cmd = NULL;
	xmlNode *xml_rsc = NULL;
	const char *value = NULL;
	xmlNode *params = NULL;
	xmlNode *msg_data = NULL;
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
	crm_free(key);
	
	xml_rsc = create_xml_node(msg_data, XML_CIB_TAG_RESOURCE);
	if(rsc->clone_name) {
	    crm_xml_add(xml_rsc, XML_ATTR_ID, rsc->clone_name);
	    crm_xml_add(xml_rsc, XML_ATTR_ID_LONG, rsc->id);
	    
	} else {
	    crm_xml_add(xml_rsc, XML_ATTR_ID, rsc->id);
	    crm_xml_add(xml_rsc, XML_ATTR_ID_LONG, rsc->long_name);
	}
	
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

	key = crm_meta_name(XML_LRM_ATTR_INTERVAL);
	crm_xml_add(params, key, "60000"); /* 1 minute */
	crm_free(key);
	
	cmd = create_request(op, msg_data, host_uname,
			     CRM_SYSTEM_CRMD, crm_system_name, our_pid);

/* 	crm_log_xml_warn(cmd, "send_lrm_rsc_op"); */	
	free_xml(msg_data);

	if(send_ipc_message(crmd_channel, cmd)) {
	    rc = 0;
	    sleep(1); /* dont exit striaght away, give the crmd time
		       * to process our request
		       */
	} else {
	    CMD_ERR("Could not send %s op to the crmd", op);
	}
	
	free_xml(cmd);
	return rc;
}


static int
delete_lrm_rsc(IPC_Channel *crmd_channel, const char *host_uname,
	       resource_t *rsc, pe_working_set_t *data_set)
{
    int rc = cib_ok;
    
    if(rsc == NULL) {
	return cib_NOTEXISTS;

    } else if(rsc->children) {
	slist_iter(child, resource_t, rsc->children, lpc,
		   delete_lrm_rsc(crmd_channel, host_uname, child, data_set));
	return cib_ok;

    } else if(host_uname == NULL) {
	slist_iter(node, node_t, data_set->nodes, lpc,
		   delete_lrm_rsc(crmd_channel, node->details->uname, rsc, data_set));
	return cib_ok;	
    }

    printf("Cleaning up %s on %s\n", rsc->id, host_uname);
    rc = send_lrm_rsc_op(crmd_channel, CRM_OP_LRM_DELETE, host_uname, rsc->id, TRUE, data_set);
    if(rc == cib_ok) {
	char *attr_name = NULL;
	const char *id = rsc->id;

	if(rsc->clone_name) {
	    id = rsc->clone_name;
	}
	
	attr_name = crm_concat("fail-count", id, '-');
	attrd_lazy_update('D', host_uname, attr_name, NULL, XML_CIB_TAG_STATUS, NULL, NULL);
	crm_free(attr_name);
    }
    return rc;
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
	xmlNode *cmd = NULL;
	int rc = cib_send_failed;
	
	cmd = create_request(CRM_OP_LRM_REFRESH, NULL, host_uname,
			     CRM_SYSTEM_CRMD, crm_system_name, our_pid);
	
	if(send_ipc_message(crmd_channel, cmd)) {
		rc = 0;
	}
	free_xml(cmd);
	return rc;
}

static int
move_resource(
	const char *rsc_id,
	const char *existing_node, const char *preferred_node,
	cib_t *	cib_conn) 
{
	char *later_s = NULL;
	enum cib_errors rc = cib_ok;
	char *id = NULL;
	xmlNode *rule = NULL;
	xmlNode *expr = NULL;
	xmlNode *constraints = NULL;
	xmlNode *fragment = NULL;
	
	xmlNode *can_run = NULL;
	xmlNode *dont_run = NULL;

	fragment = create_xml_node(NULL, XML_CIB_TAG_CONSTRAINTS);
	constraints = fragment;

	id = crm_concat("cli-prefer", rsc_id, '-');
	can_run = create_xml_node(NULL, XML_CONS_TAG_RSC_LOCATION);
	crm_xml_add(can_run, XML_ATTR_ID, id);
	crm_free(id);

	id = crm_concat("cli-standby", rsc_id, '-');
	dont_run = create_xml_node(NULL, XML_CONS_TAG_RSC_LOCATION);
	crm_xml_add(dont_run, XML_ATTR_ID, id);
	crm_free(id);

	if(move_lifetime) {
		char *life = crm_strdup(move_lifetime);
		char *life_mutable = life;
		
		ha_time_t *now = NULL;
		ha_time_t *later = NULL;
		ha_time_t *duration = parse_time_duration(&life_mutable);
		
		if(duration == NULL) {
			CMD_ERR("Invalid duration specified: %s\n",
				move_lifetime);
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
		rc = cib_conn->cmds->delete(
		    cib_conn, XML_CIB_TAG_CONSTRAINTS, dont_run, cib_options);
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
			CMD_ERR("\tThis message can be disabled with -Q\n");
		}
		
		crm_xml_add(dont_run, "rsc", rsc_id);
		
		rule = create_xml_node(dont_run, XML_TAG_RULE);
		expr = create_xml_node(rule, XML_TAG_EXPRESSION);
		id = crm_concat("cli-standby-rule", rsc_id, '-');
		crm_xml_add(rule, XML_ATTR_ID, id);
		crm_free(id);
		
		crm_xml_add(rule, XML_RULE_ATTR_SCORE, MINUS_INFINITY_S);
		crm_xml_add(rule, XML_RULE_ATTR_BOOLEAN_OP, "and");
		
		id = crm_concat("cli-standby-expr", rsc_id, '-');
		crm_xml_add(expr, XML_ATTR_ID, id);
		crm_free(id);
		
		crm_xml_add(expr, XML_EXPR_ATTR_ATTRIBUTE, "#uname");
		crm_xml_add(expr, XML_EXPR_ATTR_OPERATION, "eq");
		crm_xml_add(expr, XML_EXPR_ATTR_VALUE, existing_node);
		crm_xml_add(expr, XML_EXPR_ATTR_TYPE, "string");

		if(later_s) {
		    expr = create_xml_node(rule, "date_expression");
		    id = crm_concat("cli-standby-lifetime-end",rsc_id,'-');
		    crm_xml_add(expr, XML_ATTR_ID, id);
		    crm_free(id);			
		    
		    crm_xml_add(expr, "operation", "lt");
		    crm_xml_add(expr, "end", later_s);
		}
		
		add_node_copy(constraints, dont_run);
	}

	if(preferred_node == NULL) {
		crm_log_xml_notice(can_run, "Deleting");
		rc = cib_conn->cmds->delete(
		    cib_conn, XML_CIB_TAG_CONSTRAINTS, can_run, cib_options);
		if(rc == cib_NOTEXISTS) {
			rc = cib_ok;

		} else if(rc != cib_ok) {
			goto bail;
		}

	} else {
		crm_xml_add(can_run, "rsc", rsc_id);

		rule = create_xml_node(can_run, XML_TAG_RULE);
		expr = create_xml_node(rule, XML_TAG_EXPRESSION);
		id = crm_concat("cli-prefer-rule", rsc_id, '-');
		crm_xml_add(rule, XML_ATTR_ID, id);
		crm_free(id);

		crm_xml_add(rule, XML_RULE_ATTR_SCORE, INFINITY_S);
		crm_xml_add(rule, XML_RULE_ATTR_BOOLEAN_OP, "and");
	
		id = crm_concat("cli-prefer-expr", rsc_id, '-');
		crm_xml_add(expr, XML_ATTR_ID, id);
		crm_free(id);

		crm_xml_add(expr, XML_EXPR_ATTR_ATTRIBUTE, "#uname");
		crm_xml_add(expr, XML_EXPR_ATTR_OPERATION, "eq");
		crm_xml_add(expr, XML_EXPR_ATTR_VALUE, preferred_node);
		crm_xml_add(expr, XML_EXPR_ATTR_TYPE, "string");

		if(later_s) {
		    expr = create_xml_node(rule, "date_expression");
		    id = crm_concat("cli-prefer-lifetime-end", rsc_id, '-');
		    crm_xml_add(expr, XML_ATTR_ID, id);
		    crm_free(id);			
		    
		    crm_xml_add(expr, "operation", "lt");
		    crm_xml_add(expr, "end", later_s);
		}
		
		add_node_copy(constraints, can_run);
	}

	if(preferred_node != NULL || existing_node != NULL) {
		crm_log_xml_notice(fragment, "CLI Update");
		rc = cib_conn->cmds->update(
		    cib_conn, XML_CIB_TAG_CONSTRAINTS, fragment, cib_options);
	}

  bail:
	free_xml(fragment);
	free_xml(dont_run);
	free_xml(can_run);
	crm_free(later_s);
	return rc;
}

static int
list_resource_operations(
    const char *rsc_id, const char *host_uname, gboolean active, pe_working_set_t *data_set) 
{
    resource_t *rsc = NULL;
    int opts = pe_print_printf|pe_print_rsconly|pe_print_suppres_nl;
    GListPtr ops = find_operations(rsc_id, host_uname, active, data_set);
    slist_iter(xml_op, xmlNode, ops, lpc,
	       const char *op_rsc = crm_element_value(xml_op, "resource");
	       const char *last = crm_element_value(xml_op, "last_run");
	       const char *status_s = crm_element_value(xml_op, XML_LRM_ATTR_OPSTATUS);
	       int status = crm_parse_int(status_s, "0");

	       rsc = pe_find_resource(data_set->resources, op_rsc);
	       rsc->fns->print(rsc, "", opts, stdout);
	       
	       fprintf(stdout, ": %s (node=%s, call=%s, rc=%s",
		       ID(xml_op),
		       crm_element_value(xml_op, XML_ATTR_UNAME),
		       crm_element_value(xml_op, XML_LRM_ATTR_CALLID),
		       crm_element_value(xml_op, XML_LRM_ATTR_RC));
	       if(last) {
		   time_t run_at = crm_parse_int(last, "0");
		   fprintf(stdout, ", last-run=%s, exec=%sms\n",
			    ctime(&run_at), crm_element_value(xml_op, "exec_time"));
	       }
	       fprintf(stdout, "): %s\n", op_status2text(status));
	);
    return cib_ok;
}

#include "../pengine/pengine.h"

static void show_location(resource_t *rsc) 
{
    GListPtr list = rsc->rsc_location;

    slist_iter(cons, rsc_to_node_t, list, lpc,
	       slist_iter(node, node_t, cons->node_list_rh, lpc2,
			  fprintf(stdout, "+ '%s': %s = %s \n",
				  cons->id, node->details->uname, score2char(node->weight));
		   );
	);
}


static void show_colocation(resource_t *rsc, gboolean dependants, gboolean raw) 
{
    const char *prefix = "    ";
    GListPtr list = rsc->rsc_cons;

    if(dependants) {
	 prefix = "   ";
	 list = rsc->rsc_cons_lhs;
    }
    
    if(is_set(rsc->flags, pe_rsc_allocating)) {
	/* Break colocation loops */
	return;
    }
	       
    set_bit(rsc->flags, pe_rsc_allocating);
    slist_iter(cons, rsc_colocation_t, list, lpc,
	       resource_t *peer = cons->rsc_rh;

	       if(dependants) {
		   peer = cons->rsc_lh;
	       }
	       
	       if(raw) {
		   fprintf(stdout, "%s '%s': %s = %s\n", prefix, cons->id, peer->id, score2char(cons->score));
		   continue;
	       }
	       
	       if(dependants) {
		   if(is_set(peer->flags, pe_rsc_allocating)) {
		       continue;
		   }
		   show_colocation(peer, dependants, raw);
	       }
	       fprintf(stdout, "%s%s%s\n", prefix, peer->id, is_set(peer->flags, pe_rsc_allocating)?" (loop) ":"");
	       if(!dependants) {
		   show_colocation(peer, dependants, raw);
	       }
	);
    clear_bit(rsc->flags, pe_rsc_allocating);
}	

static struct crm_option long_options[] = {
    /* Top-level Options */
    {"help",    0, 0, '?', "\t\tThis text"},
    {"version", 0, 0, '$', "\t\tVersion information"  },
    {"verbose", 0, 0, 'V', "\t\tIncrease debug output"},
    {"quiet",   0, 0, 'Q', "\t\tPrint only the value on stdout\n"},

    {"resource",   1, 0, 'r', "\tResource ID" },

    {"-spacer-",1, 0, '-', "\nQueries:"},
    {"list",       0, 0, 'L', "\t\tList all resources"},
    {"list-raw",   0, 0, 'l', "\tList the IDs of all instansiated resources (no groups/clones/...)"},
    {"list-cts",   0, 0, 'c', NULL, 1},
    {"list-operations", 0, 0, 'O', "\tList active resource operations.  Optionally filtered by resource (-r) and/or node (-N)"},
    {"list-all-operations", 0, 0, 'o', "List all resource operations.  Optionally filtered by resource (-r) and/or node (-N)\n"},    
    {"query-xml",  0, 0, 'q', "\tQuery the definition of a resource"},
    {"locate",     0, 0, 'W', "\t\tDisplay the current location(s) of a resource"},
    {"stack",      0, 0, 'A', "\t\tDisplay the pre-requisits and depandants of a resource"},
    {"constraints",0, 0, 'a', "\tDisplay the (co)location constraints that apply to a resource"},

    {"-spacer-",	1, 0, '-', "\nCommands:"},
    {"set-parameter",   1, 0, 'p', "Set the named parameter for a resource. See also -m, --meta"},
    {"get-parameter",   1, 0, 'g', "Display the named parameter for a resource. See also -m, --meta"},
    {"delete-parameter",1, 0, 'd', "Delete the named parameter for a resource. See also -m, --meta"},
    {"get-property",    1, 0, 'G', "Display the 'class', 'type' or 'provider' of a resource", 1},
    {"set-property",    1, 0, 'S', "(Advanced) Set the class, type or provider of a resource", 1},
    {"move",    0, 0, 'M',
     "\t\tMove a resource from its current location, optionally specifying a destination (-N) and/or a period for which it should take effect (-u)"
     "\n\t\t\t\tIf -N is not specified, the cluster will force the resource to move by creating a rule for the current location and a score of -INFINITY"
     "\n\t\t\t\tNOTE: This will prevent the resource from running on this node until the constraint is removed with -U"},
    {"un-move", 0, 0, 'U', "\tRemove all constraints created by a move command"},
    
    {"-spacer-",	1, 0, '-', "\nAdvanced Commands:"},
    {"delete",     0, 0, 'D', "\t\tDelete a resource from the CIB"},
    {"fail",       0, 0, 'F', "\t\tTell the cluster this resource has failed"},
    {"refresh",    0, 0, 'R', "\t\t(Advanced) Refresh the CIB from the LRM"},
    {"cleanup",    0, 0, 'C', "\t\t(Advanced) Delete a resource from the LRM"},
    {"reprobe",    0, 0, 'P', "\t\t(Advanced) Re-check for resources started outside of the CRM\n"},    
    
    {"-spacer-",	1, 0, '-', "\nAdditional Options:"},
    {"node",		1, 0, 'N', "\tHost uname"},
    {"resource-type",	1, 0, 't', "Resource type (primitive, clone, group, ...)"},
    {"parameter-value", 1, 0, 'v', "Value to use with -p, -g or -d"},
    {"lifetime",	1, 0, 'u', "\tLifespan of migration constraints\n"},
    {"meta",		0, 0, 'm', "\t\tModify a resource's configuration option rather than one which is passed to the resource agent script. For use with -p, -g, -d"},
    {"set-name",        1, 0, 's', "\t(Advanced) ID of the instance_attributes object to change"},
    {"nvpair",          1, 0, 'i', "\t(Advanced) ID of the nvpair object to change/delete"},    
    {"force",		0, 0, 'f', "\n" /* Is this actually true anymore? 
     "\t\tForce the resource to move by creating a rule for the current location and a score of -INFINITY"
     "\n\t\tThis should be used if the resource's stickiness and constraint scores total more than INFINITY (Currently 100,000)"
     "\n\t\tNOTE: This will prevent the resource from running on this node until the constraint is removed with -U or the --lifetime duration expires\n"*/ },
    
    {"xml-file", 1, 0, 'x', NULL, 1},\

     /* legacy options */
    {"host-uname", 1, 0, 'H', NULL, 1},
    {"migrate",    0, 0, 'M', NULL, 1},
    {"un-migrate", 0, 0, 'U', NULL, 1},

    {"-spacer-",	1, 0, '-', "\nExamples:", pcmk_option_paragraph},
    {"-spacer-",	1, 0, '-', "List the configured resources:", pcmk_option_paragraph},
    {"-spacer-",	1, 0, '-', " crm_resource --list", pcmk_option_example},
    {"-spacer-",	1, 0, '-', "Display the current location of 'myResource':", pcmk_option_paragraph},
    {"-spacer-",	1, 0, '-', " crm_resource --resource myResource --locate", pcmk_option_example},
    {"-spacer-",	1, 0, '-', "Move 'myResource' to another machine:", pcmk_option_paragraph},
    {"-spacer-",	1, 0, '-', " crm_resource --resource myResource --move", pcmk_option_example},
    {"-spacer-",	1, 0, '-', "Move 'myResource' to a specific machine:", pcmk_option_paragraph},
    {"-spacer-",	1, 0, '-', " crm_resource --resource myResource --move --node altNode", pcmk_option_example},
    {"-spacer-",	1, 0, '-', "Allow (but not force) 'myResource' to move back to its original location:", pcmk_option_paragraph},
    {"-spacer-",	1, 0, '-', " crm_resource --resource myResource --un-move", pcmk_option_example},
    {"-spacer-",	1, 0, '-', "Tell the cluster that 'myResource' failed:", pcmk_option_paragraph},
    {"-spacer-",	1, 0, '-', " crm_resource --resource myResource --fail", pcmk_option_example},
    {"-spacer-",	1, 0, '-', "Stop a 'myResource' (and anything that depends on it):", pcmk_option_paragraph},
    {"-spacer-",	1, 0, '-', " crm_resource --resource myResource --set-parameter target-role --meta --parameter-value Stopped", pcmk_option_example},
    {"-spacer-",	1, 0, '-', "Tell the cluster not to manage 'myResource':", pcmk_option_paragraph},
    {"-spacer-",	1, 0, '-', "The cluster will not attempt to start or stop the resource under any circumstances."},
    {"-spacer-",	1, 0, '-', "Useful when performing maintenance tasks on a resource.", pcmk_option_paragraph},
    {"-spacer-",	1, 0, '-', " crm_resource --resource myResource --set-parameter is-managed --meta --parameter-value false", pcmk_option_example},
    {"-spacer-",	1, 0, '-', "Erase the operation history of 'myResource' on 'aNode':", pcmk_option_paragraph},
    {"-spacer-",	1, 0, '-', "The cluster will 'forget' the existing resource state (including any errors) and attempt to recover the resource."},
    {"-spacer-",	1, 0, '-', "Useful when a resource had failed permanently and has been repaired by an administrator.", pcmk_option_paragraph},
    {"-spacer-",	1, 0, '-', " crm_resource --resource myResource --cleanup --node aNode", pcmk_option_example},
    
    {0, 0, 0, 0}
};

int
main(int argc, char **argv)
{
	pe_working_set_t data_set;
	xmlNode *cib_xml_copy = NULL;

	cib_t *	cib_conn = NULL;
	enum cib_errors rc = cib_ok;

	gboolean need_cib = TRUE;
	int option_index = 0;
	int argerr = 0;
	int flag;

	crm_log_init(basename(argv[0]), LOG_ERR, FALSE, FALSE, argc, argv);
	crm_set_options("V?$LRQxDCPp:WMUr:H:h:v:t:p:g:d:i:s:G:S:fx:lmu:FOocqN:aA", "(query|command) [options]", long_options,
			"Perform tasks related to cluster resources.\n  Allows resources to be queried (definition and location), modified, and moved around the cluster.\n");

	if(argc < 2) {
	    crm_help('?', LSB_EXIT_EINVAL);
	}

	while (1) {
		flag = crm_get_option(argc, argv, &option_index);
		if (flag == -1)
			break;
			    
		switch(flag) {
			case 'V':
				cl_log_enable_stderr(TRUE);
				alter_debug(DEBUG_INC);
				break;
			case '$':
			case '?':
				crm_help(flag, LSB_EXIT_OK);
				break;
			case 'x':
				xml_file = crm_strdup(optarg);
				break;
			case 'Q':
				BE_QUIET = TRUE;
				break;
			case 'm':
				attr_set_type = XML_TAG_META_SETS;
				break;
			case 'u':
				move_lifetime = crm_strdup(optarg);
				break;
			case 'f':
				do_force = TRUE;
				break;
			case 'i':
				prop_id = optarg;
				break;
			case 's':
				prop_set = optarg;
				break;
			case 'r':
				rsc_id = optarg;
				break;
			case 'v':
				prop_value = optarg;
				break;
			case 't':
				rsc_type = optarg;
				break;
			case 'R':
			case 'P':
				need_cib = FALSE;
				rsc_cmd = flag;
				break;		
			case 'L':
			case 'c':
			case 'l':
			case 'q':
			case 'D':
			case 'F':
			case 'C':
			case 'W':
			case 'M':
			case 'U':
			case 'O':
			case 'o':
			case 'A':
			case 'a':
				rsc_cmd = flag;
				break;	
			case 'p':
			case 'g':
			case 'd':
			case 'S':
			case 'G':
				prop_name = optarg;
				rsc_cmd = flag;
				break;
			case 'h':
			case 'H':
			case 'N':
				crm_debug_2("Option %c => %s", flag, optarg);
				host_uname = optarg;
				break;
				
			default:
				CMD_ERR("Argument code 0%o (%c) is not (?yet?) supported\n", flag, flag);
				++argerr;
				break;
		}
	}

	if (optind < argc && argv[optind] != NULL) {
		CMD_ERR("non-option ARGV-elements: ");
		while (optind < argc && argv[optind] != NULL) {
			CMD_ERR("%s ", argv[optind++]);
			++argerr;
		}
		CMD_ERR("\n");
	}

	if (optind > argc) {
		++argerr;
	}

	if (argerr) {
		crm_help('?', LSB_EXIT_GENERIC);
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

	if(need_cib) {
		resource_t *rsc = NULL;
		if(xml_file != NULL) {
		    cib_xml_copy = filename2xml(xml_file);

		} else {
			cib_conn = cib_new();
			rc = cib_conn->cmds->signon(
				cib_conn, crm_system_name, cib_command);
			if(rc != cib_ok) {
				CMD_ERR("Error signing on to the CIB service: %s\n",
					cib_error2string(rc));
				return rc;
			}

			cib_xml_copy = get_cib_copy(cib_conn);
		}
		
		set_working_set_defaults(&data_set);
		if(cli_config_update(&cib_xml_copy, NULL, FALSE) == FALSE) {
		    return cib_STALE;
		}

		data_set.input = cib_xml_copy;
		data_set.now = new_ha_date(TRUE);

		cluster_status(&data_set);
		if(rsc_id) {
		    rsc = find_rsc_or_clone(rsc_id, &data_set);
		}
		if(rsc == NULL) {
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

	if(rsc_cmd == 'L') {
		rc = cib_ok;
		do_find_resource_list(&data_set, FALSE);
		
	} else if(rsc_cmd == 'l') {
	    int found = 0;
	    rc = cib_ok;
	    slist_iter(
		rsc, resource_t, data_set.resources, lpc,
		found++;
		print_raw_rsc(rsc);
		);
	    
	    if(found == 0) {
		printf("NO resources configured\n");
		return cib_NOTEXISTS;
	    }
		
	} else if(rsc_cmd == 'A') {
	    resource_t *rsc = pe_find_resource(data_set.resources, rsc_id);
	    xmlNode * cib_constraints = get_object_root(XML_CIB_TAG_CONSTRAINTS, data_set.input);
	    if(rsc == NULL) {
		CMD_ERR("Must supply a resource id with -r\n");
		return cib_NOTEXISTS;
	    }

	    unpack_constraints(cib_constraints, &data_set);

	    show_colocation(rsc, TRUE, FALSE);
	    fprintf(stdout, "* %s\n", rsc->id);	       
	    show_colocation(rsc, FALSE, FALSE);
	    
	} else if(rsc_cmd == 'a') {
	    resource_t *rsc = pe_find_resource(data_set.resources, rsc_id);
	    xmlNode * cib_constraints = get_object_root(XML_CIB_TAG_CONSTRAINTS, data_set.input);
	    if(rsc == NULL) {
		CMD_ERR("Must supply a resource id with -r\n");
		return cib_NOTEXISTS;
	    }
	    unpack_constraints(cib_constraints, &data_set);

	    show_colocation(rsc, TRUE, TRUE);
	    fprintf(stdout, "* %s\n", rsc->id);	       
	    show_colocation(rsc, FALSE, TRUE);

	    show_location(rsc);
	    
	    
	} else if(rsc_cmd == 'c') {
	    int found = 0;
	    rc = cib_ok;
	    slist_iter(
		rsc, resource_t, data_set.resources, lpc,
		found++;
		print_cts_rsc(rsc);
		);
	    print_cts_constraints(&data_set);
		
	} else if(rsc_cmd == 'C') {
	    resource_t *rsc = pe_find_resource(data_set.resources, rsc_id);
	    delete_lrm_rsc(crmd_channel, host_uname, rsc, &data_set);
		
	} else if(rsc_cmd == 'F') {
		rc = fail_lrm_rsc(crmd_channel, host_uname, rsc_id, &data_set);
		
	} else if(rsc_cmd == 'O') {
	    rc = list_resource_operations(rsc_id, host_uname, TRUE, &data_set);
	    
	} else if(rsc_cmd == 'o') {
	    rc = list_resource_operations(rsc_id, host_uname, FALSE, &data_set);
	    
	} else if(rc == cib_NOTEXISTS) {
		CMD_ERR("Resource %s not found: %s\n",
			crm_str(rsc_id), cib_error2string(rc));

	} else if(rsc_cmd == 'W') {
		if(rsc_id == NULL) {
			CMD_ERR("Must supply a resource id with -r\n");
			return cib_NOTEXISTS;
		} 
		rc = do_find_resource(rsc_id, &data_set);
		
	} else if(rsc_cmd == 'q') {
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
		rc = move_resource(rsc_id, NULL, NULL, cib_conn);

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
			CMD_ERR("Resource %s not moved:"
				" not found\n", rsc_id);

		} else if(rsc->variant == pe_native
			  && g_list_length(rsc->running_on) > 1) {
			CMD_ERR("Resource %s not moved:"
				" active on multiple nodes\n", rsc_id);
			
		} else if(host_uname != NULL && dest == NULL) {
			CMD_ERR("Error performing operation: "
				"%s is not a known node\n", host_uname);
			rc = cib_NOTEXISTS;

		} else if(host_uname != NULL
			  && safe_str_eq(current_uname, host_uname)) {
			CMD_ERR("Error performing operation: "
				"%s is already active on %s\n",
				rsc_id, host_uname);

		} else if(current_uname != NULL
			  && (do_force || host_uname == NULL)) {
			rc = move_resource(rsc_id, current_uname,
					      host_uname, cib_conn);

			
		} else if(host_uname != NULL) {
			rc = move_resource(
				rsc_id, NULL, host_uname, cib_conn);

		} else {
			CMD_ERR("Resource %s not moved: "
				"not-active and no prefered location"
				" specified.\n", rsc_id);
			rc = cib_missing;
		}
		
	} else if(rsc_cmd == 'G') {
		if(rsc_id == NULL) {
			CMD_ERR("Must supply a resource id with -r\n");
			return cib_NOTEXISTS;
		} 
		rc = dump_resource_prop(rsc_id, prop_name, &data_set);

	} else if(rsc_cmd == 'S') {
		xmlNode *msg_data = NULL;
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
		
		rc = cib_conn->cmds->modify(
		    cib_conn, XML_CIB_TAG_RESOURCES, msg_data, cib_options);
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
		rc = delete_resource_attr(rsc_id, prop_set, prop_id, prop_name,
					  cib_conn, &data_set);

	} else if(rsc_cmd == 'P') {
		xmlNode *cmd = NULL;
		
		cmd = create_request(CRM_OP_REPROBE, NULL, host_uname,
				     CRM_SYSTEM_CRMD, crm_system_name, our_pid);
		send_ipc_message(crmd_channel, cmd);
		free_xml(cmd);

	} else if(rsc_cmd == 'R') {
		refresh_lrm(crmd_channel, host_uname);

	} else if(rsc_cmd == 'D') {
		xmlNode *msg_data = NULL;
		
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

		rc = cib_conn->cmds->delete(
		    cib_conn, XML_CIB_TAG_RESOURCES, msg_data, cib_options);
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

