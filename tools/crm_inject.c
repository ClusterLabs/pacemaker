/* 
 * Copyright (C) 2009 Andrew Beekhof <andrew@beekhof.net>
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

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#include <sys/param.h>
#include <sys/types.h>

#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/common/util.h>
#include <crm/transition.h>
#include <crm/common/iso8601.h>
#include <crm/pengine/status.h>
#include <allocate.h>

cib_t *global_cib = NULL;
GListPtr op_fail = NULL;
 
#define node_template "//"XML_CIB_TAG_STATE"[@uname='%s']"
#define rsc_template "//"XML_CIB_TAG_STATE"[@uname='%s']//"XML_LRM_TAG_RESOURCE"[@id='%s']"
#define op_template  "//"XML_CIB_TAG_STATE"[@uname='%s']//"XML_LRM_TAG_RESOURCE"[@id='%s']/"XML_LRM_TAG_RSC_OP"[@id='%s']"
/* #define op_template  "//"XML_CIB_TAG_STATE"[@uname='%s']//"XML_LRM_TAG_RESOURCE"[@id='%s']/"XML_LRM_TAG_RSC_OP"[@id='%s' and @"XML_LRM_ATTR_CALLID"='%d']" */

#define FAKE_TE_ID	"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

extern xmlNode * do_calculations(
    pe_working_set_t *data_set, xmlNode *xml_input, ha_time_t *now);

static xmlNode *find_resource(xmlNode *cib_node, const char *resource)
{
    char *xpath = NULL;
    xmlNode *match = NULL;
    const char *node = crm_element_value(cib_node, XML_ATTR_UNAME);
    int max = strlen(rsc_template) + strlen(resource) + strlen(node) + 1;
    crm_malloc0(xpath, max);
    
    snprintf(xpath, max, rsc_template, node, resource);
    match = get_xpath_object(xpath, cib_node, LOG_DEBUG_2);
    
    crm_free(xpath);
    return match;
}

static xmlNode *inject_node(cib_t *cib_conn, char *node)
{
    int rc = cib_ok;
    int max = strlen(rsc_template) + strlen(node) + 1;
    char *xpath = NULL;
    xmlNode *cib_object = NULL;
    crm_malloc0(xpath, max);
    
    snprintf(xpath, max, node_template, node);
    rc = cib_conn->cmds->query(cib_conn, xpath, &cib_object, cib_xpath|cib_sync_call|cib_scope_local);

    if(rc == cib_NOTEXISTS) {
	char *uuid = NULL;

	cib_object = create_xml_node(NULL, XML_CIB_TAG_STATE);	
	determine_host(cib_conn, &node, &uuid);
	crm_xml_add(cib_object, XML_ATTR_UUID,  uuid);
	crm_xml_add(cib_object, XML_ATTR_UNAME, node);
	cib_conn->cmds->create(cib_conn, XML_CIB_TAG_STATUS, cib_object, cib_sync_call|cib_scope_local);

	rc = cib_conn->cmds->query(cib_conn, xpath, &cib_object, cib_xpath|cib_sync_call|cib_scope_local);
    }
    
    CRM_ASSERT(rc == cib_ok);
    return cib_object;
}

static xmlNode *modify_node(cib_t *cib_conn, char *node, gboolean up) 
{
    xmlNode *cib_node = inject_node(cib_conn, node);
    if(up) {
	crm_xml_add(cib_node, XML_CIB_ATTR_HASTATE,   ACTIVESTATUS);
	crm_xml_add(cib_node, XML_CIB_ATTR_INCCM,     XML_BOOLEAN_YES);
	crm_xml_add(cib_node, XML_CIB_ATTR_CRMDSTATE, ONLINESTATUS);
	crm_xml_add(cib_node, XML_CIB_ATTR_JOINSTATE, CRMD_JOINSTATE_MEMBER);
	crm_xml_add(cib_node, XML_CIB_ATTR_EXPSTATE,  CRMD_JOINSTATE_MEMBER);

    } else {
	crm_xml_add(cib_node, XML_CIB_ATTR_HASTATE,   DEADSTATUS);
	crm_xml_add(cib_node, XML_CIB_ATTR_INCCM,     XML_BOOLEAN_NO);
	crm_xml_add(cib_node, XML_CIB_ATTR_CRMDSTATE, OFFLINESTATUS);
	crm_xml_add(cib_node, XML_CIB_ATTR_JOINSTATE, CRMD_JOINSTATE_DOWN);
	crm_xml_add(cib_node, XML_CIB_ATTR_EXPSTATE,  CRMD_JOINSTATE_DOWN);
    }
    
    crm_xml_add(cib_node, XML_ATTR_ORIGIN, crm_system_name);
    return cib_node;
}

static xmlNode *inject_resource(xmlNode *cib_node, const char *resource, const char *rclass, const char *rtype, const char *rprovider)
{
    xmlNode *lrm = NULL;
    xmlNode *container = NULL;
    xmlNode *cib_resource = NULL;

    cib_resource = find_resource(cib_node, resource);
    if(cib_resource != NULL) {
	return cib_resource;
    }
    
    /* One day, add query for class, provider, type */
    
    if(rclass == NULL || rtype == NULL) {
	fprintf(stderr, "Resource %s not found in the status section of %s."
		"  Please supply the class and type to continue\n", resource, ID(cib_node));
	return NULL;
	
    } else if(safe_str_neq(rclass, "ocf") 
	      && safe_str_neq(rclass, "lsb")) {
	fprintf(stderr, "Invalid class for %s: %s\n", resource, rclass);
	return NULL;
	
    } else if(safe_str_eq(rclass, "ocf") && rprovider == NULL) {
	fprintf(stderr, "Please specify the provider for resource %s\n", resource);
	return NULL;
    }

    crm_info("Injecting new resource %s into %s '%s'", resource, xmlGetNodePath(cib_node), ID(cib_node));
    
    lrm = first_named_child(cib_node, XML_CIB_TAG_LRM);
    if(lrm == NULL) {
	const char *node_uuid = ID(cib_node);
	lrm = create_xml_node(cib_node, XML_CIB_TAG_LRM);
	crm_xml_add(lrm, XML_ATTR_ID, node_uuid);
    }
    
    container = first_named_child(lrm, XML_LRM_TAG_RESOURCES);
    if(container == NULL) {
	container = create_xml_node(lrm, XML_LRM_TAG_RESOURCES);
    }
    
    cib_resource = create_xml_node(container, XML_LRM_TAG_RESOURCE);
    crm_xml_add(cib_resource, XML_ATTR_ID, resource);
    
    crm_xml_add(cib_resource, XML_AGENT_ATTR_CLASS, rclass);
    crm_xml_add(cib_resource, XML_AGENT_ATTR_PROVIDER, rprovider);
    crm_xml_add(cib_resource, XML_ATTR_TYPE, rtype);
    
    return cib_resource;
}

static lrm_op_t *create_op(
    xmlNode *cib_resource, const char *task, int interval, int outcome)
{
    lrm_op_t *op = NULL;
    crm_malloc0(op, sizeof(lrm_op_t));
    
    op->app_name = crm_strdup(crm_system_name);

    op->rsc_id = crm_strdup(ID(cib_resource));
    op->interval = interval;
    op->op_type = crm_strdup(task);

    op->rc = outcome;
    op->op_status = 0;
    op->params = NULL; /* TODO: Fill me in */

    op->call_id = 0;
    xml_child_iter(cib_resource, xop,
		   int tmp = 0;
		   crm_element_value_int(xop, XML_LRM_ATTR_CALLID, &tmp);
		   if(tmp > op->call_id) {
		       op->call_id = tmp;
		   }
	);
    op->call_id++;
    
    return op;
}

static xmlNode *inject_op(xmlNode *cib_resource, lrm_op_t *op, int target_rc)
{
    return create_operation_update(cib_resource, op, CRM_FEATURE_SET, target_rc, crm_system_name);
}

static gboolean exec_pseudo_action(crm_graph_t *graph, crm_action_t *action) 
{
    action->confirmed = TRUE;
    update_graph(graph, action);
    return TRUE;
}

static gboolean exec_rsc_action(crm_graph_t *graph, crm_action_t *action) 
{
    int rc = 0;
    lrm_op_t *op = NULL;
    int target_outcome = 0;

    const char *rtype = NULL;
    const char *rclass = NULL;
    const char *resource = NULL;
    const char *rprovider = NULL;
    const char *target_rc_s = crm_meta_value(action->params, XML_ATTR_TE_TARGET_RC);
    
    xmlNode *cib_op = NULL;
    xmlNode *cib_node = NULL;
    xmlNode *cib_object = NULL;
    xmlNode *cib_resource = NULL;
    xmlNode *action_rsc = first_named_child(action->xml, XML_CIB_TAG_RESOURCE);
    
    char *node = crm_element_value_copy(action->xml, XML_LRM_ATTR_TARGET);

    if(safe_str_eq(crm_element_value(action->xml, "operation"), "probe_complete")) {
	crm_notice("Skipping %s op for %s", crm_element_value(action->xml, "operation"), node);
	goto done;
    }
    
    if(action_rsc == NULL) {
	crm_log_xml_err(action->xml, "Bad");
	return FALSE;
    }
    
    resource = ID(action_rsc);
    rclass = crm_element_value(action_rsc, XML_AGENT_ATTR_CLASS);
    rtype = crm_element_value(action_rsc, XML_ATTR_TYPE);
    rprovider = crm_element_value(action_rsc, XML_AGENT_ATTR_PROVIDER);

    if(target_rc_s != NULL) {
	target_outcome = crm_parse_int(target_rc_s, "0");
    }

    CRM_ASSERT(global_cib->cmds->query(global_cib, NULL, &cib_object, cib_sync_call|cib_scope_local) == cib_ok);

    cib_node = inject_node(global_cib, node);
    CRM_ASSERT(cib_node != NULL);

    cib_resource = inject_resource(cib_node, resource, rclass, rtype, rprovider);
    CRM_ASSERT(cib_resource != NULL);

    op = convert_graph_action(cib_resource, action, 0, target_outcome);
    printf(" * Executing action %d: %s_%s_%d on %s\n", action->id, resource, op->op_type, op->interval, node);

    slist_iter(spec, char, op_fail, lpc,
	       
	       char *key = NULL;	       
	       crm_malloc0(key, strlen(spec));
	       snprintf(key, strlen(spec), "%s_%s_%d@%s=", resource, op->op_type, op->interval, node);

	       if(strncasecmp(key, spec, strlen(key)) == 0) {
		   rc = sscanf(spec, "%*[^=]=%d", &op->rc);
		   
		   action->failed = TRUE;
		   graph->abort_priority = INFINITY;
		   printf("\tPretending action %d failed with rc=%d\n", action->id, op->rc);
		   
		   break;
	       }
	);
	
    cib_op = inject_op(cib_resource, op, target_outcome);
    
    rc = global_cib->cmds->modify(global_cib, XML_CIB_TAG_STATUS, cib_node, cib_sync_call|cib_scope_local);
    CRM_ASSERT(rc == cib_ok);

  done:
    action->confirmed = TRUE;
    update_graph(graph, action);
    return TRUE;
}

static gboolean exec_crmd_action(crm_graph_t *graph, crm_action_t *action)
{
    action->confirmed = TRUE;
    update_graph(graph, action);
    return TRUE;
}

#define STATUS_PATH_MAX 512
static gboolean exec_stonith_action(crm_graph_t *graph, crm_action_t *action)
{
    int rc = 0;
    char xpath[STATUS_PATH_MAX];
    char *target = crm_element_value_copy(action->xml, XML_LRM_ATTR_TARGET);
    xmlNode *cib_node = modify_node(global_cib, target, FALSE);	       
    crm_xml_add(cib_node, XML_ATTR_ORIGIN, __FUNCTION__);
    CRM_ASSERT(cib_node != NULL);

    printf(" * Fencing %s\n", target);
    rc = global_cib->cmds->replace(global_cib, XML_CIB_TAG_STATUS, cib_node, cib_sync_call|cib_scope_local);
    CRM_ASSERT(rc == cib_ok);

    snprintf(xpath, STATUS_PATH_MAX, "//node_state[@uname='%s']/%s", target, XML_CIB_TAG_LRM);
    rc = global_cib->cmds->delete(global_cib, xpath, NULL, cib_xpath|cib_sync_call|cib_scope_local);

    snprintf(xpath, STATUS_PATH_MAX, "//node_state[@uname='%s']/%s", target, XML_TAG_TRANSIENT_NODEATTRS);
    rc = global_cib->cmds->delete(global_cib, xpath, NULL, cib_xpath|cib_sync_call|cib_scope_local);
    
    action->confirmed = TRUE;
    update_graph(graph, action);
    return TRUE;
}

static char *
add_list_element(char *list, const char *value) 
{
    int len = 0;
    int last = 0;

    if(value == NULL) {
	return list;
    }
    if(list) {
	last = strlen(list);
    }
    len = last + 2;  /* +1 space, +1 EOS */
    len += strlen(value);
    crm_realloc(list, len);
    sprintf(list + last, " %s", value);
    return list;
}

static void print_cluster_status(pe_working_set_t *data_set) 
{
    char *online_nodes = NULL;
    char *offline_nodes = NULL;

    slist_iter(node, node_t, data_set->nodes, lpc2,
	       const char *node_mode = NULL;
	       
	       if(node->details->unclean) {
		   if(node->details->online && node->details->unclean) {
		       node_mode = "UNCLEAN (online)";
		       
		   } else if(node->details->pending) {
		       node_mode = "UNCLEAN (pending)";

		   } else {
		       node_mode = "UNCLEAN (offline)";
		   }

	       } else if(node->details->pending) {
		   node_mode = "pending";

	       } else if(node->details->standby_onfail && node->details->online) {
		   node_mode = "standby (on-fail)";

	       } else if(node->details->standby) {
		   if(node->details->online) {
		       node_mode = "standby";
		   } else {
		       node_mode = "OFFLINE (standby)";
		   }
		   
	       } else if(node->details->online) {
		   node_mode = "online";
		   online_nodes = add_list_element(online_nodes, node->details->uname);
		   continue;

	       } else {
		   node_mode = "OFFLINE";
		   offline_nodes = add_list_element(offline_nodes, node->details->uname);
		   continue;
	       }
	       
	       if(safe_str_eq(node->details->uname, node->details->id)) {
		   printf("Node %s: %s\n",
			    node->details->uname, node_mode);
	       } else {
		   printf("Node %s (%s): %s\n",
			node->details->uname, node->details->id,
			node_mode);
	       }
	);

    if(online_nodes) {
	printf("Online: [%s ]\n", online_nodes);
	crm_free(online_nodes);
    }
    if(offline_nodes) {
	printf("OFFLINE: [%s ]\n", offline_nodes);
	crm_free(offline_nodes);
    }
    
    fprintf(stdout, "\n");
    slist_iter(rsc, resource_t, data_set->resources, lpc,
	       if(is_set(rsc->flags, pe_rsc_orphan)
		  && rsc->role == RSC_ROLE_STOPPED) {
		   continue;
	       }
	       rsc->fns->print(rsc, NULL, pe_print_printf, stdout);
	);
    fprintf(stdout, "\n");
}

static char *
create_action_name(action_t *action) 
{
	char *action_name = NULL;
	const char *action_host = NULL;
	if(action->node) {
		action_host = action->node->details->uname;
		action_name = crm_concat(action->uuid, action_host, ' ');

	} else if(action->pseudo) {
		action_name = crm_strdup(action->uuid);
		
	} else {
		action_host = "<none>";
		action_name = crm_concat(action->uuid, action_host, ' ');
	}
	if(safe_str_eq(action->task, RSC_CANCEL)) {
	    char *tmp_action_name = action_name;
	    action_name = crm_concat("Cancel", tmp_action_name, ' ');
	    crm_free(tmp_action_name);
	}
	
	return action_name;
}

static void
create_dotfile(pe_working_set_t *data_set, const char *dot_file, gboolean all_actions)
{
    FILE *dot_strm = fopen(dot_file, "w");
    if(dot_strm == NULL) {
	crm_perror(LOG_ERR,"Could not open %s for writing", dot_file);
	return;
    }

    fprintf(dot_strm, " digraph \"g\" {\n");
    slist_iter(
	action, action_t, data_set->actions, lpc,

	const char *style = "filled";
	const char *font  = "black";
	const char *color = "black";
	const char *fill  = NULL;
	char *action_name = create_action_name(action);
	crm_debug_3("Action %d: %p", action->id, action);

	if(action->pseudo) {
	    font = "orange";
	}
		
	style = "dashed";
	if(action->dumped) {
	    style = "bold";
	    color = "green";
			
	} else if(action->rsc != NULL
		  && is_not_set(action->rsc->flags, pe_rsc_managed)) {
	    color = "purple";
	    if(all_actions == FALSE) {
		goto dont_write;
	    }			
			
	} else if(action->optional) {
	    color = "blue";
	    if(all_actions == FALSE) {
		goto dont_write;
	    }			
				
	} else {
	    color = "red";
	    CRM_CHECK(action->runnable == FALSE, ;);	
	}

	action->dumped = TRUE;
	fprintf(dot_strm, "\"%s\" [ style=%s color=\"%s\" fontcolor=\"%s\"  %s%s]\n",
		  action_name, style, color, font, fill?"fillcolor=":"", fill?fill:"");
      dont_write:
	crm_free(action_name);
	);


    slist_iter(
	action, action_t, data_set->actions, lpc,
	slist_iter(
	    before, action_wrapper_t, action->actions_before, lpc2,
	    char *before_name = NULL;
	    char *after_name = NULL;
	    const char *style = "dashed";
	    gboolean optional = TRUE;
	    if(before->state == pe_link_dumped) {
		optional = FALSE;
		style = "bold";
	    } else if(action->pseudo
		      && (before->type & pe_order_stonith_stop)) {
		continue;
	    } else if(before->state == pe_link_dup) {
		continue;
	    } else if(before->type == pe_order_none) {
		continue;
	    } else if(action->dumped && before->action->dumped) {
		optional = FALSE;
	    }

	    if(all_actions || optional == FALSE) {
		before_name = create_action_name(before->action);
		after_name = create_action_name(action);
		fprintf(dot_strm, "\"%s\" -> \"%s\" [ style = %s]\n",
			before_name, after_name, style);
		crm_free(before_name);
		crm_free(after_name);
	    }
	    );
	);
    fprintf(dot_strm, "}\n");
    if(dot_strm != NULL) {
	fflush(dot_strm);
	fclose(dot_strm);
    }
}


static struct crm_option long_options[] = {
    /* Top-level Options */
    {"help",    0, 0, '?', "\tThis text"},
    {"version", 0, 0, '$', "\tVersion information"  },
    {"quiet",   0, 0, 'Q', "\tDisplay only essentialoutput"},
    {"verbose", 0, 0, 'V', "\tIncrease debug output"},

    {"-spacer-",      0, 0, '-', "\nOperations:"},
    {"run",           0, 0, 'R', "\tDetermine the cluster's response to the given configuration and status"},
    {"simulate",      0, 0, 'S', "Simulate the transition's execution and display the resulting cluster status"},
    {"in-place",      0, 0, 'X', "Simulate the transition's execution and store the result back to the input file"},
    {"show-scores",   0, 0, 's', "Show allocation scores"},

    {"-spacer-",  0, 0, '-', "\nSynthetic Cluster Events:"},
    {"node-up",   1, 0, 'u', "\tBring a node online"},
    {"node-down", 1, 0, 'd', "\tTake a node offline"},
    {"node-fail", 1, 0, 'f', "\tMark a node as failed"},
    {"op-inject", 1, 0, 'i', "\t$node;$rsc_$task_$interval;$rc - Inject the specified task before running the simulation"},
    {"set-datetime", 1, 0, 't', "Set date/time"},
    {"quorum",       1, 0, 'q', "\tSpecify a value for quorum"},

    {"-spacer-",     0, 0, '-', "\nOutput Options:"},
    
    {"save-input",   1, 0, 'I', "\tSave the input configuration to the named file"},
    {"save-output",  1, 0, 'O', "Save the output configuration to the named file"},
    {"save-graph",   1, 0, 'G', "\tSave the transition graph (XML format) to the named file"},
    {"save-dotfile", 1, 0, 'D', "Save the transition graph (DOT format) to the named file"},
    {"all-actions",  0, 0, 'a', "\tDisplay all possible actions in the DOT graph - even ones not part of the transition"},
    
    {"-spacer-",    0, 0, '-', "\nData Source:"},
    {"live-check",  0, 0, 'L', "\tConnect to the CIB and use the current contents as input"},
    {"xml-file",    1, 0, 'x', "\tRetrieve XML from the named file"},
    {"xml-pipe",    0, 0, 'p', "\tRetrieve XML from stdin"},
    
    {0, 0, 0, 0}
};

#define quiet_log(fmt, args...) do {	\
	if(quiet == FALSE) {		\
	    printf(fmt , ##args);	\
	}				\
    } while(0)

int
main(int argc, char ** argv)
{
    int rc = 0;
    cib_t *cib_conn = NULL;
    guint modified = 0;

    gboolean quiet = FALSE;
    gboolean store = FALSE;
    gboolean process = FALSE;
    gboolean verbose = FALSE;
    gboolean simulate = FALSE;
    gboolean all_actions = FALSE;

    pe_working_set_t data_set;
    ha_time_t *a_date = NULL;

    const char *quorum = NULL;
    const char *dot_file = NULL;
    const char *graph_file = NULL;
    const char *input_file = NULL;
    const char *output_file = NULL;
    
    int flag = 0;
    int index = 0;
    int argerr = 0;
    char *use_date = NULL;
    lrm_op_t *op = NULL;

    xmlNode *cib_object = NULL;
    xmlNode *cib_node = NULL;
    xmlNode *cib_resource = NULL;
    xmlNode *cib_op = NULL;

    GListPtr node_up = NULL;
    GListPtr node_down = NULL;
    GListPtr node_fail = NULL;
    GListPtr op_inject = NULL;
    
    const char *xml_file = "-";

    crm_log_init("crm_inject", LOG_ERR, FALSE, FALSE, argc, argv);
    crm_set_options("?$VQx:Lpu:d:f:i:RSXD:G:I:O:sa", "datasource operation [additional options]",
		    long_options, "Tool for simulating the cluster's response to events");

    if(argc < 2) {
	crm_help('?', LSB_EXIT_EINVAL);
    }

    while (1) {
	flag = crm_get_option(argc, argv,  &index);
	if (flag == -1)
	    break;

	switch(flag) {
	    case 'V':
		verbose = TRUE;
		alter_debug(DEBUG_INC);
		cl_log_enable_stderr(TRUE);
		break;
	    case '?':
	    case '$':
		crm_help(flag, LSB_EXIT_OK);
		break;
	    case 'p':
		xml_file = "-";
		break;
	    case 'Q':
		quiet = TRUE;
		break;
	    case 'L':
		xml_file = NULL;
		break;
	    case 'x':
		xml_file = optarg;
		break;
	    case 'u':
		modified++;
		node_up = g_list_append(node_up, optarg);
		break;
	    case 'd':
		modified++;
		node_down = g_list_append(node_down, optarg);
		break;
	    case 'f':
		modified++;
		node_fail = g_list_append(node_fail, optarg);
		break;
	    case 'i':
		modified++;
		op_inject = g_list_append(op_inject, optarg);
		break;
	    case 'q':
		modified++;
		quorum = optarg;
		break;	
	    case 'a':
		all_actions = TRUE;
		break;
	    case 's':
		process = TRUE;
		show_scores = TRUE;
		break;
	    case 'S':
		process = TRUE;
		simulate = TRUE;
		break;
	    case 'X':
		store = TRUE;
		process = TRUE;
		simulate = TRUE;
		break;
	    case 'R':
		process = TRUE;
		break;
	    case 'D':
		dot_file = optarg;
		break;
	    case 'G':
		graph_file = optarg;
		break;
	    case 'I':
		input_file = optarg;
		break;
	    case 'O':
		store = TRUE;
		simulate = TRUE;
		output_file = optarg;
		break;
	    default:
		++argerr;
		break;
	}
    }

    if (optind > argc) {
	++argerr;
    }

    if (argerr) {
	crm_help('?', LSB_EXIT_GENERIC);
    }

    if(xml_file == NULL) {
	/* Use live CIB */

    } else if(safe_str_eq(xml_file, "-")) {
	crm_err("Piping from stdin is not yet supported");
	return 1;
	
	/* cib_object = filename2xml(NULL); */
	/* write to a temp file */
	
    } else {
	setenv("CIB_file", xml_file, 1);
    }

    if(output_file || store == FALSE) {
	xmlNode *output = NULL;

	if(output_file == NULL) {
	    char *pid = crm_itoa(getpid());
	    output_file = get_shadow_file(pid);
	}
	
	cib_conn = cib_new_no_shadow();
	rc = cib_conn->cmds->signon(cib_conn, crm_system_name, cib_command);
	if(rc == cib_ok) {
	    rc = cib_conn->cmds->query(cib_conn, NULL, &output, cib_sync_call);
	}
	if(rc != cib_ok) {
	    fprintf(stderr, "Could not connect to the CIB: %s\n", cib_error2string(rc));
	    return rc;
	}
	
	rc = write_xml_file(output, output_file, FALSE);
	if(rc < 0) {
	    fprintf(stderr, "Could not create '%s': %s\n", output_file, strerror(errno));
	    return rc;
	}
	setenv("CIB_file", output_file, 1);
	if(simulate) {
	    quiet_log("\nUsing %s for simulation results\n", output_file);
	}
	rc = cib_conn->cmds->signoff(cib_conn);
	cib_delete(cib_conn);
    }
    
    cib_conn = cib_new();
    global_cib = cib_conn;
    cib_conn->cmds->signon(cib_conn, crm_system_name, cib_command);

    if(quiet == FALSE) {
	rc = cib_conn->cmds->query(cib_conn, NULL, &cib_object, cib_sync_call|cib_scope_local);
	CRM_ASSERT(rc == cib_ok);
	
	set_working_set_defaults(&data_set);
	data_set.input = cib_object;
	data_set.now = new_ha_date(TRUE);
	
	cluster_status(&data_set);
	quiet_log("\nCurrent cluster status:\n");
	print_cluster_status(&data_set);
	if(process == FALSE && modified == FALSE) {
	    return 0;
	}	
    }    

    if(modified || use_date) {
	quiet_log("Performing requested %s modifications\n", store?"permanent":"temporary");
    }
    
    if(use_date != NULL) {
	a_date = parse_date(&use_date);
	quiet_log(" + Setting effective cluster time: %s", use_date);
	log_date(LOG_WARNING, "Set fake 'now' to", a_date, ha_log_date|ha_log_time);
    }
    
    if(quorum) {
	xmlNode *top = create_xml_node(NULL, XML_TAG_CIB);
	quiet_log(" + Setting quorum: %s\n", quorum);
	/* crm_xml_add(top, XML_ATTR_DC_UUID, dc_uuid);	     */
	crm_xml_add(top, XML_ATTR_HAVE_QUORUM, quorum);

	rc = global_cib->cmds->modify(cib_conn, NULL, top, cib_sync_call|cib_scope_local);
	CRM_ASSERT(rc == cib_ok);
    }
    
    slist_iter(node, char, node_up, lpc,
	       quiet_log(" + Bringing node %s online\n", node);
	       cib_node = modify_node(cib_conn, node, TRUE);	       
	       CRM_ASSERT(cib_node != NULL);

	       rc = global_cib->cmds->modify(global_cib, XML_CIB_TAG_STATUS, cib_node, cib_sync_call|cib_scope_local);
	       CRM_ASSERT(rc == cib_ok);
	);

    slist_iter(node, char, node_down, lpc,
	       quiet_log(" + Taking node %s offline\n", node);
	       cib_node = modify_node(cib_conn, node, FALSE);	       
	       CRM_ASSERT(cib_node != NULL);

	       rc = global_cib->cmds->modify(global_cib, XML_CIB_TAG_STATUS, cib_node, cib_sync_call|cib_scope_local);
	       CRM_ASSERT(rc == cib_ok);
	);

    slist_iter(node, char, node_fail, lpc,
	       quiet_log(" + Failing node %s\n", node);
	       cib_node = modify_node(cib_conn, node, TRUE);	       
	       crm_xml_add(cib_node, XML_CIB_ATTR_INCCM, XML_BOOLEAN_NO);
	       CRM_ASSERT(cib_node != NULL);

	       rc = global_cib->cmds->modify(global_cib, XML_CIB_TAG_STATUS, cib_node, cib_sync_call|cib_scope_local);
	       CRM_ASSERT(rc == cib_ok);
	);


    slist_iter(spec, char, op_inject, lpc,

	       int rc = 0;
	       int outcome = 0;
	       int interval = 0;

	       char *key = NULL;
	       char *node = NULL;
	       char *task = NULL;
	       char *resource = NULL;

	       const char *rtype = NULL;
	       const char *rclass = NULL;
	       const char *rprovider = NULL;

	       resource_t *rsc = NULL;
	       quiet_log(" + Injecting %s into the configuration\n", spec);
	       
	       crm_malloc0(key, strlen(spec));
	       crm_malloc0(node, strlen(spec));
	       rc = sscanf(spec, "%[^@]@%[^=]=%d", key, node, &outcome);
	       CRM_CHECK(rc == 3, fprintf(stderr, "Invalid operation spec: %s.  Only found %d fields\n", spec, rc); continue);
	       
	       parse_op_key(key, &resource, &task, &interval);

	       rsc = pe_find_resource(data_set.resources, resource);
	       CRM_CHECK(rsc != NULL, fprintf(stderr, "Invalid resource name: %s\n", resource); continue);

	       rclass = crm_element_value(rsc->xml, XML_AGENT_ATTR_CLASS);
	       rtype = crm_element_value(rsc->xml, XML_ATTR_TYPE);
	       rprovider = crm_element_value(rsc->xml, XML_AGENT_ATTR_PROVIDER);
	       
	       cib_node = inject_node(cib_conn, node);
	       CRM_ASSERT(cib_node != NULL);

	       cib_resource = inject_resource(cib_node, resource, rclass, rtype, rprovider);
	       CRM_ASSERT(cib_resource != NULL);
	       
	       op = create_op(cib_resource, task, interval, outcome);
	       CRM_ASSERT(op != NULL);
	       
	       cib_op = inject_op(cib_resource, op, 0);
	       CRM_ASSERT(cib_op != NULL);
	       
	       rc = cib_conn->cmds->modify(cib_conn, XML_CIB_TAG_STATUS, cib_node, cib_sync_call|cib_scope_local);
	       CRM_ASSERT(rc == cib_ok);
	);
    
    if(process) {
	crm_graph_t *transition = NULL;
	enum transition_status graph_rc = -1;

	crm_graph_functions_t exec_fns = 
	    {
		exec_pseudo_action,
		exec_rsc_action,
		exec_crmd_action,
		exec_stonith_action,
	    };

	set_graph_functions(&exec_fns);

	if(show_scores) {
	    printf("Allocation scores:\n");
	}
	
	rc = cib_conn->cmds->query(cib_conn, NULL, &cib_object, cib_sync_call|cib_scope_local);
	CRM_ASSERT(rc == cib_ok);	

	do_calculations(&data_set, cib_object, a_date);

	if(show_scores) {
	    printf("\n");
	}
	
	if(graph_file != NULL) {
	    char *msg_buffer = dump_xml_formatted(data_set.graph);
	    FILE *graph_strm = fopen(graph_file, "w");
	    if(graph_strm == NULL) {
		crm_perror(LOG_ERR,"Could not open %s for writing", graph_file);

	    } else {
		if(fprintf(graph_strm, "%s\n\n", msg_buffer) < 0) {
		    crm_perror(LOG_ERR,"Write to %s failed", graph_file);
		}
		fflush(graph_strm);
		fclose(graph_strm);
	    }
	    crm_free(msg_buffer);
	}

	if(dot_file != NULL) {
	    create_dotfile(&data_set, dot_file, all_actions);
	}

	if(quiet == FALSE) {
	    int level = crm_log_level;
	    if(level < LOG_NOTICE) {
		crm_log_level = LOG_NOTICE;
	    }
	    
	    quiet_log("Transition Summary:\n");
	    cl_log_enable_stderr(TRUE);
	    slist_iter(
		rsc, resource_t, data_set.resources, lpc,
		LogActions(rsc, &data_set);
		);

	    crm_log_level = level;
	    cl_log_enable_stderr(verbose);
	}

	if(simulate) {
	    quiet_log("\nExecuting cluster transition:\n");
	    transition = unpack_graph(data_set.graph, crm_system_name);
	    print_graph(LOG_DEBUG, transition);
	    
	    do {
		graph_rc = run_graph(transition);
		
	    } while(graph_rc == transition_active);
	    
	    if(graph_rc != transition_complete) {
		fprintf(stderr, "Transition failed: %s\n", transition_status(graph_rc));
		print_graph(LOG_ERR, transition);
	    }
	    destroy_graph(transition);
	    CRM_CHECK(graph_rc == transition_complete, fprintf(stderr, "An invalid transition was produced"));
	}
    }
    
    rc = cib_conn->cmds->query(cib_conn, NULL, &cib_object, cib_sync_call|cib_scope_local);
    CRM_ASSERT(rc == cib_ok);

    if(quiet) {
    } else if(simulate || (process == FALSE && modified == 0)) {
	quiet_log("\nRevised cluster status:\n");
	set_working_set_defaults(&data_set);
	data_set.input = cib_object;
	data_set.now = a_date;
	
	cluster_status(&data_set);
	print_cluster_status(&data_set);
    }
    
    rc = cib_conn->cmds->signoff(cib_conn);
    cib_delete(cib_conn);
    fflush(stderr);
    
    return 0;
}
