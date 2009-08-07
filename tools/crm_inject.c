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

static struct crm_option long_options[] = {
    /* Top-level Options */
    {"help",    0, 0, '?', "\tThis text"},
    {"version", 0, 0, '$', "\tVersion information"  },
    {"verbose", 0, 0, 'V', "\tIncrease debug output\n"},

    {"-spacer-",0, 0, '-', "\nRequired Options:"},
    {"resource",1, 0, 'r', "The resource to update"},
    {"action",  1, 0, 'a', "The task to inject"},
    {"rc",      1, 0, 'o', "\tThe task's result"},
    
    {"-spacer-", 0, 0, '-', "\nAdditional Options:"},
    {"node",	 1, 0, 'N', "Host uname (defaults to current host)"},
    {"-spacer-",0, 0, '-', ""},
    {"interval", 1, 0, 'i', "The task's interval (defaults to zero)"},
    {"target-rc",1, 0, 't', "The task's expected result (defaults to zero)"},
    {"digest",   1, 0, 'd', "The task's digest"},
    {"-spacer-",0, 0, '-', ""},
    {"class",    1, 0, 'C', "The resource's class"},
    {"provider", 1, 0, 'P', "The resource's provider"},
    {"type",     1, 0, 'T', "The resource's type"},
    
    {"-spacer-",0, 0, '-', "\nData Source:"},
    {"live-check",  0, 0, 'L', "Connect to the CIB and use the current contents as input"},
    {"xml-file",    1, 0, 'x', "Retrieve XML from the named file"},
    {"xml-pipe",    0, 0, 'p', "Retrieve XML from stdin"},
    
    {0, 0, 0, 0}
};

#define node_template "//"XML_CIB_TAG_STATE"[@uname='%s']"
#define rsc_template "//"XML_CIB_TAG_STATE"[@uname='%s']//"XML_LRM_TAG_RESOURCE"[@id='%s']"
#define op_template  "//"XML_CIB_TAG_STATE"[@uname='%s']//"XML_LRM_TAG_RESOURCE"[@id='%s']/"XML_LRM_TAG_RSC_OP"[@id='%s']"
/* #define op_template  "//"XML_CIB_TAG_STATE"[@uname='%s']//"XML_LRM_TAG_RESOURCE"[@id='%s']/"XML_LRM_TAG_RSC_OP"[@id='%s' and @"XML_LRM_ATTR_CALLID"='%d']" */

#define FAKE_TE_ID	"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"


static xmlNode *find_node(xmlNode *cib, const char *node)
{
    char *xpath = NULL;
    xmlNode *match = NULL;
    int max = strlen(rsc_template) + strlen(node) + 1;
    crm_malloc0(xpath, max);
    
    snprintf(xpath, max, node_template, node);
    match = get_xpath_object(xpath, cib, LOG_DEBUG_2);
    
    crm_free(xpath);
    return match;
}

static xmlNode *find_resource(xmlNode *cib, const char *node, const char *resource)
{
    char *xpath = NULL;
    xmlNode *match = NULL;
    int max = strlen(rsc_template) + strlen(resource) + strlen(node) + 1;
    crm_malloc0(xpath, max);
    
    snprintf(xpath, max, rsc_template, node, resource);
    match = get_xpath_object(xpath, cib, LOG_DEBUG_2);
    
    crm_free(xpath);
    return match;
}

static int inject_node(cib_t *cib_conn, char *node)
{
    return 0;
}

static int inject_resource(cib_t *cib_conn, char *node, const char *resource, const char *rclass, const char *rtype, const char *rprovider)
{
    int rc = 0;

    xmlNode *tmp = NULL;
    xmlNode *cib_node = NULL;
    xmlNode *cib_object = NULL;
    xmlNode *cib_resource = NULL;

    rc = cib_conn->cmds->query(cib_conn, NULL, &cib_object, cib_sync_call|cib_scope_local);
    CRM_ASSERT(rc == cib_ok);
    
    cib_resource = find_resource(cib_object, node, resource);
    if(cib_resource != NULL) {
	return cib_ok;
    }
    
    /* One day, add query for class, provider, type */
    
    if(rclass == NULL || rtype == NULL) {
	fprintf(stderr, "Resource %s not found in the status section of %s."
		"  Please supply the class and type to continue\n", resource, node);
	return 1;
	
    } else if(safe_str_neq(rclass, "ocf") 
	      && safe_str_neq(rclass, "lsb")) {
	fprintf(stderr, "Invalid class for %s: %s\n", resource, rclass);
	return 1;
	
    } else if(safe_str_eq(rclass, "ocf") && rprovider == NULL) {
	fprintf(stderr, "Please specify the provider for resource %s\n", resource);
	return 1;
    }

    cib_node = find_node(cib_object, node);
    if(cib_node == NULL) {
	fprintf(stderr, "Node %s not found in the status section\n", node);
	return 1;
    }
    
    crm_info("Injecting new resource %s into %s '%s'", resource, xmlGetNodePath(cib_node), node);
    
    tmp = first_named_child(cib_node, XML_CIB_TAG_LRM);
    if(tmp == NULL) {
	char *node_uuid = NULL;
	determine_host(cib_conn, &node, &node_uuid);

	tmp = create_xml_node(cib_node, XML_CIB_TAG_LRM);
	crm_xml_add(tmp, XML_ATTR_ID, node_uuid);

	crm_free(node_uuid);
    }
    
    tmp = first_named_child(tmp, XML_LRM_TAG_RESOURCES);
    if(tmp == NULL) {
	tmp = create_xml_node(tmp, XML_LRM_TAG_RESOURCES);
    }
    
    cib_resource = create_xml_node(tmp, XML_LRM_TAG_RESOURCE);
    crm_xml_add(cib_resource, XML_ATTR_ID, resource);
    
    crm_xml_add(cib_resource, XML_AGENT_ATTR_CLASS, rclass);
    crm_xml_add(cib_resource, XML_AGENT_ATTR_PROVIDER, rprovider);
    crm_xml_add(cib_resource, XML_ATTR_TYPE, rtype);

    rc = cib_conn->cmds->replace(cib_conn, NULL, cib_object, cib_sync_call|cib_scope_local);
    return rc;
}


static int inject_op(
    cib_t *cib_conn, char *node, const char *resource, const char *task, const char *interval,
    const char *outcome, const char *target_outcome, const char *digest)
{
    int rc = 0;
    int max = 0;
    int call = 1;

    char *key = NULL;
    char *xpath = NULL;
    char *t_key = NULL;
    char *t_magic = NULL;

    xmlNode *cib_object = NULL;
    xmlNode *cib_resource = NULL;
    xmlNode *cib_operation = NULL;

    rc = cib_conn->cmds->query(cib_conn, NULL, &cib_object, cib_sync_call|cib_scope_local);
    CRM_ASSERT(rc == cib_ok);
    
    key = generate_op_key(resource, task, crm_atoi(interval, "0"));
    crm_info("Injecting %s=%s on %s", key, outcome, node);

    max = strlen(op_template) + strlen(resource) + strlen(node) + strlen(key) + 1;
    crm_malloc0(xpath, max);
    
    snprintf(xpath, max, op_template, node, resource, key);
    cib_operation = get_xpath_object(xpath, cib_object, LOG_DEBUG_2);
    
    crm_free(xpath);

    cib_resource = find_resource(cib_object, node, resource);
    if(cib_resource == NULL) {
	fprintf(stderr, "Resource %s not found in %s's status section\n", resource, node);
	return 1;
    }
    
    xml_child_iter(cib_resource, op,
		   int tmp = 0;
		   crm_element_value_int(op, XML_LRM_ATTR_CALLID, &tmp);
		   if(tmp > call) {
		       call = tmp;
		   }
	);
    
    if(cib_operation == NULL) {
	char *node_uuid = NULL;
	determine_host(cib_conn, &node, &node_uuid);
	
	crm_info("Injecting new operation into %s", resource);
	cib_operation = create_xml_node(cib_resource, XML_LRM_TAG_RSC_OP);
	crm_xml_add(cib_operation, XML_LRM_ATTR_RSCID, resource);
	crm_xml_add(cib_operation, XML_LRM_ATTR_TASK, task);
	crm_xml_add(cib_operation, XML_LRM_ATTR_INTERVAL, interval);
	crm_xml_add(cib_operation, XML_LRM_ATTR_TARGET, node);
	crm_xml_add(cib_operation, XML_LRM_ATTR_TARGET_UUID, node_uuid);
    }

    CRM_ASSERT(cib_operation);
    
    t_key = generate_transition_key(call, 1, crm_atoi(target_outcome, "0"), FAKE_TE_ID);
    t_magic = generate_transition_magic(t_key, 0, crm_atoi(outcome, "0"));
    
    crm_info("Updating operation %d: %s", call, xmlGetNodePath(cib_operation));
    crm_xml_add(cib_operation, XML_ATTR_ID, key);
    crm_xml_add(cib_operation, XML_ATTR_ORIGIN, crm_system_name);
    crm_xml_add(cib_operation, XML_ATTR_TRANSITION_MAGIC, t_magic);
    crm_xml_add(cib_operation, XML_ATTR_TRANSITION_KEY, t_key);
    
    crm_xml_add(cib_operation, XML_LRM_ATTR_OPSTATUS, "0");
    crm_xml_add(cib_operation, XML_LRM_ATTR_RC, outcome);
    crm_xml_add_int(cib_operation, XML_LRM_ATTR_CALLID, call);

    if(digest) {
	crm_xml_add(cib_operation, XML_LRM_ATTR_OP_DIGEST, digest);
    }
/*
  crm_xml_add(cib_operation, XML_LRM_ATTR_OP_RESTART, );
  crm_xml_add(cib_operation, XML_LRM_ATTR_RESTART_DIGEST, );
*/
    
    rc = cib_conn->cmds->replace(cib_conn, NULL, cib_object, cib_sync_call|cib_scope_local);
    return rc;
}

int
main(int argc, char ** argv)
{
    int rc = 0;
    cib_t *cib_conn = NULL;
    
    int flag = 0;
    int index = 0;
    int argerr = 0;
    char *node = NULL;

    const char *rclass = NULL;
    const char *rtype = NULL;
    const char *rprovider = NULL;
    
    const char *task = NULL;
    const char *digest = NULL;
    const char *resource = NULL;
    const char *interval = "0";
    const char *outcome = NULL;
    const char *xml_file = NULL;
    const char *target_outcome = "0";
    
    crm_log_init("crm_inject", LOG_DEBUG, FALSE, TRUE, argc, argv);
    crm_set_options("?$Vr:a:o:i:N:Lx:pt:d:C:T:P:", "-r [name] -a [task] -o [outcome] [additional options]",
		    long_options, "Tool for injecting tasks into a configuration");

    if(argc < 2) {
	crm_help('?', LSB_EXIT_EINVAL);
    }

    while (1) {
	flag = crm_get_option(argc, argv,  &index);
	if (flag == -1)
	    break;

	switch(flag) {
	    case 'V':
		alter_debug(DEBUG_INC);
		break;
	    case '?':
	    case '$':
		crm_help(flag, LSB_EXIT_OK);
		break;
	    case 'p':
		xml_file = "-";
		break;
	    case 'x':
		xml_file = optarg;
		break;
	    case 'r':
		resource = optarg;
		break;
	    case 'a':
		task = optarg;
		break;
	    case 'o':
		outcome = optarg;
		break;
	    case 'd':
		digest = optarg;
		break;
	    case 't':
		target_outcome = optarg;
		break;
	    case 'i':
		interval = optarg;
		break;
	    case 'C':
		rclass = optarg;
		break;
	    case 'T':
		rtype = optarg;
		break;
	    case 'P':
		rprovider = optarg;
		break;
	    case 'N':
		node = crm_strdup(optarg);
		break;
	    default:
		++argerr;
		break;
	}
    }

    if (optind > argc) {
	++argerr;
    }

    if(resource == NULL) {
	fprintf(stderr, "No resource specfied\n");
	++argerr;
    }
    if(task == NULL) {
	fprintf(stderr, "No task specfied\n");
	++argerr;
    }
    if(outcome == NULL) {
	fprintf(stderr, "No outcome specfied\n");
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

    cib_conn = cib_new();
    cib_conn->cmds->signon(cib_conn, crm_system_name, cib_command);

    determine_host(cib_conn, &node, NULL);
    
    rc = inject_node(cib_conn, node);
    CRM_ASSERT(rc == cib_ok);

    rc = inject_resource(cib_conn, node, resource, rclass, rtype, rprovider);
    CRM_ASSERT(rc == cib_ok);

    rc = inject_op(cib_conn, node, resource, task, interval, outcome, target_outcome, digest);
    CRM_ASSERT(rc == cib_ok);
    
    rc = cib_conn->cmds->signoff(cib_conn);
    return 0;
}
