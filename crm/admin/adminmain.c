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

#include <crm/common/crm.h>

#include <portability.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <hb_api.h>
#include <apphb.h>

#include <clplumbing/ipc.h>
#include <clplumbing/Gmain_timeout.h>
#include <clplumbing/cl_log.h>
#include <clplumbing/cl_signal.h>
#include <clplumbing/lsb_exitcodes.h>
#include <clplumbing/uids.h>
#include <clplumbing/realtime.h>
#include <clplumbing/GSource.h>
#include <clplumbing/cl_poll.h>

#include <crm/common/crmutils.h>
#include <crm/common/msgutils.h>
#include <crm/common/ipcutils.h>
#include <crm/common/xmltags.h>
#include <crm/common/xmlvalues.h>
#include <crm/cib/cibprimatives.h>

#define OPTARGS	"V?i:o:D:C:S:HA:U:M:I:EWRFt:m:a:d:w:c:r:p:s:"

#include <getopt.h>

GMainLoop*  mainloop = NULL;
const char* daemon_name = "crmadmin";

void usage(const char* cmd, int exit_status);
ll_cluster_t* ha_register(ll_cluster_t* hb_fd);
void test_messaging(ll_cluster_t* hb_fd);
ll_cluster_t* do_init(void);
int do_work(ll_cluster_t *hb_fd);
xmlNodePtr handleCreate(void);
xmlNodePtr handleDelete(void);
xmlNodePtr handleModify(void);
gboolean decodeNVpair(const char *srcstring, char separator, char **name, char **value);
gboolean hb_input_dispatch(int fd, gpointer user_data);
void hb_input_destroy(gpointer user_data);
void admin_msg_callback(const struct ha_msg* msg, void* private_data);
xmlNodePtr wrapUpdate(xmlNodePtr update, const char *section_name);


// from cibmessages.c
extern xmlNodePtr createCibRequest(gboolean isLocal, const char *operation, const char *section,
				   const char *verbose, xmlNodePtr data);



gboolean DO_CREATE  = FALSE;
gboolean DO_MODIFY  = FALSE;
gboolean DO_DELETE  = FALSE;
gboolean DO_QUERY   = FALSE;
gboolean BE_VERBOSE = FALSE;
int expected_responses = 1;

gboolean DO_HEALTH       = FALSE;
gboolean DO_ELECT_DC     = FALSE;
gboolean DO_WHOIS_DC     = FALSE;
gboolean DO_RECALC_TREE  = FALSE;
gboolean DO_FLUSH_RECALC = FALSE;

typedef struct str_list_s 
{
	int num_items;
	char *value;
	struct str_list_s *next;
} str_list_t;

const char *verbose = "false";
char *id = NULL;
char *obj_type = NULL;
char *description = NULL;
char *clear = NULL;
char *status = NULL;
char *disconnect = NULL;
char *unload_ha = NULL;
char *migrate_from = NULL;
char *migrate_res = NULL;
char *subtype = NULL;
char *priority = NULL;
char *res_timeout = NULL;
char *max_instances = NULL;
str_list_t *list_add = NULL;
str_list_t *list_add_last = NULL;
str_list_t *list_del = NULL;
str_list_t *list_del_last = NULL;
gboolean list_wipe = FALSE;
char *reset = NULL;
int num_resources = 0;
char *resource[2];

char *instance = NULL;
char *node = NULL;

int operation_status = 0;




int
main(int argc, char ** argv)
{
    
    cl_log_set_entity(daemon_name);
    cl_log_enable_stderr(TRUE);
    cl_log_set_facility(LOG_USER);
    
    int	argerr = 0;
    int flag;

    list_add = (str_list_t *)ha_malloc(sizeof(struct str_list_s));
    list_add_last = list_add;
    list_del = (str_list_t *)ha_malloc(sizeof(struct str_list_s));
    list_del_last = list_del;
    list_add->num_items = 0;
    list_del->num_items = 0;

//    while ((flag = getopt(argc, argv, OPTARGS)) != EOF) {
//    while ((flag = getopt_long(argc, argv, OPTARGS)) != EOF) {

    while (1) {
//	int this_option_optind = optind ? optind : 1;
	int option_index = 0;
	static struct option long_options[] = {
	    // Top-level Options
	    {"daemon"  , 0, 0, 0},
	    {"query"   , 0, 0, 0},
	    {"create"  , 0, 0, 0},
	    {"modify"  , 0, 0, 0},
	    {"delete"  , 0, 0, 0},
	    {"instance"  , 0, 0, 0}, // undocumented, for testing only
	    {"node"  , 0, 0, 0}, // undocumented, for testing only
	    {"verbose" , 0, 0, 'V'},
	    {"help" , 0, 0, '?'},

	    // common options
	    {"id"         , 1, 0, 'i'},
	    {"obj_type"   , 1, 0, 'o'},
	    {"description", 1, 0, 'D'},

	    // daemon options
	    {"reset"            , 1, 0, 'C'},
	    {"status"           , 1, 0, 'S'},
	    {"health"           , 0, 0, 'H'},
	    {"disconnect"       , 1, 0, 'A'},
	    {"unload_ha"        , 1, 0, 'U'},
	    {"migrate_from"     , 1, 0, 'M'},
	    {"migrate_res"      , 1, 0, 'I'},
	    {"elect_dc"         , 0, 0, 'E'},
	    {"whois_dc"         , 0, 0, 'W'},
	    {"recalc_tree"      , 0, 0, 'R'},
	    {"flush_recalc_tree", 0, 0, 'F'},

	    // create_modify options
	    {"subtype"       , 1, 0, 's'},
	    {"max_instances" , 1, 0, 'm'},
	    {"list_add"      , 1, 0, 'a'},
	    {"list_del"      , 1, 0, 'd'},
	    {"list_wipe"     , 0, 0, 'w'},
	    {"clear"         , 1, 0, 'c'},
	    {"resource"      , 1, 0, 'r'},
	    {"priority"      , 1, 0, 'p'},
	    {"res_timeout"   , 1, 0, 't'},

	    {0, 0, 0, 0}
	};

	flag = getopt_long (argc, argv, OPTARGS,
			    long_options, &option_index);
	if (flag == -1)
	    break;
	
	switch(flag) {
	    case 0:
		printf ("option %s", long_options[option_index].name);
		if (optarg)
		    printf (" with arg %s", optarg);
		printf ("\n");

		if(     strcmp("create" , long_options[option_index].name) == 0) DO_CREATE  = TRUE;
		else if(strcmp("modify" , long_options[option_index].name) == 0) DO_MODIFY  = TRUE;
		else if(strcmp("delete" , long_options[option_index].name) == 0) DO_DELETE  = TRUE;
		else if(strcmp("query"  , long_options[option_index].name) == 0) DO_QUERY   = TRUE;
		else if(strcmp("instance"  , long_options[option_index].name) == 0)
		{
		     	instance = strdup(optarg);
			if (!instance) {
			     	printf ("?? instance option memory "
			    			"allocation failed ??\n");
				argerr++;
			}
		}
		else if(strcmp("node"  , long_options[option_index].name) == 0)
		{
			node = strdup(optarg);
			if (!node) {
			     	printf ("?? node option memory "
			    			"allocation failed ??\n");
				argerr++;
			}
		}
		else 
		{
		    printf ("?? Long option (--%s) is not yet properly supported ??\n", long_options[option_index].name);
		    ++argerr;
		}
		break;
/* a sample test for multiple instance
		if (digit_optind != 0 && digit_optind != this_option_optind)
		    printf ("digits occur in two different argv-elements.\n");
		digit_optind = this_option_optind;
		printf ("option %c\n", c);
*/

	    case 'V':
		BE_VERBOSE = TRUE;
		verbose = "true";
		break;
	    case '?':
		usage(daemon_name, LSB_EXIT_OK);
		break;
	    case 'i':
		id = strdup(optarg);
		if (!id) {
			printf ("?? id option memory allocation failed ??\n");
			argerr++;
		}
		break;
	    case 'o':
		node = strdup(obj_type);
		if (!node) {
			printf ("?? obj_type option memory "
					"allocation failed ??\n");
			argerr++;
		}
		break;
	    case 'D':
		description = strdup(optarg);
		if (!description) {
			printf ("?? description option memory "
					"allocation failed ??\n");
			argerr++;
		}
		break;
	    case 'C':
		printf ("Option %c is not yet supported\n", flag);
		++argerr;
		break;
	    case 'S':
		DO_HEALTH       = TRUE;
		status = strdup(optarg);
		if (!status) {
			printf ("?? status option memory "
					"allocation failed ??\n");
			argerr++;
		}
		break;
	    case 'H':
		DO_HEALTH       = TRUE;
		break;
	    case 'A':
		printf ("Option %c is not yet supported\n", flag);
		++argerr;
		break;
	    case 'U':
		printf ("Option %c is not yet supported\n", flag);
		++argerr;
		break;
	    case 'M':
		printf ("Option %c is not yet supported\n", flag);
		++argerr;
		break;
	    case 'I':
		printf ("Option %c is not yet supported\n", flag);
		++argerr;
		break;
	    case 'E':
		DO_ELECT_DC     = TRUE;
		printf ("Option %c is not yet supported\n", flag);
		++argerr;
		break;
	    case 'W':
		DO_WHOIS_DC     = TRUE;
		printf ("Option %c is not yet supported\n", flag);
		++argerr;
		break;
	    case 'R':
		DO_RECALC_TREE  = TRUE;
		printf ("Option %c is not yet supported\n", flag);
		++argerr;
		break;
	    case 'F':
		DO_FLUSH_RECALC = TRUE;
		printf ("Option %c is not yet supported\n", flag);
		++argerr;
		break;
	    case 'm':
		max_instances = strdup(optarg);
		if (!max_instances) {
			printf ("?? max_instances option memory "
					"allocation failed ??\n");
			argerr++;
		}
		break;
	    case 'a':
		list_add->num_items++;
		if(list_add->num_items != 1)
		    list_add_last->next = (str_list_t *)ha_malloc(
				    sizeof(str_list_t));
		list_add_last->value = strdup(optarg);
		if (!list_add_last->value) {
			printf ("?? option memory allocation failed ??\n");
			argerr++;
			break;
		}
		list_add_last->next = NULL;
		break;
	    case 'd':
		list_del->num_items++;
		if(list_del->num_items != 1)
		    list_del_last->next = (str_list_t *)ha_malloc(sizeof(str_list_t));
		list_add_last->value = strdup(optarg);
		if (!list_add_last->value) {
			printf ("?? option memory allocation failed ??\n");
			argerr++;
			break;
		}
		list_del_last->next = NULL;
		break;
	    case 'w':
		list_wipe = TRUE;
		break;
	    case 'c':
		clear = strdup(optarg);
		if (!clear) {
			printf ("?? clear option memory "
					"allocation failed ??\n");
			argerr++;
		}
		break;
	    case 'r':
		if(num_resources > 1) {
			printf ("?? too many (> 2) resources ?? \n");
			argerr++;
			break;
		}
	    	resource[num_resources] = strdup(optarg);
		if (!resource[num_resources]) {
			printf ("?? resource[%d] option memory allocation "
					"failed ??\n", num_resources);
			argerr++;
		}
		else {
			num_resources++;
		}
		break;
	    case 't':
		res_timeout = strdup(optarg);
		if (!res_timeout) {
			printf ("?? res_timeout option memory "
					"allocation failed ??\n");
			argerr++;
		}
		break;
	    case 'p':
		priority = strdup(optarg);
		if (!priority) {
			printf ("?? priority option memory "
					"allocation failed ??\n");
			argerr++;
		}
		break;
	    case 's':
		subtype = strdup(optarg);
		if (!subtype) {
			printf ("?? subtype option memory "
					"allocation failed ??\n");
			argerr++;
		}
		break;
	    default:
		printf ("?? getopt returned character code 0%o ??\n", flag);
		++argerr;
		break;
	}
    }

    if (optind < argc) {
	printf ("non-option ARGV-elements: ");
	while (optind < argc)
	    printf ("%s ", argv[optind++]);
	printf ("\n");
    }
    
    if (optind > argc) {
	++argerr;
    }
    
    if (argerr) {
	usage(daemon_name,LSB_EXIT_GENERIC);
    }

    ll_cluster_t *hb_fd = do_init();
    if(hb_fd != NULL)
    {
	if(do_work(hb_fd) > 0)
	{
	    /* wait for the reply by creating a mainloop and running it until
	     * the callbacks are invoked...
	     */
	    mainloop = g_main_new(FALSE);
	    cl_log(LOG_INFO, "%s waiting for reply from the local CRM", daemon_name);
	    
	    g_main_run(mainloop);
	    return_to_orig_privs();
	}
	else
	{
//	    cl_log(LOG_ERR, "No message to send");
	    operation_status = -1;
	}
    }
    else
    {
	cl_log(LOG_ERR, "Init failed, could not perform requested operations");	
	operation_status = -2;
    }
    
    cl_log(LOG_DEBUG, "%s exiting normally", daemon_name);	
    return operation_status;
}

xmlNodePtr
handleCreate(void)
{
    if(subtype == NULL) return NULL;// error
    xmlNodePtr root, new_xml_node;
    const char *section_name = NULL;
    
    if(strcmp("node", obj_type) == 0)
    {
	section_name = XML_CIB_TAG_NODES;
	if(id == NULL || subtype == NULL || description == NULL) return NULL;

	new_xml_node = newHaNode(id, subtype);
	if(description != NULL) xmlSetProp(new_xml_node, XML_ATTR_DESC, description);
    }
    else if(strcmp("resource", obj_type) == 0)
    {
	section_name = XML_CIB_TAG_RESOURCES;
	if(id == NULL || subtype == NULL || description == NULL) return NULL;

	new_xml_node = newResource(id, subtype, description, max_instances);
	if(priority    != NULL) xmlSetProp(new_xml_node, XML_CIB_ATTR_PRIORITY   , priority);
	if(res_timeout  != NULL) xmlSetProp(new_xml_node, XML_CIB_ATTR_RESTIMEOUT , res_timeout);
	
	// add Nodes To Resources
	if(list_add->num_items > 0)
	{
	    str_list_t *iter = list_add;
	    while(list_add != list_add_last)
	    {
		char *name  = NULL;
		char *value = NULL;
		if(decodeNVpair(iter->value, '=', &name, &value))
		{
		    xmlNodePtr node_entry = xmlNewNode(NULL, XML_CIB_ATTR_NODEREF);			
		    xmlSetProp(node_entry, XML_ATTR_ID, name);
		    xmlSetProp(node_entry, XML_CIB_ATTR_WEIGHT, value);
		    xmlSetProp(node_entry, XML_ATTR_TSTAMP, getNow());
		    xmlSetProp(node_entry, XML_CIB_ATTR_ACTION, "add");
		    xmlAddChild(new_xml_node, node_entry);
		}
		iter = iter->next;
	    }
	}
    }
    // move somewhere else... this could get big
    else if(strcmp("constraint", obj_type) == 0)
    {
	section_name = XML_CIB_TAG_CONSTRAINTS;
	if(strcmp(CIB_VAL_CONTYPE_BLOCK, subtype) == 0)
	{
	    if(clear == NULL || description == NULL || resource[0] == NULL || id == NULL) return NULL;

	    id = (char*)ha_malloc(256*(sizeof(char)));
	    sprintf(id, "failed-%s-%s-%s", node, resource[0], instance);
	    new_xml_node = newConstraint(id);

	    xmlSetProp(new_xml_node, XML_CIB_ATTR_CONTYPE, CIB_VAL_CONTYPE_BLOCK);
	    xmlSetProp(new_xml_node, XML_CIB_ATTR_RESID1, resource[0]);
	    xmlSetProp(new_xml_node, XML_CIB_ATTR_CLEAR, clear);
	    
	    xmlNodePtr node_entry = xmlNewNode(NULL, XML_CIB_TAG_NVPAIR);			
	    xmlSetProp(node_entry, XML_ATTR_ID, "blockHost");
//			xmlSetProp(node_entry, XML_CIB_ATTR_VARTYPE, subtype);
	    xmlSetProp(node_entry, XML_CIB_ATTR_VARVALUE, node);
	    xmlSetProp(node_entry, XML_CIB_ATTR_ACTION, "add");
	    xmlAddChild(new_xml_node, node_entry);
	}
	else if(strcmp(CIB_VAL_CONTYPE_VAR, subtype) == 0)
	{
	    if(list_add->num_items == 1 || description == NULL ||  id == NULL || subtype == NULL || num_resources != 1) return NULL;

	    new_xml_node = newConstraint(id);

	    xmlSetProp(new_xml_node, XML_CIB_ATTR_CONTYPE, subtype);
	    xmlSetProp(new_xml_node, XML_CIB_ATTR_RESID1, resource[0]);
	    
	    // add Name Value pairs To constraint s
	    if(list_add->num_items > 0)
	    {
		str_list_t *iter = list_add;
		while(list_add != list_add_last)
		{
		    char *name  = NULL;
		    char *value = NULL;
		    if(decodeNVpair(iter->value, '=', &name, &value))
		    {
			xmlNodePtr node_entry = xmlNewNode(NULL, XML_CIB_TAG_NVPAIR);			
			xmlSetProp(node_entry, XML_ATTR_ID, name);
//			xmlSetProp(node_entry, XML_CIB_ATTR_VARTYPE, subtype);
			xmlSetProp(node_entry, XML_CIB_ATTR_VARVALUE, value);
			xmlSetProp(node_entry, XML_CIB_ATTR_ACTION, "add");
			xmlAddChild(new_xml_node, node_entry);
		    }
		    iter = iter->next;
		}
	    }
	}
	else
	{
	    if(id == NULL || description == NULL || subtype == NULL ||  num_resources != 2) return NULL;
	    new_xml_node = newConstraint(id);

	    xmlSetProp(new_xml_node, XML_CIB_ATTR_CONTYPE, subtype);
	    xmlSetProp(new_xml_node, XML_CIB_ATTR_RESID1, resource[0]);
	    xmlSetProp(new_xml_node, XML_CIB_ATTR_RESID2, resource[1]);
	}
	if(description != NULL) xmlSetProp(new_xml_node, XML_ATTR_DESC, description);
    }
    else
    {
	cl_log(LOG_INFO, "Object Type (%s) not supported", obj_type);
	return NULL;
    }
    
    // create the cib request
    root = wrapUpdate(new_xml_node, section_name);

    return root;
    
}

xmlNodePtr
handleDelete(void)
{
    if(subtype == NULL) return NULL;// error
    xmlNodePtr root, new_xml_node = NULL;;
    const char *section_name = NULL;
    
    if(strcmp("node", obj_type) == 0)
    {
	section_name = XML_CIB_TAG_NODES;
	if(id == NULL) return NULL;

	new_xml_node = xmlNewNode( NULL, XML_CIB_TAG_NODE);
	xmlSetProp(new_xml_node, XML_ATTR_ID, id);
	if(subtype != NULL) xmlSetProp(new_xml_node, XML_CIB_ATTR_NODETYPE, subtype);
    }
    else if(strcmp("resource", obj_type) == 0)
    {
	section_name = XML_CIB_TAG_RESOURCES;
	if(id == NULL) return NULL;

	new_xml_node = xmlNewNode( NULL, XML_CIB_TAG_RESOURCE);
	xmlSetProp(new_xml_node, XML_ATTR_ID, id);
	if(subtype != NULL) xmlSetProp(new_xml_node, XML_CIB_ATTR_NODETYPE, subtype);
    }
    else if(strcmp("constraint", obj_type) == 0)
    {
	section_name = XML_CIB_TAG_CONSTRAINTS;
	if(id == NULL) return NULL;

	new_xml_node = xmlNewNode( NULL, XML_CIB_TAG_RESOURCE);
	xmlSetProp(new_xml_node, XML_ATTR_ID, id);
	if(subtype != NULL) xmlSetProp(new_xml_node, XML_CIB_ATTR_NODETYPE, subtype);
    }
    else
    {
	cl_log(LOG_INFO, "Object Type (%s) not supported", obj_type);
	return NULL;
    }
    
    // create the cib request
    root = wrapUpdate(new_xml_node, section_name);

    return root;
    
}

xmlNodePtr
handleModify(void)
{
    if(subtype == NULL) return NULL;// error
    xmlNodePtr root, new_xml_node = NULL;
    const char *section_name = NULL;
    
    if(strcmp("node", obj_type) == 0)
    {
	section_name = XML_CIB_TAG_NODES;
	if(id == NULL) return NULL;
	new_xml_node = xmlNewNode( NULL, XML_CIB_TAG_NODE);
	xmlSetProp(new_xml_node, XML_ATTR_ID, id);

	if(subtype != NULL) xmlSetProp(new_xml_node, XML_CIB_ATTR_NODETYPE, subtype);
    }
    else if(strcmp("resource", obj_type) == 0)
    {
	section_name = XML_CIB_TAG_RESOURCES;

	if(id == NULL) return NULL;
	new_xml_node = xmlNewNode( NULL, XML_CIB_TAG_RESOURCE);
	xmlSetProp(new_xml_node, XML_ATTR_ID, id);

	if(subtype       != NULL) xmlSetProp(new_xml_node, XML_CIB_ATTR_RESTYPE     , subtype);
	if(description   != NULL) xmlSetProp(new_xml_node, XML_ATTR_DESC            , description);
	if(max_instances != NULL) xmlSetProp(new_xml_node, XML_CIB_ATTR_MAXINSTANCE , max_instances);
	if(priority      != NULL) xmlSetProp(new_xml_node, XML_CIB_ATTR_PRIORITY    , priority);
	if(res_timeout   != NULL) xmlSetProp(new_xml_node, XML_CIB_ATTR_RESTIMEOUT , res_timeout);
	xmlSetProp(new_xml_node, XML_ATTR_TSTAMP, getNow());

	// TODO: need to handle add/remove of allowed nodes
	// add Nodes To Resources
	if(list_del->num_items > 0)
	{
	    str_list_t *iter = list_del;
	    while(list_del != list_del_last)
	    {
		char *name  = NULL;
		char *value = NULL;
		if(decodeNVpair(iter->value, '=', &name, &value))
		{
		    xmlNodePtr node_entry = xmlNewNode(NULL, XML_CIB_ATTR_NODEREF);			
		    xmlSetProp(node_entry, XML_ATTR_ID, name);
		    xmlSetProp(node_entry, XML_CIB_ATTR_WEIGHT, value);
		    xmlSetProp(node_entry, XML_ATTR_TSTAMP, getNow());
		    xmlSetProp(node_entry, XML_CIB_ATTR_ACTION, "del");
		    xmlAddChild(new_xml_node, node_entry);
		}
		iter = iter->next;
	    }
	}
	// add Nodes To Resources
	if(list_add->num_items > 0)
	{
	    str_list_t *iter = list_add;
	    while(list_add != list_add_last)
	    {
		char *name  = NULL;
		char *value = NULL;
		if(decodeNVpair(iter->value, '=', &name, &value))
		{
		    xmlNodePtr node_entry = xmlNewNode(NULL, XML_CIB_ATTR_NODEREF);			
		    xmlSetProp(node_entry, XML_ATTR_ID, name);
		    xmlSetProp(node_entry, XML_CIB_ATTR_WEIGHT, value);
		    xmlSetProp(node_entry, XML_ATTR_TSTAMP, getNow());
		    xmlSetProp(node_entry, XML_CIB_ATTR_ACTION, "add");
		    xmlAddChild(new_xml_node, node_entry);
		}
		iter = iter->next;
	    }
	}
    }
    else if(strcmp("constraint", obj_type) == 0)
    {
	section_name = XML_CIB_TAG_CONSTRAINTS;

	if(id == NULL) return NULL;
	new_xml_node = xmlNewNode( NULL, XML_CIB_TAG_RESOURCE);
	xmlSetProp(new_xml_node, XML_ATTR_ID, id);

	if(subtype     != NULL) xmlSetProp(new_xml_node, XML_CIB_ATTR_CONTYPE, subtype);
	if(description != NULL) xmlSetProp(new_xml_node, XML_ATTR_DESC       , description);
	if(resource[0] != NULL) xmlSetProp(new_xml_node, XML_CIB_ATTR_RESID1 , resource[0]);
	if(resource[1] != NULL) xmlSetProp(new_xml_node, XML_CIB_ATTR_RESID2 , resource[1]);
	if(clear       != NULL) xmlSetProp(new_xml_node, XML_CIB_ATTR_CLEAR  , clear);

	// del Name Value pairs To constraint s
	if(list_del->num_items > 0)
	{
	    str_list_t *iter = list_del;
	    while(list_del != list_del_last)
	    {
		char *name  = NULL;
		char *value = NULL;
		if(decodeNVpair(iter->value, '=', &name, &value))
		{
		    xmlNodePtr node_entry = xmlNewNode(NULL, XML_CIB_TAG_NVPAIR);			
		    xmlSetProp(node_entry, XML_ATTR_ID, name);
//			xmlSetProp(node_entry, XML_CIB_ATTR_VARTYPE, subtype);
		    xmlSetProp(node_entry, XML_CIB_ATTR_VARVALUE, value);
		    xmlSetProp(node_entry, XML_CIB_ATTR_ACTION, "del");
		    xmlAddChild(new_xml_node, node_entry);
		}
		iter = iter->next;
	    }
	}
	
	// add Name Value pairs To constraint s
	if(list_add->num_items > 0)
	{
	    str_list_t *iter = list_add;
	    while(list_add != list_add_last)
	    {
		char *name  = NULL;
		char *value = NULL;
		if(decodeNVpair(iter->value, '=', &name, &value))
		{
		    xmlNodePtr node_entry = xmlNewNode(NULL, XML_CIB_ATTR_NODEREF);			
		    xmlSetProp(node_entry, XML_ATTR_ID, name);
//			xmlSetProp(node_entry, XML_CIB_ATTR_VARTYPE, subtype);
		    xmlSetProp(node_entry, XML_CIB_ATTR_VARVALUE, value);
		    xmlSetProp(node_entry, XML_CIB_ATTR_ACTION, "add");
		    xmlAddChild(new_xml_node, node_entry);
		}
		iter = iter->next;
	    }
	}
	xmlSetProp(new_xml_node, XML_ATTR_TSTAMP, getNow());
    }
    else
    {
	cl_log(LOG_INFO, "Object Type (%s) not supported", obj_type);
	return NULL;
    }

    
    // create the cib request
    root = wrapUpdate(new_xml_node, section_name);
    
    return root;
    
}


xmlNodePtr
wrapUpdate(xmlNodePtr update, const char *section_name)
{
    // create the update section
    xmlNodePtr section = xmlNewNode(NULL, section_name);
    xmlAddChild(section, update);

    xmlNodePtr cib_req = createCibRequest(TRUE, "modify", section_name, verbose, section);

    char *reference = xmlGetProp(cib_req, XML_MSG_ATTR_REFERENCE);
    // create the real request
    xmlNodePtr request = xmlNewNode( NULL, XML_REQ_TAG_DC);
    xmlSetProp(request, XML_DC_ATTR_OP, "cib_op");
    xmlSetProp(request, XML_ATTR_TIMEOUT, "0");
    xmlSetProp(request, XML_MSG_ATTR_REFERENCE, reference);
    xmlAddChild(request, cib_req);
    
    // create the real message
    return createCrmMsg(NULL, "admin", "dc", request, TRUE);
}


int
do_work(ll_cluster_t *hb_fd)
{
    /* construct the request */
    xmlNodePtr root = NULL;
    const char *dest_node = NULL;

    if(DO_QUERY == TRUE)
    {
	cl_log(LOG_DEBUG, "Querying the CIB");
	char *obj_type_parent = NULL;
	if(obj_type == NULL)
	{
	    obj_type_parent = strdup("all");
	    if (obj_type_parent == NULL) {
		    return -1;
	    }
	}
	else
	{
	    obj_type_parent = (char*)ha_malloc(sizeof(char)*
			    (strlen(obj_type)+1));
	    if (obj_type_parent == NULL) {
		    return -1;
	    }
	    cl_log(LOG_DEBUG, "Building the request - 0");
	    sprintf(obj_type_parent, "%s%c", obj_type, 's');
	}
	cl_log(LOG_DEBUG, "Building the request - 1");
	xmlNodePtr request = createCibRequest(TRUE, "query", obj_type_parent, "false", NULL);

	const char *reference = xmlGetProp(request, XML_MSG_ATTR_REFERENCE);

	cl_log(LOG_DEBUG, "Building the request - 2");
	root = createCrmMsg(reference, "admin", "cib", request, TRUE);
	cl_log(LOG_DEBUG, "Building the request - 3");
	dest_node = status;
    }
    else if(DO_CREATE == TRUE)
    {
	root = handleCreate();
    }
    else if(DO_DELETE == TRUE)
    {
	root = handleDelete();
    }
    else if(DO_MODIFY == TRUE)
    {
	root = handleModify();
    }
    else if(DO_HEALTH == TRUE)
    {
	cl_log(LOG_DEBUG, "Querying the system");
/*
<!ATTLIST dc_request
          dc_operation	(noop|ping|deep_ping|dc_query|cib_op)	'noop'
	  reference	#CDATA
          timeout       #CDATA          '0'>
	*/
	if(status != NULL)
	{
	    const char* ping_type = "ping";
	    if(BE_VERBOSE)
	    {
		ping_type = "ping_deep";
		if(status != NULL) expected_responses = 2; // 5; // CRM/DC, LRMD, CIB, PENGINE, TENGINE
		else expected_responses = -1; // wait until timeout instead
	    }
	    
	    xmlNodePtr request = NULL;
	    if(status != NULL)
	    {
		request = xmlNewNode(NULL, XML_REQ_TAG_CRM);
		xmlSetProp(request, XML_CRM_ATTR_OP, ping_type);
	    }
	    else
	    {
		request = xmlNewNode(NULL, XML_REQ_TAG_DC);
		xmlSetProp(request, XML_DC_ATTR_OP, ping_type);
	    }

	    xmlSetProp(request, XML_ATTR_TIMEOUT, "0");

	    root = createCrmMsg(NULL, "admin", "crm", request, TRUE);
	    dest_node = status;
	}
	else
	    cl_log(LOG_INFO, "Cluster-wide health not available yet");
    }
    
    /* send it */
    if(root != NULL)
    {
	cl_log(LOG_DEBUG, "sending: [%s]", dump_xml(root));
	xmlSetProp(root, XML_MSG_ATTR_SRCSUBSYS, "admin");
	send_xmlha_message(hb_fd, root, dest_node, "crmd");
    }
    else
    {
	// no message to send... error
	cl_log(LOG_ERR, "No message to send");
	return -1;
    }
    return 1;
    
}

ll_cluster_t*
do_init(void)
{
/*     cl_log_set_logfile(DAEMON_LOG); */
/* //    if (crm_debug()) { */
/*     cl_log_set_debugfile(DAEMON_DEBUG); */
//    }

    xmlInitParser();  // docs say only do this once, but in their code they do it every time!

    (void)_ha_msg_h_Id;
    
    /* change the logging facility to the one used by heartbeat daemon */
    ll_cluster_t*	hb_fd = ll_cluster_new("heartbeat");
    
    int facility;
    cl_log(LOG_INFO, "Switching to Heartbeat logger");
    if ((facility = hb_fd->llc_ops->get_logfacility(hb_fd))>0) {
	cl_log_set_facility(facility);
    }

    hb_fd = ha_register(hb_fd);


    return hb_fd;
}

void
usage(const char* cmd, int exit_status)
{
    FILE* stream;

    stream = exit_status ? stderr : stdout;

    fprintf(stream, "usage: %s [-srkh]"
	    "[-c configure file]\n", cmd);
/* 	fprintf(stream, "\t-d\tsets debug level\n"); */
/* 	fprintf(stream, "\t-s\tgets daemon status\n"); */
/* 	fprintf(stream, "\t-r\trestarts daemon\n"); */
/* 	fprintf(stream, "\t-k\tstops daemon\n"); */
/* 	fprintf(stream, "\t-h\thelp message\n"); */
    fflush(stream);

    exit(exit_status);
}

const char * ournode;

ll_cluster_t*
ha_register(ll_cluster_t* hb_fd)
{
    cl_log(LOG_DEBUG, "Register with HA");

    /* we want hb_input_dispatch to be called when some input is
     * pending on the heartbeat fd, and every 1 second 
     */
  
    //	(void)_heartbeat_h_Id;
    (void)_ha_msg_h_Id;
  
  
    cl_log(LOG_INFO, "Signing in with Heartbeat");
    if (hb_fd->llc_ops->signon(hb_fd, daemon_name)!= HA_OK) {
	cl_log(LOG_ERR, "Cannot sign on with heartbeat");
	cl_log(LOG_ERR, "REASON: %s", hb_fd->llc_ops->errmsg(hb_fd));
	return NULL;
    }
  
    cl_log(LOG_INFO, "Finding our node name");
    if((ournode = hb_fd->llc_ops->get_mynodeid(hb_fd)) == NULL) {
	cl_log(LOG_ERR, "get_mynodeid() failebd");
	return NULL;
    }
    cl_log(LOG_INFO, "Hostname: %s", ournode);
  
    cl_log(LOG_INFO, "Be informed of CRM messages");
    if (hb_fd->llc_ops->set_msg_callback(hb_fd, "CRM", admin_msg_callback, NULL)
	!=HA_OK){
	cl_log(LOG_ERR, "Cannot set CRM message callback");
	cl_log(LOG_ERR, "REASON: %s", hb_fd->llc_ops->errmsg(hb_fd));
	return NULL;
    }

    G_main_add_fd(G_PRIORITY_HIGH,
		  hb_fd->llc_ops->inputfd(hb_fd),
		  FALSE,
		  hb_input_dispatch,
		  hb_fd,  // usrdata
		  hb_input_destroy);

    /* it seems we need to poke the message receiving stuff in order for it to
     *    start seeing messages.  Its like it gets blocked or something.
     */
    hb_input_dispatch(0, hb_fd);

    return hb_fd;
    
}

// keep the compiler happy
gboolean
waitCh_client_connect(IPC_Channel *newclient, gpointer user_data)
{
    return TRUE;
}

gboolean
hb_input_dispatch(int fd, gpointer user_data)
{
  cl_log(LOG_DEBUG, "input_dispatch...");
  
  ll_cluster_t*	hb_fd = (ll_cluster_t*)user_data;

  while(hb_fd->llc_ops->msgready(hb_fd))
  {
      cl_log(LOG_DEBUG, "there was another message...");
      hb_fd->llc_ops->rcvmsg(hb_fd, 0);  // invoke the callbacks but dont block
  }
  
  return TRUE;
}

void
hb_input_destroy(gpointer user_data)
{
  cl_log(LOG_INFO, "in my hb_input_destroy");
}

void
admin_msg_callback(const struct ha_msg* msg, void* private_data)
{
    static int recieved_responses = 0;

    cl_log(LOG_DEBUG, "admin_msg_callback: processing HA message");
    xmlNodePtr root = validate_and_decode_hamessage(msg);
    if(root == NULL)
    {
	cl_log(LOG_INFO, "Message (%s from %s) was not valid... discarding message.", ha_msg_value(msg, F_SEQ), ha_msg_value(msg, F_ORIG));
	return;
    }

    if(validate_crm_message(root, "admin", "response") == FALSE)
    {
	cl_log(LOG_INFO, "Message (%s from %s) was not valid... discarding message.", ha_msg_value(msg, F_SEQ), ha_msg_value(msg, F_ORIG));
	return;
    }

    if(strcmp("response", xmlGetProp(root, XML_MSG_ATTR_MSGTYPE)) != 0)
    {
	cl_log(LOG_ERR, "The admin client does not accept requests");
	return;
    }

    recieved_responses++;

    // do stuff

    if(recieved_responses >= expected_responses)
    {
	cl_log(LOG_INFO, "Recieved expected number (%d) of messages from Heartbeat.  Exiting normally.", expected_responses);
	g_main_quit(mainloop);
    }
    
}

