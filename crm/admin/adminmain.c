
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
#include <crm/common/xmlutils.h>
#include <crm/common/xmltags.h>
#include <crm/common/xmlvalues.h>
#include <crm/cib/cibprimatives.h>
#include <crm/cib/cibmessages.h>
#include <crm/cib/cibio.h>

#define OPTARGS	"V?i:o:D:C:S:HA:U:M:I:EWRFt:m:a:d:w:c:r:p:s:"

#include <getopt.h>

#include <crm/dmalloc_wrapper.h>


GMainLoop *mainloop = NULL;
const char *crm_system_name = "crmadmin";
IPC_Channel *crmd_channel = NULL;
char *adminuid = NULL;

void usage(const char *cmd, int exit_status);
void test_messaging(ll_cluster_t * hb_cluster);
ll_cluster_t *do_init(void);
int do_work(ll_cluster_t * hb_cluster);
xmlNodePtr handleCreate(void);
xmlNodePtr handleDelete(void);
xmlNodePtr handleModify(void);
gboolean decodeNVpair(const char *srcstring, char separator,
		      char **name, char **value);
gboolean admin_msg_callback(IPC_Channel * source_data, void *private_data);
xmlNodePtr wrapUpdate(xmlNodePtr update,
		      const char *section_name, const char *action);
char *pluralSection(void);


gboolean DO_DAEMON  = FALSE;
gboolean DO_ERASE   = FALSE;
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
char *this_msg_reference = NULL;
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
main(int argc, char **argv)
{

	cl_log_set_entity(crm_system_name);
	cl_log_enable_stderr(TRUE);
	cl_log_set_facility(LOG_USER);

	int argerr = 0;
	int flag;

	list_add =(str_list_t *) ha_malloc(sizeof(struct str_list_s));
	list_add_last = list_add;
	list_del =(str_list_t *) ha_malloc(sizeof(struct str_list_s));
	list_del_last = list_del;
	list_add->num_items = 0;
	list_del->num_items = 0;

	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
			// Top-level Options
			{"daemon", 0, 0, 0},
			{"erase", 0, 0, 0},
			{"query", 0, 0, 0},
			{"create", 0, 0, 0},
			{"modify", 0, 0, 0},
			{"delete", 0, 0, 0},
			{"instance", 1, 0, 0},	// undocumented, for testing only
			{"node", 1, 0, 0},	// undocumented, for testing only
			{"reference", 1, 0, 0},	// undocumented, for testing only
			{"verbose", 0, 0, 'V'},
			{"help", 0, 0, '?'},

			// common options
			{"id", 1, 0, 'i'},
			{"obj_type", 1, 0, 'o'},
			{"description", 1, 0, 'D'},

			// daemon options
			{"reset", 1, 0, 'C'},
			{"status", 1, 0, 'S'},
			{"health", 0, 0, 'H'},
			{"disconnect", 1, 0, 'A'},
			{"unload_ha", 1, 0, 'U'},
			{"migrate_from", 1, 0, 'M'},
			{"migrate_res", 1, 0, 'I'},
			{"elect_dc", 0, 0, 'E'},
			{"whois_dc", 0, 0, 'W'},
			{"recalc_tree", 0, 0, 'R'},
			{"flush_recalc_tree", 0, 0, 'F'},

			// create_modify options
			{"subtype", 1, 0, 's'},
			{"max_instances", 1, 0, 'm'},
			{"list_add", 1, 0, 'a'},
			{"list_del", 1, 0, 'd'},
			{"list_wipe", 0, 0, 'w'},
			{"clear", 1, 0, 'c'},
			{"resource", 1, 0, 'r'},
			{"priority", 1, 0, 'p'},
			{"res_timeout", 1, 0, 't'},

			{0, 0, 0, 0}
		};

		flag = getopt_long(argc, argv, OPTARGS,
				   long_options, &option_index);
		if (flag == -1)
			break;

		switch(flag) {
			case 0:
				printf("option %s", long_options[option_index].name);
				if (optarg)
					printf(" with arg %s", optarg);
				printf("\n");
			
				if (strcmp("daemon", long_options[option_index].name) == 0)
					DO_DAEMON = TRUE;
				else if (strcmp("erase",
						long_options[option_index].name) == 0)
					DO_ERASE  = TRUE;
				else if (strcmp("create",
						long_options[option_index].name) == 0)
					DO_CREATE = TRUE;
				else if (strcmp("modify",
						long_options[option_index].name) == 0)
					DO_MODIFY = TRUE;
				else if (strcmp("delete",
						long_options[option_index].name) == 0)
					DO_DELETE = TRUE;
				else if (strcmp("query",
						long_options[option_index].name) == 0)
					DO_QUERY = TRUE;
				else if (strcmp("instance",
						long_options[option_index].name) == 0) {
					instance = ha_strdup(optarg);
				} else if (strcmp("reference",
						  long_options[option_index].name) == 0) {
					this_msg_reference =
						ha_strdup(optarg);
				} else if (strcmp("node",
						  long_options[option_index].name) == 0) {
					node = ha_strdup(optarg);
				} else {
					printf
						( "?? Long option (--%s) is not yet properly supported ??\n",
						  long_options[option_index].name);
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
				usage(crm_system_name, LSB_EXIT_OK);
				break;
			case 'i':
				CRM_DEBUG3("Option %c => %s", flag, optarg);
				id = ha_strdup(optarg);
				break;
			case 'o':
				CRM_DEBUG3("Option %c => %s", flag, optarg);
				obj_type = ha_strdup(optarg);
				break;
			case 'D':
				CRM_DEBUG3("Option %c => %s", flag, optarg);
				description = ha_strdup(optarg);
				break;
			case 'C':
				printf("Option %c is not yet supported\n", flag);
				++argerr;
				break;
			case 'S':
				DO_HEALTH = TRUE;
				status = ha_strdup(optarg);
				break;
			case 'H':
				DO_HEALTH = TRUE;
				break;
			case 'A':
				printf("Option %c is not yet supported\n", flag);
				++argerr;
				break;
			case 'U':
				printf("Option %c is not yet supported\n", flag);
				++argerr;
				break;
			case 'M':
				printf("Option %c is not yet supported\n", flag);
				++argerr;
				break;
			case 'I':
				printf("Option %c is not yet supported\n", flag);
				++argerr;
				break;
			case 'E':
				DO_ELECT_DC = TRUE;
				printf("Option %c is not yet supported\n", flag);
				++argerr;
				break;
			case 'W':
				DO_WHOIS_DC = TRUE;
				printf("Option %c is not yet supported\n", flag);
				++argerr;
				break;
			case 'R':
				DO_RECALC_TREE = TRUE;
				printf("Option %c is not yet supported\n", flag);
				++argerr;
				break;
			case 'F':
				DO_FLUSH_RECALC = TRUE;
				printf("Option %c is not yet supported\n", flag);
				++argerr;
				break;
			case 'm':
				CRM_DEBUG3("Option %c => %s", flag, optarg);
				max_instances = ha_strdup(optarg);
				break;
			case 'a':
				CRM_DEBUG3("Option %c => %s", flag, optarg);
				list_add->num_items++;
				if (list_add->num_items != 1) {
					list_add_last->next =
						( str_list_t *) ha_malloc(sizeof(str_list_t));
					list_add_last->value = ha_strdup(optarg);
				}
				list_add_last->next = NULL;
				break;
			case 'd':
				CRM_DEBUG3("Option %c => %s", flag, optarg);
				list_del->num_items++;
				if (list_del->num_items != 1) {
					list_del_last->next =
						( str_list_t *) ha_malloc(sizeof(str_list_t));
					list_add_last->value = ha_strdup(optarg);
				}
				list_del_last->next = NULL;
				break;
			case 'w':
				list_wipe = TRUE;
				break;
			case 'c':
				CRM_DEBUG3("Option %c => %s", flag, optarg);
				clear = ha_strdup(optarg);
				break;
			case 'r':
				if (num_resources > 1) {
					printf("?? too many (> 2) resources ?? \n");
					argerr++;
					break;
				}
				resource[num_resources] = ha_strdup(optarg);
				if (!resource[num_resources]) {
					printf("?? resource[%d] option memory allocation "
					       "failed ??\n", num_resources);
					argerr++;
				} else {
					num_resources++;
				}
				break;
			case 't':
				CRM_DEBUG3("Option %c => %s", flag, optarg);
				res_timeout = ha_strdup(optarg);
				break;
			case 'p':
				CRM_DEBUG3("Option %c => %s", flag, optarg);
				priority = ha_strdup(optarg);
				break;
			case 's':
				CRM_DEBUG3("Option %c => %s", flag, optarg);
				subtype = ha_strdup(optarg);
				break;
			default:
				printf("?? getopt returned character code 0%o ??\n", flag);
				++argerr;
				break;
		}
	}

	if (optind < argc) {
		printf("non-option ARGV-elements: ");
		while (optind < argc)
			printf("%s ", argv[optind++]);
		printf("\n");
	}

	if (optind > argc) {
		++argerr;
	}

	if (argerr) {
		usage(crm_system_name, LSB_EXIT_GENERIC);
	}

	ll_cluster_t *hb_cluster = do_init();
	if (hb_cluster != NULL) {
		if (do_work(hb_cluster) > 0) {
			/* wait for the reply by creating a mainloop and running it until
			 * the callbacks are invoked...
			 */
			mainloop = g_main_new(FALSE);
			cl_log(LOG_INFO,
			       "%s waiting for reply from the local CRM",
			       crm_system_name);

			g_main_run(mainloop);
			return_to_orig_privs();
		} else {
			cl_log(LOG_ERR, "No message to send");
			operation_status = -1;
		}
	} else {
		cl_log(LOG_ERR,
		       "Init failed, could not perform requested operations");
		operation_status = -2;
	}

	cl_log(LOG_DEBUG, "%s exiting normally", crm_system_name);
	return operation_status;
}

xmlNodePtr
handleCreate(void)
{
	CRM_DEBUG2("Creating new CIB object (%s)", obj_type);
	if (obj_type == NULL) {
		cl_log(LOG_ERR,
		       "You must specify an object type.  Use the -o option.");
		return NULL;		// error
	}
	xmlNodePtr xml_root_node, new_xml_node;
	const char *section_name = NULL;

	if (strcmp("node", obj_type) == 0) {
		section_name = XML_CIB_TAG_NODES;
		CRM_DEBUG2("Creating new %s object", section_name);
		if (id == NULL || description == NULL)
			return NULL;

		new_xml_node = newHaNode(id, subtype);
		if (description != NULL)
			set_xml_property_copy(new_xml_node,
					      XML_ATTR_DESC,
					      description);
	} else if (strcmp("resource", obj_type) == 0) {
		section_name = XML_CIB_TAG_RESOURCES;
		CRM_DEBUG2("Creating new %s object", section_name);
		if (id == NULL || subtype == NULL || description == NULL)
			return NULL;

		new_xml_node =
			newResource(id, subtype, description, max_instances);
		if (priority != NULL)
			set_xml_property_copy(new_xml_node,
					      XML_CIB_ATTR_PRIORITY,
					      priority);
		if (res_timeout != NULL)
			set_xml_property_copy(new_xml_node,
					      XML_CIB_ATTR_RESTIMEOUT,
					      res_timeout);

		// add Nodes To Resources
		if (list_add->num_items > 0) {
			str_list_t *iter = list_add;
			while (list_add != list_add_last) {
				char *name = NULL;
				char *value = NULL;
				if (decodeNVpair(iter->value,
						 '=',
						 &name,
						 &value)) {
					xmlNodePtr node_entry =
						create_xml_node(
							NULL,
							XML_CIB_ATTR_NODEREF);
					set_xml_property_copy(
						node_entry,
						XML_ATTR_ID,
						name);
					set_xml_property_copy(
						node_entry,
						XML_CIB_ATTR_WEIGHT,
						value);
					set_node_tstamp(node_entry);
					set_xml_property_copy(
						node_entry,
						XML_CIB_ATTR_ACTION,
						"add");
					xmlAddChild(new_xml_node
						    , node_entry);
				}
				iter = iter->next;
			}
		}
	}
	// move somewhere else... this could get big
	else if (strcmp("constraint", obj_type) == 0) {
		section_name = XML_CIB_TAG_CONSTRAINTS;
		CRM_DEBUG2("Creating new %s object", section_name);

		if (subtype == NULL) {
			cl_log(LOG_ERR,
			       "You must specify a subtype for %s objects.  Use the -s option.",
			       section_name);
			return NULL;
		}

		if (strcmp(CIB_VAL_CONTYPE_BLOCK, subtype) == 0) {
			CRM_DEBUG3("Creating new %s (%s) object", section_name,
				   CIB_VAL_CONTYPE_BLOCK);
			if (clear == NULL
			    || description == NULL
			    || resource[0] == NULL
			    || id == NULL) {
				cl_log(LOG_ERR,
				       "Not all required args were filled in."
				       "  -c [%s] -D [%s] -r [%s] -i [%s] ",
				       clear, description, resource[0], id);
				return NULL;
			}

			id =(char *) ha_malloc(256 *(sizeof(char)));
			sprintf(id, "failed-%s-%s", node, resource[0]);
			new_xml_node = newConstraint(id);

			set_xml_property_copy(new_xml_node,
					      XML_CIB_ATTR_CONTYPE,
					      CIB_VAL_CONTYPE_BLOCK);
			set_xml_property_copy(new_xml_node,
					      XML_CIB_ATTR_RESID1,
					      resource[0]);
			set_xml_property_copy(new_xml_node,
					      XML_CIB_ATTR_CLEAR,
					      clear);

			xmlNodePtr node_entry = create_xml_node(
				NULL,
				XML_CIB_TAG_NVPAIR);
			
			set_xml_property_copy(node_entry,
					      XML_ATTR_ID,
					      "blockHost");
			set_xml_property_copy(node_entry,
					      XML_CIB_ATTR_VARVALUE,
					      node);
			set_xml_property_copy(node_entry,
					      XML_CIB_ATTR_ACTION,
					      "add");
			
			xmlAddChild(new_xml_node, node_entry);
		} else if (strcmp(CIB_VAL_CONTYPE_VAR, subtype) == 0) {
			CRM_DEBUG3("Creating new %s (%s) object",
				   section_name,
				   CIB_VAL_CONTYPE_VAR);
			if (list_add->num_items == 1
			    || description == NULL
			    || id == NULL
			    || num_resources != 1) {
				cl_log(LOG_ERR,
				       "Not all required args were filled in."
				       "  -a [# %d] -D [%s] -r [# %d] -i [%s] ",
				       list_add->num_items,
				       description,
				       num_resources,
				       id);
				return NULL;
			}

			new_xml_node = newConstraint(id);

			set_xml_property_copy(new_xml_node,
					      XML_CIB_ATTR_CONTYPE,
					      subtype);
			set_xml_property_copy(new_xml_node,
					      XML_CIB_ATTR_RESID1,
					      resource[0]);
			

			// add Name Value pairs To constraint s
			if (list_add->num_items > 0) {
				str_list_t *iter = list_add;
				while (list_add != list_add_last) {
					char *name = NULL;
					char *value = NULL;
					if (decodeNVpair(iter->value, '=', &name, &value)) {
						xmlNodePtr node_entry =
							create_xml_node(NULL, XML_CIB_TAG_NVPAIR);
						set_xml_property_copy(node_entry,
								      XML_ATTR_ID,
								      name);
						set_xml_property_copy(node_entry,
								      XML_CIB_ATTR_VARVALUE,
								      value);
						set_xml_property_copy(node_entry,
								      XML_CIB_ATTR_ACTION,
								      "add");
						xmlAddChild(new_xml_node, node_entry);
					}
					iter = iter->next;
				}
			}
		} else {
			CRM_DEBUG3("Creating new %s (%s)[any] object",
				   section_name,
				   subtype);
			if (id == NULL || description == NULL || num_resources != 2) {
				cl_log(LOG_ERR,
				       "Not all required args were filled in."
				       "  -i [%s] -D [%s] -r [# %d] ",
				       id, description, num_resources);
				return NULL;
			}
			new_xml_node = newConstraint(id);

			set_xml_property_copy(new_xml_node,
					      XML_CIB_ATTR_CONTYPE,
					      subtype);
			set_xml_property_copy(new_xml_node,
					      XML_CIB_ATTR_RESID1,
					      resource[0]);
			set_xml_property_copy(new_xml_node,
					      XML_CIB_ATTR_RESID2,
					      resource[1]);
		}
		if (description != NULL)
			set_xml_property_copy(new_xml_node,
					      XML_ATTR_DESC,
					      description);
	} else {
		cl_log(LOG_INFO,
		       "Object Type (%s) not supported",
		       obj_type);
		return NULL;
	}
	CRM_DEBUG("Object creation complete");

	// create the cib request
	xml_root_node = wrapUpdate(new_xml_node, section_name, "create");

	return xml_root_node;

}

xmlNodePtr
handleDelete(void)
{
	CRM_DEBUG2("Deleting existing CIB object %p", obj_type);
	if (obj_type == NULL) {
		cl_log(LOG_ERR,
		       "You must specify an object type.  Use the -o option.");
		return NULL;		// error
	}

	xmlNodePtr xml_root_node, new_xml_node = NULL;;
	const char *section_name = NULL;

	if (strcmp("node", obj_type) == 0) {
		section_name = XML_CIB_TAG_NODES;
		CRM_DEBUG2("Deleting exiting %s object", section_name);
		if (id == NULL)
			return NULL;

		new_xml_node = create_xml_node(NULL, XML_CIB_TAG_NODE);
		set_xml_property_copy(new_xml_node, XML_ATTR_ID, id);
		if (subtype != NULL)
			set_xml_property_copy(new_xml_node,
					      XML_CIB_ATTR_NODETYPE,
					      subtype);
	} else if (strcmp("resource", obj_type) == 0) {
		section_name = XML_CIB_TAG_RESOURCES;
		CRM_DEBUG2("Deleting exiting %s object", section_name);
		if (id == NULL)
			return NULL;

		new_xml_node = create_xml_node(NULL, XML_CIB_TAG_RESOURCE);
		set_xml_property_copy(new_xml_node, XML_ATTR_ID, id);
		if (subtype != NULL)
			set_xml_property_copy(new_xml_node,
					      XML_CIB_ATTR_NODETYPE,
					      subtype);
	} else if (strcmp("constraint", obj_type) == 0) {
		section_name = XML_CIB_TAG_CONSTRAINTS;
		CRM_DEBUG2("Deleting exiting %s object", section_name);
		if (id == NULL)
			return NULL;

		new_xml_node = create_xml_node(NULL, XML_CIB_TAG_CONSTRAINT);
		set_xml_property_copy(new_xml_node, XML_ATTR_ID, id);
		if (subtype != NULL)
			set_xml_property_copy(new_xml_node,
					      XML_CIB_ATTR_NODETYPE,
					      subtype);
	} else {
		cl_log(LOG_INFO, "Object Type (%s) not supported", obj_type);
		return NULL;
	}

	// create the cib request
	xml_root_node = wrapUpdate(new_xml_node, section_name, "delete");

	CRM_DEBUG("Creation of removal request complete");

	return xml_root_node;

}

xmlNodePtr
handleModify(void)
{
	CRM_DEBUG("Modifying existing CIB object");
	if (obj_type == NULL) {
		cl_log(LOG_ERR,
		       "You must specify an object type.  Use the -o option.");
		return NULL;	
	}

	xmlNodePtr xml_root_node, new_xml_node = NULL;
	const char *section_name = NULL;

	if (strcmp("node", obj_type) == 0) {
		section_name = XML_CIB_TAG_NODES;
		CRM_DEBUG3("Modifing existing %s (%s) object",
			   section_name,
			   id);
		
		if (id == NULL) return NULL;
		
		new_xml_node = create_xml_node(NULL, XML_CIB_TAG_NODE);
		set_xml_property_copy(new_xml_node, XML_ATTR_ID, id);

		if (subtype != NULL)
			set_xml_property_copy(new_xml_node,
					      XML_CIB_ATTR_NODETYPE,
					      subtype);
		
	} else if (strcmp("resource", obj_type) == 0) {
		section_name = XML_CIB_TAG_RESOURCES;
		CRM_DEBUG3("Modifing existing %s (%s) object",
			   section_name,
			   id);

		if (id == NULL) return NULL;
		new_xml_node = create_xml_node(NULL, XML_CIB_TAG_RESOURCE);
		set_xml_property_copy(new_xml_node, XML_ATTR_ID, id);

		if (subtype != NULL)
			set_xml_property_copy(new_xml_node,
					      XML_CIB_ATTR_RESTYPE,
					      subtype);
		if (description != NULL)
			set_xml_property_copy(new_xml_node,
					      XML_ATTR_DESC,
					      description);
		if (max_instances != NULL)
			set_xml_property_copy(new_xml_node,
					      XML_CIB_ATTR_MAXINSTANCE,
					      max_instances);
		if (priority != NULL)
			set_xml_property_copy(new_xml_node,
					      XML_CIB_ATTR_PRIORITY,
					      priority);
		if (res_timeout != NULL)
			set_xml_property_copy(new_xml_node,
					      XML_CIB_ATTR_RESTIMEOUT,
					      res_timeout);

		set_node_tstamp(new_xml_node);

		// TODO: need to handle add/remove of allowed nodes
		// add Nodes To Resources
		if (list_del->num_items > 0) {
			str_list_t *iter = list_del;
			while (list_del != list_del_last) {
				char *name = NULL;
				char *value = NULL;
				if (decodeNVpair(iter->value, '=',
						 &name,
						 &value)) {
					
					xmlNodePtr node_entry =
						create_xml_node(
							NULL,
							XML_CIB_ATTR_NODEREF);
					set_xml_property_copy(
						node_entry,
						XML_ATTR_ID,
						name);
					
					set_xml_property_copy(
						node_entry,
						XML_CIB_ATTR_WEIGHT,
						value);
					
					set_node_tstamp(node_entry);
					
					set_xml_property_copy(
						node_entry,
						XML_CIB_ATTR_ACTION,
						"del");
					
					xmlAddChild(new_xml_node,
						    node_entry);
				}
				iter = iter->next;
			}
		}
		// add Nodes To Resources
		if (list_add->num_items > 0) {
			str_list_t *iter = list_add;
			while (list_add != list_add_last) {
				char *name = NULL;
				char *value = NULL;
				if (decodeNVpair(iter->value, '=',
						 &name,
						 &value)) {
					
					xmlNodePtr node_entry =
						create_xml_node(
							NULL,
							XML_CIB_ATTR_NODEREF);
					set_xml_property_copy(node_entry,
							      XML_ATTR_ID,
							      name);
					
					set_xml_property_copy(
						node_entry,
						XML_CIB_ATTR_WEIGHT,
						value);
					
					set_node_tstamp(node_entry);
					
					set_xml_property_copy(
						node_entry,
						XML_CIB_ATTR_ACTION,
						"add");
					
					xmlAddChild(new_xml_node,
						    node_entry);
				}
				iter = iter->next;
			}
		}
	} else if (strcmp("constraint", obj_type) == 0) {
		section_name = XML_CIB_TAG_CONSTRAINTS;
		CRM_DEBUG3("Modifing existing %s (%s) object", section_name, id);

		if (id == NULL)
			return NULL;
		new_xml_node = create_xml_node(NULL,
					       XML_CIB_TAG_CONSTRAINT);
		set_xml_property_copy(new_xml_node,
				      XML_ATTR_ID,
				      id);

		if (subtype != NULL)
			set_xml_property_copy(new_xml_node,
					      XML_CIB_ATTR_CONTYPE,
					      subtype);
		if (description != NULL)
			set_xml_property_copy(new_xml_node,
					      XML_ATTR_DESC,
					      description);
		if (resource[0] != NULL)
			set_xml_property_copy(new_xml_node,
					      XML_CIB_ATTR_RESID1,
					      resource[0]);
		if (resource[1] != NULL)
			set_xml_property_copy(new_xml_node,
					      XML_CIB_ATTR_RESID2,
					      resource[1]);
		if (clear != NULL)
			set_xml_property_copy(new_xml_node,
					      XML_CIB_ATTR_CLEAR,
					      clear);

		// del Name Value pairs To constraint s
		if (list_del->num_items > 0) {
			str_list_t *iter = list_del;
			while (list_del != list_del_last) {
				char *name = NULL;
				char *value = NULL;
				if (decodeNVpair(iter->value, '=', &name, &value)) {
					xmlNodePtr node_entry =
						create_xml_node(
							NULL,
							XML_CIB_TAG_NVPAIR);
					set_xml_property_copy(
						node_entry,
						XML_ATTR_ID,
						name);
					set_xml_property_copy(
						node_entry,
						XML_CIB_ATTR_VARVALUE,
						value);
					set_xml_property_copy (
						node_entry,
						XML_CIB_ATTR_ACTION,
						"del");
					xmlAddChild(new_xml_node,
						    node_entry);
				}
				iter = iter->next;
			}
		}
		// add Name Value pairs To constraint s
		if (list_add->num_items > 0) {
			str_list_t *iter = list_add;
			while (list_add != list_add_last) {
				char *name = NULL;
				char *value = NULL;
				if (decodeNVpair(iter->value, '=', &name, &value)) {
					xmlNodePtr node_entry =
						create_xml_node(
							NULL,
							XML_CIB_ATTR_NODEREF);
					set_xml_property_copy(
						node_entry,
						XML_ATTR_ID,
						name);
					set_xml_property_copy(
						node_entry,
						XML_CIB_ATTR_VARVALUE,
						value);
					set_xml_property_copy(
						node_entry,
						XML_CIB_ATTR_ACTION,
						"add");
					xmlAddChild(
						new_xml_node,
						node_entry);
				}
				iter = iter->next;
			}
		}
		set_node_tstamp(new_xml_node);
	} else {
		cl_log(LOG_INFO,
		       "Object Type (%s) not supported",
		       obj_type);
		return NULL;
	}


	// create the cib request
	xml_root_node = wrapUpdate(new_xml_node, section_name, "update");

	CRM_DEBUG("Creation of modify request complete");

	return xml_root_node;

}


xmlNodePtr
wrapUpdate(xmlNodePtr update, const char *section_name,
	   const char *action)
{
	xmlNodePtr dc_req = NULL, cib_req = NULL;
	xmlNodePtr cib = NULL, fragment = NULL, object_root = NULL;
	FNIN();

	// create the cib request
	cib_req = create_xml_node(NULL, XML_REQ_TAG_CIB);
	set_xml_property_copy(cib_req, XML_CIB_ATTR_OP, action);
	set_xml_property_copy(cib_req, XML_ATTR_VERBOSE, verbose);
	set_xml_property_copy(cib_req, XML_CIB_ATTR_SECTION, section_name);

	// create the update section
	fragment = create_xml_node(cib_req, XML_CIB_TAG_FRAGMENT);
	set_xml_property_copy(fragment, XML_CIB_ATTR_SECTION, section_name);

	cib = createEmptyCib();
	object_root = get_object_root(section_name, cib);
	xmlAddChild(object_root, update);

	xmlAddChild(fragment, cib);

	// create the real request
	dc_req = create_xml_node(NULL, XML_REQ_TAG_DC);
	set_xml_property_copy(dc_req, XML_DC_ATTR_OP, "cib_op");
	set_xml_property_copy(dc_req, XML_ATTR_TIMEOUT, "0");
	xmlAddChild(dc_req, cib_req);

	return dc_req;
}


char *
pluralSection(void)
{
	char *obj_type_parent = NULL;
	if (obj_type == NULL) {
		obj_type_parent = ha_strdup("all");
	} else {
		CRM_DEBUG2("Constructing CIB section from %s", obj_type);
		obj_type_parent =(char *) ha_malloc(sizeof(char) *
						    (strlen(obj_type) + 2));
		sprintf(obj_type_parent, "%s%c%c", obj_type, 's', '\0');
	}
	return obj_type_parent;
}


int
do_work(ll_cluster_t * hb_cluster)
{
	/* construct the request */
	xmlNodePtr xml_root_node = NULL, cib_req = NULL;
	const char *dest_node = NULL;
	

	
	if (DO_DAEMON == TRUE && DO_QUERY == TRUE) {
		cl_log(LOG_DEBUG, "Querying the CIB");
		char *obj_type_parent = pluralSection();

		CRM_DEBUG2("Querying the CIB for section: %s",
			   obj_type_parent);
		xml_root_node = create_xml_node(NULL, XML_REQ_TAG_DC);
		set_xml_property_copy(xml_root_node, XML_DC_ATTR_OP, "cib_op");

		cib_req = create_xml_node(xml_root_node, XML_REQ_TAG_CIB);
		set_xml_property_copy(cib_req, XML_CIB_ATTR_OP, "query");
		set_xml_property_copy(cib_req, XML_ATTR_VERBOSE, verbose);
		set_xml_property_copy(cib_req,
				      XML_CIB_ATTR_SECTION,
				      obj_type_parent);

		dest_node = status;
		CRM_DEBUG2("CIB query creation %s",
			   xml_root_node == NULL ? "failed." : "passed.");
	} else if (DO_DAEMON == TRUE && DO_ERASE == TRUE) {
		xml_root_node = create_xml_node(NULL, XML_REQ_TAG_DC);
		set_xml_property_copy(xml_root_node, XML_DC_ATTR_OP, "cib_op");

		cib_req = create_xml_node(xml_root_node, XML_REQ_TAG_CIB);
		set_xml_property_copy(cib_req, XML_CIB_ATTR_OP, "erase");
		set_xml_property_copy(cib_req, XML_ATTR_VERBOSE, verbose);

		dest_node = status;
		CRM_DEBUG2("CIB Erase creation %s",
			   xml_root_node == NULL ? "failed." : "passed.");

	} else if (DO_DAEMON == FALSE && DO_CREATE == TRUE) {
		xml_root_node = handleCreate();
	} else if (DO_DAEMON == FALSE && DO_DELETE == TRUE) {
		xml_root_node = handleDelete();
	} else if (DO_DAEMON == FALSE && DO_MODIFY == TRUE) {
		xml_root_node = handleModify();
	} else if (DO_DAEMON == TRUE && DO_HEALTH == TRUE) {
		cl_log(LOG_DEBUG, "Querying the system");

/*
  <!ATTLIST dc_request
  dc_operation	(noop|ping|deep_ping|dc_query|cib_op)	'noop'
  crm_msg_reference	#CDATA
  timeout       #CDATA          '0'>
*/
		if (status != NULL) {
			const char *ping_type = "ping";
			if (BE_VERBOSE) {
				ping_type = "ping_deep";
				if (status != NULL)
					expected_responses = 2;	// 5; // CRM/DC, LRMD, CIB, PENGINE, TENGINE
				else
					expected_responses = -1;// wait until timeout instead
			}

			if (status != NULL) {
				xml_root_node =
					create_xml_node(NULL,
							XML_REQ_TAG_CRM);
				set_xml_property_copy(xml_root_node,
						      XML_CRM_ATTR_OP,
						      ping_type);
				set_xml_property_copy(xml_root_node,
						      XML_MSG_ATTR_SYSTO,
						      CRM_SYSTEM_CRMD);
			} else {
				xml_root_node =
					create_xml_node(NULL,
							XML_REQ_TAG_DC);
				set_xml_property_copy(xml_root_node,
						      XML_DC_ATTR_OP,
						      ping_type);
				set_xml_property_copy(xml_root_node,
						      XML_MSG_ATTR_SYSTO,
						      CRM_SYSTEM_DC);
			}

			set_xml_property_copy(xml_root_node,
					      XML_ATTR_TIMEOUT, "0");
			dest_node = status;
		} else
			cl_log(LOG_INFO, "Cluster-wide health not available yet");
	}

	CRM_DEBUG2("Creation of request %s",
		   xml_root_node == NULL ? "failed. Aborting.": "passed.  Sending.");

/* send it */
	if (xml_root_node != NULL && crmd_channel != NULL) {
//      CRM_DEBUG2("sending message: %s", xml_root_node->name);
		const char *sys_to = CRM_SYSTEM_DC;
		if (dest_node != NULL) sys_to = CRM_SYSTEM_CRMD;

		send_ipc_request(crmd_channel,
				 xml_root_node,
				 dest_node,
				 sys_to,
				 crm_system_name,
				 adminuid,
				 this_msg_reference);
	} else if (crmd_channel == NULL) {
		cl_log(LOG_ERR,
		       "The IPC connection is not valid, cannot send anything");
		return -1;
	} else {
		cl_log(LOG_ERR, "No message to send");
		return -1;
	}
	return 1;

}

ll_cluster_t *
do_init(void)
{

	/* docs say only do this once, but in their code they do it every time! */
	xmlInitParser (); 

	( void) _ha_msg_h_Id;
	
	/* change the logging facility to the one used by heartbeat daemon */
	ll_cluster_t *hb_cluster = ll_cluster_new("heartbeat");
	
	int facility;
	cl_log(LOG_INFO, "Switching to Heartbeat logger");
	if (( facility =
	      hb_cluster->llc_ops->get_logfacility(hb_cluster)) > 0) {
		cl_log_set_facility(facility);
	}

	adminuid = ha_malloc(sizeof(char) * 11);
	snprintf(adminuid, 10, "%d", getpid());
	adminuid[10] = '\0';

	crmd_channel =
		init_client_ipc_comms(CRM_SYSTEM_CRMD,
				      admin_msg_callback,
				      NULL);
	send_hello_message(crmd_channel,
			   adminuid,
			   crm_system_name,
			   "0",
			   "1");

	return hb_cluster;
}

void
usage(const char *cmd, int exit_status)
{
	FILE *stream;

	stream = exit_status ? stderr : stdout;

	fprintf(stream, "usage: %s [-srkh]" "[-c configure file]\n", cmd);

/* 	fprintf(stream, "\t-d\tsets debug level\n"); */
/* 	fprintf(stream, "\t-s\tgets daemon status\n"); */
/* 	fprintf(stream, "\t-r\trestarts daemon\n"); */
/* 	fprintf(stream, "\t-k\tstops daemon\n"); */
/* 	fprintf(stream, "\t-h\thelp message\n"); */
	fflush(stream);

	exit(exit_status);
}

const char *ournode;

gboolean
admin_msg_callback(IPC_Channel * server, void *private_data)
{
	FNIN();
	int lpc = 0;
	IPC_Message *msg = NULL;
	gboolean hack_return_good = TRUE;
	static int recieved_responses = 0;

	CRM_DEBUG("admin_msg_callback: in IPC callback");

	while (server->ch_status != IPC_DISCONNECT
	       && server->ops->is_message_pending(server) == TRUE) {
		if (server->ops->recv(server, &msg) != IPC_OK) {
			perror("Receive failure:");
			FNRET(!hack_return_good);
		}

		if (msg == NULL) {
			CRM_DEBUG("No message this time");
			continue;
		}

		lpc++;
		char *buffer =(char *) msg->msg_body;
		CRM_DEBUG2("Got xml [text=%s]", buffer);

		CRM_DEBUG("crmd_ipc_input_dispatch: validating and decoding");
		xmlNodePtr xml_root_node =
			find_xml_in_ipcmessage(msg, TRUE);

		if (xml_root_node == NULL) {
			cl_log(LOG_INFO, "IPC message was not valid... discarding.");
			continue;
		}

		if (validate_crm_message(xml_root_node,
					 crm_system_name,
					 adminuid,
					 "response") == FALSE) {
			cl_log(LOG_INFO,
			       "CRM message was not valid... discarding.");
			continue;
		}

		if (strcmp("response",
			   xmlGetProp(xml_root_node, XML_MSG_ATTR_MSGTYPE)) != 0) {
			cl_log(LOG_ERR,
			       "The admin client does not accept requests");
			continue;
		}

		recieved_responses++;
		CRM_DEBUG2("upated counter to %d", recieved_responses);

		// do stuff

		if (this_msg_reference != NULL) {
			// in testing mode...
			char *filename;
			/* 31 = "test-_.xml" + an_int_as_string + '\0' */
			int filename_len = 31 + strlen(this_msg_reference);

			filename = ha_malloc(sizeof(char) * filename_len);
			sprintf(filename, "test-%s_%d.xml", this_msg_reference,
				recieved_responses);
			filename[filename_len - 1] = '\0';
			if (xmlSaveFormatFile(filename, xml_root_node->doc, 1) < 0) {
				cl_log(LOG_CRIT,
				       "Couuld not save response to file test-%s_%d.xml",
				       this_msg_reference,
				       recieved_responses);
			}
		}
	}

	if (server->ch_status == IPC_DISCONNECT) {
		cl_log(LOG_INFO, "admin_msg_callback: received HUP");
		FNRET(!hack_return_good);
	}

	cl_log(LOG_DEBUG, "admin_msg_callback: processing IPC message");

	if (recieved_responses >= expected_responses) {
		cl_log(LOG_INFO,
		       "Recieved expected number (%d) of messages from Heartbeat."
		       "  Exiting normally.", expected_responses);
		g_main_quit(mainloop);
		return !hack_return_good;
	}
	FNRET(hack_return_good);
}
