/* $Id: cibadmin.c,v 1.3 2004/08/03 09:21:43 andrew Exp $ */

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

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <hb_api.h>
#include <clplumbing/uids.h>

#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/ctrl.h>
#include <crm/common/ipc.h>

#include <crm/cib.h>

#include <getopt.h>
#include <ha_msg.h> // someone complaining about _ha_msg_mod not being found
#include <crm/dmalloc_wrapper.h>


GMainLoop *mainloop = NULL;
const char *crm_system_name = "cibadmin";
IPC_Channel *crmd_channel = NULL;
char *admin_uuid = NULL;

void usage(const char *cmd, int exit_status);
ll_cluster_t *do_init(void);
int do_work(ll_cluster_t * hb_cluster, const char *xml_text);

gboolean admin_msg_callback(IPC_Channel * source_data, void *private_data);
xmlNodePtr handleCibMod(const char *xml);


gboolean BE_VERBOSE = FALSE;
int expected_responses = 1;

gboolean DO_HEALTH       = FALSE;

const char *cib_action = NULL;
xmlNodePtr msg_options = NULL;

typedef struct str_list_s
{
		int num_items;
		char *value;
		struct str_list_s *next;
} str_list_t;

const char *verbose = XML_BOOLEAN_FALSE;
char *id = NULL;
char *this_msg_reference = NULL;
char *obj_type = NULL;
char *clear = NULL;
char *status = NULL;
char *migrate_from = NULL;
char *migrate_res = NULL;
char *subtype = NULL;
char *reset = NULL;

int operation_status = 0;
const char *sys_to = NULL;;

#define OPTARGS	"V?i:o:QDSUCEX:"

int
main(int argc, char **argv)
{
	int option_index = 0;
	int argerr = 0;
	int flag;
	ll_cluster_t *hb_cluster = NULL;
	int level = 0;
	char *xml_text = NULL;
	
	static struct option long_options[] = {
		// Top-level Options
		{CRM_OP_ERASE,   0, 0, 'E'},
		{CRM_OP_QUERY,   0, 0, 'Q'},
		{CRM_OP_CREATE,  0, 0, 'C'},
		{CRM_OP_REPLACE, 0, 0, 'R'},
		{CRM_OP_STORE,   0, 0, 'S'},
		{CRM_OP_UPDATE,  0, 0, 'U'},
		{CRM_OP_DELETE,  0, 0, 'D'},
		{"xml",          1, 0, 'X'},
		{"verbose",      0, 0, 'V'},
		{"help",         0, 0, '?'},
		{"reference",    1, 0, 0},

		// common options
		{XML_ATTR_ID, 1, 0, 'i'},
		{"obj_type", 1, 0, 'o'},

		{0, 0, 0, 0}
	};

	if(argc < 2) {
		usage(crm_system_name, LSB_EXIT_EINVAL);
	}

	cl_log_set_entity(crm_system_name);
	cl_log_set_facility(LOG_USER);

	while (1) {
		flag = getopt_long(argc, argv, OPTARGS,
				   long_options, &option_index);
		if (flag == -1)
			break;

		switch(flag) {
			case 0:
				printf("option %s",
				       long_options[option_index].name);
				if (optarg)
					printf(" with arg %s", optarg);
				printf("\n");
			
	if ((safe_str_eq(CRM_OP_ERASE,      long_options[option_index].name))
	    || (safe_str_eq(CRM_OP_CREATE,  long_options[option_index].name))
	    || (safe_str_eq(CRM_OP_UPDATE,  long_options[option_index].name))
	    || (safe_str_eq(CRM_OP_DELETE,  long_options[option_index].name))
	    || (safe_str_eq(CRM_OP_REPLACE, long_options[option_index].name))
	    || (safe_str_eq(CRM_OP_STORE,   long_options[option_index].name))
	    || (safe_str_eq(CRM_OP_QUERY,   long_options[option_index].name))){
		cib_action = crm_strdup(long_options[option_index].name);
					
	} else if (safe_str_eq("reference", long_options[option_index].name)) {
		this_msg_reference = crm_strdup(optarg);

	} else {
		printf("Long option (--%s) is not (yet?) properly supported\n",
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
				
			case 'E':
				cib_action = crm_strdup(CRM_OP_ERASE);
				break;
			case 'Q':
				cib_action = crm_strdup(CRM_OP_QUERY);
				break;
			case 'U':
				cib_action = crm_strdup(CRM_OP_UPDATE);
				break;
			case 'R':
				cib_action = crm_strdup(CRM_OP_REPLACE);
				break;
			case 'S':
				cib_action = crm_strdup(CRM_OP_STORE);
				break;
			case 'C':
				cib_action = crm_strdup(CRM_OP_CREATE);
				break;
			case 'D':
				cib_action = crm_strdup(CRM_OP_DELETE);
				break;
			case 'V':
				level = get_crm_log_level();
				BE_VERBOSE = TRUE;
				verbose = XML_BOOLEAN_TRUE;
				cl_log_enable_stderr(TRUE);
				set_crm_log_level(level+1);
				break;
			case '?':
				usage(crm_system_name, LSB_EXIT_OK);
				break;
			case 'i':
				crm_verbose("Option %c => %s", flag, optarg);
				id = crm_strdup(optarg);
				break;
			case 'o':
				crm_verbose("Option %c => %s", flag, optarg);
				obj_type = crm_strdup(optarg);
				break;
			case 'X':
				xml_text = crm_strdup(optarg);
				break;
			default:
				printf("Argument code 0%o (%c)"
				       " is not (?yet?) supported\n",
				       flag, flag);
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

	hb_cluster = do_init();
	if (hb_cluster != NULL) {
		if (do_work(hb_cluster, xml_text) > 0) {
			/* wait for the reply by creating a mainloop and running it until
			 * the callbacks are invoked...
			 */
			mainloop = g_main_new(FALSE);
			crm_info("%s waiting for reply from the local CRM",
				 crm_system_name);

			g_main_run(mainloop);
			return_to_orig_privs();
		} else {
			crm_err("No message to send");
			operation_status = -1;
		}
	} else {
		crm_err("Init failed, could not perform requested operations");
		operation_status = -2;
	}

	crm_debug("%s exiting normally", crm_system_name);
	return operation_status;
}

xmlNodePtr
handleCibMod(const char *xml)
{
	const char *attr_name = NULL;
	const char *attr_value = NULL;
	xmlNodePtr fragment = NULL;
	xmlNodePtr cib_object = NULL;

	if(xml == NULL) {
		cib_object = file2xml(stdin);
	} else {
		cib_object = string2xml(xml);
	}
	
	
	if(cib_object == NULL) {
		return NULL;
	}
	
	attr_name = XML_ATTR_ID;
	
	attr_value = xmlGetProp(cib_object, attr_name);
	if(attr_name == NULL || strlen(attr_name) == 0) {
		crm_err("No value for %s specified.", attr_name);
		return NULL;
	}
	
	crm_trace("Object creation complete");

	// create the cib request
	fragment = create_cib_fragment(cib_object, NULL);

	set_xml_property_copy(msg_options, XML_ATTR_OP, cib_action);

	return fragment;
}


int
do_work(ll_cluster_t * hb_cluster, const char *xml_text)
{
	/* construct the request */
	xmlNodePtr msg_data = NULL;
	const char *dest_node = NULL;
	gboolean all_is_good = TRUE;
	char *obj_type_parent = NULL;
	
	msg_options = create_xml_node(NULL, XML_TAG_OPTIONS);
	set_xml_property_copy(msg_options, XML_ATTR_VERBOSE, verbose);
	set_xml_property_copy(msg_options, XML_ATTR_TIMEOUT, "0");

	if(strcmp(CRM_OP_QUERY, cib_action) == 0) {
		crm_debug("Querying the CIB");
		obj_type_parent = pluralSection(obj_type);
		
		crm_verbose("Querying the CIB for section: %s",
			    obj_type_parent);
		
		set_xml_property_copy(msg_options, XML_ATTR_OP, CRM_OP_QUERY);

		if(obj_type_parent != NULL) {
			set_xml_property_copy(
				msg_options,
				XML_ATTR_FILTER_TYPE, obj_type_parent);
		}
		if(id != NULL) {
			set_xml_property_copy(
				msg_options, XML_ATTR_FILTER_ID, id);
		}
		
		dest_node = status;
		crm_verbose("CIB query creation %s",
			    msg_data == NULL ? "failed." : "passed.");
		
		sys_to = CRM_SYSTEM_DCIB;
		
	} else if (strcmp(CRM_OP_ERASE, cib_action) == 0) {
		set_xml_property_copy(msg_options,
				      XML_ATTR_OP,
				      CRM_OP_ERASE);
		
		dest_node = status;
		crm_trace("CIB Erase op in progress");
		
		sys_to = CRM_SYSTEM_DCIB;
		
	} else if(cib_action != NULL) {
		msg_data = handleCibMod(xml_text);
		sys_to = CRM_SYSTEM_DCIB;
		if(msg_data == NULL)
			all_is_good = FALSE;
		
	} else {
		crm_err("Unknown options");
		all_is_good = FALSE;
	}
	
	if(all_is_good == FALSE) {
		crm_err("Creation of request failed.  No message to send");
		return -1;
	}

/* send it */
	if (crmd_channel == NULL) {
		crm_err("The IPC connection is not valid, cannot send anything");
		return -1;
	}

	if(sys_to == NULL) {
		if (dest_node != NULL)
			sys_to = CRM_SYSTEM_CRMD;
		else
			sys_to = CRM_SYSTEM_DC;				
	}
		
	send_ipc_request(
		crmd_channel, msg_options, msg_data,
		dest_node, sys_to,
		crm_system_name, admin_uuid, this_msg_reference);

	return 1;

}

ll_cluster_t *
do_init(void)
{
	int facility;
	ll_cluster_t *hb_cluster = NULL;

	/* docs say only do this once, but in their code they do it every time! */
	xmlInitParser (); 

	/* change the logging facility to the one used by heartbeat daemon */
	hb_cluster = ll_cluster_new("heartbeat");
	
	crm_info("Switching to Heartbeat logger");
	if (( facility =
	      hb_cluster->llc_ops->get_logfacility(hb_cluster)) > 0) {
		cl_log_set_facility(facility);
	}

	admin_uuid = crm_malloc(sizeof(char) * 11);
	snprintf(admin_uuid, 10, "%d", getpid());
	admin_uuid[10] = '\0';

	crmd_channel =
		init_client_ipc_comms(CRM_SYSTEM_CRMD,admin_msg_callback,NULL);

	if(crmd_channel != NULL) {
		send_hello_message(crmd_channel,
				   admin_uuid,
				   crm_system_name,
				   "0",
				   "1");

		return hb_cluster;
	} 
	return NULL;
}


gboolean
admin_msg_callback(IPC_Channel * server, void *private_data)
{
	int lpc = 0;
	IPC_Message *msg = NULL;
	gboolean hack_return_good = TRUE;
	static int received_responses = 0;
	char *filename;
	int filename_len = 0;
	const char *result = NULL;
	xmlNodePtr options = NULL;
	xmlNodePtr xml_root_node = NULL;
	char *buffer = NULL;

	

	while (server->ch_status != IPC_DISCONNECT
	       && server->ops->is_message_pending(server) == TRUE) {
		if (server->ops->recv(server, &msg) != IPC_OK) {
			perror("Receive failure:");
			return !hack_return_good;
		}

		if (msg == NULL) {
			crm_trace("No message this time");
			continue;
		}

		lpc++;
		buffer =(char *) msg->msg_body;
		crm_verbose("Got xml [text=%s]", buffer);

		xml_root_node = find_xml_in_ipcmessage(msg, TRUE);

		if (xml_root_node == NULL) {
			crm_info(
			       "XML in IPC message was not valid... "
			       "discarding.");
			continue;
		} else if (validate_crm_message(xml_root_node,
					 crm_system_name,
					 admin_uuid,
					 "response") == FALSE) {
			crm_info(
			       "Message was not a CRM response. Discarding.");
			continue;
		}

		options = find_xml_node(xml_root_node, XML_TAG_OPTIONS);
		
		result = xmlGetProp(options, XML_ATTR_RESULT);
		if(result == NULL || strcmp(result, "ok") == 0) {
			result = "pass";
		} else {
			result = "fail";
		}
		
		received_responses++;

		if(strcmp(CRM_OP_QUERY, cib_action) == 0) {
			print_xml_formatted(xml_root_node);
			
		} else if (strcmp(CRM_OP_ERASE, cib_action) == 0) {
			print_xml_formatted(xml_root_node);
		
		} else if(cib_action != NULL) {
			print_xml_formatted(xml_root_node);
		
		}

		if (this_msg_reference != NULL) {
			// in testing mode...
			/* 31 = "test-_.xml" + an_int_as_string + '\0' */
			filename_len = 31 + strlen(this_msg_reference);

			filename = crm_malloc(sizeof(char) * filename_len);
			sprintf(filename, "%s-%s_%d.xml",
				result,
				this_msg_reference,
				received_responses);
			
			filename[filename_len - 1] = '\0';
			if (xmlSaveFormatFile(
				    filename, xml_root_node->doc, 1) < 0) {
				crm_crit("Could not save response %s_%s_%d.xml",
					 this_msg_reference,
					 result,
					 received_responses);
			}
		}
	}

	if (server->ch_status == IPC_DISCONNECT) {
		crm_info("admin_msg_callback: received HUP");
		return !hack_return_good;
	}

	if (received_responses >= expected_responses) {
		crm_info(
		       "Recieved expected number (%d) of messages from Heartbeat."
		       "  Exiting normally.", expected_responses);
		g_main_quit(mainloop);
		return !hack_return_good;
	}
	return hack_return_good;
}


void
usage(const char *cmd, int exit_status)
{
	FILE *stream;

	stream = exit_status ? stderr : stdout;

	fprintf(stream, "usage: %s [-?Vio] command\n"
		"\twhere necessary, XML data will be expected using -X"
		" or on STDIN if -X isnt specified\n", cmd);

	fprintf(stream, "Options\n");
	fprintf(stream, "\t--%s (-%c) <id>\tid of the object being operated on\n",
		XML_ATTR_ID, 'i');
	fprintf(stream, "\t--%s (-%c) <type>\tobject type being operated on\n",
		"obj_type", 'o');
	fprintf(stream, "\t--%s (-%c)\tturn on debug info."
		"  additional instance increase verbosity\n", "verbose", 'V');
	fprintf(stream, "\t--%s (-%c)\tthis help message\n", "help", '?');
	fprintf(stream, "\nCommands\n");
	fprintf(stream, "\t--%s (-%c)\t\n", CRM_OP_ERASE, 'E');
	fprintf(stream, "\t--%s (-%c)\t\n", CRM_OP_QUERY, 'Q');
	fprintf(stream, "\t--%s (-%c)\t\n", CRM_OP_CREATE, 'C');
	fprintf(stream, "\t--%s (-%c)\t\n", CRM_OP_REPLACE, 'R');
	fprintf(stream, "\t--%s (-%c)\t\n", CRM_OP_STORE, 'S');
	fprintf(stream, "\t--%s (-%c)\t\n", CRM_OP_UPDATE, 'U');
	fprintf(stream, "\t--%s (-%c)\t\n", CRM_OP_DELETE, 'D');
	fprintf(stream, "\nXML data\n");
	fprintf(stream, "\t--%s (-%c) <string>\t\n", "xml", 'X');

	fflush(stream);

	exit(exit_status);
}
