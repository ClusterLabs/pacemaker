/* $Id: adminmain.c,v 1.15 2004/03/19 10:43:42 andrew Exp $ */

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
char *admin_uuid = NULL;

void usage(const char *cmd, int exit_status);
ll_cluster_t *do_init(void);
int do_work(ll_cluster_t * hb_cluster);
gboolean decodeNVpair(const char *srcstring, char separator,
		      char **name, char **value);
gboolean admin_msg_callback(IPC_Channel * source_data, void *private_data);
char *pluralSection(const char *a_section);
xmlNodePtr handleCibMod(void);


gboolean DO_DAEMON  = FALSE;
gboolean BE_VERBOSE = FALSE;
int expected_responses = 1;

gboolean DO_HEALTH       = FALSE;
gboolean DO_ELECT_DC     = FALSE;
gboolean DO_WHOIS_DC     = FALSE;
gboolean DO_RECALC_TREE  = FALSE;
gboolean DO_FLUSH_RECALC = FALSE;


const char *cib_action = NULL;
xmlNodePtr msg_options = NULL;

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
char *clear = NULL;
char *status = NULL;
char *disconnect = NULL;
char *unload_ha = NULL;
char *migrate_from = NULL;
char *migrate_res = NULL;
char *subtype = NULL;
char *reset = NULL;

int operation_status = 0;
const char *sys_to = NULL;;

int
main(int argc, char **argv)
{

	cl_log_set_entity(crm_system_name);
	cl_log_enable_stderr(TRUE);
	cl_log_set_facility(LOG_USER);

	int argerr = 0;
	int flag;

	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
			// Top-level Options
			{"daemon", 0, 0, 0},
			{CRM_OPERATION_ERASE, 0, 0, 0},
			{CRM_OPERATION_QUERY, 0, 0, 0},
			{CRM_OPERATION_CREATE, 0, 0, 0},
			{CRM_OPERATION_REPLACE, 0, 0, 0},
			{CRM_OPERATION_STORE, 0, 0, 0},
			{CRM_OPERATION_UPDATE, 0, 0, 0},
			{CRM_OPERATION_DELETE, 0, 0, 0},
			{"verbose", 0, 0, 'V'},
			{"help", 0, 0, '?'},
			{"reference", 1, 0, 0},

			// common options
			{"id", 1, 0, 'i'},
			{"obj_type", 1, 0, 'o'},

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
				else if (strcmp(CRM_OPERATION_ERASE,
						long_options[option_index].name) == 0
					 || strcmp(CRM_OPERATION_CREATE,
						   long_options[option_index].name) == 0
					 || strcmp(CRM_OPERATION_UPDATE,
						   long_options[option_index].name) == 0
					 || strcmp(CRM_OPERATION_DELETE,
						   long_options[option_index].name) == 0
					 || strcmp(CRM_OPERATION_REPLACE,
						   long_options[option_index].name) == 0
					 || strcmp(CRM_OPERATION_STORE,
						   long_options[option_index].name) == 0
					 || strcmp(CRM_OPERATION_QUERY,
						   long_options[option_index].name) == 0){
					
					cib_action = ha_strdup(long_options[option_index].name);

				} else if (strcmp("reference",
						  long_options[option_index].name) == 0) {
					this_msg_reference =
						ha_strdup(optarg);
				} else {
					printf( "?? Long option (--%s) is not yet properly supported ??\n",
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
handleCibMod(void)
{

	char ch = 0;
	gboolean more = TRUE;
	gboolean inTag = FALSE;
	xmlBufferPtr xml_buffer = xmlBufferCreate();
	
	while (more) {
		ch = fgetc(stdin);
//		cl_log(LOG_DEBUG, "Got [%c]", ch);
		switch(ch) {
			case EOF: 
			case 0:
				ch = 0;
				more = FALSE; 
				xmlBufferAdd(xml_buffer, &ch, 1);
				break;
			case '>':
			case '<':
				inTag = TRUE;
				if(ch == '>') inTag = FALSE;
				xmlBufferAdd(xml_buffer, &ch, 1);
				break;
			case '\n':
			case '\t':
			case ' ':
				ch = ' ';
				if(inTag) {
					xmlBufferAdd(xml_buffer, &ch, 1);
				} 
				break;
			default:
				xmlBufferAdd(xml_buffer, &ch, 1);
				break;
		}
	}

	
	xmlNodePtr cib_object = NULL;
	const char *the_xml = xmlBufferContent(xml_buffer);
	xmlDocPtr doc = xmlParseMemory(the_xml, strlen(the_xml));
	if (doc == NULL) {
		cl_log(LOG_ERR, "Malformed XML [xml=%s]", the_xml);
		return NULL;
	}
	cib_object = xmlDocGetRootElement(doc);

	xml_message_debug(cib_object, "Created fragment");
	
	if(strcmp(cib_object->name, obj_type) != 0) {
		cl_log(LOG_ERR, "Mismatching xml."
		       "  Expected root element <%s>, got <%s>",
		       obj_type, cib_object->name);
		return NULL;
	}

	const char *attr_name = NULL;
	const char *attr_value = NULL;

	attr_name = XML_ATTR_ID;
	
	attr_value = xmlGetProp(cib_object, attr_name);
	if(attr_name == NULL || strlen(attr_name) == 0) {
		cl_log(LOG_ERR, "No value for %s specified.", attr_name);
		return NULL;
	}
	
	CRM_DEBUG("Object creation complete");

	// create the cib request
	xmlNodePtr cib = NULL, fragment = NULL, object_root = NULL;
	set_xml_property_copy(msg_options, XML_ATTR_OP, cib_action);
	
	// create the update section
	char *section_name = pluralSection(obj_type);

	CRM_DEBUG("xml things");
	fragment = create_xml_node(NULL, XML_TAG_FRAGMENT);
	set_xml_property_copy(fragment, XML_ATTR_SECTION, section_name);
	set_xml_property_copy(msg_options, XML_ATTR_FILTER_TYPE, section_name);

	cib = createEmptyCib();
	CRM_DEBUG("get the right section");
	object_root = get_object_root(section_name, cib);
	xmlAddChild(object_root, cib_object);

	xmlAddChild(fragment, cib);
	CRM_DEBUG("Fragment created");

	return fragment;
}


char *
pluralSection(const char *a_section)
{
	char *a_section_parent = NULL;
	if (a_section == NULL) {
		a_section_parent = ha_strdup("all");

	} else if(strcmp(a_section, "node") == 0) {
		a_section_parent = ha_strdup("nodes");

	} else if(strcmp(a_section, "state") == 0) {
		a_section_parent = ha_strdup("status");

	} else if(strcmp(a_section, "constraint") == 0) {
		a_section_parent = ha_strdup("constraints");
		
	} else if(strcmp(a_section, "resource") == 0) {
		a_section_parent = ha_strdup("resources");

	} else {
		cl_log(LOG_ERR, "Unknown section %s", a_section);
	}
	
	CRM_DEBUG2("Plural is %s", a_section_parent);
	return a_section_parent;
}



int
do_work(ll_cluster_t * hb_cluster)
{
	/* construct the request */
	xmlNodePtr msg_data = NULL;
	const char *dest_node = NULL;
	gboolean all_is_good = TRUE;
	
	msg_options = create_xml_node(NULL, XML_TAG_OPTIONS);
	set_xml_property_copy(msg_options, XML_ATTR_VERBOSE, verbose);
	set_xml_property_copy(msg_options, XML_ATTR_TIMEOUT, "0");


	if (DO_DAEMON == TRUE && cib_action != NULL) {

		if(strcmp(CRM_OPERATION_QUERY, cib_action) == 0) {
			cl_log(LOG_DEBUG, "Querying the CIB");
			char *obj_type_parent = pluralSection(obj_type);
			
			CRM_DEBUG2("Querying the CIB for section: %s",
				   obj_type_parent);
			
			set_xml_property_copy(msg_options, XML_ATTR_OP, CRM_OPERATION_QUERY);
			set_xml_property_copy(msg_options, XML_ATTR_FILTER_ID,
					      obj_type_parent);
			
			dest_node = status;
			CRM_DEBUG2("CIB query creation %s",
				   msg_data == NULL ? "failed." : "passed.");
			
			sys_to = CRM_SYSTEM_DCIB;
			
		} else if (strcmp(CRM_OPERATION_ERASE, cib_action) == 0) {
			set_xml_property_copy(msg_options,
					      XML_ATTR_OP,
					      CRM_OPERATION_ERASE);
			
			dest_node = status;
			CRM_DEBUG("CIB Erase op in progress");
			
			sys_to = CRM_SYSTEM_DCIB;
		} else {
			cl_log(LOG_ERR, "Unknown daemon options");
			all_is_good = FALSE;
		}
		
	} else if(cib_action != NULL) {
			msg_data = handleCibMod();
			sys_to = CRM_SYSTEM_DCIB;
			if(msg_data == NULL)
				all_is_good = FALSE;
		
	} else if (DO_DAEMON == TRUE && DO_HEALTH == TRUE) {
		CRM_DEBUG("Querying the system");

		sys_to = CRM_SYSTEM_DC;

		if (status != NULL) {
			sys_to = CRM_SYSTEM_CRMD;
			const char *ping_type = CRM_OPERATION_PING;
			if (BE_VERBOSE) {
				ping_type = "ping_deep";
				if (status != NULL)
					expected_responses = 2;	// 5; // CRM/DC, LRMD, CIB, PENGINE, TENGINE
				else
					expected_responses = -1;// wait until timeout instead
			}

			set_xml_property_copy(msg_options,
					      XML_ATTR_OP,
					      ping_type);
			
			set_xml_property_copy(msg_options,
					      XML_ATTR_TIMEOUT,
					      "0");

			dest_node = status;
		} else {
			cl_log(LOG_INFO, "Cluster-wide health not available yet");
			all_is_good = FALSE;
		}
	} else {
		cl_log(LOG_ERR, "Unknown options");
		all_is_good = FALSE;
	}
	

	if(all_is_good == FALSE) {
		cl_log(LOG_ERR, "Creation of request failed.  No message to send");
		return -1;
	}

/* send it */
	if (crmd_channel == NULL) {
		cl_log(LOG_ERR,
		       "The IPC connection is not valid, cannot send anything");
		return -1;
	}

	if(sys_to == NULL) {
		if (dest_node != NULL)
			sys_to = CRM_SYSTEM_CRMD;
		else
			sys_to = CRM_SYSTEM_DC;				
	}
		
	send_ipc_request(crmd_channel,
			 msg_options,
			 msg_data,
			 dest_node, sys_to,
			 crm_system_name,
			 admin_uuid,
			 this_msg_reference);

	return 1;

}

ll_cluster_t *
do_init(void)
{

	/* docs say only do this once, but in their code they do it every time! */
	xmlInitParser (); 

	/* change the logging facility to the one used by heartbeat daemon */
	ll_cluster_t *hb_cluster = ll_cluster_new("heartbeat");
	
	int facility;
	cl_log(LOG_INFO, "Switching to Heartbeat logger");
	if (( facility =
	      hb_cluster->llc_ops->get_logfacility(hb_cluster)) > 0) {
		cl_log_set_facility(facility);
	}

	admin_uuid = ha_malloc(sizeof(char) * 11);
	snprintf(admin_uuid, 10, "%d", getpid());
	admin_uuid[10] = '\0';

	crmd_channel =
		init_client_ipc_comms(CRM_SYSTEM_CRMD,
				      admin_msg_callback,
				      NULL);
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
	static int received_responses = 0;

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

		xmlNodePtr xml_root_node =
			find_xml_in_ipcmessage(msg, TRUE);

		if (xml_root_node == NULL) {
			cl_log(LOG_INFO,
			       "XML in IPC message was not valid... "
			       "discarding.");
			continue;
		} else if (validate_crm_message(xml_root_node,
					 crm_system_name,
					 admin_uuid,
					 "response") == FALSE) {
			cl_log(LOG_INFO,
			       "Message was not a CRM response. Discarding.");
			continue;
		}

		xmlNodePtr options = find_xml_node(xml_root_node,
						   XML_TAG_OPTIONS);
		
		const char *result = xmlGetProp(options, XML_ATTR_RESULT);
		if(result == NULL || strcmp(result, "ok") == 0) {
			result = "pass";
		} else {
			result = "fail";
		}
		
		received_responses++;

		// do stuff

		if (this_msg_reference != NULL) {
			// in testing mode...
			char *filename;
			/* 31 = "test-_.xml" + an_int_as_string + '\0' */
			int filename_len = 31 + strlen(this_msg_reference);

			filename = ha_malloc(sizeof(char) * filename_len);
			sprintf(filename, "%s-%s_%d.xml",
				result,
				this_msg_reference,
				received_responses);
			
			filename[filename_len - 1] = '\0';
			if (xmlSaveFormatFile(filename,
					      xml_root_node->doc, 1) < 0) {
				cl_log(LOG_CRIT,
				       "Could not save response %s_%s_%d.xml",
				       this_msg_reference,
				       result,
				       received_responses);
			}
		}
	}

	if (server->ch_status == IPC_DISCONNECT) {
		cl_log(LOG_INFO, "admin_msg_callback: received HUP");
		FNRET(!hack_return_good);
	}

	if (received_responses >= expected_responses) {
		cl_log(LOG_INFO,
		       "Recieved expected number (%d) of messages from Heartbeat."
		       "  Exiting normally.", expected_responses);
		g_main_quit(mainloop);
		return !hack_return_good;
	}
	FNRET(hack_return_good);
}
