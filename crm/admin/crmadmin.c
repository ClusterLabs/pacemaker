/* $Id: crmadmin.c,v 1.2 2004/07/30 15:31:04 andrew Exp $ */

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
#include <libgen.h>

#include <hb_api.h>
#include <clplumbing/uids.h>

#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/ctrl.h>
#include <crm/common/ipc.h>

#include <crm/cib.h>

#include <getopt.h>
#include <crm/dmalloc_wrapper.h>

GMainLoop *mainloop = NULL;
IPC_Channel *crmd_channel = NULL;
char *admin_uuid = NULL;

void usage(const char *cmd, int exit_status);
ll_cluster_t *do_init(void);
int do_work(ll_cluster_t * hb_cluster);

gboolean admin_msg_callback(IPC_Channel * source_data, void *private_data);
char *pluralSection(const char *a_section);
xmlNodePtr handleCibMod(void);
int do_find_resource(const char *rsc, xmlNodePtr xml_node);
int do_find_resource_list(xmlNodePtr xml_node);
int do_find_node_list(xmlNodePtr xml_node);

enum debug {
	debug_none,
	debug_dec,
	debug_inc
};

gboolean BE_VERBOSE = FALSE;
int expected_responses = 1;

gboolean DO_HEALTH        = FALSE;
gboolean DO_RESET         = FALSE;
gboolean DO_RESOURCE      = FALSE;
gboolean DO_ELECT_DC      = FALSE;
gboolean DO_WHOIS_DC      = FALSE;
gboolean DO_NODE_LIST     = FALSE;
gboolean BE_SILENT        = FALSE;
gboolean DO_RESOURCE_LIST = FALSE;
enum debug DO_DEBUG       = debug_none;

xmlNodePtr msg_options = NULL;

const char *verbose = XML_BOOLEAN_FALSE;
char *id = NULL;
char *this_msg_reference = NULL;
char *disconnect = NULL;
char *dest_node  = NULL;
char *rsc_name   = NULL;

int operation_status = 0;
const char *sys_to = NULL;;
const char *crm_system_name = "crmadmin";

#define OPTARGS	"V?K:S:HE:DW:d:i:RNs"

int
main(int argc, char **argv)
{
	int option_index = 0;
	int argerr = 0;
	int flag;
	ll_cluster_t *hb_cluster = NULL;
	int level = 0;

	static struct option long_options[] = {
		// Top-level Options
		{"verbose", 0, 0, 'V'},
		{"help", 0, 0, '?'},
		{"silent", 0, 0, 's'},
		{"reference", 1, 0, 0},

		// daemon options
		{"kill", 1, 0, 'K'},  // stop a node
		{"crm_debug_inc", 1, 0, 'i'},
		{"crm_debug_dec", 1, 0, 'd'},
		{"status", 1, 0, 'S'},
		{"health", 0, 0, 'H'},
		{"election", 0, 0, 'E'},
		{"dc_lookup", 0, 0, 'D'},
		{"resources", 0, 0, 'R'},
		{"nodes", 0, 0, 'N'},
		{"whereis", 1, 0, 'W'},

		{0, 0, 0, 0}
	};

	crm_system_name = basename(argv[0]);
	cl_log_set_entity(crm_system_name);
	cl_log_set_facility(LOG_USER);

	if(argc < 2) {
		usage(crm_system_name, LSB_EXIT_EINVAL);
	}
	
	while (1) {
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
			
				if (strcmp("reference",
					   long_options[option_index].name) == 0) {
					this_msg_reference =
						crm_strdup(optarg);

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
				level = get_crm_log_level();
				BE_VERBOSE = TRUE;
				verbose = XML_BOOLEAN_TRUE;
				cl_log_enable_stderr(TRUE);
				set_crm_log_level(level+1);
				break;
			case '?':
				usage(crm_system_name, LSB_EXIT_OK);
				break;
			case 'D':
				DO_WHOIS_DC = TRUE;
				break;
			case 'W':
				DO_RESOURCE = TRUE;
				crm_verbose("Option %c => %s", flag, optarg);
				rsc_name = crm_strdup(optarg);
				break;
			case 'K':
				DO_RESET = TRUE;
				crm_verbose("Option %c => %s", flag, optarg);
				dest_node = crm_strdup(optarg);
				break;
			case 's':
				BE_SILENT = TRUE;
				break;
			case 'i':
				DO_DEBUG = debug_inc;
				crm_verbose("Option %c => %s", flag, optarg);
				dest_node = crm_strdup(optarg);
				break;
			case 'd':
				DO_DEBUG = debug_dec;
				crm_verbose("Option %c => %s", flag, optarg);
				dest_node = crm_strdup(optarg);
				break;
			case 'S':
				DO_HEALTH = TRUE;
				crm_verbose("Option %c => %s", flag, optarg);
				dest_node = crm_strdup(optarg);
				break;
			case 'E':
				DO_ELECT_DC = TRUE;
				break;
			case 'N':
				DO_NODE_LIST = TRUE;
				break;
			case 'R':
				DO_RESOURCE_LIST = TRUE;
				break;
			case 'H':
				DO_HEALTH = TRUE;
				break;
			default:
				printf("Argument code 0%o (%c) is not (?yet?) supported\n", flag, flag);
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
		int res = do_work(hb_cluster);
		if (res > 0) {
			/* wait for the reply by creating a mainloop and running it until
			 * the callbacks are invoked...
			 */
			mainloop = g_main_new(FALSE);
			crm_verbose("%s waiting for reply from the local CRM",
				 crm_system_name);

			g_main_run(mainloop);
			return_to_orig_privs();
			
		} else if(res == 0) {
			crm_verbose("%s: no reply expected",
				 crm_system_name);
			
		} else {
			crm_err("No message to send");
			operation_status = -1;
		}
	} else {
		crm_err("Init failed, could not perform requested operations");
		operation_status = -2;
	}

	crm_verbose("%s exiting normally", crm_system_name);
	return operation_status;
}



int
do_work(ll_cluster_t * hb_cluster)
{
	int ret = 1;
	/* construct the request */
	xmlNodePtr msg_data = NULL;
	gboolean all_is_good = TRUE;
	
	msg_options = create_xml_node(NULL, XML_TAG_OPTIONS);
	set_xml_property_copy(msg_options, XML_ATTR_VERBOSE, verbose);
	set_xml_property_copy(msg_options, XML_ATTR_TIMEOUT, "0");

	if (DO_HEALTH == TRUE) {
		crm_verbose("Querying the system");
		
		sys_to = CRM_SYSTEM_DC;
		
		if (dest_node != NULL) {
			sys_to = CRM_SYSTEM_CRMD;
			if (BE_VERBOSE) {
				expected_responses = -1;// wait until timeout instead
			}
			
			set_xml_property_copy(
				msg_options, XML_ATTR_OP, CRM_OP_PING);
			
			set_xml_property_copy(
				msg_options, XML_ATTR_TIMEOUT, "0");

		} else {
			crm_info("Cluster-wide health not available yet");
			all_is_good = FALSE;
		}
		
	} else if(DO_ELECT_DC) {
		/* tell the local node to initiate an election */

		sys_to = CRM_SYSTEM_CRMD;

		set_xml_property_copy(
			msg_options, XML_ATTR_OP, CRM_OP_VOTE);
		
		set_xml_property_copy(
			msg_options, XML_ATTR_TIMEOUT, "0");
		
		dest_node = NULL;

		ret = 0; // no return message
		
	} else if(DO_WHOIS_DC) {
		sys_to = CRM_SYSTEM_DC;

		set_xml_property_copy(
			msg_options, XML_ATTR_OP, CRM_OP_PING);
			
		set_xml_property_copy(
			msg_options, XML_ATTR_TIMEOUT, "0");

		dest_node = NULL;
		
		
	} else if(DO_RESOURCE) {
		set_xml_property_copy(msg_options, XML_ATTR_OP, CRM_OP_QUERY);
		set_xml_property_copy(
			msg_options, XML_ATTR_FILTER_TYPE, XML_CIB_TAG_STATUS);
		
		sys_to = CRM_SYSTEM_CIB;

	} else if(DO_RESOURCE_LIST) {
		set_xml_property_copy(msg_options, XML_ATTR_OP, CRM_OP_QUERY);
		set_xml_property_copy(
			msg_options, XML_ATTR_FILTER_TYPE, XML_CIB_TAG_RESOURCES);
		
		sys_to = CRM_SYSTEM_CIB;

	} else if(DO_NODE_LIST) {
		set_xml_property_copy(msg_options, XML_ATTR_OP, CRM_OP_QUERY);
		set_xml_property_copy(
			msg_options, XML_ATTR_FILTER_TYPE, XML_CIB_TAG_NODES);
		
		sys_to = CRM_SYSTEM_CIB;

	} else if(DO_RESET) {
		/* tell dest_node to initiate the shutdown proceedure
		 *
		 * if dest_node is NULL, the request will be sent to the
		 *   local node
		 */
		sys_to = CRM_SYSTEM_CRMD;

		set_xml_property_copy(
			msg_options, XML_ATTR_OP, "init_shutdown");
		
		set_xml_property_copy(
			msg_options, XML_ATTR_TIMEOUT, "0");
		
		ret = 0; // no return message
		
	} else if(DO_DEBUG == debug_inc) {
		/* tell dest_node to increase its debug level
		 *
		 * if dest_node is NULL, the request will be sent to the
		 *   local node
		 */
		sys_to = CRM_SYSTEM_CRMD;

		set_xml_property_copy(msg_options, XML_ATTR_OP, "debug_inc");
		set_xml_property_copy(msg_options, XML_ATTR_TIMEOUT, "0");
		
		ret = 0; // no return message
		
	} else if(DO_DEBUG == debug_dec) {
		/* tell dest_node to increase its debug level
		 *
		 * if dest_node is NULL, the request will be sent to the
		 *   local node
		 */
		sys_to = CRM_SYSTEM_CRMD;

		set_xml_property_copy(msg_options, XML_ATTR_OP, "debug_dec");
		set_xml_property_copy(msg_options, XML_ATTR_TIMEOUT, "0");
		
		ret = 0; // no return message
		
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
		
	send_ipc_request(crmd_channel,
			 msg_options,
			 msg_data,
			 dest_node, sys_to,
			 crm_system_name,
			 admin_uuid,
			 this_msg_reference);

	return ret;

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
	
	crm_verbose("Switching to Heartbeat logger");
	if (( facility =
	      hb_cluster->llc_ops->get_logfacility(hb_cluster)) > 0) {
		cl_log_set_facility(facility);
	}

	admin_uuid = crm_malloc(sizeof(char) * 11);
	snprintf(admin_uuid, 10, "%d", getpid());
	admin_uuid[10] = '\0';

	crmd_channel = init_client_ipc_comms(
		CRM_SYSTEM_CRMD, admin_msg_callback, NULL);

	if(crmd_channel != NULL) {
		send_hello_message(
			crmd_channel, admin_uuid, crm_system_name,"0", "1");

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

		if(DO_HEALTH) {
			xmlNodePtr ping = find_xml_node(
				xml_root_node, XML_CRM_TAG_PING);

			const char *state = xmlGetProp(ping, "crmd_state");

			printf("Status of %s@%s: %s (%s)\n",
			       xmlGetProp(ping, XML_PING_ATTR_SYSFROM),
			       xmlGetProp(xml_root_node, XML_ATTR_HOSTFROM),
			       state,
			       xmlGetProp(ping, XML_PING_ATTR_STATUS));
			
			if(BE_SILENT && state != NULL) {
				fprintf(stderr, "%s\n", state);
			}
			
		} else if(DO_RESOURCE) {
			do_find_resource(rsc_name, xml_root_node);
			
		} else if(DO_RESOURCE_LIST) {
			do_find_resource_list(xml_root_node);

		} else if(DO_NODE_LIST) {
			do_find_node_list(xml_root_node);

		} else if(DO_WHOIS_DC) {
			const char *dc = xmlGetProp(
				xml_root_node, XML_ATTR_HOSTFROM);
			
			printf("Designated Controller is: %s\n", dc);
			if(BE_SILENT && dc != NULL) {
				fprintf(stderr, "%s\n", dc);
			}
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
			if (xmlSaveFormatFile(filename,
					      xml_root_node->doc, 1) < 0) {
				crm_crit("Could not save response %s_%s_%d.xml",
					 this_msg_reference,
					 result,
					 received_responses);
			}
		}
	}

	if (server->ch_status == IPC_DISCONNECT) {
		crm_verbose("admin_msg_callback: received HUP");
		return !hack_return_good;
	}

	if (received_responses >= expected_responses) {
		crm_verbose(
		       "Recieved expected number (%d) of messages from Heartbeat."
		       "  Exiting normally.", expected_responses);
		g_main_quit(mainloop);
		return !hack_return_good;
	}
	return hack_return_good;
}

int
do_find_resource(const char *rsc, xmlNodePtr xml_node)
{
	int found = 0;
	const char *path[] = {
		XML_TAG_FRAGMENT,
		XML_TAG_CIB,
		XML_CIB_TAG_STATUS,
		XML_CIB_TAG_STATE
	};
	const char *path2[] = {
		XML_CIB_TAG_LRM,
		XML_LRM_TAG_RESOURCES,
		XML_LRM_TAG_RESOURCE
	};
	xmlNodePtr nodestates = find_xml_node_nested(
		xml_node, path, DIMOF(path));

	while(nodestates != NULL) {
		xmlNodePtr rscstates = find_xml_node_nested(
			nodestates, path2, DIMOF(path2));
		nodestates = nodestates->next;

		
		while(rscstates != NULL) {
			const char *id = xmlGetProp(rscstates,XML_ATTR_ID);
			const char *target =
				xmlGetProp(rscstates,XML_LRM_ATTR_TARGET);

			rscstates = rscstates->next;
			
			crm_debug("checking %s:%s for %s", target, id, rsc);

			
			if(safe_str_eq(rsc, id)){
				printf("resource %s is running on: %s\n",
				       rsc, target);
				if(BE_SILENT) {
					fprintf(stderr, "%s ", target);
				}
				found++;
			}
		}
		if(BE_SILENT) {
			fprintf(stderr, "\n");
		}
	}
	if(found == 0) {
		printf("resource %s is NOT running\n", rsc);
	}
					
	return found;
}

int
do_find_resource_list(xmlNodePtr xml_node)
{
	int found = 0;
	const char *path[] = {
		XML_TAG_FRAGMENT,
		XML_TAG_CIB,
		XML_CIB_TAG_RESOURCES,
		XML_CIB_TAG_RESOURCE
	};
	xmlNodePtr rscs = find_xml_node_nested(
		xml_node, path, DIMOF(path));

	while(rscs != NULL) {
		printf("%s resource: %s (%s)\n",
		       xmlGetProp(rscs, "class"),
		       xmlGetProp(rscs, XML_ATTR_ID),
		       xmlGetProp(rscs, XML_ATTR_TYPE));

		rscs = rscs->next;

		found++;
	}
	if(found == 0) {
		printf("no resources configured\n");
	}
					
	return found;
}

int
do_find_node_list(xmlNodePtr xml_node)
{
	int found = 0;
	const char *path[] = {
		XML_TAG_FRAGMENT,
		XML_TAG_CIB,
		XML_CIB_TAG_NODES,
		XML_CIB_TAG_NODE
	};
	xmlNodePtr nodes = find_xml_node_nested(
		xml_node, path, DIMOF(path));

	while(nodes != NULL) {
		printf("%s node %s: %s\n",
		       xmlGetProp(nodes, XML_ATTR_TYPE),
		       xmlGetProp(nodes, XML_ATTR_ID),
		       xmlGetProp(nodes, XML_ATTR_UNAME));

		nodes = nodes->next;

		found++;
	}
	if(found == 0) {
		printf("No resources configured\n");
	}
					
	return found;
}


void
usage(const char *cmd, int exit_status)
{
	FILE *stream;

	stream = exit_status ? stderr : stdout;

	fprintf(stream, "usage: %s [-?vs] [command] [command args]\n", cmd);

	fprintf(stream, "Options\n");
	fprintf(stream, "\t--%s (-%c)\t: "
		"turn on debug info. additional instances increase verbosity\n",
		"verbose", 'V');
	fprintf(stream, "\t--%s (-%c)\t: be very very quiet\n", "silent", 's');
	fprintf(stream, "\t--%s (-%c)\t: this help message\n", "help", '?');
	fprintf(stream, "\nCommands\n");
	fprintf(stream, "\t--%s (-%c) <node>\t: "
		"increment the CRMd debug level on <node>\n", "debug_inc",'i');
	fprintf(stream, "\t--%s (-%c) <node>\t: "
		"decrement the CRMd debug level on <node>\n", "debug_dec",'d');
	fprintf(stream, "\t--%s (-%c) <node>\t: "
		"shutdown the CRMd on <node>\n", "kill", 'K');
	fprintf(stream, "\t--%s (-%c) <node>\t: "
		"request the status of <node>\n", "status", 'S');
	fprintf(stream, "\t--%s (-%c)\t\t: "
		"request the status of all nodes\n", "health", 'H');
	fprintf(stream, "\t--%s (-%c) <node>\t: "
		"initiate an election from <node>\n", "election", 'E');
	fprintf(stream, "\t--%s (-%c)\t: "
		"request the uname of the DC\n", "dc_lookup", 'D');
	fprintf(stream, "\t--%s (-%c)\t\t: "
		"request the uname of all member nodes\n", "nodes", 'N');
	fprintf(stream, "\t--%s (-%c)\t: "
		"request the names of all resources\n", "resources", 'R');
	fprintf(stream, "\t--%s (-%c) <rsc>\t: "
		"request the location of <rsc>\n", "whereis", 'W');
//	fprintf(stream, "\t--%s (-%c)\t\n", "disconnect", 'D');
	fflush(stream);

	exit(exit_status);
}
