/* $Id: crmadmin.c,v 1.38 2005/04/27 08:49:08 andrew Exp $ */

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

#include <heartbeat.h>
#include <hb_api.h>
#include <clplumbing/uids.h>
#include <clplumbing/Gmain_timeout.h>

#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/ctrl.h>
#include <crm/common/ipc.h>

#include <crm/cib.h>

#include <getopt.h>
#include <crm/dmalloc_wrapper.h>

int message_timer_id = -1;
int message_timeout_ms = 30*1000;

GMainLoop *mainloop = NULL;
IPC_Channel *crmd_channel = NULL;
char *admin_uuid = NULL;

void usage(const char *cmd, int exit_status);
ll_cluster_t *do_init(void);
int do_work(ll_cluster_t * hb_cluster);

gboolean admin_msg_callback(IPC_Channel * source_data, void *private_data);
char *pluralSection(const char *a_section);
crm_data_t *handleCibMod(void);
int do_find_resource(const char *rsc, crm_data_t *xml_node);
int do_find_resource_list(crm_data_t *xml_node);
int do_find_node_list(crm_data_t *xml_node);
gboolean admin_message_timeout(gpointer data);
gboolean is_node_online(crm_data_t *node_state);

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
gboolean DO_OPTION        = FALSE;
gboolean DO_STANDBY       = FALSE;
enum debug DO_DEBUG       = debug_none;
const char *crmd_operation = NULL;

crm_data_t *msg_options = NULL;

const char *standby_on_off = "on";
const char *admin_verbose = XML_BOOLEAN_FALSE;
char *id = NULL;
char *this_msg_reference = NULL;
char *disconnect = NULL;
char *dest_node  = NULL;
char *rsc_name   = NULL;
char *crm_option = NULL;

int operation_status = 0;
const char *sys_to = NULL;
const char *crm_system_name = "crmadmin";

#define OPTARGS	"V?K:S:HE:DW:d:i:RNs:a:qt:o:"

int
main(int argc, char **argv)
{
	int option_index = 0;
	int argerr = 0;
	int flag;
	ll_cluster_t *hb_cluster = NULL;

	static struct option long_options[] = {
		/* Top-level Options */
		{"verbose", 0, 0, 'V'},
		{"help", 0, 0, '?'},
		{"quiet", 0, 0, 'q'},
		{"reference", 1, 0, 0},
		{XML_ATTR_TIMEOUT, 1, 0, 't'},

		/* daemon options */
		{"kill", 1, 0, 'K'},  /* stop a node */
		{"die", 0, 0, 0},  /* kill a node, no respawn */
		{"crm_debug_inc", 1, 0, 'i'},
		{"crm_debug_dec", 1, 0, 'd'},
		{"status", 1, 0, 'S'},
		{"standby", 1, 0, 's'},
		{"active", 1, 0, 'a'},
		{"health", 0, 0, 'H'},
		{"election", 0, 0, 'E'},
		{"dc_lookup", 0, 0, 'D'},
		{"resources", 0, 0, 'R'},
		{"nodes", 0, 0, 'N'},
		{"whereis", 1, 0, 'W'},
		{"option", 1, 0, 'o'},

		{0, 0, 0, 0}
	};

	crm_system_name = basename(argv[0]);
	crm_log_level = 0;
	crm_log_init(crm_system_name);
	crm_log_level = 0;

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

				} else if (strcmp("die",
						  long_options[option_index].name) == 0) {
					DO_RESET = TRUE;
					crmd_operation = CRM_OP_DIE;
					
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
				admin_verbose = XML_BOOLEAN_TRUE;
				cl_log_enable_stderr(TRUE);
				alter_debug(DEBUG_INC);
				break;
			case 't':
				message_timeout_ms = atoi(optarg);
				if(message_timeout_ms < 1) {
					message_timeout_ms = 30*1000;
				}
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
				crmd_operation = CRM_OP_LOCAL_SHUTDOWN;
				break;
			case 'o':
				DO_OPTION = TRUE;
				crm_verbose("Option %c => %s", flag, optarg);
				crm_option = crm_strdup(optarg);
				break;
			case 'q':
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
			case 's':
				DO_STANDBY = TRUE;
				crm_verbose("Option %c => %s", flag, optarg);
				dest_node = crm_strdup(optarg);
				break;
			case 'a':
				DO_STANDBY = TRUE;
				crm_verbose("Option %c => %s", flag, optarg);
				dest_node = crm_strdup(optarg);
				standby_on_off = "off";
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

			message_timer_id = Gmain_timeout_add(
				message_timeout_ms, admin_message_timeout, NULL);
			
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
	crm_data_t *msg_data = NULL;
	gboolean all_is_good = TRUE;
	
	msg_options = create_xml_node(NULL, XML_TAG_OPTIONS);
	set_xml_property_copy(msg_options, XML_ATTR_VERBOSE, admin_verbose);
	set_xml_property_copy(msg_options, XML_ATTR_TIMEOUT, "0");

	if (DO_HEALTH == TRUE) {
		crm_verbose("Querying the system");
		
		sys_to = CRM_SYSTEM_DC;
		
		if (dest_node != NULL) {
			sys_to = CRM_SYSTEM_CRMD;
			crmd_operation = CRM_OP_PING;

			if (BE_VERBOSE) {
				expected_responses = -1;/* wait until timeout instead */
			}
			
			set_xml_property_copy(
				msg_options, XML_ATTR_TIMEOUT, "0");

		} else {
			crm_info("Cluster-wide health not available yet");
			all_is_good = FALSE;
		}		
		
	} else if(DO_ELECT_DC) {
		/* tell the local node to initiate an election */

		sys_to = CRM_SYSTEM_CRMD;
		crmd_operation = CRM_OP_VOTE;
		
		set_xml_property_copy(
			msg_options, XML_ATTR_TIMEOUT, "0");
		
		dest_node = NULL;

		ret = 0; /* no return message */
		
	} else if(DO_WHOIS_DC) {
		sys_to = CRM_SYSTEM_DC;
		crmd_operation = CRM_OP_PING;
			
		set_xml_property_copy(
			msg_options, XML_ATTR_TIMEOUT, "0");

		dest_node = NULL;

	} else if(DO_RESOURCE || DO_RESOURCE_LIST || DO_NODE_LIST || DO_OPTION){
		cib_t *	the_cib = cib_new();
		crm_data_t *output = NULL;
		int call_options = cib_sync_call;
		
		enum cib_errors rc = the_cib->cmds->signon(
			the_cib, crm_system_name, cib_command);

		if(rc != cib_ok) {
			return -1;
			
		} else if(DO_RESOURCE) {
			output = get_cib_copy(the_cib);
			do_find_resource(rsc_name, output);

		} else if(DO_RESOURCE_LIST) {
			output = get_cib_copy(the_cib);
			do_find_resource_list(output);
			
		} else if(DO_NODE_LIST) {
			output = get_cib_copy(the_cib);
			do_find_node_list(output);
			
		} else if(DO_OPTION) {
			char *name = NULL;
			char *value = NULL;
			crm_data_t *xml_option = NULL;
			crm_data_t *fragment = NULL;

			if(decodeNVpair(crm_option, '=', &name, &value)==FALSE){
				crm_err("%s needs to be of the form"
					" <name>=<value>", crm_option);
				return -1;
			}
			
			xml_option = create_xml_node(NULL, XML_CIB_TAG_NVPAIR);
			set_xml_property_copy(
				xml_option, XML_NVPAIR_ATTR_NAME, name);
			set_xml_property_copy(
				xml_option, XML_NVPAIR_ATTR_VALUE, value);
			
			fragment = create_cib_fragment(xml_option, NULL);

			free_xml(xml_option);
			crm_free(name);
			crm_free(value);
			
			rc = the_cib->cmds->modify(
				the_cib, XML_CIB_TAG_CRMCONFIG, fragment,
				NULL, call_options|cib_discard_reply);
			
			free_xml(fragment);

		} else if(DO_STANDBY) {
			char *name = NULL;
			char *value = NULL;
			crm_data_t *a_node = NULL;
			crm_data_t *xml_obj = NULL;
			crm_data_t *fragment = NULL;

			if(decodeNVpair(crm_option, '=', &name, &value)==FALSE){
				crm_err("%s needs to be of the form"
					" <name>=<value>", crm_option);
				return -1;
			}
			
			a_node = create_xml_node(NULL, XML_CIB_TAG_NODE);
			set_xml_property_copy(a_node, XML_ATTR_ID, dest_node);

			xml_obj = create_xml_node(a_node, XML_TAG_ATTR_SETS);
			xml_obj = create_xml_node(xml_obj, XML_TAG_ATTRS);
			xml_obj = create_xml_node(xml_obj, XML_CIB_TAG_NVPAIR);

			set_xml_property_copy(
				xml_obj, XML_NVPAIR_ATTR_NAME, "standby");
			set_xml_property_copy(
				xml_obj, XML_NVPAIR_ATTR_VALUE, standby_on_off);
			
			fragment = create_cib_fragment(a_node, NULL);

			free_xml(a_node);
			crm_free(name);
			crm_free(value);
			
			rc = the_cib->cmds->modify(
				the_cib, XML_CIB_TAG_NODES, fragment,
				NULL, call_options|cib_discard_reply);
			
			free_xml(fragment);
		}

		free_xml(output);
		the_cib->cmds->signoff(the_cib);
		return rc;
		
	} else if(DO_RESET) {
		/* tell dest_node to initiate the shutdown proceedure
		 *
		 * if dest_node is NULL, the request will be sent to the
		 *   local node
		 */
		sys_to = CRM_SYSTEM_CRMD;
		set_xml_property_copy(
			msg_options, XML_ATTR_TIMEOUT, "0");
		
		ret = 0; /* no return message */
		
	} else if(DO_DEBUG == debug_inc) {
		/* tell dest_node to increase its debug level
		 *
		 * if dest_node is NULL, the request will be sent to the
		 *   local node
		 */
		sys_to = CRM_SYSTEM_CRMD;
		crmd_operation = CRM_OP_DEBUG_UP;
		
		ret = 0; /* no return message */
		
	} else if(DO_DEBUG == debug_dec) {
		/* tell dest_node to increase its debug level
		 *
		 * if dest_node is NULL, the request will be sent to the
		 *   local node
		 */
		sys_to = CRM_SYSTEM_CRMD;
		crmd_operation = CRM_OP_DEBUG_DOWN;
		
		ret = 0; /* no return message */
		
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
	
	{
		HA_Message *cmd = create_request(
			crmd_operation, msg_data, dest_node, sys_to,
			crm_system_name, admin_uuid);

		if(this_msg_reference != NULL) {
			ha_msg_mod(cmd, XML_ATTR_REFERENCE, this_msg_reference);
		}
		send_ipc_message(crmd_channel, cmd);
	}
	
	return ret;

}


ll_cluster_t *
do_init(void)
{
	int facility;
	ll_cluster_t *hb_cluster = NULL;

#ifdef USE_LIBXML
	/* docs say only do this once, but in their code they do it every time! */
	xmlInitParser (); 
#endif
	/* change the logging facility to the one used by heartbeat daemon */
	hb_cluster = ll_cluster_new("heartbeat");
	
	crm_verbose("Switching to Heartbeat logger");
	if (( facility =
	      hb_cluster->llc_ops->get_logfacility(hb_cluster)) > 0) {
		cl_log_set_facility(facility);
	}

	crm_malloc0(admin_uuid, sizeof(char) * 11);
	if(admin_uuid != NULL) {
		snprintf(admin_uuid, 10, "%d", getpid());
		admin_uuid[10] = '\0';
	}
	
	init_client_ipc_comms(
		CRM_SYSTEM_CRMD, admin_msg_callback, NULL, &crmd_channel);

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
	ha_msg_input_t *new_input = NULL;
	gboolean hack_return_good = TRUE;
	static int received_responses = 0;
	char *filename = NULL;
	int filename_len = 0;
	const char *result = NULL;

	g_source_remove(message_timer_id);

	while (server->ch_status != IPC_DISCONNECT
	       && server->ops->is_message_pending(server) == TRUE) {
		if(new_input != NULL) {
			delete_ha_msg_input(new_input);
		}
		
		if (server->ops->recv(server, &msg) != IPC_OK) {
			perror("Receive failure:");
			return !hack_return_good;
		}

		if (msg == NULL) {
			crm_trace("No message this time");
			continue;
		}

		lpc++;
		new_input = new_ipc_msg_input(msg);
		msg->msg_done(msg);
		crm_log_message(LOG_MSG, new_input->msg);
		
		if (new_input->xml == NULL) {
			crm_info(
			       "XML in IPC message was not valid... "
			       "discarding.");
			continue;
		} else if (validate_crm_message(
				   new_input->msg, crm_system_name, admin_uuid,
				   XML_ATTR_RESPONSE) == FALSE) {
			crm_info(
			       "Message was not a CRM response. Discarding.");
			continue;
		}

		result = cl_get_string(new_input->msg, XML_ATTR_RESULT);
		if(result == NULL || strcmp(result, "ok") == 0) {
			result = "pass";
		} else {
			result = "fail";
		}
		
		received_responses++;

		if(DO_HEALTH) {
			const char *state = crm_element_value(
				new_input->xml, "crmd_state");

			printf("Status of %s@%s: %s (%s)\n",
			       crm_element_value(new_input->xml,XML_PING_ATTR_SYSFROM),
			       cl_get_string(new_input->msg, F_CRM_HOST_FROM),
			       state,
			       crm_element_value(new_input->xml,XML_PING_ATTR_STATUS));
			
			if(BE_SILENT && state != NULL) {
				fprintf(stderr, "%s\n", state);
			}
			
		} else if(DO_WHOIS_DC) {
			const char *dc = cl_get_string(
				new_input->msg, F_CRM_HOST_FROM);
			
			printf("Designated Controller is: %s\n", dc);
			if(BE_SILENT && dc != NULL) {
				fprintf(stderr, "%s\n", dc);
			}
		}
		
		if (this_msg_reference != NULL) {
			/* in testing mode... */
			/* 31 = "test-_.xml" + an_int_as_string + '\0' */
			filename_len = 31 + strlen(this_msg_reference);

			crm_malloc0(filename, sizeof(char) * filename_len);
			if(filename != NULL) {
				sprintf(filename, "%s-%s_%d.xml",
					result, this_msg_reference,
					received_responses);
				
				filename[filename_len - 1] = '\0';
				if (0 > write_xml_file(new_input->xml, filename)) {
					crm_crit("Could not save response to"
						 " %s", filename);
				}
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

	message_timer_id = Gmain_timeout_add(
		message_timeout_ms, admin_message_timeout, NULL);
	
	
	return hack_return_good;
}

gboolean
admin_message_timeout(gpointer data)
{
	fprintf(stderr, "No messages received in %d seconds.. aborting\n",
		(int)message_timeout_ms/1000);
	crm_err("No messages received in %d seconds",
		(int)message_timeout_ms/1000);
	g_main_quit(mainloop);
	return FALSE;
}


int
do_find_resource(const char *rsc, crm_data_t *xml_node)
{
	int found = 0;
	crm_data_t *nodestates = get_object_root(XML_CIB_TAG_STATUS, xml_node);
	const char *path2[] = {
		XML_CIB_TAG_LRM,
		XML_LRM_TAG_RESOURCES
	};

	xml_child_iter(
		nodestates, a_node, XML_CIB_TAG_STATE,
		crm_data_t *rscstates = NULL;

		if(is_node_online(a_node) == FALSE) {
			crm_devel("Skipping offline node: %s",
				crm_element_value(a_node, XML_ATTR_ID));
			continue;
		}
		
		rscstates = find_xml_node_nested(a_node, path2, DIMOF(path2));
		xml_child_iter(
			rscstates, rsc_state, XML_LRM_TAG_RESOURCE,
			const char *id = crm_element_value(
				rsc_state,XML_ATTR_ID);
			const char *target = crm_element_value(
				a_node, XML_ATTR_UNAME);
			const char *last_op = crm_element_value(
				rsc_state,XML_LRM_ATTR_LASTOP);
			const char *op_code = crm_element_value(
				rsc_state,XML_LRM_ATTR_OPSTATUS);
			
			crm_devel("checking %s:%s for %s", target, id, rsc);

			if(safe_str_neq(rsc, id)){
				crm_trace("no match");
				continue;
			}
			
			if(safe_str_eq("stop", last_op)) {
				crm_devel("resource %s is stopped on: %s",
					  rsc, target);
				
			} else if(safe_str_eq(op_code, "-1")) {
				crm_devel("resource %s is pending on: %s",
					  rsc, target);				

			} else if(safe_str_neq(op_code, "0")) {
				crm_devel("resource %s is failed on: %s",
					  rsc, target);				

			} else {
				crm_devel("resource %s is running on: %s",
					  rsc, target);				
				printf("resource %s is running on: %s\n",
				       rsc, target);
				if(BE_SILENT) {
					fprintf(stderr, "%s ", target);
				}
				found++;
			}
			);
		if(BE_SILENT) {
			fprintf(stderr, "\n");
		}
		);
	
	if(found == 0) {
		printf("resource %s is NOT running\n", rsc);
	}
					
	return found;
}

gboolean
is_node_online(crm_data_t *node_state) 
{
	const char *uname      = crm_element_value(node_state,XML_ATTR_UNAME);
	const char *join_state = crm_element_value(node_state,XML_CIB_ATTR_JOINSTATE);
	const char *exp_state  = crm_element_value(node_state,XML_CIB_ATTR_EXPSTATE);
	const char *crm_state  = crm_element_value(node_state,XML_CIB_ATTR_CRMDSTATE);
	const char *ha_state   = crm_element_value(node_state,XML_CIB_ATTR_HASTATE);
	const char *ccm_state  = crm_element_value(node_state,XML_CIB_ATTR_INCCM);

	if(safe_str_neq(join_state, CRMD_JOINSTATE_DOWN)
	   && (ha_state == NULL || safe_str_eq(ha_state, ACTIVESTATUS))
	   && crm_is_true(ccm_state)
	   && safe_str_eq(crm_state, ONLINESTATUS)) {
		crm_devel("Node %s is online", uname);
		return TRUE;
	}
	crm_devel("Node %s: ha=%s ccm=%s join=%s exp=%s crm=%s",
		  uname, ha_state, ccm_state, join_state, exp_state, crm_state);
	crm_devel("Node %s is offline", uname);
	return FALSE;
}


int
do_find_resource_list(crm_data_t *xml_node)
{
	int found = 0;
	crm_data_t *rscs = get_object_root(XML_CIB_TAG_RESOURCES, xml_node);

	xml_child_iter(
		rscs, rsc, XML_CIB_TAG_RESOURCE,
		printf("%s resource: %s (%s)\n",
		       crm_element_value(rsc, "class"),
		       crm_element_value(rsc, XML_ATTR_ID),
		       crm_element_value(rsc, XML_ATTR_TYPE));

		found++;
		);
	if(found == 0) {
		printf("NO resources configured\n");
	}
					
	return found;
}

int
do_find_node_list(crm_data_t *xml_node)
{
	int found = 0;
	crm_data_t *nodes = get_object_root(XML_CIB_TAG_NODES, xml_node);

	xml_child_iter(
		nodes, node, XML_CIB_TAG_NODE,	
		printf("%s node: %s (%s)\n",
		       crm_element_value(node, XML_ATTR_TYPE),
		       crm_element_value(node, XML_ATTR_UNAME),
		       crm_element_value(node, XML_ATTR_ID));
		found++;
		);
	if(found == 0) {
		printf("NO nodes configured\n");
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
	fprintf(stream, "\t--%s (-%c)\t: be very *very* quiet\n", "quiet", 'q');
	fprintf(stream, "\t--%s (-%c)\t: this help message\n", "help", '?');
	fprintf(stream, "\nCommands\n");
	fprintf(stream, "\t--%s (-%c) <node>\t: "
		"increment the CRMd debug level on <node>\n", CRM_OP_DEBUG_UP,'i');
	fprintf(stream, "\t--%s (-%c) <node>\t: "
		"decrement the CRMd debug level on <node>\n", CRM_OP_DEBUG_DOWN,'d');
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
	fprintf(stream, "\t--%s (-%c) <node_uuid>\t: "
		"Tell the node to enter \"standby\" mode\n", "standby", 's');
	fprintf(stream, "\t--%s (-%c) <node_uuid>\t: "
		"Tell the node to exit \"standby\" mode\n", "active", 'a');
/*	fprintf(stream, "\t--%s (-%c)\t\n", "disconnect", 'D'); */
	fflush(stream);

	exit(exit_status);
}
