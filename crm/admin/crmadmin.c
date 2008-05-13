
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
#include <ha_version.h>

#include <sys/param.h>

#include <crm/crm.h>

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>

#include <clplumbing/uids.h>
#include <clplumbing/Gmain_timeout.h>

#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/ctrl.h>
#include <crm/common/ipc.h>

#include <crm/cib.h>

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif

int message_timer_id = -1;
int message_timeout_ms = 30*1000;

GMainLoop *mainloop = NULL;
IPC_Channel *crmd_channel = NULL;
char *admin_uuid = NULL;

void usage(const char *cmd, int exit_status);
gboolean do_init(void);
int do_work(void);
void crmadmin_ipc_connection_destroy(gpointer user_data);

gboolean admin_msg_callback(IPC_Channel * source_data, void *private_data);
char *pluralSection(const char *a_section);
xmlNode *handleCibMod(void);
int do_find_node_list(xmlNode *xml_node);
gboolean admin_message_timeout(gpointer data);
gboolean is_node_online(xmlNode *node_state);

enum debug {
	debug_none,
	debug_dec,
	debug_inc
};

gboolean BE_VERBOSE = FALSE;
int expected_responses = 1;

gboolean BASH_EXPORT      = FALSE;
gboolean DO_HEALTH        = FALSE;
gboolean DO_RESET         = FALSE;
gboolean DO_RESOURCE      = FALSE;
gboolean DO_ELECT_DC      = FALSE;
gboolean DO_WHOIS_DC      = FALSE;
gboolean DO_NODE_LIST     = FALSE;
gboolean BE_SILENT        = FALSE;
gboolean DO_RESOURCE_LIST = FALSE;
enum debug DO_DEBUG       = debug_none;
const char *crmd_operation = NULL;

xmlNode *msg_options = NULL;

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

#define OPTARGS	"V?K:S:HE:Dd:i:RNqt:Bv"

int
main(int argc, char **argv)
{
	int argerr = 0;
	int flag;

#ifdef HAVE_GETOPT_H
	int option_index = 0;
	static struct option long_options[] = {
		/* Top-level Options */
		{"verbose", 0, 0, 'V'},
		{"help", 0, 0, '?'},
		{"quiet", 0, 0, 'q'},
		{"reference", 1, 0, 0},
		{XML_ATTR_TIMEOUT, 1, 0, 't'},
		{"bash-export", 0, 0, 'B'},
		
		/* daemon options */
		{"kill", 1, 0, 'K'},  /* stop a node */
		{"die", 0, 0, 0},  /* kill a node, no respawn */
		{"debug_inc", 1, 0, 'i'},
		{"debug_dec", 1, 0, 'd'},
		{"status", 1, 0, 'S'},
		{"standby", 1, 0, 's'},
		{"active", 1, 0, 'a'},
		{"health", 0, 0, 'H'},
		{"election", 0, 0, 'E'},
		{"dc_lookup", 0, 0, 'D'},
		{"nodes", 0, 0, 'N'},
		{"option", 1, 0, 'o'},
		{"version", 0, 0, 'v'},

		{0, 0, 0, 0}
	};
#endif

	crm_log_init(basename(argv[0]), LOG_ERR, FALSE, TRUE, argc, argv);
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
#ifdef HAVE_GETOPT_H
			case 0:
				if (strcasecmp("reference",
					   long_options[option_index].name) == 0) {
					this_msg_reference =
						crm_strdup(optarg);

				} else if (strcasecmp("die",
						  long_options[option_index].name) == 0) {
					DO_RESET = TRUE;
					crmd_operation = CRM_OP_DIE;
					
				} else {
					printf( "?? Long option (--%s) is not yet properly supported ??\n",
						long_options[option_index].name);
					++argerr;
				}
				break;
#endif
			
/* a sample test for multiple instance
   if (digit_optind != 0 && digit_optind != this_option_optind)
   printf ("digits occur in two different argv-elements.\n");
   digit_optind = this_option_optind;
   printf ("option %c\n", c);
*/

			case 'v':
				fprintf(stdout, "HA Version %s, CRM Version %s (CIB feature set %s) %s\n",
					VERSION, CRM_FEATURE_SET, CIB_FEATURE_SET, HA_HG_VERSION);
				exit(0);
				break;
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
			case 'B':
				BASH_EXPORT = TRUE;
				break;
			case 'K':
				DO_RESET = TRUE;
				crm_debug_2("Option %c => %s", flag, optarg);
				dest_node = crm_strdup(optarg);
				crmd_operation = CRM_OP_LOCAL_SHUTDOWN;
				break;
			case 'q':
				BE_SILENT = TRUE;
				break;
			case 'i':
				DO_DEBUG = debug_inc;
				crm_debug_2("Option %c => %s", flag, optarg);
				dest_node = crm_strdup(optarg);
				break;
			case 'd':
				DO_DEBUG = debug_dec;
				crm_debug_2("Option %c => %s", flag, optarg);
				dest_node = crm_strdup(optarg);
				break;
			case 'S':
				DO_HEALTH = TRUE;
				crm_debug_2("Option %c => %s", flag, optarg);
				dest_node = crm_strdup(optarg);
				break;
			case 'E':
				DO_ELECT_DC = TRUE;
				break;
			case 'N':
				DO_NODE_LIST = TRUE;
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

	if (do_init()) {
		int res = 0;
		res = do_work();
		if (res > 0) {
			/* wait for the reply by creating a mainloop and running it until
			 * the callbacks are invoked...
			 */
			mainloop = g_main_new(FALSE);
			expected_responses++;
			crm_debug_2("Waiting for %d replies from the local CRM", expected_responses);

			message_timer_id = Gmain_timeout_add(
				message_timeout_ms, admin_message_timeout, NULL);
			
			g_main_run(mainloop);
			return_to_orig_privs();
			
		} else if(res < 0) {
			crm_err("No message to send");
			operation_status = -1;
		}
	} else {
		crm_warn("Init failed, could not perform requested operations");
		operation_status = -2;
	}

	crm_debug_2("%s exiting normally", crm_system_name);
	return operation_status;
}



int
do_work(void)
{
	int ret = 1;
	/* construct the request */
	xmlNode *msg_data = NULL;
	gboolean all_is_good = TRUE;
	
	msg_options = create_xml_node(NULL, XML_TAG_OPTIONS);
	crm_xml_add(msg_options, XML_ATTR_VERBOSE, admin_verbose);
	crm_xml_add(msg_options, XML_ATTR_TIMEOUT, "0");

	if (DO_HEALTH == TRUE) {
		crm_debug_2("Querying the system");
		
		sys_to = CRM_SYSTEM_DC;
		
		if (dest_node != NULL) {
			sys_to = CRM_SYSTEM_CRMD;
			crmd_operation = CRM_OP_PING;

			if (BE_VERBOSE) {
				expected_responses = 1;
			}
			
			crm_xml_add(msg_options, XML_ATTR_TIMEOUT, "0");

		} else {
			crm_info("Cluster-wide health not available yet");
			all_is_good = FALSE;
		}		
		
	} else if(DO_ELECT_DC) {
		/* tell the local node to initiate an election */

		sys_to = CRM_SYSTEM_CRMD;
		crmd_operation = CRM_OP_VOTE;
		
		crm_xml_add(msg_options, XML_ATTR_TIMEOUT, "0");
		
		dest_node = NULL;

		ret = 0; /* no return message */
		
	} else if(DO_WHOIS_DC) {
		sys_to = CRM_SYSTEM_DC;
		crmd_operation = CRM_OP_PING;
			
		crm_xml_add(msg_options, XML_ATTR_TIMEOUT, "0");

		dest_node = NULL;

	} else if(DO_NODE_LIST) {

		cib_t *	the_cib = cib_new();
		xmlNode *output = NULL;
		
		enum cib_errors rc = the_cib->cmds->signon(
		    the_cib, crm_system_name, cib_command);

		if(rc != cib_ok) {
			return -1;
		}
			
		output = get_cib_copy(the_cib);
		do_find_node_list(output);
		
		free_xml(output);
		the_cib->cmds->signoff(the_cib);
		exit(rc);
		
	} else if(DO_RESET) {
		/* tell dest_node to initiate the shutdown proceedure
		 *
		 * if dest_node is NULL, the request will be sent to the
		 *   local node
		 */
		sys_to = CRM_SYSTEM_CRMD;
		crm_xml_add(msg_options, XML_ATTR_TIMEOUT, "0");
		
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
		if (dest_node != NULL) {
			sys_to = CRM_SYSTEM_CRMD;
		} else {
			sys_to = CRM_SYSTEM_DC;				
		}
	}
	
	{
		xmlNode *cmd = create_request(
			crmd_operation, msg_data, dest_node, sys_to,
			crm_system_name, admin_uuid);

		if(this_msg_reference != NULL) {
			crm_xml_add(cmd, XML_ATTR_REFERENCE, this_msg_reference);
		}
		send_ipc_message(crmd_channel, cmd);
		free_xml(cmd);
	}
	
	return ret;
}

void
crmadmin_ipc_connection_destroy(gpointer user_data)
{
    crm_err("Connection to CRMd was terminated");
    if(mainloop) {
	g_main_quit(mainloop);
    } else {
	exit(1);
    }
}


gboolean
do_init(void)
{
	GCHSource *src = NULL;
	
	crm_malloc0(admin_uuid, 11);
	if(admin_uuid != NULL) {
		snprintf(admin_uuid, 10, "%d", getpid());
		admin_uuid[10] = '\0';
	}
	
	src = init_client_ipc_comms(
		CRM_SYSTEM_CRMD, admin_msg_callback, NULL, &crmd_channel);

	if(DO_RESOURCE || DO_RESOURCE_LIST || DO_NODE_LIST) {
		return TRUE;
		
	} else if(crmd_channel != NULL) {
		send_hello_message(
			crmd_channel, admin_uuid, crm_system_name,"0", "1");

		set_IPC_Channel_dnotify(src, crmadmin_ipc_connection_destroy);
		
		return TRUE;
	} 
	return FALSE;
}

gboolean
admin_msg_callback(IPC_Channel * server, void *private_data)
{
	int rc = 0;
	int lpc = 0;
	xmlNode *xml = NULL;
	IPC_Message *msg = NULL;
	gboolean hack_return_good = TRUE;
	static int received_responses = 0;
	char *filename = NULL;
	int filename_len = 0;
	const char *result = NULL;

	Gmain_timeout_remove(message_timer_id);

	while (server->ch_status != IPC_DISCONNECT
	       && server->ops->is_message_pending(server) == TRUE) {
		rc = server->ops->recv(server, &msg);
		if (rc != IPC_OK) {
		    cl_perror("Receive failure (%d)", rc);
			return !hack_return_good;
		}

		if (msg == NULL) {
			crm_debug_4("No message this time");
			continue;
		}

		lpc++;
		received_responses++;

		xml = convert_ipc_message(msg, __FUNCTION__);
		msg->msg_done(msg);
		crm_log_xml(LOG_MSG, "ipc", xml);
		
		if (xml == NULL) {
			crm_info("XML in IPC message was not valid... "
				 "discarding.");
			goto cleanup;
			
		} else if (validate_crm_message(
				   xml, crm_system_name, admin_uuid,
				   XML_ATTR_RESPONSE) == FALSE) {
			crm_debug_2("Message was not a CRM response. Discarding.");
			goto cleanup;
		}

		result = crm_element_value(xml, XML_ATTR_RESULT);
		if(result == NULL || strcasecmp(result, "ok") == 0) {
			result = "pass";
		} else {
			result = "fail";
		}
		
		if(DO_HEALTH) {
			xmlNode *data = get_message_xml(xml, F_CRM_DATA);
			const char *state = crm_element_value(data, "crmd_state");

			printf("Status of %s@%s: %s (%s)\n",
			       crm_element_value(data,XML_PING_ATTR_SYSFROM),
			       crm_element_value(xml, F_CRM_HOST_FROM),
			       state,
			       crm_element_value(data,XML_PING_ATTR_STATUS));
			
			if(BE_SILENT && state != NULL) {
				fprintf(stderr, "%s\n", state);
			}
			
		} else if(DO_WHOIS_DC) {
			const char *dc = crm_element_value(xml, F_CRM_HOST_FROM);
			
			printf("Designated Controller is: %s\n", dc);
			if(BE_SILENT && dc != NULL) {
				fprintf(stderr, "%s\n", dc);
			}
		}
		
		if (this_msg_reference != NULL) {
			/* in testing mode... */
			/* 31 = "test-_.xml" + an_int_as_string + '\0' */
			xmlNode *data = get_message_xml(xml, F_CRM_DATA);
			filename_len = 31 + strlen(this_msg_reference);

			crm_malloc0(filename, filename_len);
			if(filename != NULL) {
				snprintf(filename, filename_len,
					"%s-%s_%d.xml",
					result, this_msg_reference,
					received_responses);
				
				filename[filename_len - 1] = '\0';
				if (0 > write_xml_file(data, filename, FALSE)) {
					crm_crit("Could not save response to"
						 " %s", filename);
				}
			}
		}
	  cleanup:
		free_xml(xml);
		xml = NULL;		
	}

	if (server->ch_status == IPC_DISCONNECT) {
		crm_debug_2("admin_msg_callback: received HUP");
		return !hack_return_good;
	}

	if (received_responses >= expected_responses) {
		crm_debug_2(
		       "Recieved expected number (%d) of messages from Heartbeat."
		       "  Exiting normally.", expected_responses);
		exit(0);
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
	operation_status = -3;
	g_main_quit(mainloop);
	return FALSE;
}


gboolean
is_node_online(xmlNode *node_state) 
{
	const char *uname      = crm_element_value(node_state,XML_ATTR_UNAME);
	const char *join_state = crm_element_value(node_state,XML_CIB_ATTR_JOINSTATE);
	const char *exp_state  = crm_element_value(node_state,XML_CIB_ATTR_EXPSTATE);
	const char *crm_state  = crm_element_value(node_state,XML_CIB_ATTR_CRMDSTATE);
	const char *ha_state   = crm_element_value(node_state,XML_CIB_ATTR_HASTATE);
	const char *ccm_state  = crm_element_value(node_state,XML_CIB_ATTR_INCCM);

	if(safe_str_neq(join_state, CRMD_JOINSTATE_DOWN)
	   && (ha_state == NULL || safe_str_eq(ha_state, "active"))
	   && crm_is_true(ccm_state)
	   && safe_str_eq(crm_state, "online")) {
		crm_debug_3("Node %s is online", uname);
		return TRUE;
	}
	crm_debug_3("Node %s: ha=%s ccm=%s join=%s exp=%s crm=%s",
		  uname, crm_str(ha_state), crm_str(ccm_state),
                  crm_str(join_state), crm_str(exp_state),
                  crm_str(crm_state));
	crm_debug_3("Node %s is offline", uname);
	return FALSE;
}

int
do_find_node_list(xmlNode *xml_node)
{
	int found = 0;
	xmlNode *nodes = get_object_root(XML_CIB_TAG_NODES, xml_node);

	xml_child_iter_filter(
		nodes, node, XML_CIB_TAG_NODE,	
		if(BASH_EXPORT) {
			printf("export %s=%s\n",
			       crm_element_value(node, XML_ATTR_UNAME),
			       crm_element_value(node, XML_ATTR_ID));
		} else {
			printf("%s node: %s (%s)\n",
			       crm_element_value(node, XML_ATTR_TYPE),
			       crm_element_value(node, XML_ATTR_UNAME),
			       crm_element_value(node, XML_ATTR_ID));
		}
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

	fprintf(stream, "usage: %s [-?Vs] [command] [command args]\n", cmd);

	fprintf(stream, "Options\n");
	fprintf(stream, "\t--%s (-%c)\t: this help message\n", "help", '?');
	fprintf(stream, "\t--%s (-%c)\t: version details\n", "version", 'v');
	fprintf(stream, "\t--%s (-%c)\t: "
		"turn on debug info. additional instances increase verbosity\n",
		"verbose", 'V');
	fprintf(stream, "\t--%s (-%c)\t: be very *very* quiet\n", "quiet", 'q');
	fprintf(stream, "\t--%s (-%c)\t: Only applies to -N.\n"
		"\t\tCreate Bash export entries of the form \"export uname=uuid\"\n", "bash-export", 'B');
	fprintf(stream, "\nCommands\n");
	fprintf(stream, "\t--%s (-%c) <node>\t: "
		"increment the CRMd debug level on <node>\n", CRM_OP_DEBUG_UP,'i');
	fprintf(stream, "\t--%s (-%c) <node>\t: "
		"decrement the CRMd debug level on <node>\n", CRM_OP_DEBUG_DOWN,'d');
	fprintf(stream, "\t--%s (-%c) <node>\t: "
		"shutdown the CRMd on <node>\n", "kill", 'K');
	fprintf(stream, "\t--%s (-%c) <node>\t: "
		"request the status of <node>\n", "status", 'S');
#if 0
	fprintf(stream, "\t--%s (-%c)\t\t: "
		"request the status of all nodes\n", "health", 'H');
#endif
	fprintf(stream, "\t--%s (-%c) <node>\t: "
		"initiate an election from <node>\n", "election", 'E');
	fprintf(stream, "\t--%s (-%c)\t: "
		"request the uname of the DC\n", "dc_lookup", 'D');
	fprintf(stream, "\t--%s (-%c)\t\t: "
		"request the uname of all member nodes\n", "nodes", 'N');
/*	fprintf(stream, "\t--%s (-%c)\t\n", "disconnect", 'D'); */
	fflush(stream);

	exit(exit_status);
}
