/* $Id: crm_resource.c,v 1.4 2005/10/12 19:10:09 andrew Exp $ */

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

#include <portability.h>

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
#include <crm/pengine/pengine.h>
#include <crm/pengine/pe_utils.h>

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif
#include <crm/dmalloc_wrapper.h>
void usage(const char *cmd, int exit_status);

gboolean BE_QUIET = FALSE;
char *host_id = NULL;
const char *rsc_id = NULL;
const char *host_uname = NULL;
const char *crm_system_name = NULL;
const char *prop_name = NULL;
const char *prop_value = NULL;
const char *rsc_type = NULL;
char rsc_cmd = 0;
char *our_pid = NULL;
IPC_Channel *crmd_channel = NULL;

#define OPTARGS	"V?SLRQDCPp:WMr:H:v:t:"

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
			   fprintf(stdout, "%s\n ", node->details->uname);
		   } else {
			   fprintf(stdout, "resource %s is running on: %s\n",
				   rsc, node->details->uname);
		   }
		   
		   found++;
		);
	
	if(BE_QUIET) {
		fprintf(stderr, "\n");
	}
	
	if(found == 0) {
		printf("resource %s is NOT running\n", rsc);
	}
					
	return found;
}

static int
do_find_resource_list(pe_working_set_t *data_set)
{
	int found = 0;
	
	slist_iter(
		rsc, resource_t, data_set->resources, lpc,
		rsc->fns->print(
			rsc, NULL, pe_print_printf|pe_print_rsconly, stdout);
			found++;
		);

	if(found == 0) {
		printf("NO resources configured\n");
		return cib_NOTEXISTS;
	}

	return found;
}

static int
dump_resource(const char *rsc, pe_working_set_t *data_set)
{
	char *rsc_xml = NULL;
	resource_t *the_rsc = pe_find_resource(data_set->resources, rsc);

	if(the_rsc == NULL) {
		return cib_NOTEXISTS;
	}
	the_rsc->fns->print(the_rsc, NULL, pe_print_printf, stdout);

	rsc_xml = dump_xml_formatted(the_rsc->xml);

	fprintf(stdout, "raw xml:\n%s", rsc_xml);
	
	crm_free(rsc_xml);
	
	return 1;
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
	ha_msg_input_t *new_input = NULL;
	gboolean hack_return_good = TRUE;

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
			crm_debug_4("No message this time");
			continue;
		}

		lpc++;
		new_input = new_ipc_msg_input(msg);
		crm_log_message(LOG_MSG, new_input->msg);
		msg->msg_done(msg);
		
		if (validate_crm_message(
			    new_input->msg, crm_system_name, our_pid,
			    XML_ATTR_RESPONSE) == FALSE) {
			crm_info("Message was not a CRM response. Discarding.");
			continue;
		}

/* 		result = cl_get_string(new_input->msg, XML_ATTR_RESULT); */
/* 		if(result == NULL || strcmp(result, "ok") == 0) { */
/* 			result = "pass"; */
/* 		} else { */
/* 			result = "fail"; */
/* 		} */
		
	}

	if (server->ch_status == IPC_DISCONNECT) {
		crm_debug_2("admin_msg_callback: received HUP");
		return !hack_return_good;
	}

	return hack_return_good;
}

static int
delete_lrm_rsc(
	IPC_Channel *crmd_channel, const char *host_uname, const char *rsc_id)
{
	HA_Message *cmd = NULL;
	crm_data_t *msg_data = NULL;
	crm_data_t *rsc = NULL;
	char *key = crm_concat(crm_system_name, our_pid, '-');
	
	CRM_DEV_ASSERT(rsc_id != NULL);
	
	msg_data = create_xml_node(NULL, XML_GRAPH_TAG_RSC_OP);
	crm_xml_add(msg_data, XML_ATTR_TRANSITION_KEY, key);
	
	rsc = create_xml_node(msg_data, XML_CIB_TAG_RESOURCE);
	crm_xml_add(rsc, XML_ATTR_ID, rsc_id);
	
	cmd = create_request(CRM_OP_LRM_DELETE, msg_data, host_uname,
			     CRM_SYSTEM_CRMD, crm_system_name, our_pid);

	free_xml(msg_data);
	crm_free(key);

	if(send_ipc_message(crmd_channel, cmd)) {
		return 0;
	}
	return -1;
}

static int
refresh_lrm(IPC_Channel *crmd_channel, const char *host_uname)  
{
	HA_Message *cmd = NULL;
	
	cmd = create_request(CRM_OP_LRM_REFRESH, NULL, host_uname,
			     CRM_SYSTEM_CRMD, crm_system_name, our_pid);
	
	if(send_ipc_message(crmd_channel, cmd)) {
		return 0;
	}
	return -1;
}

static int
migrate_resource(
	const char *rsc_id,
	const char *existing_node, const char *preferred_node,
	cib_t *	cib_conn) 
{
	enum cib_errors rc = cib_ok;
	char *id = NULL;
	crm_data_t *cib = NULL;
	crm_data_t *rule = NULL;
	crm_data_t *expr = NULL;
	crm_data_t *constraints = NULL;
	crm_data_t *fragment = NULL;

	crm_data_t *can_run = NULL;
	crm_data_t *dont_run = NULL;
	
	constraints = get_object_root(XML_CIB_TAG_CONSTRAINTS, cib);
	
	id = crm_concat("cli-prefer", rsc_id, '-');
	can_run = create_xml_node(constraints, XML_CIB_TAG_CONSTRAINT);
	crm_xml_add(can_run, XML_ATTR_ID, id);
	crm_free(id);

	id = crm_concat("cli-standby", rsc_id, '-');
	dont_run = create_xml_node(constraints, XML_CIB_TAG_CONSTRAINT);
	crm_xml_add(dont_run, XML_ATTR_ID, id);
	crm_free(id);

	if(existing_node == NULL) {
		rc = cib_conn->cmds->delete(cib_conn, XML_CIB_TAG_CONSTRAINTS,
					    dont_run, NULL, cib_sync_call);

	} else {
		rule = create_xml_node(dont_run, XML_TAG_RULE);
		expr = create_xml_node(rule, XML_TAG_EXPRESSION);
		id = crm_concat("cli-standby-rule", rsc_id, '-');
		crm_xml_add(rule, XML_ATTR_ID, id);
		crm_free(id);
		
		crm_xml_add(rule, XML_RULE_ATTR_SCORE, MINUS_INFINITY_S);
		
		id = crm_concat("cli-standby-expr", rsc_id, '-');
		crm_xml_add(expr, XML_ATTR_ID, id);
		crm_free(id);
		
		crm_xml_add(expr, XML_EXPR_ATTR_ATTRIBUTE, "#uname");
		crm_xml_add(expr, XML_EXPR_ATTR_OPERATION, "eq");
		crm_xml_add(expr, XML_EXPR_ATTR_VALUE, existing_node);
		crm_xml_add(expr, XML_EXPR_ATTR_TYPE, "string");
	}
	
	if(preferred_node == NULL) {
		rc = cib_conn->cmds->delete(cib_conn, XML_CIB_TAG_CONSTRAINTS,
					    can_run, NULL, cib_sync_call);

	} else {
		rule = create_xml_node(can_run, XML_TAG_RULE);
		expr = create_xml_node(rule, XML_TAG_EXPRESSION);
		id = crm_concat("cli-prefer-rule", rsc_id, '-');
		crm_xml_add(rule, XML_ATTR_ID, id);
		crm_free(id);

		crm_xml_add(rule, XML_RULE_ATTR_SCORE, INFINITY_S);
	
		id = crm_concat("cli-prefer-expr", rsc_id, '-');
		crm_xml_add(expr, XML_ATTR_ID, id);
		crm_free(id);

		crm_xml_add(expr, XML_EXPR_ATTR_ATTRIBUTE, "#uname");
		crm_xml_add(expr, XML_EXPR_ATTR_OPERATION, "eq");
		crm_xml_add(expr, XML_EXPR_ATTR_VALUE, preferred_node);
		crm_xml_add(expr, XML_EXPR_ATTR_TYPE, "string");
	}
	rc = cib_conn->cmds->delete(cib_conn, XML_CIB_TAG_CONSTRAINTS,
				    fragment, NULL, cib_sync_call);
	return rc;
}

int
main(int argc, char **argv)
{
	pe_working_set_t data_set;
	crm_data_t *cib_xml_copy = NULL;

	cib_t *	cib_conn = NULL;
	enum cib_errors rc = cib_ok;
	
	int argerr = 0;
	int flag;

#ifdef HAVE_GETOPT_H
	int option_index = 0;
	static struct option long_options[] = {
		/* Top-level Options */
		{"verbose", 0, 0, 'V'},
		{"help",    0, 0, '?'},
		{"silent",  0, 0, 'S'},
		{"list",    0, 0, 'L'},
		{"refresh", 0, 0, 'R'},
		{"reprobe", 0, 0, 'P'},
		{"query",   0, 0, 'Q'},
		{"delete",  0, 0, 'D'},
		{"cleanup", 0, 0, 'C'},
		{"locate",  0, 0, 'W'},
		{"migrate", 0, 0, 'M'},
		{"resource",1, 0, 'r'},
		{"host_uname", 1, 0, 'H'},
		{"host_uuid",  1, 0, 'h'},
		{"set-property",    1, 0, 'p'},
		{"property-value",  1, 0, 'v'},
		{"resource-type",  1, 0, 't'},

		{0, 0, 0, 0}
	};
#endif

	crm_system_name = basename(argv[0]);
	crm_log_init(crm_system_name);
	crm_log_level = LOG_ERR;
	cl_log_enable_stderr(TRUE);
	
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
			case 'V':
				cl_log_enable_stderr(TRUE);
				alter_debug(DEBUG_INC);
				break;
			case '?':
				usage(crm_system_name, LSB_EXIT_OK);
				break;
			case 'S':
				BE_QUIET = TRUE;
				break;

			case 'L':
				rsc_cmd = flag;
				break;
				
			case 'R':
				rsc_cmd = flag;
				break;
				
			case 'Q':
				rsc_cmd = flag;
				break;
				
			case 'D':
				rsc_cmd = flag;
				break;
				
			case 'C':
				rsc_cmd = flag;
				break;
				
			case 'P':
				rsc_cmd = flag;
				break;
				
			case 'p':
				crm_debug_2("Option %c => %s", flag, optarg);
				prop_name = optarg;
				rsc_cmd = flag;
				break;
				
			case 'W':
				rsc_cmd = flag;
				break;
				
			case 'M':
				rsc_cmd = flag;
				break;				
			case 'r':
				crm_debug_2("Option %c => %s", flag, optarg);
				rsc_id = optarg;
				break;

			case 'v':
				crm_debug_2("Option %c => %s", flag, optarg);
				prop_value = optarg;
				break;

			case 't':
				crm_debug_2("Option %c => %s", flag, optarg);
				rsc_type = optarg;
				break;

			case 'H':
				crm_debug_2("Option %c => %s", flag, optarg);
				host_uname = optarg;
				break;
				
			case 'h':
				crm_debug_2("Option %c => %s", flag, optarg);
				host_id = crm_strdup(optarg);
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

	crm_malloc0(our_pid, sizeof(char) * 11);
	if(our_pid != NULL) {
		snprintf(our_pid, 10, "%d", getpid());
		our_pid[10] = '\0';
	}

	if(rc != cib_ok) {
		crm_err("Error signing on to the CIB service: %s",
			cib_error2string(rc));
		return rc;
	}

	if(rsc_cmd == 'L' || rsc_cmd == 'W' || rsc_cmd == 'D'
	   || rsc_cmd == 'Q' || rsc_cmd == 'p') {
		cib_conn = cib_new();
		rc = cib_conn->cmds->signon(cib_conn, crm_system_name, cib_command);
		if(rsc_cmd == 'D') {
			set_working_set_defaults(&data_set);
		} else {
			cib_xml_copy = get_cib_copy(cib_conn);
			set_working_set_defaults(&data_set);
			data_set.input = cib_xml_copy;
			stage0(&data_set);
		}
		
	} else if(rsc_cmd == 'R' || rsc_cmd == 'D' || rsc_cmd == 'C' || rsc_cmd == 'P') {
		GCHSource *src = NULL;
		src = init_client_ipc_comms(CRM_SYSTEM_CRMD, crmd_msg_callback,
				      NULL, &crmd_channel);

		send_hello_message(
			crmd_channel, our_pid, crm_system_name, "0", "1");

		set_IPC_Channel_dnotify(src, resource_ipc_connection_destroy);
	}
	

	if(rsc_cmd == 'L') {
		do_find_resource_list(&data_set);
		
	} else if(rsc_cmd == 'W') {
		CRM_DEV_ASSERT(rsc_id != NULL);
		rc = do_find_resource(rsc_id, &data_set);
		
	} else if(rsc_cmd == 'Q') {
		CRM_DEV_ASSERT(rsc_id != NULL);
		rc = dump_resource(rsc_id, &data_set);

	} else if(rsc_cmd == 'M') {
		rc = migrate_resource(rsc_id, NULL, host_uname, cib_conn);

	} else if(rsc_cmd == 'p') {
		crm_data_t *msg_data = NULL;

		CRM_DEV_ASSERT(rsc_id != NULL);
		CRM_DEV_ASSERT(rsc_type != NULL);
		CRM_DEV_ASSERT(prop_name != NULL);
		CRM_DEV_ASSERT(prop_value != NULL);

		msg_data = create_xml_node(NULL, rsc_type);
		crm_xml_add(msg_data, XML_ATTR_ID, rsc_id);
		crm_xml_add(msg_data, prop_name, prop_value);
		
		rc = cib_conn->cmds->modify(cib_conn, XML_CIB_TAG_RESOURCES,
					    msg_data, NULL, cib_sync_call);
		free_xml(msg_data);

	} else if(rsc_cmd == 'P') {
		HA_Message *cmd = NULL;
		
		cmd = create_request(CRM_OP_REPROBE, NULL, host_uname,
				     CRM_SYSTEM_CRMD, crm_system_name, our_pid);
		send_ipc_message(crmd_channel, cmd);

	} else if(rsc_cmd == 'R') {
		refresh_lrm(crmd_channel, host_uname);

	} else if(rsc_cmd == 'D') {
		crm_data_t *msg_data = NULL;

		CRM_DEV_ASSERT(rsc_type != NULL);
		CRM_DEV_ASSERT(rsc_id != NULL);

		msg_data = create_xml_node(NULL, rsc_type);
		crm_xml_add(msg_data, XML_ATTR_ID, rsc_id);
		
		rc = cib_conn->cmds->delete(cib_conn, XML_CIB_TAG_RESOURCES,
					    msg_data, NULL, cib_sync_call);
		free_xml(msg_data);

	} else if(rsc_cmd == 'C') {
		delete_lrm_rsc(crmd_channel, host_uname, rsc_id);
		refresh_lrm(crmd_channel, host_uname);

	} else {
		crm_err("Unknown command: %c", rsc_cmd);
	}

	if(cib_conn != NULL) {
		cleanup_calculations(&data_set);
		cib_conn->cmds->signoff(cib_conn);
	}
	if(rc == cib_NOTEXISTS) {
		crm_warn("Error performing operation: %s",
			 cib_error2string(rc));

	} else if(rc < cib_ok) {
		crm_warn("Error performing operation: %s",
			 cib_error2string(rc));
	}
	
	return rc;
}



void
usage(const char *cmd, int exit_status)
{
	FILE *stream;

	stream = exit_status ? stderr : stdout;
	fprintf(stream, "usage: %s [-?VS] -(L|Q|W|D|C|P|p) [options]\n", cmd);

	fprintf(stream, "\t--%s (-%c)\t: this help message\n", "help", '?');
	fprintf(stream, "\t--%s (-%c)\t: "
		"turn on debug info. additional instances increase verbosity\n",
		"verbose", 'V');
	fprintf(stream, "\t--%s (-%c)\t: Print only the value on stdout (for use with -W)\n",
		"silent", 'S');

	fprintf(stream, "\nCommands\n");
	fprintf(stream, "\t--%s (-%c)\t: List all resources\n", "list", 'L');
	fprintf(stream, "\t--%s (-%c)\t: Query a resource\n"
		"\t\t\t  Requires: -r\n", "query", 'Q');
	fprintf(stream, "\t--%s (-%c)\t: Locate a resource\n"
		"\t\t\t  Requires: -r\n", "locate", 'W');
	fprintf(stream, "\t--%s (-%c)\t: Delete a resource from the CIB\n"
		"\t\t\t  Requires: -r, -t\n", "delete", 'D');
	fprintf(stream, "\t--%s (-%c)\t: Delete a resource from the LRM\n"
		"\t\t\t  Requires: -r, -t.  Optional: -H\n", "cleanup", 'C');
	fprintf(stream, "\t--%s (-%c)\t: Recheck for resources started outside of the CRM\n"
		"\t\t\t  Optional: -H\n", "reprobe", 'P');
	fprintf(stream, "\t--%s (-%c)\t: Refresh the CIB from the LRM\n"
		"\t\t\t  Optional: -H\n", "refresh", 'R');
	fprintf(stream, "\t--%s (-%c) <string>\t: "
		"Set the named property for a resource\n"
		"\t\t\t  Requires: -r, -t, -v", "set-property", 'p');
	fprintf(stream, "\nOptions\n");
	fprintf(stream, "\t--%s (-%c) <string>\t: Resource ID\n", "resource", 'r');
	fprintf(stream, "\t--%s (-%c) <string>\t: "
		"Resource type (primitive, clone, group, ...)\n",
		"resource-type", 't');

	fprintf(stream, "\t--%s (-%c) <string>\t: "
		"Property value\n", "property-value", 'v');
	fprintf(stream, "\t--%s (-%c) <string>\t: "
		"Host name\n", "host-uname", 'H');
	fflush(stream);

	exit(exit_status);
}
