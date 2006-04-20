/* $Id: crm_resource.c,v 1.20 2006/04/20 11:29:14 andrew Exp $ */

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

gboolean do_force = FALSE;
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

#define OPTARGS	"V?SLRQDCPp:WMUr:H:v:t:g:G:g:f"

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

static int
dump_resource_attr(
	const char *rsc, const char *attr, pe_working_set_t *data_set)
{
	crm_data_t *attrs = create_xml_node(NULL, "fake");
	node_t *current = NULL;
	resource_t *the_rsc = pe_find_resource(data_set->resources, rsc);
	const char *value = NULL;

	if(the_rsc == NULL) {
		return cib_NOTEXISTS;
	}

	if(g_list_length(the_rsc->running_on) == 1) {
		current = the_rsc->running_on->data;

	} else if(g_list_length(the_rsc->running_on) > 1) {
		fprintf(stderr, "%s is active on more than one node,"
			" returning the default value for %s\n",
			the_rsc->id, value);
	} 
	
	unpack_instance_attributes(
		the_rsc->xml, XML_TAG_ATTR_SETS, current, the_rsc->parameters,
		NULL, 0, data_set);

	if(the_rsc->parameters != NULL) {
		crm_debug("Looking up %s in %s", attr, the_rsc->id);
		value = g_hash_table_lookup(the_rsc->parameters, attr);
	}
	if(value != NULL) {
		fprintf(stdout, "%s\n", value);
		return 1;

	} else {
		/* debug */
		g_hash_table_foreach(the_rsc->parameters, hash2field, attrs);
	}
	return cib_NOTEXISTS;
}


static int
dump_resource_prop(
	const char *rsc, const char *attr, pe_working_set_t *data_set)
{
	const char *value = NULL;
	resource_t *the_rsc = pe_find_resource(data_set->resources, rsc);

	if(the_rsc == NULL) {
		return cib_NOTEXISTS;
	}

	value = crm_element_value(the_rsc->xml, attr);

	if(value != NULL) {
		fprintf(stdout, "%s\n", value);
		return 1;
	}
	return cib_NOTEXISTS;
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
	HA_Message *params = NULL;
	char *key = crm_concat(crm_system_name, our_pid, '-');
	
	CRM_DEV_ASSERT(rsc_id != NULL);
	
	msg_data = create_xml_node(NULL, XML_GRAPH_TAG_RSC_OP);
	crm_xml_add(msg_data, XML_ATTR_TRANSITION_KEY, key);
	
	rsc = create_xml_node(msg_data, XML_CIB_TAG_RESOURCE);
	crm_xml_add(rsc, XML_ATTR_ID, rsc_id);

	params = create_xml_node(msg_data, XML_TAG_ATTRS);
	crm_xml_add(params, XML_ATTR_CRM_VERSION, CRM_FEATURE_SET);
	
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

	fragment = create_cib_fragment(NULL, NULL);
#if CRM_DEPRECATED_SINCE_2_0_4
	if(safe_str_eq(crm_element_name(fragment), XML_TAG_CIB)) {
		cib = fragment;
	} else {
		cib = find_xml_node(fragment, XML_TAG_CIB, TRUE);
	}
#else
	cib = fragment;
	CRM_DEV_ASSERT(safe_str_eq(crm_element_name(cib), XML_TAG_CIB));
#endif
	constraints = get_object_root(XML_CIB_TAG_CONSTRAINTS, cib);
	
	id = crm_concat("cli-prefer", rsc_id, '-');
	can_run = create_xml_node(constraints, XML_CONS_TAG_RSC_LOCATION);
	crm_xml_add(can_run, XML_ATTR_ID, id);
	crm_free(id);

	id = crm_concat("cli-standby", rsc_id, '-');
	dont_run = create_xml_node(constraints, XML_CONS_TAG_RSC_LOCATION);
	crm_xml_add(dont_run, XML_ATTR_ID, id);
	crm_free(id);

	if(existing_node == NULL) {
		crm_log_xml_notice(can_run, "Deleting");
		rc = cib_conn->cmds->delete(cib_conn, XML_CIB_TAG_CONSTRAINTS,
					    dont_run, NULL, cib_sync_call);
		if(rc == cib_NOTEXISTS) {
			rc = cib_ok;

		} else if(rc != cib_ok) {
			return rc;
		}

	} else {
		if(BE_QUIET == FALSE) {
			fprintf(stderr,
				"WARNING: Creating rsc_location constraint '%s'"
				" with a score of -INFINITY for resource %s"
				" on %s.\n",
				ID(dont_run), rsc_id, existing_node);
			fprintf(stderr, "\tThis will prevent %s from running"
				" on %s until the constraint is removed using"
				" the 'crm_resource -U' command or manually"
				" with cibadmin\n", rsc_id, existing_node);
			fprintf(stderr, "\tThis will be the case even if %s is"
				" the last node in the cluster", existing_node);
		}
		
		crm_xml_add(dont_run, "rsc", rsc_id);
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
		crm_log_xml_notice(can_run, "Deleting");
		rc = cib_conn->cmds->delete(cib_conn, XML_CIB_TAG_CONSTRAINTS,
					    can_run, NULL, cib_sync_call);
		if(rc == cib_NOTEXISTS) {
			rc = cib_ok;

		} else if(rc != cib_ok) {
			return rc;
		}

	} else {
		crm_xml_add(can_run, "rsc", rsc_id);
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

	if(preferred_node != NULL || existing_node != NULL) {
		crm_log_xml_notice(fragment, "CLI Update");
		rc = cib_conn->cmds->update(cib_conn, XML_CIB_TAG_CONSTRAINTS,
					    fragment, NULL, cib_sync_call);
	}
	
	free_xml(fragment);
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
		{"un-migrate", 0, 0, 'U'},
		{"get-parameter",1, 0, 'G'},
		{"get-property",1, 0, 'g'},
		{"resource",1, 0, 'r'},
		{"host-uname", 1, 0, 'H'},
		{"host-uuid",  1, 0, 'h'},
		{"set-property",    1, 0, 'p'},
		{"property-value",  1, 0, 'v'},
		{"resource-type",  1, 0, 't'},
		{"force-relocation",  0, 0, 'f'},

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

			case 'g':
				crm_debug_2("Option %c => %s", flag, optarg);
				prop_name = optarg;
				rsc_cmd = flag;
				break;

			case 'G':
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
			case 'U':
				rsc_cmd = flag;
				break;				
			case 'f':
				do_force = TRUE;
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
				fprintf(stderr, "Argument code 0%o (%c) is not (?yet?) supported\n", flag, flag);
				++argerr;
				break;
		}
	}

	if (optind < argc) {
		fprintf(stderr, "non-option ARGV-elements: ");
		while (optind < argc) {
			fprintf(stderr, "%s ", argv[optind++]);
		}
		fprintf(stderr, "\n");
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

	if(rsc_cmd == 'L' || rsc_cmd == 'W' || rsc_cmd == 'D' || rsc_cmd == 'Q'
	   || rsc_cmd == 'p' || rsc_cmd == 'M' || rsc_cmd == 'U'
	   || rsc_cmd == 'G' || rsc_cmd == 'g') {
		cib_conn = cib_new();
		rc = cib_conn->cmds->signon(
			cib_conn, crm_system_name, cib_command_synchronous);
		if(rc != cib_ok) {
			fprintf(stderr, "Error signing on to the CIB service: %s\n",
				cib_error2string(rc));
			return rc;
		}
		set_working_set_defaults(&data_set);

		if(rsc_cmd != 'D' && rsc_cmd != 'U') {
			cib_xml_copy = get_cib_copy(cib_conn);
			data_set.input = cib_xml_copy;
			data_set.now = new_ha_date(TRUE);
			stage0(&data_set);
		}
		
	} else if(rsc_cmd == 'R' || rsc_cmd == 'D'
		  || rsc_cmd == 'C' || rsc_cmd == 'P') {
		GCHSource *src = NULL;
		src = init_client_ipc_comms(CRM_SYSTEM_CRMD, crmd_msg_callback,
				      NULL, &crmd_channel);

		if(src == NULL) {
			fprintf(stderr,
				"Error signing on to the CRMd service\n");
			return 1;
		}
		
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

	} else if(rsc_cmd == 'G') {
		CRM_DEV_ASSERT(rsc_id != NULL);
		rc = dump_resource_attr(rsc_id, prop_name, &data_set);

	} else if(rsc_cmd == 'g') {
		CRM_DEV_ASSERT(rsc_id != NULL);
		rc = dump_resource_prop(rsc_id, prop_name, &data_set);

	} else if(rsc_cmd == 'U') {
		rc = migrate_resource(rsc_id, NULL, NULL, cib_conn);

	} else if(rsc_cmd == 'M') {
		const char *current_uname = NULL;
		resource_t *rsc = pe_find_resource(data_set.resources, rsc_id);
		if(rsc != NULL && rsc->running_on != NULL) {
			node_t *current = rsc->running_on->data;
			if(current != NULL) {
				current_uname = current->details->uname;
			}
		}
		
		if(rsc == NULL) {
			fprintf(stderr, "Resource %s not migrated:"
				" not found\n", rsc_id);

		} else if(g_list_length(rsc->running_on) > 1) {
			fprintf(stderr, "Resource %s not migrated:"
				" active on multiple nodes\n", rsc_id);
			
		} else if(host_uname != NULL
			  && safe_str_eq(current_uname, host_uname)) {
			fprintf(stderr, "Error performing operation: "
				"%s is already active on %s",
				rsc_id, host_uname);

		} else if(current_uname != NULL
			  && (do_force || host_uname == NULL)) {
			rc = migrate_resource(rsc_id, current_uname,
					      host_uname, cib_conn);

			
		} else if(host_uname != NULL) {
			rc = migrate_resource(
				rsc_id, NULL, host_uname, cib_conn);

		} else {
			fprintf(stderr, "Resource %s not migrated: "
				"not-active and no prefered location"
				" specified.\n", rsc_id);
		}
		
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
		sleep(10);
		refresh_lrm(crmd_channel, host_uname);

	} else {
		fprintf(stderr, "Unknown command: %c\n", rsc_cmd);
	}

	if(cib_conn != NULL) {
		cleanup_calculations(&data_set);
		cib_conn->cmds->signoff(cib_conn);
	}
	if(rc == cib_NOTEXISTS) {
		fprintf(stderr, "Error performing operation: %s\n",
			cib_error2string(rc));

	} else if(rc < cib_ok) {
		fprintf(stderr, "Error performing operation: %s\n",
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
	fprintf(stream, "\t--%s (-%c)\t: Migrate a resource from it current"
		" location.  Use -H to specify a destination\n"
		"\t\tIf -H is not specified, we will force the resource to move by"
		" creating a rule for the current location and a score of -INFINITY\n"
		"\t\tNOTE: This will prevent the resource from running on this"
		" node until the constraint is removed with -U\n"
		"\t\t\t  Requires: -r, Optional: -H, -f\n", "migrate", 'M');
	fprintf(stream, "\t--%s (-%c)\t: Remove all constraints created by -M\n"
		"\t\t\t  Requires: -r\n", "un-migrate", 'U');
	fprintf(stream, "\t--%s (-%c)\t: Delete a resource from the CIB\n"
		"\t\t\t  Requires: -r, -t\n", "delete", 'D');
	fprintf(stream, "\t--%s (-%c)\t: Delete a resource from the LRM\n"
		"\t\t\t  Requires: -r.  Optional: -H\n", "cleanup", 'C');
	fprintf(stream, "\t--%s (-%c)\t: Recheck for resources started outside of the CRM\n"
		"\t\t\t  Optional: -H\n", "reprobe", 'P');
	fprintf(stream, "\t--%s (-%c)\t: Refresh the CIB from the LRM\n"
		"\t\t\t  Optional: -H\n", "refresh", 'R');
	fprintf(stream, "\t--%s (-%c) <string>\t: "
		"Get the named parameter for a resource\n"
		"\t\t\t  Requires: -r\n", "get-parameter", 'G');
	fprintf(stream, "\t--%s (-%c) <string>\t: "
		"Get the named property (eg. class, type, is_managed) a resource\n"
		"\t\t\t  Requires: -r\n", "get-property", 'g');
	fprintf(stream, "\t--%s (-%c) <string>\t: "
		"Set the named property (not parameter) for a resource\n"
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
	fprintf(stream, "\t--%s (-%c)\t: "
		"Force the resource to move by creating a rule for the"
		" current location and a score of -INFINITY\n"
		"\t\tThis should be used if the resource's stickiness and"
		" constraint scores total more than INFINITY (Currently 10,000)\n"
		"\t\tNOTE: This will prevent the resource from running on this"
		" node until the constraint is removed with -U\n",
		"force-relocation", 'f');
	fflush(stream);

	exit(exit_status);
}
