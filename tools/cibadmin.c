
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

#include <sys/param.h>

#include <crm/crm.h>

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

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
#include <ha_msg.h> /* someone complaining about _ha_msg_mod not being found */

int exit_code = cib_ok;
int message_timer_id = -1;
int message_timeout_ms = 30;

GMainLoop *mainloop = NULL;
IPC_Channel *crmd_channel = NULL;

const char *host = NULL;
void usage(const char *cmd, int exit_status);
enum cib_errors do_init(void);
int do_work(xmlNode *input, int command_options, xmlNode **output);

gboolean admin_msg_callback(IPC_Channel * source_data, void *private_data);
gboolean admin_message_timeout(gpointer data);
void cib_connection_destroy(gpointer user_data);
void cibadmin_op_callback(xmlNode *msg, int call_id, int rc,
			  xmlNode *output, void *user_data);

int command_options = 0;
const char *cib_action = NULL;

typedef struct str_list_s
{
		int num_items;
		char *value;
		struct str_list_s *next;
} str_list_t;

char *this_msg_reference = NULL;
char *obj_type = NULL;
char *status = NULL;
char *migrate_from = NULL;
char *migrate_res = NULL;
char *subtype = NULL;
char *reset = NULL;

int request_id = 0;
int operation_status = 0;
cib_t *the_cib = NULL;

gboolean force_flag = FALSE;
#define OPTARGS	"V?o:QDUCEX:t:Srwlsh:MmBfbRx:pP5N:A:unc"


int
main(int argc, char **argv)
{
	int argerr = 0;
	int flag;
	const char *source = NULL;
	char *admin_input_xml = NULL;
	char *admin_input_file = NULL;
	gboolean dangerous_cmd = FALSE;
	gboolean admin_input_stdin = FALSE;
	xmlNode *output = NULL;
	xmlNode *input = NULL;
	
#ifdef HAVE_GETOPT_H
	int option_index = 0;
	static struct option long_options[] = {
		/* Top-level Options */
		/* legacy names */
		{CIB_OP_ERASE,   0, 0, 'E'},
		{CIB_OP_QUERY,   0, 0, 'Q'},
		{CIB_OP_CREATE,  0, 0, 'C'},
		{CIB_OP_REPLACE, 0, 0, 'R'},
		{CIB_OP_UPDATE,  0, 0, 'U'},
		{CIB_OP_MODIFY,  0, 0, 'M'},
		{CIB_OP_DELETE,  0, 0, 'D'},
		{CIB_OP_BUMP,    0, 0, 'B'},
		{CIB_OP_SYNC,    0, 0, 'S'},
		{CIB_OP_SLAVE,   0, 0, 'r'},
		{CIB_OP_MASTER,  0, 0, 'w'},
		{CIB_OP_ISMASTER,0, 0, 'm'},

		{"upgrade",     0, 0, 'u'},
		{"erase",       0, 0, 'E'},
		{"query",       0, 0, 'Q'},
		{"create",      0, 0, 'C'},
		{"replace",     0, 0, 'R'},
		{"modify",      0, 0, 'M'},
		{"delete",      0, 0, 'D'},
		{"bump",        0, 0, 'B'},
		{"sync",        0, 0, 'S'},
		{"make-slave",  0, 0, 'r'},
		{"make-master", 0, 0, 'w'},
		{"is-master",   0, 0, 'm'},
		{"patch",	0, 0, 'P'},
		{"xpath",       1, 0, 'A'},

		{"md5-sum",	0, 0, '5'},
		
		{"file-mode",	1, 0, 0},

		{"force-quorum",0, 0, 'f'},
		{"force",	0, 0, 'f'},
		{"local",	0, 0, 'l'},
		{"sync-call",	0, 0, 's'},
		{"allow-create",0, 0, 'c'},
		{"no-children", 0, 0, 'n'},
		{"no-bcast",	0, 0, 'b'},
		{"host",	0, 0, 'h'}, /* legacy */
		{"node",	0, 0, 'N'},
		{F_CRM_DATA,    1, 0, 'X'}, /* legacy */
		{"xml-text",    1, 0, 'X'},
		{"xml-file",    1, 0, 'x'},
		{"xml-pipe",    0, 0, 'p'},
		{"verbose",     0, 0, 'V'},
		{"help",        0, 0, '?'},
		{"reference",   1, 0, 0},
		{"timeout",	1, 0, 't'},

		/* common options */
		{"obj_type", 1, 0, 'o'},

		{0, 0, 0, 0}
	};
#endif

	crm_log_init("cibadmin", LOG_CRIT, FALSE, FALSE, argc, argv);
	
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
	if (safe_str_eq("reference", long_options[option_index].name)) {
		this_msg_reference = crm_strdup(optarg);

	} else if (safe_str_eq("file-mode", long_options[option_index].name)) {
	    setenv("CIB_file", optarg, 1);

	} else {
		printf("Long option (--%s) is not (yet?) properly supported\n",
		       long_options[option_index].name);
		++argerr;
	}
	break;
#endif
			case 't':
				message_timeout_ms = atoi(optarg);
				if(message_timeout_ms < 1) {
					message_timeout_ms = 30;
				}
				break;
			case 'A':
				obj_type = crm_strdup(optarg);
				command_options |= cib_xpath;
				break;
			case 'u':
				cib_action = CIB_OP_UPGRADE;
				dangerous_cmd = TRUE;
				break;
			case 'E':
				cib_action = CIB_OP_ERASE;
				dangerous_cmd = TRUE;
				break;
			case 'Q':
				cib_action = CIB_OP_QUERY;
				break;
			case 'P':
				cib_action = CIB_OP_APPLY_DIFF;
				break;
			case 'S':
				cib_action = CIB_OP_SYNC;
				break;
			case 'U':
			case 'M':
				cib_action = CIB_OP_MODIFY;
				break;
			case 'R':
				cib_action = CIB_OP_REPLACE;
				break;
			case 'C':
				cib_action = CIB_OP_CREATE;
				break;
			case 'D':
				cib_action = CIB_OP_DELETE;
				break;
			case '5':
				cib_action = "md5-sum";
				break;
			case 'c':
				command_options |= cib_can_create;
				break;
			case 'n':
				command_options |= cib_no_children;
				break;
			case 'm':
				cib_action = CIB_OP_ISMASTER;
				command_options |= cib_scope_local;
				break;
			case 'B':
				cib_action = CIB_OP_BUMP;
				break;
			case 'r':
				dangerous_cmd = TRUE;
				cib_action = CIB_OP_SLAVE;
				break;
			case 'w':
				dangerous_cmd = TRUE;
				cib_action = CIB_OP_MASTER;
				command_options |= cib_scope_local;
				break;
			case 'V':
				command_options = command_options | cib_verbose;
				cl_log_enable_stderr(TRUE);
				alter_debug(DEBUG_INC);
				break;
			case '?':
				usage(crm_system_name, LSB_EXIT_OK);
				break;
			case 'o':
				crm_debug_2("Option %c => %s", flag, optarg);
				obj_type = crm_strdup(optarg);
				break;
			case 'X':
				crm_debug_2("Option %c => %s", flag, optarg);
				admin_input_xml = crm_strdup(optarg);
				break;
			case 'x':
				crm_debug_2("Option %c => %s", flag, optarg);
				admin_input_file = crm_strdup(optarg);
				break;
			case 'p':
				admin_input_stdin = TRUE;
				break;
			case 'h':
				host = crm_strdup(optarg);
				break;
			case 'l':
				command_options |= cib_scope_local;
				break;
			case 'b':
				dangerous_cmd = TRUE;
				command_options |= cib_inhibit_bcast;
				command_options |= cib_scope_local;
				break;
			case 's':
				command_options |= cib_sync_call;
				break;
			case 'f':
				force_flag = TRUE;
				command_options |= cib_quorum_override;
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
		usage(crm_system_name, LSB_EXIT_EINVAL);
	}

	if (optind > argc || cib_action == NULL) {
	    ++argerr;
	}
	
	if (argerr) {
		usage(crm_system_name, LSB_EXIT_GENERIC);
	}

	if(dangerous_cmd && force_flag == FALSE) {
	    fprintf(stderr, "The supplied command is considered dangerous."
		    "  To prevent accidental destruction of the cluster,"
		    " the --force flag is required in order to proceed.\n");
	    fflush(stderr);
	    usage(crm_system_name, LSB_EXIT_GENERIC);
	    
	}
	
	if(admin_input_file != NULL) {
	    input = filename2xml(admin_input_file);
	    source = admin_input_file;
		
	} else if(admin_input_xml != NULL) {
	    source = "input string";
	    input = string2xml(admin_input_xml);

	} else if(admin_input_stdin) {
	    source = "STDIN";
	    input = stdin2xml();
	}
	
	if(input != NULL) {
	    crm_log_xml_debug(input, "[admin input]");

	} else if(source) {
	    fprintf(stderr, "Couldn't parse input from %s.\n", source);
	    return 1;
	}

	if(safe_str_eq(cib_action, "md5-sum")) {
	    char *digest = NULL;
	    if(input == NULL) {
		fprintf(stderr,
			"Please supply XML to process with -X, -x or -p\n");
		exit(1);
	    }
	    
	    digest = calculate_xml_digest(input, FALSE, FALSE);
	    fprintf(stderr, "Digest: ");
	    fprintf(stdout, "%s\n", crm_str(digest));
	    crm_free(digest);
	    exit(0);
	}
	
	exit_code = do_init();
	if(exit_code != cib_ok) {
		crm_err("Init failed, could not perform requested operations");
		fprintf(stderr, "Init failed, could not perform requested operations\n");
		return -exit_code;
	}	

	exit_code = do_work(input, command_options, &output);
	if (exit_code > 0) {
		/* wait for the reply by creating a mainloop and running it until
		 * the callbacks are invoked...
		 */
		request_id = exit_code;

		the_cib->cmds->register_callback(
		    the_cib, request_id, message_timeout_ms, FALSE, NULL,
		    "cibadmin_op_callback", cibadmin_op_callback);

		mainloop = g_main_new(FALSE);

		crm_debug_3("%s waiting for reply from the local CIB",
			 crm_system_name);
		
		crm_info("Starting mainloop");
		g_main_run(mainloop);
		
	} else if(exit_code < 0) {
		crm_err("Call failed: %s", cib_error2string(exit_code));
		fprintf(stderr, "Call failed: %s\n",
			cib_error2string(exit_code));
		operation_status = exit_code;

		if(crm_str_eq(cib_action, CIB_OP_UPGRADE, TRUE)) {
		    if(exit_code == cib_dtd_validation) {
			xmlNode *obj = NULL;
			int version = 0, rc = 0;
			rc = the_cib->cmds->query(the_cib, NULL, &obj, command_options);
			if(rc == cib_ok) {
			    update_validation(&obj, &version, TRUE, FALSE);
			}
		    }
		}
	}

	if(output != NULL) {
		char *buffer = dump_xml_formatted(output);
		fprintf(stdout, "%s\n", crm_str(buffer));
		crm_free(buffer);
	}

	the_cib->cmds->signoff(the_cib);
	
	crm_debug_3("%s exiting normally", crm_system_name);
	return -exit_code;
}

int
do_work(xmlNode *input, int call_options, xmlNode **output) 
{
	/* construct the request */
	the_cib->call_timeout = message_timeout_ms;

	if (strcasecmp(CIB_OP_SYNC, cib_action) == 0) {
		crm_debug_4("Performing %s op...", cib_action);
		return the_cib->cmds->sync_from(
			the_cib, host, obj_type, call_options);

	} else if (strcasecmp(CIB_OP_SLAVE, cib_action) == 0
		   && (call_options ^ cib_scope_local) ) {
		crm_debug_4("Performing %s op on all nodes...", cib_action);
		return the_cib->cmds->set_slave_all(the_cib, call_options);

	} else if (strcasecmp(CIB_OP_MASTER, cib_action) == 0) {
		crm_debug_4("Performing %s op on all nodes...", cib_action);
		return the_cib->cmds->set_master(the_cib, call_options);


	} else if(cib_action != NULL) {
		crm_debug_4("Passing \"%s\" to variant_op...", cib_action);
		return the_cib->cmds->variant_op(
			the_cib, cib_action, host, obj_type,
			input, output, call_options);
		
	} else {
		crm_err("You must specify an operation");
	}
	return cib_operation;
}

enum cib_errors
do_init(void)
{
	enum cib_errors rc = cib_ok;

	the_cib = cib_new();
	rc = the_cib->cmds->signon(the_cib, crm_system_name, cib_command);
	if(rc != cib_ok) {
		crm_err("Signon to CIB failed: %s",
			cib_error2string(rc));
		fprintf(stderr, "Signon to CIB failed: %s\n",
			cib_error2string(rc));
	}
	
	return rc;
}


void
usage(const char *cmd, int exit_status)
{
	FILE *stream;

	stream = exit_status != 0 ? stderr : stdout;

	fprintf(stream, "usage: %s [%s] command\n"
		"\twhere necessary, XML data will be obtained using -X,"
		" -x, or -p options\n", cmd, OPTARGS);

	fprintf(stream, "Options\n");
	fprintf(stream, "\t--%s (-%c) <type>\tobject type being operated on\n",
		"obj_type", 'o');
	fprintf(stream, "\t\t\t\tValid values are: nodes, resources, constraints, crm_config, status\n");
	fprintf(stream, "\t--%s (-%c) <pathspec>\tSupply a valid XPath to use instead of an obj_type\n", "xpath", 'A');
	fprintf(stream, "\t--%s (-%c)\t\tturn on debug info."
		"  additional instance increase verbosity\n", "verbose", 'V');
	fprintf(stream, "\t--%s (-%c)\t\tthis help message\n", "help", '?');
	fprintf(stream, "\nCommands\n");
	fprintf(stream, "\t--%s (-%c)\tErase the contents of the whole CIB\n", "erase",  'E');
	fprintf(stream, "\t--%s (-%c)\t\n", "query",  'Q');
	fprintf(stream, "\t--%s (-%c)\t\n", "create", 'C');
	fprintf(stream, "\t--%s (-%c)\tCalculate an XML file's digest."
		"  Requires either -X, -x or -p\n", "md5-sum", '5');
	fprintf(stream, "\t--%s (-%c)\tRecursivly replace an object in the CIB\n", "replace",'R');
	fprintf(stream, "\t--%s (-%c)\tFind the object somewhere in the CIB's XML tree and update it\n", "modify", 'M');
	fprintf(stream, "\t--%s (-%c)", "delete", 'D');
	fprintf(stream, "\tDelete the first object matching the supplied criteria\n");
	fprintf(stream, "\t\t\tEg. <op id=\"rsc1_op1\" name=\"monitor\"/>\n");
	fprintf(stream, "\t\t\tThe tagname and all attributes must match in order for the element to be deleted\n");
	
	fprintf(stream, "\t--%s (-%c)\t\n", "bump",   'B');
	fprintf(stream, "\t--%s (-%c)\t\n", "is-master",'m');
	fprintf(stream, "\t--%s (-%c)\t\n", "sync",   'S');
	fprintf(stream, "\nXML data\n");
	fprintf(stream, "\t--%s (-%c) <string>\tRetrieve XML from the supplied string\n", "xml-text", 'X');
	fprintf(stream, "\t--%s (-%c) <filename>\tRetrieve XML from the named file\n", "xml-file", 'x');
	fprintf(stream, "\t--%s (-%c)\t\t\tRetrieve XML from STDIN\n", "xml-pipe", 'p');
	fprintf(stream, "\nAdvanced Options\n");
	fprintf(stream, "\t--%s (-%c)\t\t\tsend command to specified host."
		" Applies to %s and %s commands only\n", "host", 'h',
		"query", "sync");
	fprintf(stream, "\t--%s (-%c)\t\t\tcommand takes effect locally"
		" on the specified host\n", "local", 'l');
	fprintf(stream, "\t--%s (-%c)\t\t\tcommand will not be broadcast even if"
		" it altered the CIB\n", "no-bcast", 'b');
	fprintf(stream, "\t--%s (-%c)\t\twait for call to complete before"
		" returning\n", "sync-call", 's');

	fflush(stream);

	exit(exit_status);
}


void
cib_connection_destroy(gpointer user_data)
{
	crm_err("Connection to the CIB terminated... exiting");
	g_main_quit(mainloop);
	return;
}

void
cibadmin_op_callback(xmlNode *msg, int call_id, int rc,
		     xmlNode *output, void *user_data)
{
	char *admin_input_xml = NULL;
	
	exit_code = rc;

	if(output != NULL) {
		admin_input_xml = dump_xml_formatted(output);
	}
	
	if(safe_str_eq(cib_action, CIB_OP_ISMASTER) && rc != cib_ok) {
		crm_info("CIB on %s is _not_ the master instance",
			 host?host:"localhost");
		fprintf(stderr, "CIB on %s is _not_ the master instance\n",
			 host?host:"localhost");
		
	} else if(safe_str_eq(cib_action, CIB_OP_ISMASTER)) {
		crm_info("CIB on %s _is_ the master instance",
			 host?host:"localhost");
		fprintf(stderr, "CIB on %s _is_ the master instance\n",
			 host?host:"localhost");
		
	} else if(rc != 0) {
		crm_warn("Call %s failed (%d): %s",
			cib_action, rc, cib_error2string(rc));
		fprintf(stderr, "Call %s failed (%d): %s\n",
			cib_action, rc, cib_error2string(rc));
		fprintf(stdout, "%s\n",	crm_str(admin_input_xml));

	} else if(safe_str_eq(cib_action, CIB_OP_QUERY) && output==NULL) {
		crm_err("Output expected in query response");
		crm_log_xml(LOG_ERR, "no output", msg);

	} else if(output == NULL) {
		crm_info("Call passed");

	} else {
		crm_info("Call passed");
		fprintf(stdout, "%s\n", crm_str(admin_input_xml));
	}
	crm_free(admin_input_xml);

	if(call_id == request_id) {
		g_main_quit(mainloop);

	} else {
		crm_info("Message was not the response we were looking for (%d vs. %d", call_id, request_id);
	}
}
