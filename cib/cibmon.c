
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

#include <clplumbing/coredumps.h>
#include <clplumbing/uids.h>
#include <clplumbing/Gmain_timeout.h>

#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/ctrl.h>
#include <crm/common/ipc.h>
#include <crm/pengine/status.h>
#include <../lib/pengine/unpack.h>

#include <crm/cib.h>

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif

int got_signal = 0;
int max_failures = 30;
int exit_code = cib_ok;

gboolean log_diffs = FALSE;
gboolean log_updates = FALSE;

GMainLoop *mainloop = NULL;
void usage(const char *cmd, int exit_status);
void cib_connection_destroy(gpointer user_data);

gboolean cibmon_shutdown(int nsig, gpointer unused);
void cibmon_diff(const char *event, xmlNode *msg);

cib_t *cib = NULL;
xmlNode *cib_copy = NULL;

#define OPTARGS	"V?m:du"


int
main(int argc, char **argv)
{
	int argerr = 0;
	int flag;
	int level = 0;
	int attempts = 0;
	
#ifdef HAVE_GETOPT_H
	int option_index = 0;
	static struct option long_options[] = {
		/* Top-level Options */
		{"verbose",      0, 0, 'V'},
		{"help",         0, 0, '?'},
		{"log-diffs",    0, 0, 'd'},
		{"log-updates",  0, 0, 'u'},
		{"max-conn-fail",1, 0, 'm'},
		{0, 0, 0, 0}
	};
#endif

	crm_log_init("cibmon", LOG_INFO, FALSE, FALSE, 0, NULL);

	G_main_add_SignalHandler(
		G_PRIORITY_HIGH, SIGTERM, cibmon_shutdown, NULL, NULL);
	
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
				level = get_crm_log_level();
				cl_log_enable_stderr(TRUE);
				set_crm_log_level(level+1);
				break;
			case '?':
				usage(crm_system_name, LSB_EXIT_OK);
				break;
			case 'd':
				log_diffs = TRUE;
				break;
			case 'u':
				log_updates = TRUE;
				break;
			case 'm':
				max_failures = crm_parse_int(optarg, "30");
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

	cib = cib_new();

	do {
		sleep(1);
		exit_code = cib->cmds->signon(
			cib, crm_system_name, cib_query);

	} while(exit_code == cib_connection && attempts++ < max_failures);
		
	if(exit_code != cib_ok) {
		crm_err("Signon to CIB failed: %s",
			cib_error2string(exit_code));
	} 

	if(exit_code == cib_ok) {
		crm_debug("Setting dnotify");
		exit_code = cib->cmds->set_connection_dnotify(
			cib, cib_connection_destroy);
	}
	
	crm_debug("Setting diff callback");
	exit_code = cib->cmds->add_notify_callback(
	    cib, T_CIB_DIFF_NOTIFY, cibmon_diff);
	
	if(exit_code != cib_ok) {
	    crm_err("Failed to set %s callback: %s",
		    T_CIB_DIFF_NOTIFY, cib_error2string(exit_code));
	}
	
	if(exit_code != cib_ok) {
		crm_err("Setup failed, could not monitor CIB actions");
		return -exit_code;
	}

	mainloop = g_main_new(FALSE);
	crm_info("Starting mainloop");
	g_main_run(mainloop);
	crm_debug_3("%s exiting normally", crm_system_name);
	fflush(stderr);
	return -exit_code;
}


void
usage(const char *cmd, int exit_status)
{
	FILE *stream;

	stream = exit_status != 0 ? stderr : stdout;
#if 0
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
	fprintf(stream, "\t--%s (-%c)\t\n", CIB_OP_ERASE,  'E');
	fprintf(stream, "\t--%s (-%c)\t\n", CIB_OP_QUERY,  'Q');
	fprintf(stream, "\t--%s (-%c)\t\n", CIB_OP_CREATE, 'C');
	fprintf(stream, "\t--%s (-%c)\t\n", CIB_OP_REPLACE,'R');
	fprintf(stream, "\t--%s (-%c)\t\n", CIB_OP_UPDATE, 'U');
	fprintf(stream, "\t--%s (-%c)\t\n", CIB_OP_DELETE, 'D');
	fprintf(stream, "\t--%s (-%c)\t\n", CIB_OP_BUMP,   'B');
	fprintf(stream, "\t--%s (-%c)\t\n", CIB_OP_ISMASTER,'M');
	fprintf(stream, "\t--%s (-%c)\t\n", CIB_OP_SYNC,   'S');
	fprintf(stream, "\nXML data\n");
	fprintf(stream, "\t--%s (-%c) <string>\t\n", F_CRM_DATA, 'X');
	fprintf(stream, "\nAdvanced Options\n");
	fprintf(stream, "\t--%s (-%c)\tsend command to specified host."
		" Applies to %s and %s commands only\n", "host", 'h',
		CIB_OP_QUERY, CRM_OP_CIB_SYNC);
	fprintf(stream, "\t--%s (-%c)\tcommand only takes effect locally"
		" on the specified host\n", "local", 'l');
	fprintf(stream, "\t--%s (-%c)\twait for call to complete before"
		" returning\n", "sync-call", 's');
#endif
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

static void handle_rsc_op(xmlNode *rsc_op, pe_working_set_t *data_set) 
{
    int rc = -1;
    int status = -1;
    int action = -1;
    int interval = 0;
    int target_rc = -1;
    int transition_num = -1;
			
    char *rsc = NULL;
    char *task = NULL;
    const char *node = NULL;			     
    const char *magic = NULL;			     
    const char *id = ID(rsc_op);
    char *update_te_uuid = NULL;

    xmlNode *n = rsc_op;
    
    magic = crm_element_value(rsc_op, XML_ATTR_TRANSITION_MAGIC);
    if(magic == NULL) {
	/* non-change */
	return;
    }
			
    if(FALSE == decode_transition_magic(
	   magic, &update_te_uuid, &transition_num, &action,
	   &status, &rc, &target_rc)) {
	crm_err("Invalid event %s detected for %s", magic, id);
	return;
    }
			
    if(parse_op_key(id, &rsc, &task, &interval) == FALSE) {
	crm_err("Invalid event detected for %s", id);
	return;
    }

    while(n != NULL && safe_str_neq(XML_CIB_TAG_STATE, TYPE(n))) {
	n = n->parent;
    }

    node = ID(n);
    if(node == NULL) {
	crm_err("No node detected for event %s (%s)", magic, id);
	return;
    }

    /* look up where we expected it to be? */
    
    if(status == LRM_OP_DONE && target_rc == rc) {
	crm_notice("%s of %s on %s completed", task, rsc, node);
			    
    } else if(status == LRM_OP_DONE) {
	crm_warn("%s of %s on %s failed: %s",
		 task, rsc, node, execra_code2string(rc));
			    
    } else {
	crm_warn("%s of %s on %s failed: %s",
		 task, rsc, node, op_status2text(status));
    }
}

void
cibmon_diff(const char *event, xmlNode *msg)
{
    int rc = -1;
    const char *op = NULL;
    pe_working_set_t data_set;
    unsigned int log_level = LOG_INFO;

    xmlNode *diff = NULL;
    xmlNode *cib_last = NULL;
    xmlXPathObject *xpathObj = NULL;
    xmlNode *update = get_message_xml(msg, F_CIB_UPDATE);    
	
    if(msg == NULL) {
	crm_err("NULL update");
	return;
    }
    
    crm_element_value_int(msg, F_CIB_RC, &rc);	
    op = crm_element_value(msg, F_CIB_OPERATION);
    diff = get_message_xml(msg, F_CIB_UPDATE_RESULT);

    if(rc < cib_ok) {
	log_level = LOG_WARNING;
	do_crm_log(log_level, "[%s] %s ABORTED: %s",
		   event, op, cib_error2string(rc));
	return;	
    } 

    if(log_diffs) {
	log_cib_diff(log_level, diff, op);
    }
    
    if(log_updates && update != NULL) {
	print_xml_formatted(log_level+2, "raw_update", update, NULL);
    }
    
    if(cib_copy != NULL) {
	cib_last = cib_copy; cib_copy = NULL;
	rc = cib_process_diff(op, cib_force_diff, NULL, NULL, diff, cib_last, &cib_copy, NULL);
	
	if(rc != cib_ok) {
	    crm_debug("Update didn't apply, requesting full copy: %s", cib_error2string(rc));
	    free_xml(cib_copy);
	    cib_copy = NULL;
	}
    }
    
    if(cib_copy == NULL) {
	cib_copy = get_cib_copy(cib);
    }
    
    if(cib_last != NULL) {
	set_working_set_defaults(&data_set);
	data_set.input = cib_last;
	cluster_status(&data_set);	
    }
    
    /* Process operation updates */
    xpathObj = xpath_search(diff, "//"F_CIB_UPDATE_RESULT"//"XML_TAG_DIFF_ADDED"//"XML_LRM_TAG_RSC_OP);
    if(xpathObj && xpathObj->nodesetval->nodeNr > 0) {
	int lpc = 0, max = xpathObj->nodesetval->nodeNr;
	for(lpc = 0; lpc < max; lpc++) {
	    xmlNode *rsc_op = getXpathResult(xpathObj, lpc);
	    handle_rsc_op(rsc_op, &data_set);
	}
	xmlXPathFreeObject(xpathObj);
    }

    if(data_set.input != NULL) {
	data_set.input = NULL;
	cleanup_calculations(&data_set);
    }
    
    free_xml(cib_last);
}

gboolean
cibmon_shutdown(int nsig, gpointer unused)
{
	got_signal = 1;
	if (mainloop != NULL && g_main_is_running(mainloop)) {
		g_main_quit(mainloop);
	} else {
		exit(LSB_EXIT_OK);
	}
	return TRUE;
}
