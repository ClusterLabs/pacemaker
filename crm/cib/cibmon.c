/* $Id: cibmon.c,v 1.1 2004/12/10 20:07:07 andrew Exp $ */

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
#include <clplumbing/Gmain_timeout.h>

#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/ctrl.h>
#include <crm/common/ipc.h>

#include <crm/cib.h>

#include <getopt.h>
#include <ha_msg.h> /* someone complaining about _ha_msg_mod not being found */
#include <crm/dmalloc_wrapper.h>

FILE *msg_cib_strm = NULL;

int exit_code = cib_ok;

GMainLoop *mainloop = NULL;
const char *crm_system_name = "cibmon";
void usage(const char *cmd, int exit_status);
void cib_connection_destroy(gpointer user_data);

void cibmon_pre_notify(const char *event, struct ha_msg *msg);
void cibmon_post_notify(const char *event, struct ha_msg *msg);
void cibmon_update_confirm(const char *event, struct ha_msg *msg);

cib_t *the_cib = NULL;

#define OPTARGS	"V?pPUam:i"

gboolean intermediate_changes = FALSE;
gboolean pre_notify = FALSE;
gboolean post_notify = FALSE;
gboolean update_notify = FALSE;
int max_failures = 30;

int
main(int argc, char **argv)
{
	int option_index = 0;
	int argerr = 0;
	int flag;
	int level = 0;
	int attempts = 0;
	
	static struct option long_options[] = {
		/* Top-level Options */
		{"verbose",      0, 0, 'V'},
		{"help",         0, 0, '?'},
		{"pre",          0, 0, 'p'},
		{"post",         0, 0, 'P'},
		{"update",       0, 0, 'U'},
		{"all",          0, 0, 'a'},
		{"intermediate", 0, 0, 'i'},
		{"max-conn-fail",1, 0, 'm'},
		{0, 0, 0, 0}
	};

	if(argc < 2) {
		usage(crm_system_name, LSB_EXIT_EINVAL);
	}

	/* Redirect messages from glib functions to our handler */
	g_log_set_handler(NULL,
			  G_LOG_LEVEL_ERROR      | G_LOG_LEVEL_CRITICAL
			  | G_LOG_LEVEL_WARNING  | G_LOG_LEVEL_MESSAGE
			  | G_LOG_LEVEL_INFO     | G_LOG_LEVEL_DEBUG
			  | G_LOG_FLAG_RECURSION | G_LOG_FLAG_FATAL,
			  cl_glib_msg_handler, NULL);
	/* and for good measure... */
	g_log_set_always_fatal((GLogLevelFlags)0);    
	
	cl_log_set_entity(crm_system_name);
	cl_log_set_facility(LOG_LOCAL7);

	/* docs say only do this once, but in their code they do it every time! */
	xmlInitParser(); 
	msg_cib_strm = fopen(DEVEL_DIR"/cibmon.log", "w");

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
		printf("Long option (--%s) is not (yet?) properly supported\n",
		       long_options[option_index].name);
		++argerr;
			case 'V':
				level = get_crm_log_level();
				cl_log_enable_stderr(TRUE);
				set_crm_log_level(level+1);
				break;
			case '?':
				usage(crm_system_name, LSB_EXIT_OK);
				break;
			case 'm':
				max_failures = crm_atoi(optarg, "30");
				break;
			case 'a':
				pre_notify = TRUE;
				post_notify = TRUE;
				update_notify = TRUE;
				break;
			case 'p':
				pre_notify = TRUE;
				break;
			case 'P':
				post_notify = TRUE;
				break;
			case 'U':
				update_notify = TRUE;
				break;
			case 'i':
				intermediate_changes = TRUE;
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

	the_cib = cib_new();

	do {
		if(attempts != 0) {
			sleep(1);
		}
		exit_code = the_cib->cmds->signon(the_cib, cib_query);

	} while(exit_code == cib_connection && attempts++ < max_failures);
		
	if(exit_code != cib_ok) {
		crm_err("Signon to CIB failed: %s",
			cib_error2string(exit_code));
		fprintf(stderr, "Signon to CIB failed: %s\n",
			cib_error2string(exit_code));
	} 

	if(exit_code == cib_ok && pre_notify) {
		exit_code = the_cib->cmds->add_notify_callback(
			the_cib, T_CIB_PRE_NOTIFY, cibmon_pre_notify);
		
		if(exit_code != cib_ok) {
			crm_err("Failed to set %s callback: %s",
				T_CIB_PRE_NOTIFY, cib_error2string(exit_code));
			fprintf(stderr, "Failed to set %s callback: %s",
				T_CIB_PRE_NOTIFY, cib_error2string(exit_code));
		}
	}
	if(exit_code == cib_ok && post_notify) {
		exit_code = the_cib->cmds->add_notify_callback(
			the_cib, T_CIB_POST_NOTIFY, cibmon_post_notify);
		
		if(exit_code != cib_ok) {
			crm_err("Failed to set %s callback: %s",
				T_CIB_POST_NOTIFY, cib_error2string(exit_code));
			fprintf(stderr, "Failed to set %s callback: %s",
				T_CIB_POST_NOTIFY, cib_error2string(exit_code));
		}
	}
	if(exit_code == cib_ok && update_notify) {
		exit_code = the_cib->cmds->add_notify_callback(
			the_cib, T_CIB_UPDATE_CONFIRM, cibmon_update_confirm);
		
		if(exit_code != cib_ok) {
			crm_err("Failed to set %s callback: %s",
				T_CIB_UPDATE_CONFIRM, cib_error2string(exit_code));
			fprintf(stderr, "Failed to set %s callback: %s",
				T_CIB_UPDATE_CONFIRM, cib_error2string(exit_code));
		}
	}
	
	if(exit_code != cib_ok) {
		crm_err("Setup failed, could not monitor CIB actions");
		fprintf(stderr, "Setup failed, could not monitor CIB actions\n");
		fflush(stderr);
		fflush(stdout);
		return -exit_code;
	}

	mainloop = g_main_new(FALSE);
	crm_info("Starting mainloop");
	g_main_run(mainloop);
	crm_debug("%s exiting normally", crm_system_name);
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
	fprintf(stream, "\t--%s (-%c)\t\n", CRM_OP_CIB_ERASE,  'E');
	fprintf(stream, "\t--%s (-%c)\t\n", CRM_OP_CIB_QUERY,  'Q');
	fprintf(stream, "\t--%s (-%c)\t\n", CRM_OP_CIB_CREATE, 'C');
	fprintf(stream, "\t--%s (-%c)\t\n", CRM_OP_CIB_REPLACE,'R');
	fprintf(stream, "\t--%s (-%c)\t\n", CRM_OP_CIB_UPDATE, 'U');
	fprintf(stream, "\t--%s (-%c)\t\n", CRM_OP_CIB_DELETE, 'D');
	fprintf(stream, "\t--%s (-%c)\t\n", CRM_OP_CIB_BUMP,   'B');
	fprintf(stream, "\t--%s (-%c)\t\n", CRM_OP_CIB_ISMASTER,'M');
	fprintf(stream, "\t--%s (-%c)\t\n", CRM_OP_CIB_SYNC,   'S');
	fprintf(stream, "\nXML data\n");
	fprintf(stream, "\t--%s (-%c) <string>\t\n", "xml", 'X');
	fprintf(stream, "\nAdvanced Options\n");
	fprintf(stream, "\t--%s (-%c)\tsend command to specified host."
		" Applies to %s and %s commands only\n", "host", 'h',
		CRM_OP_CIB_QUERY, CRM_OP_CIB_SYNC);
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

int update_depth = 0;
gboolean last_notify_pre = TRUE;

void
cibmon_pre_notify(const char *event, struct ha_msg *msg) 
{
	int rc = -1;
	const char *op       = cl_get_string(msg, F_CIB_OPERATION);
	const char *id       = cl_get_string(msg, F_CIB_OBJID);
	const char *type     = cl_get_string(msg, F_CIB_OBJTYPE);
	const char *update_s = cl_get_string(msg, F_CIB_UPDATE);
	const char *pre_update_s = cl_get_string(msg, F_CIB_EXISTING);

	xmlNodePtr update = string2xml(update_s);
	xmlNodePtr pre_update = string2xml(pre_update_s);
	char *xml_text    = dump_xml_formatted(update);

	ha_msg_value_int(msg, F_CIB_RC, &rc);

	update_depth++;
	last_notify_pre = TRUE;
	
	if(update_depth > 1 && intermediate_changes == FALSE) {
		crm_trace("Ignoring intermediate update");
		return;
	}
	
	if(update == NULL) {
		crm_verbose("Performing operation %s (on section=%s)", op, type);
		fprintf(msg_cib_strm, "[%s] Performing %s (to %s)\n",
			event, op, crm_str(type));

	} else {
		crm_verbose("Performing %s on <%s%s%s>",
			    op, type, id?" id=":"", id?id:"");
		fprintf(msg_cib_strm, "[%s] Performing %s to <%s%s%s>."
			"  Update follows\n%s\n",
			event, op, crm_str(type), id?" id=":"", id?id:"",
			xml_text);
	}
	crm_free(xml_text);

	xml_text = dump_xml_formatted(pre_update);
	fprintf(msg_cib_strm, "[%s] Existing object\n%s\n",
		event, xml_text);
	
	fflush(msg_cib_strm);
	crm_free(xml_text);
}


void
cibmon_post_notify(const char *event, struct ha_msg *msg)
{
	int rc = -1;
	const char *op       = cl_get_string(msg, F_CIB_OPERATION);
	const char *id       = cl_get_string(msg, F_CIB_OBJID);
	const char *type     = cl_get_string(msg, F_CIB_OBJTYPE);
	const char *update_s = cl_get_string(msg, F_CIB_UPDATE);
	const char *output_s = cl_get_string(msg, F_CIB_UPDATE_RESULT);
	
	xmlNodePtr output = string2xml(output_s);
	xmlNodePtr update = string2xml(update_s);

	char *xml_text = dump_xml_formatted(output);

	update_depth--;
	if(last_notify_pre == FALSE 
	   && update_depth > 0
	   && intermediate_changes == FALSE) {
		crm_trace("Ignoring intermediate update");
		return;
	}

	last_notify_pre = FALSE;
	ha_msg_value_int(msg, F_CIB_RC, &rc);
	
	if(update == NULL) {
		if(rc == cib_ok) {
			crm_verbose("Operation %s (to section=%s) completed",
				    op, crm_str(type));
			fprintf(msg_cib_strm, "[%s] %s (to %s) completed\n",
				event, op, crm_str(type));
			
		} else {
			crm_warn("Operation %s (to section=%s) FAILED: (%d) %s",
				 op, crm_str(type), rc, cib_error2string(rc));
			fprintf(msg_cib_strm, "[%s] %s (to %s) FAILED: (%d) %s\n",
				event, op, crm_str(type), rc, cib_error2string(rc));
		}
		
	} else {
		if(rc == cib_ok) {
			crm_verbose("Completed %s of <%s%s%s>",
				    op, type, id?" id=":"", id);
			fprintf(msg_cib_strm, "[%s] Operation %s to <%s%s%s> completed.\n",
				event, op, crm_str(type), id?" id=":"", id?id:"");
			
		} else {
			crm_warn("%s of <%s%s%s> FAILED: (%d) %s", op, type,
				 id?" id=":"", id?id:"", rc, cib_error2string(rc));
			fprintf(msg_cib_strm, "[%s] Operation %s to <%s %s%s> FAILED: (%d) %s\n",
				event, op, crm_str(type), id?" id=":"", id?id:"",
				rc, cib_error2string(rc));
		}
	}
	fprintf(msg_cib_strm, "[%s] Operation %s result:\n%s\n",
		event, op, xml_text);
	crm_free(xml_text);

	fflush(msg_cib_strm);
}

void
cibmon_update_confirm(const char *event, struct ha_msg *msg)
{
	int rc = -1;
	const char *op = cl_get_string(msg, F_CIB_OPERATION);
	const char *id = cl_get_string(msg, F_CIB_OBJID);
	const char *type = cl_get_string(msg, F_CIB_OBJTYPE);

	ha_msg_value_int(msg, F_CIB_RC, &rc);

	if(id == NULL) {
		if(rc == cib_ok) {
			fprintf(msg_cib_strm, "[%s] %s (to section=%s) confirmed.\n",
				event, op, crm_str(type));
		} else {
			fprintf(msg_cib_strm, "[%s] %s (to section=%s) ABORTED: (%d) %s\n",
				event, op, crm_str(type), 
				rc, cib_error2string(rc));
		}
		
	} else {
		if(rc == cib_ok) {
			fprintf(msg_cib_strm, "[%s] %s (to <%s%s%s>) confirmed\n",
				event, op, crm_str(type), id?" id=":"", id?id:"");
		} else {
			fprintf(msg_cib_strm, "[%s] %s (to <%s%s%s>) ABORTED: (%d) %s\n",
				event, op, crm_str(type), id?" id=":"", id?id:"",
				rc, cib_error2string(rc));
		}
	}
	fprintf(msg_cib_strm, "\n=================================\n\n");
	
	fflush(msg_cib_strm);
}
