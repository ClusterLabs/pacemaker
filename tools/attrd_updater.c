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

#include <hb_config.h>

#include <sys/param.h>

#include <crm/crm.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <crm/common/ipc.h>
#include <clplumbing/lsb_exitcodes.h>
#include <attrd.h>

#define OPTARGS      "hVn:v:d:s:S:"

const char* crm_system_name = "attrd_updater";

const char *attr_name = NULL;
const char *attr_value = NULL;
const char *attr_set = NULL;
const char *attr_section = NULL;
const char *attr_dampen = NULL;

void usage(const char* cmd, int exit_status);

static gboolean
process_attrd_message(
	HA_Message *msg, crm_data_t *xml_data, IPC_Channel *sender)
{
	crm_err("Why did we get a message?");
	crm_log_message_adv(LOG_WARNING, "attrd:msg", msg);
	return TRUE;
}

int
main(int argc, char ** argv)
{
	HA_Message *update = NULL;
	IPC_Channel *attrd = NULL;
	int argerr = 0;
	int flag;
	
	crm_log_init(crm_system_name, LOG_ERR, FALSE, FALSE, argc, argv);
	crm_debug_3("Begining option processing");

	while ((flag = getopt(argc, argv, OPTARGS)) != EOF) {
		switch(flag) {
			case 'V':
				alter_debug(DEBUG_INC);
				break;
			case 'h':		/* Help message */
				usage(crm_system_name, LSB_EXIT_OK);
				break;
			case 'n':
				attr_name = crm_strdup(optarg);
				break;
			case 'v':
				attr_value = crm_strdup(optarg);
				break;
			case 's':
				attr_set = crm_strdup(optarg);
				break;
			case 'd':
				attr_dampen = crm_strdup(optarg);
				break;
			case 'S':
				attr_section = crm_strdup(optarg);
				break;
			default:
				++argerr;
				break;
		}
	}
    
	crm_debug_3("Option processing complete");

	if (optind > argc) {
		++argerr;
	}

	if(attr_name == NULL) {
		++argerr;
	}
	
	if (argerr) {
		usage(crm_system_name, LSB_EXIT_GENERIC);
	}
    
	/* read local config file */
    
	init_client_ipc_comms(T_ATTRD, subsystem_msg_dispatch,
			      (void*)process_attrd_message, &attrd);

	if(attrd == NULL) {
		fprintf(stderr, "Could not connect to "T_ATTRD"\n");
		return 1;
	}

	update = ha_msg_new(4);
	ha_msg_add(update, F_TYPE, T_ATTRD);
	ha_msg_add(update, F_ORIG, crm_system_name);
	ha_msg_add(update, F_ATTRD_TASK, "update");
	ha_msg_add(update, F_ATTRD_ATTRIBUTE, attr_name);
	if(attr_value != NULL) {
		ha_msg_add(update, F_ATTRD_VALUE,   attr_value);
	}
	if(attr_set != NULL) {
		ha_msg_add(update, F_ATTRD_SET,     attr_set);
	}
	if(attr_section != NULL) {
		ha_msg_add(update, F_ATTRD_SECTION, attr_section);
	}
	if(attr_dampen != NULL) {
		ha_msg_add(update, F_ATTRD_DAMPEN, attr_dampen);
	}
	
	if(send_ipc_message(attrd, update) == FALSE) {
		fprintf(stderr, "Could not send update\n");
		crm_msg_del(update);
		return 1;
	}
	crm_msg_del(update);
	return 0;
}

void
usage(const char* cmd, int exit_status)
{
	FILE* stream;

	stream = exit_status ? stderr : stdout;

	fprintf(stream, "usage: %s -n [-vdsS]\n", cmd);
 	fprintf(stream, "\t-n <string>\tthe attribute that changed\n");
 	fprintf(stream, "\t-v <string>\tthe attribute's value\n");
 	fprintf(stream, "\t\tIf no value is supplied, the attribute value for this node will be deleted\n");
 	fprintf(stream, "\t-d <string>\tthe time to wait (dampening) further changes occur\n");
 	fprintf(stream, "\t-s <string>\tthe attribute set in which to place the value\n");
	fprintf(stream, "\t\tMost people have no need to specify this\n");
 	fprintf(stream, "\t-S <string>\tthe section in which to place the value\n");
	fprintf(stream, "\t\tMost people have no need to specify this\n");
	fflush(stream);

	exit(exit_status);
}

