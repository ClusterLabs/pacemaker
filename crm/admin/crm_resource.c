/* $Id: crm_resource.c,v 1.2 2005/09/19 08:39:46 andrew Exp $ */

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
int do_find_resource(const char *rsc, crm_data_t *xml_node);
int do_find_resource_list(int level, crm_data_t *cib);

gboolean BE_QUIET = FALSE;
char *host_id = NULL;
const char *rsc_id = NULL;
const char *host_uname = NULL;
const char *crm_system_name = "crm_master";
char rsc_cmd = 0;

#define OPTARGS	"V?SLRQDCMWmr:h:"

int
main(int argc, char **argv)
{
	cib_t *	the_cib = NULL;
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
		{"query",   0, 0, 'Q'},
		{"delete",  0, 0, 'D'},
		{"cleanup", 0, 0, 'C'},
		{"managed", 0, 0, 'M'},
		{"locate",  0, 0, 'W'},
		{"migrate", 0, 0, 'm'},
		{"resource",1, 0, 'r'},
		{"host_uname", 1, 0, 'H'},
		{"host_uuid",  1, 0, 'h'},

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
				crm_debug_2("Option %c => %s", flag, optarg);
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
				
			case 'M':
				rsc_cmd = flag;
				break;
				
			case 'W':
				rsc_cmd = flag;
				break;
				
			case 'm':
				rsc_cmd = flag;
				break;				
			case 'r':
				rsc_id = optarg;
				break;

			case 'H':
				host_uname = optarg;
				break;
				
			case 'h':
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

	the_cib = cib_new();
	rc = the_cib->cmds->signon(the_cib, crm_system_name, cib_command);

	if(rc != cib_ok) {
		crm_err("Error signing on to the CIB service: %s",
			cib_error2string(rc));
		return rc;
	}

	if(rsc_cmd == 'L') {
		crm_data_t *cib_xml_copy = get_cib_copy(the_cib);
		crm_data_t *resource_list = get_object_root(
			XML_CIB_TAG_RESOURCES, cib_xml_copy);
		do_find_resource_list(LOG_INFO, resource_list);
		free_xml(cib_xml_copy);
		
	} else if(rsc_cmd == 'W') {
		crm_data_t *cib_xml_copy = get_cib_copy(the_cib);
		rc = do_find_resource(rsc_id, cib_xml_copy);
		free_xml(cib_xml_copy);
		
	} else if(rsc_cmd == 'R') {
	} else if(rsc_cmd == 'Q') {
	} else if(rsc_cmd == 'D') {
	} else if(rsc_cmd == 'C') {
	} else if(rsc_cmd == 'M') {
	} else if(rsc_cmd == 'r') {
	} else if(rsc_cmd == 'm') {
	}

	the_cib->cmds->signoff(the_cib);
	if(rc == cib_NOTEXISTS) {
		crm_warn("Error performing operation: %s",
			 cib_error2string(rc));

	} else if(rc < cib_ok) {
		crm_warn("Error performing operation: %s",
			 cib_error2string(rc));
	}
	return rc;
}

int
do_find_resource(const char *rsc, crm_data_t *xml_node)
{
	int found = 0;
	pe_working_set_t data_set;
	resource_t *the_rsc = NULL;
	
	set_working_set_defaults(&data_set);
	data_set.input = xml_node;
	stage0(&data_set);

	the_rsc = pe_find_resource(data_set.resources, rsc);
	if(the_rsc == NULL) {
		return cib_NOTEXISTS;
	}

	slist_iter(node, node_t, the_rsc->running_on, lpc,
		   crm_debug_3("resource %s is running on: %s",
			       rsc, node->details->uname);
		   printf("resource %s is running on: %s\n",
			       rsc, node->details->uname);
		   if(BE_QUIET) {
			   fprintf(stderr, "%s ", node->details->uname);
		   }
		   found++;
		);
	
	if(BE_QUIET) {
		fprintf(stderr, "\n");
	}
	
	if(found == 0) {
		printf("resource %s is NOT running\n", rsc);
	}
					
	data_set.input = NULL;
	cleanup_calculations(&data_set);

	return found;
}

int
do_find_resource_list(int level, crm_data_t *resource_list)
{
	int lpc = 0;
	int found = 0;
	const char *name = NULL;
	const char *type = NULL;
	const char *class = NULL;
	
	xml_child_iter(
		resource_list, rsc, NULL,
		name = crm_element_name(rsc);
		if(safe_str_eq(name, XML_CIB_TAG_RESOURCE)) {
			class = crm_element_value(rsc, "class");
			type = crm_element_value(rsc, XML_ATTR_TYPE);
			for(lpc = 0; lpc < level; lpc++) {
				printf("\t");
			}
			found++;
			printf("%s: %s (%s::%s)\n",
			       name, ID(rsc), crm_str(class), crm_str(type));
		} else if(safe_str_eq(name, XML_CIB_TAG_GROUP)
			  || safe_str_eq(name, XML_CIB_TAG_INCARNATION)) {
			for(lpc = 0; lpc < level; lpc++) {
				printf("\t");
			}
			printf("%s: %s (complex)\n", name, ID(rsc));
			do_find_resource_list(level+1, rsc);
			found++;
		}
		);
	if(found == 0) {
		for(lpc = 0; lpc < level; lpc++) {
			printf("\t");
		}
		printf("NO resources configured\n");
	}
					
	return found;
}

void
usage(const char *cmd, int exit_status)
{
	FILE *stream;

	stream = exit_status ? stderr : stdout;
	if(safe_str_eq(cmd, "crm_master")) {
		fprintf(stream, "usage: %s [-?VQ] -(D|G|v) [-l]\n", cmd);

	} else if(safe_str_eq(cmd, "crm_standby")) {
		fprintf(stream, "usage: %s [-?V] -(u|U) -(D|G|v) [-l]\n", cmd);

	} else {
		fprintf(stream, "usage: %s [-?V] -(D|G|v) [options]\n", cmd);
	}
	
	fprintf(stream, "Options\n");
	fprintf(stream, "\t--%s (-%c)\t: this help message\n", "help", '?');
	fprintf(stream, "\t--%s (-%c)\t: "
		"turn on debug info. additional instances increase verbosity\n",
		"verbose", 'V');
	fprintf(stream, "\t--%s (-%c)\t: Print only the value on stdout"
		" (use with -G)\n", "quiet", 'Q');
	fprintf(stream, "\t--%s (-%c)\t: "
		"Retrieve rather than set the attribute\n", "get-value", 'G');
	fprintf(stream, "\t--%s (-%c)\t: "
		"Delete rather than set the attribute\n", "delete-attr", 'D');
	fprintf(stream, "\t--%s (-%c) <string>\t: "
		"Value to use (ignored with -G)\n", "attr-value", 'v');

	if(safe_str_eq(cmd, "crm_master")) {
		fprintf(stream, "\t--%s (-%c) <string>\t: "
			"How long the preference lasts (reboot|forever)\n",
			"lifetime", 'l');
		exit(exit_status);
	} else if(safe_str_eq(cmd, "crm_standby")) {
		fprintf(stream, "\t--%s (-%c) <node_uuid>\t: "
			"UUID of the node to change\n", "node-uuid", 'u');
		fprintf(stream, "\t--%s (-%c) <node_uuid>\t: "
			"uname of the node to change\n", "node-uname", 'U');
		fprintf(stream, "\t--%s (-%c) <string>\t: "
			"How long the preference lasts (reboot|forever)\n"
			"\t    If a forever value exists, it is ALWAYS used by the CRM\n"
			"\t    instead of any reboot value\n", "lifetime", 'l');
		exit(exit_status);
	}
	
	fprintf(stream, "\t--%s (-%c) <node_uuid>\t: "
		"UUID of the node to change\n", "node-uuid", 'u');
	fprintf(stream, "\t--%s (-%c) <node_uuid>\t: "
		"uname of the node to change\n", "node-uname", 'U');
	fprintf(stream, "\t--%s (-%c) <string>\t: "
		"Set of attributes in which to read/write the attribute\n",
		"set-name", 's');
	fprintf(stream, "\t--%s (-%c) <string>\t: "
		"Attribute to set\n", "attr-name", 'n');
	fprintf(stream, "\t--%s (-%c) <string>\t: "
		"Which section of the CIB to set the attribute: (%s|%s|%s)\n",
		"type", 't',
		XML_CIB_TAG_NODES, XML_CIB_TAG_STATUS, XML_CIB_TAG_CRMCONFIG);
	fprintf(stream, "\t    -t=%s options: -(U|u) -n [-s]\n", XML_CIB_TAG_NODES);
	fprintf(stream, "\t    -t=%s options: -(U|u) -n [-s]\n", XML_CIB_TAG_STATUS);
	fprintf(stream, "\t    -t=%s options: -n [-s]\n", XML_CIB_TAG_CRMCONFIG);
	fflush(stream);

	exit(exit_status);
}
