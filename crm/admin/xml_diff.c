
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

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#include <ha_msg.h> /* someone complaining about _ha_msg_mod not being found */

const char *crm_system_name = "diff";
void usage(const char *cmd, int exit_status);

#define OPTARGS	"V?o:n:p:scfO:N:"

int
main(int argc, char **argv)
{
	gboolean apply = FALSE;
	gboolean raw_1  = FALSE;
	gboolean raw_2  = FALSE;
	gboolean filter = FALSE;
	gboolean use_stdin = FALSE;
	gboolean as_cib = FALSE;
	int argerr = 0;
	int flag;
	crm_data_t *object_1 = NULL;
	crm_data_t *object_2 = NULL;
	crm_data_t *output = NULL;
	const char *xml_file_1 = NULL;
	const char *xml_file_2 = NULL;

#ifdef HAVE_GETOPT_H
	int option_index = 0;
	static struct option long_options[] = {
		/* Top-level Options */
		{"original", 1, 0, 'o'},
		{"new",      1, 0, 'n'},
		{"original-string", 1, 0, 'O'},
		{"new-string",      1, 0, 'N'},
		{"patch",    1, 0, 'p'},
		{"stdin",    0, 0, 's'},
		{"cib",      0, 0, 'c'},
		{"verbose",  0, 0, 'V'},
		{"help",     0, 0, '?'},
		{0, 0, 0, 0}
	};
#endif

	cl_log_set_entity(crm_system_name);
	cl_log_set_facility(LOG_USER);
	set_crm_log_level(LOG_CRIT-1);
	
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
			case 'o':
				xml_file_1 = optarg;
				break;
			case 'O':
				xml_file_1 = optarg;
				raw_1 = TRUE;
				break;
			case 'n':
				xml_file_2 = optarg;
				break;
			case 'N':
				xml_file_2 = optarg;
				raw_2 = TRUE;
				break;
			case 'p':
				xml_file_2 = optarg;
				apply = TRUE;
				break;
			case 'f':
				filter = TRUE;
				break;
			case 's':
				use_stdin = TRUE;
				break;
			case 'c':
				as_cib = TRUE;
				break;
			case 'V':
				cl_log_enable_stderr(TRUE);
				alter_debug(DEBUG_INC);
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

	if(raw_1) {
		object_1 = string2xml(xml_file_1);

	} else if(use_stdin) {
		fprintf(stderr, "Input first XML fragment:");
		object_1 = stdin2xml();

	} else if(xml_file_1 != NULL) {
		FILE *xml_strm = fopen(xml_file_1, "r");
		if(xml_strm != NULL) {
			crm_debug("Reading: %s", xml_file_1);
			if(strstr(xml_file_1, ".bz2") != NULL) {
				object_1 = file2xml(xml_strm, TRUE);
				
			} else {
				object_1 = file2xml(xml_strm, FALSE);
			}
			fclose(xml_strm);

		} else {
			cl_perror("Couldn't open %s for reading", xml_file_1);
		}
	}
	
	if(raw_2) {
		object_2 = string2xml(xml_file_2);

	} else if(use_stdin) {
		fprintf(stderr, "Input second XML fragment:");
		object_2 = stdin2xml();

	} else if(xml_file_2 != NULL) {
		FILE *xml_strm = fopen(xml_file_2, "r");
		if(xml_strm != NULL) {
			crm_debug("Reading: %s", xml_file_2);
			if(strstr(xml_file_2, ".bz2") != NULL) {
				object_2 = file2xml(xml_strm, TRUE);
				
			} else {
				object_2 = file2xml(xml_strm, FALSE);
			}
			fclose(xml_strm);

		} else {
			cl_perror("Couldn't open %s for reading", xml_file_2);
		}
		
	}
	
	CRM_ASSERT(object_1 != NULL);
	CRM_ASSERT(object_2 != NULL);

	if(apply) {
		if(as_cib == FALSE) {
			apply_xml_diff(object_1, object_2, &output);
		} else {
			apply_cib_diff(object_1, object_2, &output);
		}
		
	} else {
		if(as_cib == FALSE) {
			output = diff_xml_object(object_1, object_2, filter);
		} else {
			output = diff_cib_object(object_1, object_2, filter);
		}
	}
	
	if(output != NULL) {
		char *buffer = dump_xml_formatted(output);
		fprintf(stdout, "%s", crm_str(buffer));
		crm_free(buffer);
	}

	free_xml(object_1);
	free_xml(object_2);
	free_xml(output);
	
	if(apply == FALSE && output != NULL) {
		return 1;
	}
	
	return 0;
	
}


void
usage(const char *cmd, int exit_status)
{
	FILE *stream;

	stream = exit_status != 0 ? stderr : stdout;

	fprintf(stream, "usage: %s [-?V] [oO] [pnN]\n", cmd);

	fprintf(stream, "Options\n");
	fprintf(stream, "\t--%s (-%c)\tthis help message\n", "help", '?');
	fprintf(stream, "\t--%s (-%c) <filename>\t\n", "original", 'o');
	fprintf(stream, "\t--%s (-%c) <filename>\t\n", "new",   'n');
	fprintf(stream, "\t--%s (-%c) <string>\t\n", "original-string",   'O');
	fprintf(stream, "\t--%s (-%c) <string>\t\n", "new-string",       'N');
	fprintf(stream, "\t--%s (-%c) <filename>\tApply a patch to the original XML\n", "patch", 'p');
	fprintf(stream, "\t--%s (-%c)\tCompare/patch the inputs as a CIB\n", "cib",   'c');
	fprintf(stream, "\t--%s (-%c)\tRead the inputs from stdin\n", "stdin", 's');

	fflush(stream);

	exit(exit_status);
}
