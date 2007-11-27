
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

#include <lha_internal.h>
#include <crm/crm.h>

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>

#include <crm/common/xml.h>
#include <crm/common/util.h>
#include <crm/msg_xml.h>
#include <clplumbing/cl_signal.h>

#include <crm/cib.h>
#include <clplumbing/lsb_exitcodes.h>

#define OPTARGS	"V?X:x:pLS:D:"

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif
#include <glib.h>
#include <crm/pengine/status.h>

gboolean USE_LIVE_CIB = FALSE;
char *cib_save = NULL;
void usage(const char *cmd, int exit_status);
extern gboolean stage0(pe_working_set_t *data_set);
extern void cleanup_alloc_calculations(pe_working_set_t *data_set);
extern crm_data_t * do_calculations(
	pe_working_set_t *data_set, crm_data_t *xml_input, ha_time_t *now);
const char *dtd_file = HA_NOARCHDATAHBDIR"/crm.dtd";

int
main(int argc, char **argv)
{
	crm_data_t *cib_object = NULL;
	crm_data_t *status = NULL;
	int argerr = 0;
	int flag;
		
	pe_working_set_t data_set;
	cib_t *	cib_conn = NULL;
	int rc = cib_ok;
	
	gboolean xml_stdin = FALSE;
	const char *xml_file = NULL;
	const char *xml_string = NULL;
	
	g_log_set_handler(NULL,
			  G_LOG_LEVEL_ERROR      | G_LOG_LEVEL_CRITICAL
			  | G_LOG_LEVEL_WARNING  | G_LOG_LEVEL_MESSAGE
			  | G_LOG_LEVEL_INFO     | G_LOG_LEVEL_DEBUG
			  | G_LOG_FLAG_RECURSION | G_LOG_FLAG_FATAL,
			  cl_glib_msg_handler, NULL);

	/* and for good measure... - this enum is a bit field (!) */
	g_log_set_always_fatal((GLogLevelFlags)0); /*value out of range*/

	crm_log_init(basename(argv[0]), LOG_ERR, FALSE, TRUE, 0, NULL);
	CL_SIGNAL(DEBUG_INC, alter_debug);
	CL_SIGNAL(DEBUG_DEC, alter_debug);	
	
	while (1) {
#ifdef HAVE_GETOPT_H
		int option_index = 0;
		static struct option long_options[] = {
			/* Top-level Options */
			{F_CRM_DATA,    1, 0, 'X'},
			{"dtd-file",    1, 0, 'D'},
			{"xml-file",    1, 0, 'x'},
			{"xml-pipe",    0, 0, 'p'},
			{"save-xml",    1, 0, 'S'},
			{"live-check",  0, 0, 'L'},
			{"help", 0, 0, '?'},
      
			{0, 0, 0, 0}
		};
#endif
    
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
				printf("option %s", long_options[option_index].name);
				if (optarg)
					printf(" with arg %s", optarg);
				printf("\n");
    
				break;
#endif
      
			case 'D':
				crm_debug_2("Option %c => %s", flag, optarg);
				dtd_file = optarg;
				break;

			case 'X':
				crm_debug_2("Option %c => %s", flag, optarg);
				xml_string = crm_strdup(optarg);
				break;
			case 'x':
				crm_debug_2("Option %c => %s", flag, optarg);
				xml_file = crm_strdup(optarg);
				break;
			case 'p':
				xml_stdin = TRUE;
				break;
			case 'S':
				cib_save = crm_strdup(optarg);
				break;
			case 'V':
				alter_debug(DEBUG_INC);
				break;
			case 'L':
				USE_LIVE_CIB = TRUE;
				break;
			case '?':
				usage(crm_system_name, LSB_EXIT_GENERIC);
				break;
			default:
				printf("?? getopt returned character code 0%o ??\n", flag);
				++argerr;
				break;
		}
	}
  
	if (optind < argc) {
		printf("non-option ARGV-elements: ");
		while (optind < argc) {
			printf("%s ", argv[optind++]);
		}
		printf("\n");
	}
  
	if (optind > argc) {
		++argerr;
	}
  
	if (argerr) {
		crm_err("%d errors in option parsing", argerr);
		usage(crm_system_name, LSB_EXIT_GENERIC);
	}
  
	crm_info("=#=#=#=#= Getting XML =#=#=#=#=");

	if(USE_LIVE_CIB) {
		cib_conn = cib_new();
		rc = cib_conn->cmds->signon(
			cib_conn, crm_system_name, cib_command_synchronous);
	}
	
	
	if(USE_LIVE_CIB) {
		if(rc == cib_ok) {
			int options = cib_scope_local|cib_sync_call;
			crm_info("Reading XML from: live cluster");
			rc = cib_conn->cmds->query(
 				cib_conn, NULL, &cib_object, options);
		}

		
		if(rc != cib_ok) {
			fprintf(stderr, "Live CIB query failed: %s\n",
				cib_error2string(rc));
			return 3;
		}
		if(cib_object == NULL) {
			fprintf(stderr, "Live CIB query failed: empty result\n");
			return 3;
		}
	
	} else if(xml_file != NULL) {
		FILE *xml_strm = fopen(xml_file, "r");
		cib_object = file2xml(xml_strm, FALSE);
		if(cib_object == NULL) {
			fprintf(stderr,
				"Couldn't parse input file: %s\n", xml_file);
			return 1;
		}
		fclose(xml_strm);
		
	} else if(xml_string != NULL) {
		cib_object = string2xml(xml_string);
		if(cib_object == NULL) {
			fprintf(stderr,
				"Couldn't parse input string: %s\n", xml_string);
			return 1;
		}
	} else if(xml_stdin) {
		cib_object = stdin2xml();
		if(cib_object == NULL) {
			fprintf(stderr, "Couldn't parse input from STDIN.\n");
			return 1;
		}

	} else {
		fprintf(stderr, "No configuration source specified."
			"  Use --help for usage information.\n");
		return 3;
	}
	
	if(cib_save != NULL) {
		write_xml_file(cib_object, cib_save, FALSE);
	}
	
	status = get_object_root(XML_CIB_TAG_STATUS, cib_object);
	if(status == NULL) {
		create_xml_node(cib_object, XML_CIB_TAG_STATUS);
	}
	
#if CRM_DEPRECATED_SINCE_2_0_4
	xml_child_iter_filter(status, node_state, XML_CIB_TAG_STATE,
		       xml_remove_prop(node_state, XML_CIB_TAG_LRM);
		);
#endif

	crm_notice("Required feature set: %s", feature_set(cib_object));
 	if(do_id_check(cib_object, NULL, FALSE, FALSE)) {
		crm_config_err("ID Check failed");
	}

	if(validate_with_dtd(cib_object, FALSE, dtd_file) == FALSE) {
		crm_config_err("CIB did not pass DTD validation");
	}

	if(USE_LIVE_CIB) {
	    /* we will always have a status section and can do a full simulation */
	    do_calculations(&data_set, cib_object, NULL);

	} else {
	    set_working_set_defaults(&data_set);
	    data_set.now = new_ha_date(TRUE);
	    data_set.input = cib_object;
	    stage0(&data_set);
	}
	
	cleanup_alloc_calculations(&data_set);

	if(crm_config_error) {
		fprintf(stderr, "Errors found during check: config not valid\n");
		if(crm_log_level < LOG_WARNING) {
			fprintf(stderr, "  -V may provide more details\n");
		}
		rc = 2;
		
	} else if(crm_config_warning) {
		fprintf(stderr, "Warnings found during check: config may not be valid\n");
		if(crm_log_level < LOG_WARNING) {
			fprintf(stderr, "  Use -V for more details\n");
		}
		rc = 1;
	}
	
	if(USE_LIVE_CIB) {
		cib_conn->cmds->signoff(cib_conn);
		cib_delete(cib_conn);
	}	

	return rc;
}


void
usage(const char *cmd, int exit_status)
{
	FILE *stream;

	stream = exit_status ? stderr : stdout;
	fprintf(stream, "usage: %s [-V] [-D] -(?|L|X|x|p)\n", cmd);

	fprintf(stream, "\t--%s (-%c)\t: this help message\n", "help", '?');
	fprintf(stream, "\t--%s (-%c)\t: "
		"turn on debug info. additional instances increase verbosity\n",
		"verbose", 'V');
	fprintf(stream, "\t--%s (-%c)\t: Connect to the running cluster\n",
		"live-check", 'L');
	fprintf(stream, "\t--%s (-%c) <string>\t: Use the configuration in the supplied string\n",
		F_CRM_DATA, 'X');
	fprintf(stream, "\t--%s (-%c) <file>\t: Use the configuration in the named file\n",
		"xml-file", 'x');
	fprintf(stream, "\t--%s (-%c) \t: Use the configuration piped in via stdin\n",
		"xml-pipe", 'p');
	fprintf(stream, "\t--%s (-%c) \t: Use the named dtd file instead of %s\n",
		"dtd-file", 'D', dtd_file);
	fflush(stream);

	exit(exit_status);
}
