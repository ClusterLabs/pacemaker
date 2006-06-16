/* $Id: crm_verify.c,v 1.14 2006/06/16 10:00:17 andrew Exp $ */

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

#define OPTARGS	"V?X:LS:"

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif
#include <glib.h>
#include <crm/pengine/status.h>

gboolean USE_LIVE_CIB = FALSE;
char *cib_save = NULL;
const char *crm_system_name = NULL;
void usage(const char *cmd, int exit_status);
extern gboolean stage0(pe_working_set_t *data_set);
void cleanup_alloc_calculations(pe_working_set_t *data_set);

int
main(int argc, char **argv)
{
	crm_data_t *cib_object = NULL;
	crm_data_t *status = NULL;
	int argerr = 0;
	int flag;
		
	pe_working_set_t data_set;
	cib_t *	cib_conn = NULL;
	enum cib_errors rc = cib_ok;
	
	const char *xml_file = NULL;
	crm_system_name = basename(argv[0]);
	
	g_log_set_handler(NULL,
			  G_LOG_LEVEL_ERROR      | G_LOG_LEVEL_CRITICAL
			  | G_LOG_LEVEL_WARNING  | G_LOG_LEVEL_MESSAGE
			  | G_LOG_LEVEL_INFO     | G_LOG_LEVEL_DEBUG
			  | G_LOG_FLAG_RECURSION | G_LOG_FLAG_FATAL,
			  cl_glib_msg_handler, NULL);

	/* and for good measure... - this enum is a bit field (!) */
	g_log_set_always_fatal((GLogLevelFlags)0); /*value out of range*/
	
	cl_log_set_entity(crm_system_name);
	cl_log_set_facility(LOG_LOCAL7);
	cl_log_enable_stderr(TRUE);
	set_crm_log_level(LOG_ERR);
	
	CL_SIGNAL(DEBUG_INC, alter_debug);
	CL_SIGNAL(DEBUG_DEC, alter_debug);
	
	while (1) {
#ifdef HAVE_GETOPT_H
		int option_index = 0;
		static struct option long_options[] = {
			/* Top-level Options */
			{"xml-file",    1, 0, 'X'},
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
      
			case 'X':
				xml_file = crm_strdup(optarg);
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
	
	crm_zero_mem_stats(NULL);
	
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
		crm_info("Reading XML from: %s", xml_file);
		cib_object = file2xml(xml_strm);
	} else {
		fprintf(stderr, "Reading XML from: stdin\n");
		cib_object = stdin2xml();
	}

 	CRM_CHECK(cib_object != NULL,
		  fprintf(stderr, "No config supplied\n");
		  return 3;
		);

	if(cib_save != NULL) {
		write_xml_file(cib_object, cib_save, FALSE);
	}
	
	status = get_object_root(XML_CIB_TAG_STATUS, cib_object);
#if CRM_DEPRECATED_SINCE_2_0_4
	xml_child_iter_filter(status, node_state, XML_CIB_TAG_STATE,
		       xml_remove_prop(node_state, XML_CIB_TAG_LRM);
		);
#endif
	crm_notice("Required feature set: %s", feature_set(cib_object));
 	if(do_id_check(cib_object, NULL, FALSE, FALSE)) {
		pe_config_err("ID Check failed");
	}

	if(validate_with_dtd(cib_object, HA_LIBDIR"/heartbeat/crm.dtd") == FALSE) {
		pe_config_err("CIB did not pass DTD validation");
	}
	set_working_set_defaults(&data_set);
	data_set.input = cib_object;
	data_set.now = new_ha_date(TRUE);
	stage0(&data_set);
	
	cleanup_alloc_calculations(&data_set);

	if(USE_LIVE_CIB) {
		/* Calling msg2ipcchan() seems to initialize something
		 *   which isn't free'd when we disconnect and free the
		 *   CIB connection.
		 * Fake this extra free and move along.
		 */
		volatile cl_mem_stats_t *active_stats = cl_malloc_getstats();
		active_stats->numfree++;
	}
	
 	CRM_CHECK(crm_mem_stats(NULL) == FALSE, ; );
	
	if(was_config_error) {
		fprintf(stderr, "Errors found during check: config not valid\n");
		if(crm_log_level < LOG_WARNING) {
			fprintf(stderr, "  -V may provide more details\n");
		}
		return 2;
		
	} else if(was_config_warning) {
		fprintf(stderr, "Warnings found during check: config may not be valid\n");
		if(crm_log_level < LOG_WARNING) {
			fprintf(stderr, "  Use -V for more details\n");
		}
		return 1;
	}
	
	if(USE_LIVE_CIB) {
		cib_conn->cmds->signoff(cib_conn);
		cib_delete(cib_conn);
	}	

	return 0;
}


void
usage(const char *cmd, int exit_status)
{
	FILE *stream;

	stream = exit_status ? stderr : stdout;
	fprintf(stream, "usage: %s [-V] -(?|L|X)\n", cmd);

	fprintf(stream, "\t--%s (-%c)\t: this help message\n", "help", '?');
	fprintf(stream, "\t--%s (-%c)\t: "
		"turn on debug info. additional instances increase verbosity\n",
		"verbose", 'V');
	fprintf(stream, "\t--%s (-%c)\t: Connect to the running cluster\n",
		"live-check", 'L');
	fprintf(stream, "\t--%s (-%c) <string>\t: Use the configuration in the named file\n",
		"xml-file", 'X');
	fflush(stream);

	exit(exit_status);
}
