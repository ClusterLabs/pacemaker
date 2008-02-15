
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
#include <crm/crm.h>

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <crm/transition.h>
#include <crm/common/xml.h>
#include <crm/common/util.h>
#include <crm/msg_xml.h>

#include <crm/cib.h>

#define OPTARGS	"V?X:D:G:I:Lwxd:aS"

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif
#include <glib.h>
#include <pengine.h>
#include <lib/crm/pengine/utils.h>
#include <allocate.h>
#if HAVE_LIBXML2
#  include <libxml/parser.h>
#endif

gboolean use_stdin = FALSE;
gboolean do_simulation = FALSE;
gboolean inhibit_exit = FALSE;
gboolean all_actions = FALSE;
extern xmlNode * do_calculations(
	pe_working_set_t *data_set, xmlNode *xml_input, ha_time_t *now);
extern void cleanup_calculations(pe_working_set_t *data_set);
char *use_date = NULL;

FILE *dot_strm = NULL;
#define DOT_PREFIX "PE_DOT: "
/* #define DOT_PREFIX "" */

#define dot_write(fmt...) if(dot_strm != NULL) {	\
		fprintf(dot_strm, fmt);			\
		fprintf(dot_strm, "\n");		\
	} else {					\
		crm_debug(DOT_PREFIX""fmt);		\
	}

static void
init_dotfile(void)
{
	dot_write(" digraph \"g\" {");
/* 	dot_write("	size = \"30,30\""); */
/* 	dot_write("	graph ["); */
/* 	dot_write("		fontsize = \"12\""); */
/* 	dot_write("		fontname = \"Times-Roman\""); */
/* 	dot_write("		fontcolor = \"black\""); */
/* 	dot_write("		bb = \"0,0,398.922306,478.927856\""); */
/* 	dot_write("		color = \"black\""); */
/* 	dot_write("	]"); */
/* 	dot_write("	node ["); */
/* 	dot_write("		fontsize = \"12\""); */
/* 	dot_write("		fontname = \"Times-Roman\""); */
/* 	dot_write("		fontcolor = \"black\""); */
/* 	dot_write("		shape = \"ellipse\""); */
/* 	dot_write("		color = \"black\""); */
/* 	dot_write("	]"); */
/* 	dot_write("	edge ["); */
/* 	dot_write("		fontsize = \"12\""); */
/* 	dot_write("		fontname = \"Times-Roman\""); */
/* 	dot_write("		fontcolor = \"black\""); */
/* 	dot_write("		color = \"black\""); */
/* 	dot_write("	]"); */
}

static void
usage(const char *cli, int exitcode)
{
	FILE *out = exitcode?stderr:stdout;
	fprintf(out, "Usage: %s -(?|L|X|x) [-V] [-D] [-G] [-I]\n", cli);
	fprintf(out, "    --%s (-%c): This text\n\n", "help", '?');
	fprintf(out, "    --%s (-%c): Increase verbosity (can be supplied multiple times)\n\n", "verbose", 'V');
	fprintf(out, "    --%s (-%c): Connect to the CIB and use the current contents as input\n", "live-check", 'L');
	fprintf(out, "    --%s (-%c): Look for xml on stdin\n", "xml-stream", 'x');
	fprintf(out, "    --%s (-%c)\t<filename> : Look for xml in the named file\n\n", "xml-file", 'X');

	fprintf(out, "    --%s (-%c)\t<filename> : Save the transition graph to the named file\n", "save-graph",   'G');
	fprintf(out, "    --%s (-%c)\t<filename> : Save the DOT formatted transition graph to the named file\n", "save-dotfile", 'D');
	fprintf(out, "    --%s (-%c)\t<filename> : Save the input to the named file\n", "save-input",   'I');
	exit(exitcode);
}

static char *
create_action_name(action_t *action) 
{
	char *action_name = NULL;
	const char *action_host = NULL;
	if(action->node) {
		action_host = action->node->details->uname;
		action_name = crm_concat(action->uuid, action_host, ' ');

	} else if(action->pseudo) {
		action_name = crm_strdup(action->uuid);
		
	} else {
		action_host = "<none>";
		action_name = crm_concat(action->uuid, action_host, ' ');
	}
	return action_name;
}

gboolean USE_LIVE_CIB = FALSE;

int
main(int argc, char **argv)
{
	gboolean all_good = TRUE;
	enum transition_status graph_rc = -1;
	crm_graph_t *transition = NULL;
	ha_time_t *a_date = NULL;
	cib_t *	cib_conn = NULL;
	
	xmlNode * cib_object = NULL;
	int argerr = 0;
	int flag;
		
	char *msg_buffer = NULL;
	gboolean optional = FALSE;
	pe_working_set_t data_set;
	
	const char *source = NULL;
	const char *xml_file = NULL;
	const char *dot_file = NULL;
	const char *graph_file = NULL;
	const char *input_file = NULL;
	
	cl_log_set_entity("ptest");
	cl_log_set_facility(LOG_USER);
	set_crm_log_level(LOG_CRIT-1);
	
	while (1) {
#ifdef HAVE_GETOPT_H
		int option_index = 0;
		static struct option long_options[] = {
			/* Top-level Options */
			{"help",        0, 0, '?'},
			{"verbose",     0, 0, 'V'},			

			{"live-check",  0, 0, 'L'},
			{"xml-stream",  0, 0, 'x'},
			{"xml-file",    1, 0, 'X'},

			{"simulate",    0, 0, 'S'},
			{"save-graph",  1, 0, 'G'},
			{"save-dotfile",1, 0, 'D'},
			{"save-input",  1, 0, 'I'},

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
			case 'S':
				do_simulation = TRUE;
				break;
			case 'a':
				all_actions = TRUE;
				break;
			case 'w':
				inhibit_exit = TRUE;
				break;
			case 'x':
				use_stdin = TRUE;
				break;
			case 'X':
				xml_file = optarg;
				break;
			case 'd':
				use_date = optarg;
				break;
			case 'D':
				dot_file = optarg;
				break;
			case 'G':
				graph_file = optarg;
				break;
			case 'I':
				input_file = optarg;
				break;
			case 'V':
				cl_log_enable_stderr(TRUE);
				alter_debug(DEBUG_INC);
				break;
			case 'L':
				USE_LIVE_CIB = TRUE;
				break;
			case '?':
				usage("ptest", 0);
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
		usage("ptest", 1);
	}
  
	crm_info("=#=#=#=#= Getting XML =#=#=#=#=");	

	if(USE_LIVE_CIB) {
		int rc = cib_ok;
		source = "live cib";
		cib_conn = cib_new();
		rc = cib_conn->cmds->signon(
			cib_conn, "ptest", cib_command_synchronous);

		if(rc == cib_ok) {
			crm_info("Reading XML from: live cluster");
			cib_object = get_cib_copy(cib_conn);
			
		} else {
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
		source = xml_file;
		if(xml_strm == NULL) {
			cl_perror("Could not open %s for reading", xml_file);
			
		} else {
			if(strstr(xml_file, ".bz2") != NULL) {
				cib_object = file2xml(xml_strm, TRUE);
				
			} else {
				cib_object = file2xml(xml_strm, FALSE);
			}
			fclose(xml_strm);
		}
		
	} else if(use_stdin) {
		source = "stdin";
		cib_object = stdin2xml();
	}

 	if(cib_object == NULL && source) {
	    fprintf(stderr, "Could not parse configuration input from: %s\n", source);
	    return 4;

 	} else if(cib_object == NULL) {
	    fprintf(stderr, "Not configuration specified\n");
	    usage("ptest", 1);
	}
	
	crm_notice("Required feature set: %s", feature_set(cib_object));
 	do_id_check(cib_object, NULL, FALSE, FALSE);
	if(!validate_with_dtd(cib_object,FALSE,DTD_DIRECTORY"/crm.dtd")) {
		crm_crit("%s does not contain a valid configuration", xml_file?xml_file:"<stdin>");
 		all_good = FALSE;
	}
	
	if(input_file != NULL) {
		FILE *input_strm = fopen(input_file, "w");
		if(input_strm == NULL) {
			cl_perror("Could not open %s for writing", input_file);
		} else {
			msg_buffer = dump_xml_formatted(cib_object);
			if(fprintf(input_strm, "%s\n", msg_buffer) < 0) {
				cl_perror("Write to %s failed", input_file);
			}
			fflush(input_strm);
			fclose(input_strm);
			crm_free(msg_buffer);
		}
	}
	
	if(use_date != NULL) {
		a_date = parse_date(&use_date);
		log_date(LOG_WARNING, "Set fake 'now' to",
			 a_date, ha_log_date|ha_log_time);
		log_date(LOG_WARNING, "Set fake 'now' to (localtime)",
			 a_date, ha_log_date|ha_log_time|ha_log_local);
	}

	do_calculations(&data_set, cib_object, a_date);

	msg_buffer = dump_xml_formatted(data_set.graph);
	if(safe_str_eq(graph_file, "-")) {
		fprintf(stdout, "%s\n", msg_buffer);
		fflush(stdout);
	} else if(graph_file != NULL) {
		FILE *graph_strm = fopen(graph_file, "w");
		if(graph_strm == NULL) {
			cl_perror("Could not open %s for writing", graph_file);
		} else {
			if(fprintf(graph_strm, "%s\n", msg_buffer) < 0) {
				cl_perror("Write to %s failed", graph_file);
			}
			fflush(graph_strm);
			fclose(graph_strm);
		}
	}
	crm_free(msg_buffer);

	if(dot_file != NULL) {
		dot_strm = fopen(dot_file, "w");
		if(dot_strm == NULL) {
			cl_perror("Could not open %s for writing", dot_file);
		}
	}

	if(dot_strm == NULL) {
	    goto simulate;
	}
	
	init_dotfile();
	slist_iter(
		action, action_t, data_set.actions, lpc,

		const char *style = "filled";
		const char *font  = "black";
		const char *color = "black";
		const char *fill  = NULL;
		char *action_name = create_action_name(action);
		crm_debug_3("Action %d: %p", action->id, action);

		if(action->pseudo) {
			font = "orange";
		}
		
		style = "dashed";
		if(action->dumped) {
			style = "bold";
			color = "green";
			
		} else if(action->rsc != NULL
			  && is_not_set(action->rsc->flags, pe_rsc_managed)) {
			color = "purple";
			if(all_actions == FALSE) {
				goto dont_write;
			}			
			
		} else if(action->optional) {
			color = "blue";
			if(all_actions == FALSE) {
				goto dont_write;
			}			
				
		} else {
			color = "red";
			CRM_CHECK(action->runnable == FALSE, ;);	
		}

		action->dumped = TRUE;
		dot_write("\"%s\" [ style=%s color=\"%s\" fontcolor=\"%s\"  %s%s]",
			  action_name, style, color, font, fill?"fillcolor=":"", fill?fill:"");
	  dont_write:
		crm_free(action_name);
		);


	slist_iter(
		action, action_t, data_set.actions, lpc,
		slist_iter(
			before, action_wrapper_t, action->actions_before, lpc2,
			char *before_name = NULL;
			char *after_name = NULL;
			const char *style = "dashed";
			optional = TRUE;
			if(before->state == pe_link_dumped) {
			    optional = FALSE;
			    style = "bold";
			} else if(action->pseudo
				  && (before->type & pe_order_stonith_stop)) {
			    continue;
			} else if(before->state == pe_link_dup) {
			    continue;
			} else if(action->dumped && before->action->dumped) {
			    optional = FALSE;
			}

			if(all_actions || optional == FALSE) {
			    before_name = create_action_name(before->action);
			    after_name = create_action_name(action);
			    dot_write("\"%s\" -> \"%s\" [ style = %s]",
				      before_name, after_name, style);
			    crm_free(before_name);
			    crm_free(after_name);
			}
			);
		);
	dot_write("}");
	if(dot_strm != NULL) {
		fflush(dot_strm);
		fclose(dot_strm);
	}

  simulate:
	
	if(do_simulation == FALSE) {
	    goto cleanup;
	}
	
	transition = unpack_graph(data_set.graph);
	transition->batch_limit = 0;
	
	print_graph(LOG_DEBUG, transition);
	do {
		graph_rc = run_graph(transition);
		
	} while(graph_rc == transition_active);

	if(graph_rc != transition_complete) {
		crm_crit("Transition failed: %s", transition_status(graph_rc));
		print_graph(LOG_ERR, transition);
	}
	destroy_graph(transition);
	CRM_CHECK(graph_rc == transition_complete, all_good = FALSE; crm_err("An invalid transition was produced"));

  cleanup:
	cleanup_alloc_calculations(&data_set);
	

#if HAVE_LIBXML2
	xmlCleanupParser();
#endif
	
	/* required for MallocDebug.app */
	if(inhibit_exit) {
		GMainLoop*  mainloop = g_main_new(FALSE);
		g_main_run(mainloop);		
	}

	if(all_good) {
		return 0;
	}
	return 5;
}
