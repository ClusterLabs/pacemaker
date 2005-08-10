/* $Id: ptest.c,v 1.60 2005/08/10 12:14:26 andrew Exp $ */

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

#include <crm/common/xml.h>
#include <crm/common/util.h>
#include <crm/msg_xml.h>

#include <crm/cib.h>

#define OPTARGS	"V?X:wD:"

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif
#include <glib.h>
#include <pengine.h>
#include <pe_utils.h>

gboolean inhibit_exit = FALSE;
extern crm_data_t * do_calculations(
	pe_working_set_t *data_set, crm_data_t *xml_input);
extern void cleanup_calculations(pe_working_set_t *data_set);

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
	dot_write("digraph \"g\" {");
	dot_write("	size = \"30,30\"");
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

int
main(int argc, char **argv)
{
	gboolean optional = FALSE;
	pe_working_set_t data_set;
	crm_data_t * cib_object = NULL;
	int argerr = 0;
	int flag;
		
	char *msg_buffer = NULL;

	const char *xml_file = NULL;
	const char *dot_file = NULL;
	
	cl_log_set_entity("ptest");
	cl_log_set_facility(LOG_USER);
	set_crm_log_level(LOG_CRIT-1);
	
	while (1) {
#ifdef HAVE_GETOPT_H
		int option_index = 0;
		static struct option long_options[] = {
			/* Top-level Options */
			{F_CRM_DATA,  1, 0, 'X'},
			{"help", 0, 0, 0},
      
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
      
			case 'w':
				inhibit_exit = TRUE;
				break;
			case 'X':
				xml_file = crm_strdup(optarg);
				break;
			case 'D':
				dot_file = crm_strdup(optarg);
				break;
			case 'V':
				cl_log_enable_stderr(TRUE);
				alter_debug(DEBUG_INC);
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
	}
  
	crm_info("=#=#=#=#= Getting XML =#=#=#=#=");
  
	
	if(xml_file != NULL) {
		FILE *xml_strm = fopen(xml_file, "r");
		cib_object = file2xml(xml_strm);
	} else {
		cib_object = stdin2xml();
	}

#ifdef MCHECK
	mtrace();
#endif
 	CRM_DEV_ASSERT(cib_object != NULL);
	crm_zero_mem_stats(NULL);
	
	do_calculations(&data_set, cib_object);

	msg_buffer = dump_xml_formatted(data_set.graph);
	fprintf(stdout, "%s\n", msg_buffer);
	fflush(stdout);
	crm_free(msg_buffer);

	dot_strm = fopen(dot_file, "w");
	
	init_dotfile();
	slist_iter(
		action, action_t, data_set.actions, lpc,
		if(action->dumped == FALSE) {
			if(action->optional) {
				dot_write("\"%s\" [ style=\"dashed\" color=\"%s\" fontcolor=\"%s\" ]",
					  action->uuid, "blue",
					  action->pseudo?"orange":"black");
			} else {
				CRM_DEV_ASSERT(action->runnable == FALSE);
				dot_write("\"%s\" [ font_color=purple style=filled fillcolor=%s ]",
					  action->uuid, "red");
			}
			
		} else {
			dot_write("\"%s\" [ tooltip=\"%s\" style=bold color=\"%s\" fontcolor=\"%s\" ]",
				  action->uuid,
				  action->pseudo?"":action->node?action->node->details->uname:"<none>",
				  "green",
				  action->pseudo?"orange":"black");
		}
		);


	slist_iter(
		action, action_t, data_set.actions, lpc,
		int last_action = -1;
		slist_iter(
			before, action_wrapper_t, action->actions_before, lpc2,
			optional = FALSE;
			if(last_action == before->action->id) {
				continue;
			}
			last_action = before->action->id;
			if(action->dumped && before->action->dumped) {
			} else if(action->optional || before->action->optional) {
				optional = TRUE;
			}
			dot_write("\"%s\" -> \"%s\" [ style = %s]",
				  before->action->uuid, action->uuid,
				  optional?"dashed":"bold");
			);
		);
	dot_write("}");

	cleanup_calculations(&data_set);

	crm_mem_stats(NULL);
 	CRM_DEV_ASSERT(crm_mem_stats(NULL) == FALSE);
	

#ifdef MCHECK
	muntrace();
#endif
	
	free_xml(cib_object);

	/* required for MallocDebug.app */
	if(inhibit_exit) {
		GMainLoop*  mainloop = g_main_new(FALSE);
		g_main_run(mainloop);		
	}
	
	return 0;
}
