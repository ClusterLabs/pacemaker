/* $Id: ptest.c,v 1.4 2004/04/27 21:40:10 andrew Exp $ */

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

#include <hb_api.h>
#include <apphb.h>

#include <clplumbing/ipc.h>
#include <clplumbing/Gmain_timeout.h>
#include <clplumbing/cl_log.h>
#include <clplumbing/cl_signal.h>
#include <clplumbing/lsb_exitcodes.h>
#include <clplumbing/uids.h>
#include <clplumbing/realtime.h>
#include <clplumbing/GSource.h>
#include <clplumbing/cl_poll.h>

#include <crm/common/xmlutils.h>
#include <crm/msg_xml.h>

#include <crm/cib.h>

#define OPTARGS	"V?i:o:D:C:S:HA:U:M:I:EWRFt:m:a:d:w:c:r:p:s:"

#include <getopt.h>
#include <glib.h>
#include <pengine.h>

int
main(int argc, char **argv)
{
	xmlNodePtr cib_object = NULL;
	int lpc = 0;
	int argerr = 0;
	int flag;
  
	cl_log_set_entity("ptest");
	cl_log_enable_stderr(TRUE);
	cl_log_set_facility(LOG_USER);

	xmlInitParser();
 
	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
			// Top-level Options
			{"daemon", 0, 0, 0},
      
			{0, 0, 0, 0}
		};
    
		flag = getopt_long(argc, argv, OPTARGS,
				   long_options, &option_index);
		if (flag == -1)
			break;
    
		switch(flag) {
			case 0:
				printf("option %s", long_options[option_index].name);
				if (optarg)
					printf(" with arg %s", optarg);
				printf("\n");
    
				break;
      
				/* a sample test for multiple instance
				   if (digit_optind != 0 && digit_optind != this_option_optind)
				   printf ("digits occur in two different argv-elements.\n");
				   digit_optind = this_option_optind;
				   printf ("option %c\n", c);
				*/
      
			case 'V':
				printf("option %d", flag);
				break;
			default:
				printf("?? getopt returned character code 0%o ??\n", flag);
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
		cl_log(LOG_ERR, "%d errors in option parsing", argerr);
	}
  
	cl_log(LOG_INFO, "=#=#=#=#= Getting XML =#=#=#=#=");
  
	cib_object = file2xml(stdin);
  
	cl_log(LOG_INFO, "=#=#=#=#= Stage 0 =#=#=#=#=");
	stage0(cib_object);

	cl_log(LOG_INFO, "========= Nodes =========");
	slist_iter(node, node_t, node_list, lpc,
		   print_node(NULL, node));

	cl_log(LOG_INFO, "========= Resources =========");
	slist_iter(resource, resource_t, rsc_list, lpc,
		   print_resource(NULL, resource, FALSE));
    

	cl_log(LOG_INFO, "========= Constraints =========");
	slist_iter(constraint, rsc_constraint_t, cons_list, lpc,
		   print_cons(NULL, constraint, FALSE));
    
	cl_log(LOG_INFO, "=#=#=#=#= Stage 1 =#=#=#=#=");
	stage1(node_list);

	cl_log(LOG_INFO, "========= Nodes =========");
	slist_iter(node, node_t, node_list, lpc,
		   print_node(NULL, node));

	cl_log(LOG_INFO, "========= Resources =========");
	slist_iter(resource, resource_t, rsc_list, lpc,
		   print_resource(NULL, resource, TRUE));

	cl_log(LOG_INFO, "=#=#=#=#= Stage 2 =#=#=#=#=");
	stage2(rsc_list, node_list, NULL);

	cl_log(LOG_INFO, "========= Nodes =========");
	slist_iter(node, node_t, node_list, lpc,
		   print_node(NULL, node));

	cl_log(LOG_INFO, "========= Resources =========");
	slist_iter(resource, resource_t, rsc_list, lpc,
		   print_resource(NULL, resource, TRUE));  
  
	cl_log(LOG_INFO, "========= Colors =========");
	slist_iter(color, color_t, colors, lpc,
		   print_color(NULL, color, FALSE));
  
	cl_log(LOG_INFO, "========= Stonith List =========");
	slist_iter(node, node_t, stonith_list, lpc,
		   print_node(NULL, node));
  
	cl_log(LOG_INFO, "=#=#=#=#= Stage 3 =#=#=#=#=");
	stage3(colors);
	cl_log(LOG_INFO, "========= Colors =========");
	slist_iter(color, color_t, colors, lpc,
		   print_color(NULL, color, FALSE));

	cl_log(LOG_INFO, "=#=#=#=#= Stage 4 =#=#=#=#=");
	stage4(colors);
	cl_log(LOG_INFO, "========= Colors =========");
	slist_iter(color, color_t, colors, lpc,
		   print_color(NULL, color, FALSE));

	cl_log(LOG_INFO, "=#=#=#=#= Stage 5 =#=#=#=#=");
	stage5(rsc_list);

	return 0;
}
					 
const char *
contype2text(enum con_type type)
{
	const char *result = "<unknown>";
	switch(type)
	{
		case none:
			result = "none";
			break;
		case rsc_to_rsc:
			result = "rsc_to_rsc";
			break;
		case rsc_to_node:
			result = "rsc_to_node";
			break;
		case rsc_to_attr:
			result = "rsc_to_attr";
			break;
		case base_weight:
			result = "base_weight";
			break;
	}
	return result;
};

const char *
strength2text(enum con_strength strength)
{
	const char *result = "<unknown>";
	switch(strength)
	{
		case must:
			result = "must";
			break;
		case should:
			result = "should";
			break;
		case should_not:
			result = "should_not";
			break;
		case must_not:
			result = "must_not";
			break;
	}
	return result;
};

const char *
modifier2text(enum con_modifier modifier)
{
	const char *result = "<unknown>";
	switch(modifier)
	{
		case modifier_none:
			result = "modifier_none";
			break;
		case set:
			result = "set";
			break;
		case inc:
			result = "inc";
			break;
		case dec: 
			result = "dec";
			break;
	}
	return result;
};

void
print_node(const char *pre_text, node_t *node)
{ 
	if(node == NULL) {
		cl_log(LOG_DEBUG, "%s: <NULL>", __FUNCTION__);
		return;
	}
	cl_log(LOG_DEBUG, "%s Node %s: (weight=%f, fixed=%s)",
	       pre_text==NULL?"":pre_text,
	       node->id, 
	       node->weight,
	       node->fixed?"True":"False"); 
}; 
 
void
print_color_details(const char *pre_text, struct color_shared_s *color, gboolean details)
{ 
	if(color == NULL) {
		cl_log(LOG_DEBUG, "%s %s: <NULL>",
		       pre_text==NULL?"":pre_text,
		       __FUNCTION__);
		return;
	}
	cl_log(LOG_DEBUG, "%s Color %d: node=%s (from %d candidates)",
	       pre_text==NULL?"":pre_text,
	       color->id, 
	       color->chosen_node->id,
	       g_slist_length(color->candidate_nodes)); 
	if(details) {
		int lpc = 0;
		slist_iter(node, node_t, color->candidate_nodes, lpc,
			   print_node("\t", node));
	}
}

void
print_color(const char *pre_text, color_t *color, gboolean details)
{ 
	if(color == NULL) {
		cl_log(LOG_DEBUG, "%s %s: <NULL>",
		       pre_text==NULL?"":pre_text,
		       __FUNCTION__);
		return;
	}
	cl_log(LOG_DEBUG, "%s Color %d: (weight=%f, node=%s, possible=%d)",
	       pre_text==NULL?"":pre_text,
	       color->id, 
	       color->local_weight,
	       color->details->chosen_node==NULL?"<unset>":color->details->chosen_node->id,
	       g_slist_length(color->details->candidate_nodes)); 
	if(details) {
		print_color_details("\t", color->details, details);
	}
}
void
print_cons(const char *pre_text, rsc_constraint_t *cons, gboolean details)
{ 
	if(cons == NULL) {
		cl_log(LOG_DEBUG, "%s %s: <NULL>",
		       pre_text==NULL?"":pre_text,
		       __FUNCTION__);
		return;
	}
	cl_log(LOG_DEBUG, "%s %s Constraint %s (%p):",
	       pre_text==NULL?"":pre_text,
	       contype2text(cons->type), cons->id, cons);

	if(details == FALSE) {

		switch(cons->type)
		{
			case none:
				cl_log(LOG_ERR, "must specify a type");
				break;
			case rsc_to_rsc:
				cl_log(LOG_DEBUG,
				       "\t%s --> %s, %s (%s rule)",
				       cons->rsc_lh==NULL?"null":cons->rsc_lh->id, 
				       cons->rsc_rh==NULL?"null":cons->rsc_rh->id, 
				       strength2text(cons->strength),
				       cons->is_placement?"placement":"ordering");
				break;
			case rsc_to_node:
			case rsc_to_attr:
				cl_log(LOG_DEBUG,
				       "\t%s --> %s, %f (node placement rule)",
				       cons->rsc_lh->id, 
				       modifier2text(cons->modifier),
				       cons->weight);
				int lpc = 0;
				slist_iter(
					node, node_t, cons->node_list_rh, lpc,
					print_node("\t\t-->", node)
					);
				break;
			case base_weight:
				cl_log(LOG_ERR, "not supported");
				break;
		}
	}
}; 

void
print_resource(const char *pre_text, resource_t *rsc, gboolean details)
{ 
	if(rsc == NULL) {
		cl_log(LOG_DEBUG, "%s %s: <NULL>",
		       pre_text==NULL?"":pre_text,
		       __FUNCTION__);
		return;
	}
	cl_log(LOG_DEBUG, "%s %sResource %s: (priority=%f, color=%d, now=%s)",
	       pre_text==NULL?"":pre_text,
	       rsc->provisional?"Provisional ":"",
	       rsc->id,
	       (double)rsc->priority,
	       rsc->color==NULL?-1:rsc->color->id,
	       rsc->cur_node_id);

	cl_log(LOG_DEBUG,
	       "\t%d candidate colors, %d allowed nodes and %d constraints",
	       g_slist_length(rsc->candidate_colors),
	       g_slist_length(rsc->allowed_nodes),
	       g_slist_length(rsc->constraints));

	if(details) {
		int lpc = 0;
		slist_iter(
			color, color_t, rsc->candidate_colors, lpc,
			print_color("\t", color, FALSE)
			);
	}
} 


