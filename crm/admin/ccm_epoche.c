/* $Id: ccm_epoche.c,v 1.1 2005/02/20 14:38:54 andrew Exp $ */
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
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <clplumbing/cl_log.h>
#include <clplumbing/cl_signal.h>
#include <clplumbing/lsb_exitcodes.h>

#include <portability.h>
#include <ocf/oc_event.h>
#include <ocf/oc_membership.h>

#include <crm/crm.h>

#include <crm/dmalloc_wrapper.h>

const char* crm_system_name = "ccm_age";
oc_ev_t *ccm_token = NULL;

#define OPTARGS	"hV"

void oc_ev_special(const oc_ev_t *, oc_ev_class_t , int );

static void ccm_age_callback(
	oc_ed_t event, void *cookie, size_t size, const void *data);
gboolean ccm_age_connect(int *ccm_fd);
void usage(const char* cmd, int exit_status);
char *lookup_host = NULL;

int
main(int argc, char ** argv)
{
	int flag;
	int argerr = 0;
	int ccm_fd = 0;
	fd_set rset;	
	oc_ev_t *ccm_token = NULL;
	
	crm_log_init(crm_system_name);

	while ((flag = getopt(argc, argv, OPTARGS)) != EOF) {
		switch(flag) {
			case 'V':
				cl_log_enable_stderr(TRUE);
				alter_debug(DEBUG_INC);
				break;
			case 'h':		/* Help message */
				usage(crm_system_name, LSB_EXIT_OK);
				break;
			default:
				++argerr;
				break;
		}
	}
    
	if (optind > argc) {
		++argerr;
	}
    
	if (argerr) {
		usage(crm_system_name,LSB_EXIT_GENERIC);
	}

	if(ccm_age_connect(&ccm_fd)) {
		for (;;) {

			FD_ZERO(&rset);
			FD_SET(ccm_fd, &rset);

			if(select(ccm_fd + 1, &rset, NULL,NULL,NULL) == -1){
				perror("select");
				return(1);
			}
			if(oc_ev_handle_event(ccm_token)){
				crm_err("terminating");
				return(1);
			}
		}
	}
	return(1);    
}


void
usage(const char* cmd, int exit_status)
{
	FILE* stream;

	stream = exit_status ? stderr : stdout;

	fprintf(stream, "usage: %s [-V]\n", cmd);
	fflush(stream);

	exit(exit_status);
}

gboolean
ccm_age_connect(int *ccm_fd) 
{
	gboolean did_fail = FALSE;
	int ret = 0;
	
	crm_debug("Registering with CCM");
	ret = oc_ev_register(&ccm_token);
	if (ret != 0) {
		crm_warn("CCM registration failed");
		did_fail = TRUE;
	}
	
	if(did_fail == FALSE) {
		crm_debug("Setting up CCM callbacks");
		ret = oc_ev_set_callback(ccm_token, OC_EV_MEMB_CLASS,
					 ccm_age_callback, NULL);
		if (ret != 0) {
			crm_warn("CCM callback not set");
			did_fail = TRUE;
		}
	}
	if(did_fail == FALSE) {
		oc_ev_special(ccm_token, OC_EV_MEMB_CLASS, 0/*don't care*/);
		
		crm_debug("Activating CCM token");
		ret = oc_ev_activate(ccm_token, ccm_fd);
		if (ret != 0){
			crm_warn("CCM Activation failed");
			did_fail = TRUE;
		}
	}
	
	return !did_fail;
}


static void 
ccm_age_callback(oc_ed_t event, void *cookie, size_t size, const void *data)
{
	int lpc;
	int node_list_size;
	const oc_ev_membership_t *oc = (const oc_ev_membership_t *)data;

	crm_devel("-----------------------");
	crm_devel("trans=%d, nodes=%d, new=%d, lost=%d n_idx=%d, "
		  "new_idx=%d, old_idx=%d",
		  oc->m_instance,
		  oc->m_n_member, oc->m_n_in, oc->m_n_out,
		  oc->m_memb_idx, oc->m_in_idx, oc->m_out_idx);

	if(crm_log_level >= LOG_DEV) {
		node_list_size = oc->m_n_member;
		for(lpc=0; lpc<node_list_size; lpc++) {
			crm_devel("\tCURRENT: %s [nodeid=%d, born=%d]",
				  oc->m_array[oc->m_memb_idx+lpc].node_uname,
				  oc->m_array[oc->m_memb_idx+lpc].node_id,
				  oc->m_array[oc->m_memb_idx+lpc].node_born_on);
		}
	
		for(lpc=0; lpc<oc->m_n_in; lpc++) {
			crm_devel("\tNEW:     %s [nodeid=%d, born=%d]",
				 oc->m_array[oc->m_in_idx+lpc].node_uname,
				 oc->m_array[oc->m_in_idx+lpc].node_id,
				 oc->m_array[oc->m_in_idx+lpc].node_born_on);
		}
		
		for(lpc=0; lpc<oc->m_n_out; lpc++) {
			crm_devel("\tLOST:    %s [nodeid=%d, born=%d]",
				 oc->m_array[oc->m_out_idx+lpc].node_uname,
				 oc->m_array[oc->m_out_idx+lpc].node_id,
				 oc->m_array[oc->m_out_idx+lpc].node_born_on);
		}
	}
	crm_devel("-----------------------");
	
	crm_debug("Searching %d members for our birth", oc->m_n_member);
	for(lpc = 0; lpc < oc->m_n_member; lpc++) {
		if(oc_ev_is_my_nodeid(ccm_token, &(oc->m_array[lpc]))){
			crm_debug("MATCH: nodeid=%d, uname=%s, born=%d",
				  oc->m_array[oc->m_memb_idx+lpc].node_id,
				  oc->m_array[oc->m_memb_idx+lpc].node_uname,
				  oc->m_array[oc->m_memb_idx+lpc].node_born_on);
			fprintf(stdout, "%d\n",
				oc->m_array[oc->m_memb_idx+lpc].node_born_on);
			fflush(stdout);
			exit(0);
		}
	}
	oc_ev_callback_done(cookie);
}
