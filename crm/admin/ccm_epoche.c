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

#include <ocf/oc_event.h>
#include <ocf/oc_membership.h>

#include <crm/crm.h>
#include <crm/ais.h>
#include <crm/common/cluster.h>


oc_ev_t *ccm_token = NULL;
int command = 0;

#define OPTARGS	"hVqep"

void oc_ev_special(const oc_ev_t *, oc_ev_class_t , int );

void ccm_age_callback(
    oc_ed_t event, void *cookie, size_t size, const void *data);
gboolean ccm_age_connect(int *ccm_fd);
void usage(const char* cmd, int exit_status);
char *lookup_host = NULL;

void ais_membership_destroy(gpointer user_data);
gboolean ais_membership_dispatch(AIS_Message *wrapper, char *data, int sender);

int
main(int argc, char ** argv)
{
	int flag;
	int argerr = 0;
	int ccm_fd = 0;
	crm_log_init("ccm_tool", LOG_WARNING, FALSE, FALSE, 0, NULL);

	while ((flag = getopt(argc, argv, OPTARGS)) != EOF) {
		switch(flag) {
			case 'V':
				cl_log_enable_stderr(TRUE);
				alter_debug(DEBUG_INC);
				break;
			case 'h':		/* Help message */
				usage(crm_system_name, LSB_EXIT_OK);
				break;
			case 'p':
			case 'e':		
			case 'q':		
				command = flag;
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

	if(init_ais_connection(
	       ais_membership_dispatch, ais_membership_destroy, NULL)) {

	    GMainLoop*  amainloop = NULL;
	    crm_info("Requesting the list of configured nodes");
	    crm_peer_init();
	    send_ais_text(
		crm_class_members, __FUNCTION__, TRUE, NULL, crm_msg_ais);
	    amainloop = g_main_new(FALSE);
	    g_main_run(amainloop);

	} else if(ccm_age_connect(&ccm_fd)) {
		int rc = 0;
		int lpc = 0;
		fd_set rset;	
		oc_ev_t *ccm_token = NULL;
		for (;;lpc++) {

			FD_ZERO(&rset);
			FD_SET(ccm_fd, &rset);

			rc = select(ccm_fd + 1, &rset, NULL,NULL,NULL);
			if(rc == -1){
				perror("select failed");
				if(errno == EINTR) {
					crm_debug("Retry...");
					continue;
				}
				
			} else if(oc_ev_handle_event(ccm_token) != 0){
				crm_err("oc_ev_handle_event failed");
			}
			return(1);
		}
	}
	
	return(1);    
}


void
usage(const char* cmd, int exit_status)
{
	FILE* stream;

	stream = exit_status ? stderr : stdout;

	fprintf(stream, "usage: %s [-V] [-p|-e|-q]\n", cmd);
	fprintf(stream, "\t-p : print the members of this partition\n");
	fprintf(stream, "\t-e : print the epoch this node joined the partition\n");
	fprintf(stream, "\t-q : print a 1 if our partition has quorum\n");
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


void 
ccm_age_callback(oc_ed_t event, void *cookie, size_t size, const void *data)
{
	int lpc;
	int node_list_size;
	const oc_ev_membership_t *oc = (const oc_ev_membership_t *)data;

	crm_debug_3("-----------------------");
	crm_debug_3("trans=%d, nodes=%d, new=%d, lost=%d n_idx=%d, "
		  "new_idx=%d, old_idx=%d",
		  oc->m_instance,
		  oc->m_n_member, oc->m_n_in, oc->m_n_out,
		  oc->m_memb_idx, oc->m_in_idx, oc->m_out_idx);

	node_list_size = oc->m_n_member;
	if(command == 'q') {
		crm_debug("Processing \"%s\" event.", 
			  event==OC_EV_MS_NEW_MEMBERSHIP?"NEW MEMBERSHIP":
			  event==OC_EV_MS_NOT_PRIMARY?"NOT PRIMARY":
			  event==OC_EV_MS_PRIMARY_RESTORED?"PRIMARY RESTORED":
			  event==OC_EV_MS_EVICTED?"EVICTED":
			  "NO QUORUM MEMBERSHIP");
		if(ccm_have_quorum(event)) {
			fprintf(stdout, "1\n");
		} else {
			fprintf(stdout, "0\n");
		}
		
	} else if(command == 'e') {
		crm_debug("Searching %d members for our birth", oc->m_n_member);
	}
	for(lpc=0; lpc<node_list_size; lpc++) {
		if(command == 'p') {
			fprintf(stdout, "%s ",
				oc->m_array[oc->m_memb_idx+lpc].node_uname);
		} else if(command == 'e') {
			if(oc_ev_is_my_nodeid(ccm_token, &(oc->m_array[lpc]))){
				crm_debug("MATCH: nodeid=%d, uname=%s, born=%d",
					  oc->m_array[oc->m_memb_idx+lpc].node_id,
					  oc->m_array[oc->m_memb_idx+lpc].node_uname,
					  oc->m_array[oc->m_memb_idx+lpc].node_born_on);
				fprintf(stdout, "%d\n",
					oc->m_array[oc->m_memb_idx+lpc].node_born_on);
			}
		}
		crm_debug_3("\tCURRENT: %s [nodeid=%d, born=%d]",
			  oc->m_array[oc->m_memb_idx+lpc].node_uname,
			  oc->m_array[oc->m_memb_idx+lpc].node_id,
			  oc->m_array[oc->m_memb_idx+lpc].node_born_on);
	}
	
	for(lpc=0; lpc < (int)oc->m_n_in; lpc++) {
		crm_debug_3("\tNEW:     %s [nodeid=%d, born=%d]",
			  oc->m_array[oc->m_in_idx+lpc].node_uname,
			  oc->m_array[oc->m_in_idx+lpc].node_id,
			  oc->m_array[oc->m_in_idx+lpc].node_born_on);
	}
	
	for(lpc=0; lpc < (int)oc->m_n_out; lpc++) {
		crm_debug_3("\tLOST:    %s [nodeid=%d, born=%d]",
			  oc->m_array[oc->m_out_idx+lpc].node_uname,
			  oc->m_array[oc->m_out_idx+lpc].node_id,
			  oc->m_array[oc->m_out_idx+lpc].node_born_on);
	}

	crm_debug_3("-----------------------");
	oc_ev_callback_done(cookie);

	if(command == 'p') {
		fprintf(stdout, "\n");
	}
	fflush(stdout);
	exit(0);
}

void
ais_membership_destroy(gpointer user_data)
{
    crm_err("AIS connection terminated");
    ais_fd_sync = -1;
    exit(1);
}

static void crm_print_member(
    gpointer key, gpointer value, gpointer user_data)
{
    crm_node_t *node = value;
    if(crm_is_member_active(node)) {
	fprintf(stdout, "%s ", node->uname);
    }
}

gboolean
ais_membership_dispatch(AIS_Message *wrapper, char *data, int sender) 
{
    crm_info("Message received");
    switch(wrapper->header.id) {
	case crm_class_members:
	case crm_class_notify:
	    break;
	default:
	    return TRUE;
	    
	    break;
    }

    if(command == 'q') {
	if(crm_have_quorum) {
	    fprintf(stdout, "1\n");
	} else {
	    fprintf(stdout, "0\n");
	}
		
    } else if(command == 'e') {
	/* Age makes no sense (yet) in an AIS cluster */
	fprintf(stdout, "1\n");

    } else if(command == 'p') {
	g_hash_table_foreach(crm_peer_cache, crm_print_member, NULL);
	fprintf(stdout, "\n");
    }

    exit(0);
    
    return TRUE;
}

