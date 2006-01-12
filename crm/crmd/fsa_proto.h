/* $Id: fsa_proto.h,v 1.20 2006/01/12 15:10:08 andrew Exp $ */
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

#ifndef XML_FSA_PROTO__H
#define XML_FSA_PROTO__H

extern crm_data_t *do_lrm_query(gboolean);

/*	 A_READCONFIG	*/
enum crmd_fsa_input
do_read_config(long long action,
	       enum crmd_fsa_cause cause,
	       enum crmd_fsa_state cur_state,
	       enum crmd_fsa_input current_input,
	       fsa_data_t *msg_data);

/*	 A_PE_INVOKE	*/
enum crmd_fsa_input
do_pe_invoke(long long action,
	     enum crmd_fsa_cause cause,
	     enum crmd_fsa_state cur_state,
	     enum crmd_fsa_input current_input,
	     fsa_data_t *msg_data);

/*	A_ERROR	*/
enum crmd_fsa_input
do_error(long long action,
	 enum crmd_fsa_cause cause,
	 enum crmd_fsa_state cur_state,
	 enum crmd_fsa_input cur_input,
	 fsa_data_t *msg_data);

/*	A_LOG	*/
enum crmd_fsa_input
do_log(long long action,
       enum crmd_fsa_cause cause,
       enum crmd_fsa_state cur_state,
       enum crmd_fsa_input cur_input,
       fsa_data_t *msg_data);

/*	A_STARTUP	*/
enum crmd_fsa_input
do_startup(long long action,
	   enum crmd_fsa_cause cause,
	   enum crmd_fsa_state cur_state,
	   enum crmd_fsa_input cur_input,
	   fsa_data_t *msg_data);

/*	A_CIB_START, STOP, RESTART	*/
enum crmd_fsa_input
do_cib_control(long long action,
	       enum crmd_fsa_cause cause,
	       enum crmd_fsa_state cur_state,
	       enum crmd_fsa_input cur_input,
	       fsa_data_t *msg_data);

/*	A_HA_CONNECT	*/
enum crmd_fsa_input
do_ha_control(long long action,
	      enum crmd_fsa_cause cause,
	      enum crmd_fsa_state cur_state,
	      enum crmd_fsa_input cur_input,
	      fsa_data_t *msg_data);

/*	A_CCM_CONNECT	*/
enum crmd_fsa_input
do_ccm_control(long long action,
	       enum crmd_fsa_cause cause,
	       enum crmd_fsa_state cur_state,
	       enum crmd_fsa_input cur_input,
	       fsa_data_t *msg_data);

/*	A_LRM_CONNECT	*/
enum crmd_fsa_input
do_lrm_control(long long action,
	       enum crmd_fsa_cause cause,
	       enum crmd_fsa_state cur_state,
	       enum crmd_fsa_input cur_input,
	       fsa_data_t *msg_data);

/*	A_PE_START, STOP, RESTART	*/
enum crmd_fsa_input
do_pe_control(long long action,
	      enum crmd_fsa_cause cause,
	      enum crmd_fsa_state cur_state,
	      enum crmd_fsa_input cur_input,
	      fsa_data_t *msg_data);

/*	A_TE_START, STOP, RESTART	*/
enum crmd_fsa_input
do_te_control(long long action,
	      enum crmd_fsa_cause cause,
	      enum crmd_fsa_state cur_state,
	      enum crmd_fsa_input cur_input,
	      fsa_data_t *msg_data);

/*	A_STARTED	*/
enum crmd_fsa_input
do_started(long long action,
	   enum crmd_fsa_cause cause,
	   enum crmd_fsa_state cur_state,
	   enum crmd_fsa_input cur_input,
	   fsa_data_t *msg_data);

/*	A_MSG_ROUTE	*/
enum crmd_fsa_input
do_msg_route(long long action,
	     enum crmd_fsa_cause cause,
	     enum crmd_fsa_state cur_state,
	     enum crmd_fsa_input cur_input,
	     fsa_data_t *msg_data);

/*	A_RECOVER	*/
enum crmd_fsa_input
do_recover(long long action,
	   enum crmd_fsa_cause cause,
	   enum crmd_fsa_state cur_state,
	   enum crmd_fsa_input cur_input,
	   fsa_data_t *msg_data);

/*	A_ELECTION_VOTE	*/
enum crmd_fsa_input
do_election_vote(long long action,
		 enum crmd_fsa_cause cause,
		 enum crmd_fsa_state cur_state,
		 enum crmd_fsa_input cur_input,
		 fsa_data_t *msg_data);

/*	A_ELECTION_COUNT	*/
enum crmd_fsa_input
do_election_count_vote(long long action,
		       enum crmd_fsa_cause cause,
		       enum crmd_fsa_state cur_state,
		       enum crmd_fsa_input cur_input,
		       fsa_data_t *msg_data);

/*	A_ELECTION_CHECK	*/
enum crmd_fsa_input
do_election_check(long long action,
		  enum crmd_fsa_cause cause,
		  enum crmd_fsa_state cur_state,
		  enum crmd_fsa_input cur_input,
		  fsa_data_t *msg_data);

/*	A_ELECT_TIMER_START, A_ELECTION_TIMEOUT	*/
enum crmd_fsa_input
do_election_timer_ctrl(long long action,
		       enum crmd_fsa_cause cause,
		       enum crmd_fsa_state cur_state,
		       enum crmd_fsa_input cur_input,
		       fsa_data_t *msg_data);

/*	A_DC_TIMER_STOP	*/
enum crmd_fsa_input
do_timer_control(long long action,
		    enum crmd_fsa_cause cause,
		    enum crmd_fsa_state cur_state,
		    enum crmd_fsa_input cur_input,
		    fsa_data_t *msg_data);

/*	A_CCM_UPDATE_CACHE	*/
enum crmd_fsa_input
do_ccm_update_cache(long long action,
		    enum crmd_fsa_cause cause,
		    enum crmd_fsa_state cur_state,
		    enum crmd_fsa_input cur_input,
		    fsa_data_t *msg_data);

/*	A_CCM_EVENT	*/
enum crmd_fsa_input
do_ccm_event(long long action,
	     enum crmd_fsa_cause cause,
	     enum crmd_fsa_state cur_state,
	     enum crmd_fsa_input cur_input,
	     fsa_data_t *msg_data);

/*	A_DC_TAKEOVER	*/
enum crmd_fsa_input
do_dc_takeover(long long action,
	       enum crmd_fsa_cause cause,
	       enum crmd_fsa_state cur_state,
	       enum crmd_fsa_input cur_input,
	       fsa_data_t *msg_data);

/*	A_DC_RELEASE	*/
enum crmd_fsa_input
do_dc_release(long long action,
	      enum crmd_fsa_cause cause,
	      enum crmd_fsa_state cur_state,
	      enum crmd_fsa_input cur_input,
	      fsa_data_t *msg_data);

/*	A_DC_JOIN_OFFER_ALL	*/
enum crmd_fsa_input
do_dc_join_offer_all(long long action,
		     enum crmd_fsa_cause cause,
		     enum crmd_fsa_state cur_state,
		     enum crmd_fsa_input cur_input,
		     fsa_data_t *msg_data);

/*	A_DC_JOIN_OFFER_ONE	*/
enum crmd_fsa_input
do_dc_join_offer_one(long long action,
		     enum crmd_fsa_cause cause,
		     enum crmd_fsa_state cur_state,
		     enum crmd_fsa_input cur_input,
		     fsa_data_t *msg_data);

/*	A_DC_JOIN_ACK	*/
enum crmd_fsa_input
do_dc_join_ack(long long action,
	       enum crmd_fsa_cause cause,
	       enum crmd_fsa_state cur_state,
	       enum crmd_fsa_input cur_input,
	       fsa_data_t *msg_data);

/*	A_DC_JOIN_REQ	*/
enum crmd_fsa_input
do_dc_join_filter_offer(long long action,
	       enum crmd_fsa_cause cause,
	       enum crmd_fsa_state cur_state,
	       enum crmd_fsa_input cur_input,
	       fsa_data_t *msg_data);

/*	A_DC_JOIN_FINALIZE	*/
enum crmd_fsa_input
do_dc_join_finalize(long long action,
		    enum crmd_fsa_cause cause,
		    enum crmd_fsa_state cur_state,
		    enum crmd_fsa_input cur_input,
		    fsa_data_t *msg_data);

/*	A_CL_JOIN_QUERY		*/
/* is there a DC out there? */
enum crmd_fsa_input
do_cl_join_query(long long action,
		 enum crmd_fsa_cause cause,
		 enum crmd_fsa_state cur_state,
		 enum crmd_fsa_input current_input,
		 fsa_data_t *msg_data);

/*	 A_CL_JOIN_ANNOUNCE	*/
enum crmd_fsa_input
do_cl_join_announce(long long action,
		    enum crmd_fsa_cause cause,
		    enum crmd_fsa_state cur_state,
		    enum crmd_fsa_input current_input,
		    fsa_data_t *msg_data);

/*	 A_CL_JOIN_REQUEST	*/
enum crmd_fsa_input
do_cl_join_offer_respond(long long action,
		   enum crmd_fsa_cause cause,
		   enum crmd_fsa_state cur_state,
		   enum crmd_fsa_input current_input,
		   fsa_data_t *msg_data);

/*	 A_CL_JOIN_RESULT	*/
enum crmd_fsa_input
do_cl_join_finalize_respond(long long action,
		  enum crmd_fsa_cause cause,
		  enum crmd_fsa_state cur_state,
		  enum crmd_fsa_input current_input,
		  fsa_data_t *msg_data);

/*	A_CIB_INVOKE	*/
enum crmd_fsa_input
do_cib_invoke(long long action,
	      enum crmd_fsa_cause cause,
	      enum crmd_fsa_state cur_state,
	      enum crmd_fsa_input cur_input,
	      fsa_data_t *msg_data);


/*	 A_UPDATE_NODESTATUS */
enum crmd_fsa_input
do_update_node_status(long long action,
		      enum crmd_fsa_cause cause,
		      enum crmd_fsa_state cur_state,
		      enum crmd_fsa_input cur_input,
		      fsa_data_t *msg_data);

/*	A_LRM_INVOKE	*/
enum crmd_fsa_input
do_lrm_invoke(long long action,
	      enum crmd_fsa_cause cause,
	      enum crmd_fsa_state cur_state,
	      enum crmd_fsa_input cur_input,
	      fsa_data_t *msg_data);

/*	A_LRM_EVENT	*/
enum crmd_fsa_input
do_lrm_event(long long action,
	     enum crmd_fsa_cause cause,
	     enum crmd_fsa_state cur_state,
	     enum crmd_fsa_input cur_input,
	     fsa_data_t *msg_data);

/*	A_PE_INVOKE	*/
enum crmd_fsa_input
do_pe_invoke(long long action,
	     enum crmd_fsa_cause cause,
	     enum crmd_fsa_state cur_state,
	     enum crmd_fsa_input cur_input,
	     fsa_data_t *msg_data);

/*	A_TE_INVOKE, A_TE_CANCEL	*/
enum crmd_fsa_input
do_te_invoke(long long action,
	     enum crmd_fsa_cause cause,
	     enum crmd_fsa_state cur_state,
	     enum crmd_fsa_input cur_input,
	     fsa_data_t *msg_data);

/*	A_TE_INVOKE	*/
enum crmd_fsa_input
do_te_copyto(long long action,
	     enum crmd_fsa_cause cause,
	     enum crmd_fsa_state cur_state,
	     enum crmd_fsa_input cur_input,
	     fsa_data_t *msg_data);

/*	A_SHUTDOWN_REQ	*/
enum crmd_fsa_input
do_shutdown_req(long long action,
		enum crmd_fsa_cause cause,
		enum crmd_fsa_state cur_state,
		enum crmd_fsa_input cur_input,
		fsa_data_t *msg_data);

/*	A_SHUTDOWN	*/
enum crmd_fsa_input
do_shutdown(long long action,
	    enum crmd_fsa_cause cause,
	    enum crmd_fsa_state cur_state,
	    enum crmd_fsa_input cur_input,
	    fsa_data_t *msg_data);

/*	A_STOP	*/
enum crmd_fsa_input
do_stop(long long action,
	enum crmd_fsa_cause cause,
	enum crmd_fsa_state cur_state,
	enum crmd_fsa_input cur_input,
	fsa_data_t *msg_data);

/*	A_EXIT_0, A_EXIT_1	*/
enum crmd_fsa_input
do_exit(long long action,
	enum crmd_fsa_cause cause,
	enum crmd_fsa_state cur_state,
	enum crmd_fsa_input cur_input,
	fsa_data_t *msg_data);


#endif
