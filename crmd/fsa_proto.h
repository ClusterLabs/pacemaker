/* 
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef XML_FSA_PROTO__H
#  define XML_FSA_PROTO__H

extern xmlNode *do_lrm_query(gboolean, const char *node_name);

/*	 A_READCONFIG	*/
void

do_read_config(long long action,
               enum crmd_fsa_cause cause,
               enum crmd_fsa_state cur_state,
               enum crmd_fsa_input current_input, fsa_data_t * msg_data);

/*	 A_PE_INVOKE	*/
void

do_pe_invoke(long long action,
             enum crmd_fsa_cause cause,
             enum crmd_fsa_state cur_state,
             enum crmd_fsa_input current_input, fsa_data_t * msg_data);

/*	A_ERROR	*/
void

do_error(long long action,
         enum crmd_fsa_cause cause,
         enum crmd_fsa_state cur_state, enum crmd_fsa_input cur_input, fsa_data_t * msg_data);

/*	A_LOG	*/
void

do_log(long long action,
       enum crmd_fsa_cause cause,
       enum crmd_fsa_state cur_state, enum crmd_fsa_input cur_input, fsa_data_t * msg_data);

/*	A_STARTUP	*/
void

do_startup(long long action,
           enum crmd_fsa_cause cause,
           enum crmd_fsa_state cur_state, enum crmd_fsa_input cur_input, fsa_data_t * msg_data);

/*	A_CIB_START, STOP, RESTART	*/
void

do_cib_control(long long action,
               enum crmd_fsa_cause cause,
               enum crmd_fsa_state cur_state, enum crmd_fsa_input cur_input, fsa_data_t * msg_data);

/*	A_HA_CONNECT	*/
void

do_ha_control(long long action,
              enum crmd_fsa_cause cause,
              enum crmd_fsa_state cur_state, enum crmd_fsa_input cur_input, fsa_data_t * msg_data);

/*	A_CCM_CONNECT	*/
void

do_ccm_control(long long action,
               enum crmd_fsa_cause cause,
               enum crmd_fsa_state cur_state, enum crmd_fsa_input cur_input, fsa_data_t * msg_data);

/*	A_LRM_CONNECT	*/
void

do_lrm_control(long long action,
               enum crmd_fsa_cause cause,
               enum crmd_fsa_state cur_state, enum crmd_fsa_input cur_input, fsa_data_t * msg_data);

/*	A_PE_START, STOP, RESTART	*/
void

do_pe_control(long long action,
              enum crmd_fsa_cause cause,
              enum crmd_fsa_state cur_state, enum crmd_fsa_input cur_input, fsa_data_t * msg_data);

/*	A_TE_START, STOP, RESTART	*/
void

do_te_control(long long action,
              enum crmd_fsa_cause cause,
              enum crmd_fsa_state cur_state, enum crmd_fsa_input cur_input, fsa_data_t * msg_data);

/*	A_STARTED	*/
void

do_started(long long action,
           enum crmd_fsa_cause cause,
           enum crmd_fsa_state cur_state, enum crmd_fsa_input cur_input, fsa_data_t * msg_data);

/*	A_MSG_ROUTE	*/
void

do_msg_route(long long action,
             enum crmd_fsa_cause cause,
             enum crmd_fsa_state cur_state, enum crmd_fsa_input cur_input, fsa_data_t * msg_data);

/*	A_RECOVER	*/
void

do_recover(long long action,
           enum crmd_fsa_cause cause,
           enum crmd_fsa_state cur_state, enum crmd_fsa_input cur_input, fsa_data_t * msg_data);

/*	A_ELECTION_VOTE	*/
void

do_election_vote(long long action,
                 enum crmd_fsa_cause cause,
                 enum crmd_fsa_state cur_state,
                 enum crmd_fsa_input cur_input, fsa_data_t * msg_data);

/*	A_ELECTION_COUNT	*/
void

do_election_count_vote(long long action,
                       enum crmd_fsa_cause cause,
                       enum crmd_fsa_state cur_state,
                       enum crmd_fsa_input cur_input, fsa_data_t * msg_data);

/*	A_ELECTION_CHECK	*/
void

do_election_check(long long action,
                  enum crmd_fsa_cause cause,
                  enum crmd_fsa_state cur_state,
                  enum crmd_fsa_input cur_input, fsa_data_t * msg_data);

/*	A_ELECT_TIMER_START, A_ELECTION_TIMEOUT	*/
void

do_election_timer_ctrl(long long action,
                       enum crmd_fsa_cause cause,
                       enum crmd_fsa_state cur_state,
                       enum crmd_fsa_input cur_input, fsa_data_t * msg_data);

/*	A_DC_TIMER_STOP	*/
void

do_timer_control(long long action,
                 enum crmd_fsa_cause cause,
                 enum crmd_fsa_state cur_state,
                 enum crmd_fsa_input cur_input, fsa_data_t * msg_data);

#  if SUPPORT_HEARTBEAT
/*	A_CCM_UPDATE_CACHE	*/
void do_ccm_update_cache(enum crmd_fsa_cause cause, enum crmd_fsa_state cur_state,
                         oc_ed_t event, const oc_ev_membership_t * oc, xmlNode * xml);
#  endif

/*	A_CCM_EVENT	*/
void

do_ccm_event(long long action,
             enum crmd_fsa_cause cause,
             enum crmd_fsa_state cur_state, enum crmd_fsa_input cur_input, fsa_data_t * msg_data);

/*	A_DC_TAKEOVER	*/
void

do_dc_takeover(long long action,
               enum crmd_fsa_cause cause,
               enum crmd_fsa_state cur_state, enum crmd_fsa_input cur_input, fsa_data_t * msg_data);

/*	A_DC_RELEASE	*/
void

do_dc_release(long long action,
              enum crmd_fsa_cause cause,
              enum crmd_fsa_state cur_state, enum crmd_fsa_input cur_input, fsa_data_t * msg_data);

/*	A_DC_JOIN_OFFER_ALL	*/
void

do_dc_join_offer_all(long long action,
                     enum crmd_fsa_cause cause,
                     enum crmd_fsa_state cur_state,
                     enum crmd_fsa_input cur_input, fsa_data_t * msg_data);

/*	A_DC_JOIN_OFFER_ONE	*/
void

do_dc_join_offer_one(long long action,
                     enum crmd_fsa_cause cause,
                     enum crmd_fsa_state cur_state,
                     enum crmd_fsa_input cur_input, fsa_data_t * msg_data);

/*	A_DC_JOIN_ACK	*/
void

do_dc_join_ack(long long action,
               enum crmd_fsa_cause cause,
               enum crmd_fsa_state cur_state, enum crmd_fsa_input cur_input, fsa_data_t * msg_data);

/*	A_DC_JOIN_REQ	*/
void

do_dc_join_filter_offer(long long action,
                        enum crmd_fsa_cause cause,
                        enum crmd_fsa_state cur_state,
                        enum crmd_fsa_input cur_input, fsa_data_t * msg_data);

/*	A_DC_JOIN_FINALIZE	*/
void

do_dc_join_finalize(long long action,
                    enum crmd_fsa_cause cause,
                    enum crmd_fsa_state cur_state,
                    enum crmd_fsa_input cur_input, fsa_data_t * msg_data);

/*	A_CL_JOIN_QUERY		*/
/* is there a DC out there? */
void

do_cl_join_query(long long action,
                 enum crmd_fsa_cause cause,
                 enum crmd_fsa_state cur_state,
                 enum crmd_fsa_input current_input, fsa_data_t * msg_data);

/*	 A_CL_JOIN_ANNOUNCE	*/
void

do_cl_join_announce(long long action,
                    enum crmd_fsa_cause cause,
                    enum crmd_fsa_state cur_state,
                    enum crmd_fsa_input current_input, fsa_data_t * msg_data);

/*	 A_CL_JOIN_REQUEST	*/
void

do_cl_join_offer_respond(long long action,
                         enum crmd_fsa_cause cause,
                         enum crmd_fsa_state cur_state,
                         enum crmd_fsa_input current_input, fsa_data_t * msg_data);

/*	 A_CL_JOIN_RESULT	*/
void

do_cl_join_finalize_respond(long long action,
                            enum crmd_fsa_cause cause,
                            enum crmd_fsa_state cur_state,
                            enum crmd_fsa_input current_input, fsa_data_t * msg_data);

/*	 A_UPDATE_NODESTATUS */
void

do_update_node_status(long long action,
                      enum crmd_fsa_cause cause,
                      enum crmd_fsa_state cur_state,
                      enum crmd_fsa_input cur_input, fsa_data_t * msg_data);

/*	A_LRM_INVOKE	*/
void

do_lrm_invoke(long long action,
              enum crmd_fsa_cause cause,
              enum crmd_fsa_state cur_state, enum crmd_fsa_input cur_input, fsa_data_t * msg_data);

/*	A_LRM_EVENT	*/
void

do_lrm_event(long long action,
             enum crmd_fsa_cause cause,
             enum crmd_fsa_state cur_state, enum crmd_fsa_input cur_input, fsa_data_t * msg_data);

/*	A_PE_INVOKE	*/
void

do_pe_invoke(long long action,
             enum crmd_fsa_cause cause,
             enum crmd_fsa_state cur_state, enum crmd_fsa_input cur_input, fsa_data_t * msg_data);

/*	A_TE_INVOKE, A_TE_CANCEL	*/
void

do_te_invoke(long long action,
             enum crmd_fsa_cause cause,
             enum crmd_fsa_state cur_state, enum crmd_fsa_input cur_input, fsa_data_t * msg_data);

/*	A_TE_INVOKE	*/
void

do_te_copyto(long long action,
             enum crmd_fsa_cause cause,
             enum crmd_fsa_state cur_state, enum crmd_fsa_input cur_input, fsa_data_t * msg_data);

/*	A_SHUTDOWN_REQ	*/
void

do_shutdown_req(long long action,
                enum crmd_fsa_cause cause,
                enum crmd_fsa_state cur_state,
                enum crmd_fsa_input cur_input, fsa_data_t * msg_data);

/*	A_SHUTDOWN	*/
void

do_shutdown(long long action,
            enum crmd_fsa_cause cause,
            enum crmd_fsa_state cur_state, enum crmd_fsa_input cur_input, fsa_data_t * msg_data);

/*	A_STOP	*/
void

do_stop(long long action,
        enum crmd_fsa_cause cause,
        enum crmd_fsa_state cur_state, enum crmd_fsa_input cur_input, fsa_data_t * msg_data);

/*	A_EXIT_0, A_EXIT_1	*/
void

do_exit(long long action,
        enum crmd_fsa_cause cause,
        enum crmd_fsa_state cur_state, enum crmd_fsa_input cur_input, fsa_data_t * msg_data);

void

do_dc_join_final(long long action,
                 enum crmd_fsa_cause cause,
                 enum crmd_fsa_state cur_state,
                 enum crmd_fsa_input current_input, fsa_data_t * msg_data);

#endif
