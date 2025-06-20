/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdint.h>                 // uint64_t

#include <pacemaker-controld.h>

/*
 *	The state transition table.  The rows are inputs, and
 *	the columns are states.
 */
static const enum crmd_fsa_state fsa_next_states[MAXINPUT][MAXSTATE] = {
/* Got an I_NULL */
    {
     /* S_IDLE               ==> */ S_IDLE,
     /* S_ELECTION           ==> */ S_ELECTION,
     /* S_INTEGRATION        ==> */ S_INTEGRATION,
     /* S_FINALIZE_JOIN      ==> */ S_FINALIZE_JOIN,
     /* S_NOT_DC             ==> */ S_NOT_DC,
     /* S_POLICY_ENGINE      ==> */ S_POLICY_ENGINE,
     /* S_RECOVERY           ==> */ S_RECOVERY,
     /* S_RELEASE_DC         ==> */ S_RELEASE_DC,
     /* S_STARTING           ==> */ S_STARTING,
     /* S_PENDING            ==> */ S_PENDING,
     /* S_STOPPING           ==> */ S_STOPPING,
     /* S_TERMINATE          ==> */ S_TERMINATE,
     /* S_TRANSITION_ENGINE  ==> */ S_TRANSITION_ENGINE,
     /* S_HALT               ==> */ S_HALT,
     },

/* Got an I_CIB_UPDATE */
    {
     /* S_IDLE               ==> */ S_IDLE,
     /* S_ELECTION           ==> */ S_ELECTION,
     /* S_INTEGRATION        ==> */ S_INTEGRATION,
     /* S_FINALIZE_JOIN      ==> */ S_FINALIZE_JOIN,
     /* S_NOT_DC             ==> */ S_RECOVERY,
     /* S_POLICY_ENGINE      ==> */ S_POLICY_ENGINE,
     /* S_RECOVERY           ==> */ S_RECOVERY,
     /* S_RELEASE_DC         ==> */ S_RELEASE_DC,
     /* S_STARTING           ==> */ S_RECOVERY,
     /* S_PENDING            ==> */ S_RECOVERY,
     /* S_STOPPING           ==> */ S_STOPPING,
     /* S_TERMINATE          ==> */ S_TERMINATE,
     /* S_TRANSITION_ENGINE  ==> */ S_TRANSITION_ENGINE,
     /* S_HALT               ==> */ S_HALT,
     },

/* Got an I_DC_TIMEOUT */
    {
     /* S_IDLE               ==> */ S_RECOVERY,
     /* S_ELECTION           ==> */ S_ELECTION,
     /* S_INTEGRATION        ==> */ S_RECOVERY,
     /* S_FINALIZE_JOIN      ==> */ S_RECOVERY,
     /* S_NOT_DC             ==> */ S_ELECTION,
     /* S_POLICY_ENGINE      ==> */ S_RECOVERY,
     /* S_RECOVERY           ==> */ S_RECOVERY,
     /* S_RELEASE_DC         ==> */ S_RECOVERY,
     /* S_STARTING           ==> */ S_STARTING,
     /* S_PENDING            ==> */ S_ELECTION,
     /* S_STOPPING           ==> */ S_STOPPING,
     /* S_TERMINATE          ==> */ S_TERMINATE,
     /* S_TRANSITION_ENGINE  ==> */ S_RECOVERY,
     /* S_HALT               ==> */ S_ELECTION,
     },

/* Got an I_ELECTION */
    {
     /* S_IDLE               ==> */ S_ELECTION,
     /* S_ELECTION           ==> */ S_ELECTION,
     /* S_INTEGRATION        ==> */ S_ELECTION,
     /* S_FINALIZE_JOIN      ==> */ S_ELECTION,
     /* S_NOT_DC             ==> */ S_ELECTION,
     /* S_POLICY_ENGINE      ==> */ S_ELECTION,
     /* S_RECOVERY           ==> */ S_RECOVERY,
     /* S_RELEASE_DC         ==> */ S_RELEASE_DC,
     /* S_STARTING           ==> */ S_STARTING,
     /* S_PENDING            ==> */ S_ELECTION,
     /* S_STOPPING           ==> */ S_STOPPING,
     /* S_TERMINATE          ==> */ S_TERMINATE,
     /* S_TRANSITION_ENGINE  ==> */ S_ELECTION,
     /* S_HALT               ==> */ S_HALT,
     },

/* Got an I_PE_CALC */
    {
     /* S_IDLE               ==> */ S_POLICY_ENGINE,
     /* S_ELECTION           ==> */ S_ELECTION,
     /* S_INTEGRATION        ==> */ S_INTEGRATION,
     /* S_FINALIZE_JOIN      ==> */ S_FINALIZE_JOIN,
     /* S_NOT_DC             ==> */ S_NOT_DC,
     /* S_POLICY_ENGINE      ==> */ S_POLICY_ENGINE,
     /* S_RECOVERY           ==> */ S_RECOVERY,
     /* S_RELEASE_DC         ==> */ S_RELEASE_DC,
     /* S_STARTING           ==> */ S_RECOVERY,
     /* S_PENDING            ==> */ S_PENDING,
     /* S_STOPPING           ==> */ S_STOPPING,
     /* S_TERMINATE          ==> */ S_TERMINATE,
     /* S_TRANSITION_ENGINE  ==> */ S_POLICY_ENGINE,
     /* S_HALT               ==> */ S_HALT,
     },

/* Got an I_RELEASE_DC */
    {
     /* S_IDLE               ==> */ S_RELEASE_DC,
     /* S_ELECTION           ==> */ S_RELEASE_DC,
     /* S_INTEGRATION        ==> */ S_RELEASE_DC,
     /* S_FINALIZE_JOIN      ==> */ S_RELEASE_DC,
     /* S_NOT_DC             ==> */ S_NOT_DC,
     /* S_POLICY_ENGINE      ==> */ S_RELEASE_DC,
     /* S_RECOVERY           ==> */ S_RECOVERY,
     /* S_RELEASE_DC         ==> */ S_RELEASE_DC,
     /* S_STARTING           ==> */ S_RECOVERY,
     /* S_PENDING            ==> */ S_PENDING,
     /* S_STOPPING           ==> */ S_STOPPING,
     /* S_TERMINATE          ==> */ S_TERMINATE,
     /* S_TRANSITION_ENGINE  ==> */ S_RELEASE_DC,
     /* S_HALT               ==> */ S_HALT,
     },

/* Got an I_ELECTION_DC */
    {
     /* S_IDLE               ==> */ S_INTEGRATION,
     /* S_ELECTION           ==> */ S_INTEGRATION,
     /* S_INTEGRATION        ==> */ S_INTEGRATION,
     /* S_FINALIZE_JOIN      ==> */ S_INTEGRATION,
     /* S_NOT_DC             ==> */ S_INTEGRATION,
     /* S_POLICY_ENGINE      ==> */ S_INTEGRATION,
     /* S_RECOVERY           ==> */ S_RECOVERY,
     /* S_RELEASE_DC         ==> */ S_RELEASE_DC,
     /* S_STARTING           ==> */ S_RECOVERY,
     /* S_PENDING            ==> */ S_PENDING,
     /* S_STOPPING           ==> */ S_STOPPING,
     /* S_TERMINATE          ==> */ S_TERMINATE,
     /* S_TRANSITION_ENGINE  ==> */ S_INTEGRATION,
     /* S_HALT               ==> */ S_HALT,
     },

/* Got an I_ERROR */
    {
     /* S_IDLE               ==> */ S_RECOVERY,
     /* S_ELECTION           ==> */ S_RECOVERY,
     /* S_INTEGRATION        ==> */ S_RECOVERY,
     /* S_FINALIZE_JOIN      ==> */ S_RECOVERY,
     /* S_NOT_DC             ==> */ S_RECOVERY,
     /* S_POLICY_ENGINE      ==> */ S_RECOVERY,
     /* S_RECOVERY           ==> */ S_RECOVERY,
     /* S_RELEASE_DC         ==> */ S_RECOVERY,
     /* S_STARTING           ==> */ S_RECOVERY,
     /* S_PENDING            ==> */ S_RECOVERY,
     /* S_STOPPING           ==> */ S_TERMINATE,
     /* S_TERMINATE          ==> */ S_TERMINATE,
     /* S_TRANSITION_ENGINE  ==> */ S_RECOVERY,
     /* S_HALT               ==> */ S_RECOVERY,
     },

/* Got an I_FAIL */
    {
     /* S_IDLE               ==> */ S_RECOVERY,
     /* S_ELECTION           ==> */ S_RELEASE_DC,
     /* S_INTEGRATION        ==> */ S_INTEGRATION,
     /* S_FINALIZE_JOIN      ==> */ S_INTEGRATION,
     /* S_NOT_DC             ==> */ S_RECOVERY,
     /* S_POLICY_ENGINE      ==> */ S_INTEGRATION,
     /* S_RECOVERY           ==> */ S_RECOVERY,
     /* S_RELEASE_DC         ==> */ S_RELEASE_DC,
     /* S_STARTING           ==> */ S_STOPPING,
     /* S_PENDING            ==> */ S_STOPPING,
     /* S_STOPPING           ==> */ S_STOPPING,
     /* S_TERMINATE          ==> */ S_TERMINATE,
     /* S_TRANSITION_ENGINE  ==> */ S_POLICY_ENGINE,
     /* S_HALT               ==> */ S_RELEASE_DC,
     },

/* Got an I_INTEGRATED */
    {
     /* S_IDLE               ==> */ S_IDLE,
     /* S_ELECTION           ==> */ S_ELECTION,
     /* S_INTEGRATION        ==> */ S_FINALIZE_JOIN,
     /* S_FINALIZE_JOIN      ==> */ S_FINALIZE_JOIN,
     /* S_NOT_DC             ==> */ S_NOT_DC,
     /* S_POLICY_ENGINE      ==> */ S_POLICY_ENGINE,
     /* S_RECOVERY           ==> */ S_RECOVERY,
     /* S_RELEASE_DC         ==> */ S_RELEASE_DC,
     /* S_STARTING           ==> */ S_RECOVERY,
     /* S_PENDING            ==> */ S_RECOVERY,
     /* S_STOPPING           ==> */ S_STOPPING,
     /* S_TERMINATE          ==> */ S_TERMINATE,
     /* S_TRANSITION_ENGINE  ==> */ S_TRANSITION_ENGINE,
     /* S_HALT               ==> */ S_HALT,
     },

/* Got an I_FINALIZED */
    {
     /* S_IDLE               ==> */ S_IDLE,
     /* S_ELECTION           ==> */ S_ELECTION,
     /* S_INTEGRATION        ==> */ S_INTEGRATION,
     /* S_FINALIZE_JOIN      ==> */ S_POLICY_ENGINE,
     /* S_NOT_DC             ==> */ S_NOT_DC,
     /* S_POLICY_ENGINE      ==> */ S_POLICY_ENGINE,
     /* S_RECOVERY           ==> */ S_RECOVERY,
     /* S_RELEASE_DC         ==> */ S_RELEASE_DC,
     /* S_STARTING           ==> */ S_RECOVERY,
     /* S_PENDING            ==> */ S_RECOVERY,
     /* S_STOPPING           ==> */ S_STOPPING,
     /* S_TERMINATE          ==> */ S_TERMINATE,
     /* S_TRANSITION_ENGINE  ==> */ S_TRANSITION_ENGINE,
     /* S_HALT               ==> */ S_HALT,
     },

/* Got an I_NODE_JOIN */
    {
     /* S_IDLE               ==> */ S_INTEGRATION,
     /* S_ELECTION           ==> */ S_ELECTION,
     /* S_INTEGRATION        ==> */ S_INTEGRATION,
     /* S_FINALIZE_JOIN      ==> */ S_INTEGRATION,
     /* S_NOT_DC             ==> */ S_NOT_DC,
     /* S_POLICY_ENGINE      ==> */ S_INTEGRATION,
     /* S_RECOVERY           ==> */ S_RECOVERY,
     /* S_RELEASE_DC         ==> */ S_RELEASE_DC,
     /* S_STARTING           ==> */ S_RECOVERY,
     /* S_PENDING            ==> */ S_PENDING,
     /* S_STOPPING           ==> */ S_STOPPING,
     /* S_TERMINATE          ==> */ S_TERMINATE,
     /* S_TRANSITION_ENGINE  ==> */ S_INTEGRATION,
     /* S_HALT               ==> */ S_HALT,
     },

/* Got an I_NOT_DC */
    {
     /* S_IDLE               ==> */ S_RECOVERY,
     /* S_ELECTION           ==> */ S_ELECTION,
     /* S_INTEGRATION        ==> */ S_RECOVERY,
     /* S_FINALIZE_JOIN      ==> */ S_RECOVERY,
     /* S_NOT_DC             ==> */ S_NOT_DC,
     /* S_POLICY_ENGINE      ==> */ S_RECOVERY,
     /* S_RECOVERY           ==> */ S_RECOVERY,
     /* S_RELEASE_DC         ==> */ S_RELEASE_DC,
     /* S_STARTING           ==> */ S_RECOVERY,
     /* S_PENDING            ==> */ S_NOT_DC,
     /* S_STOPPING           ==> */ S_STOPPING,
     /* S_TERMINATE          ==> */ S_TERMINATE,
     /* S_TRANSITION_ENGINE  ==> */ S_RECOVERY,
     /* S_HALT               ==> */ S_HALT,
     },

/* Got an I_RECOVERED */
    {
     /* S_IDLE               ==> */ S_IDLE,
     /* S_ELECTION           ==> */ S_ELECTION,
     /* S_INTEGRATION        ==> */ S_INTEGRATION,
     /* S_FINALIZE_JOIN      ==> */ S_INTEGRATION,
     /* S_NOT_DC             ==> */ S_NOT_DC,
     /* S_POLICY_ENGINE      ==> */ S_POLICY_ENGINE,
     /* S_RECOVERY           ==> */ S_PENDING,
     /* S_RELEASE_DC         ==> */ S_RELEASE_DC,
     /* S_STARTING           ==> */ S_STARTING,
     /* S_PENDING            ==> */ S_PENDING,
     /* S_STOPPING           ==> */ S_STOPPING,
     /* S_TERMINATE          ==> */ S_TERMINATE,
     /* S_TRANSITION_ENGINE  ==> */ S_TRANSITION_ENGINE,
     /* S_HALT               ==> */ S_HALT,
     },

/* Got an I_RELEASE_FAIL */
    {
     /* S_IDLE               ==> */ S_STOPPING,
     /* S_ELECTION           ==> */ S_STOPPING,
     /* S_INTEGRATION        ==> */ S_STOPPING,
     /* S_FINALIZE_JOIN      ==> */ S_STOPPING,
     /* S_NOT_DC             ==> */ S_NOT_DC,
     /* S_POLICY_ENGINE      ==> */ S_STOPPING,
     /* S_RECOVERY           ==> */ S_STOPPING,
     /* S_RELEASE_DC         ==> */ S_STOPPING,
     /* S_STARTING           ==> */ S_RECOVERY,
     /* S_PENDING            ==> */ S_PENDING,
     /* S_STOPPING           ==> */ S_STOPPING,
     /* S_TERMINATE          ==> */ S_TERMINATE,
     /* S_TRANSITION_ENGINE  ==> */ S_STOPPING,
     /* S_HALT               ==> */ S_HALT,
     },

/* Got an I_RELEASE_SUCCESS */
    {
     /* S_IDLE               ==> */ S_RECOVERY,
     /* S_ELECTION           ==> */ S_ELECTION,
     /* S_INTEGRATION        ==> */ S_RECOVERY,
     /* S_FINALIZE_JOIN      ==> */ S_RECOVERY,
     /* S_NOT_DC             ==> */ S_NOT_DC,
     /* S_POLICY_ENGINE      ==> */ S_RECOVERY,
     /* S_RECOVERY           ==> */ S_RECOVERY,
     /* S_RELEASE_DC         ==> */ S_PENDING,
     /* S_STARTING           ==> */ S_RECOVERY,
     /* S_PENDING            ==> */ S_PENDING,
     /* S_STOPPING           ==> */ S_STOPPING,
     /* S_TERMINATE          ==> */ S_TERMINATE,
     /* S_TRANSITION_ENGINE  ==> */ S_RECOVERY,
     /* S_HALT               ==> */ S_HALT,
     },

/* Got an I_RESTART */
    {
     /* S_IDLE               ==> */ S_IDLE,
     /* S_ELECTION           ==> */ S_ELECTION,
     /* S_INTEGRATION        ==> */ S_INTEGRATION,
     /* S_FINALIZE_JOIN      ==> */ S_FINALIZE_JOIN,
     /* S_NOT_DC             ==> */ S_NOT_DC,
     /* S_POLICY_ENGINE      ==> */ S_POLICY_ENGINE,
     /* S_RECOVERY           ==> */ S_RECOVERY,
     /* S_RELEASE_DC         ==> */ S_RELEASE_DC,
     /* S_STARTING           ==> */ S_STARTING,
     /* S_PENDING            ==> */ S_PENDING,
     /* S_STOPPING           ==> */ S_STOPPING,
     /* S_TERMINATE          ==> */ S_TERMINATE,
     /* S_TRANSITION_ENGINE  ==> */ S_TRANSITION_ENGINE,
     /* S_HALT               ==> */ S_HALT,
     },

/* Got an I_TE_SUCCESS */
    {
     /* S_IDLE               ==> */ S_IDLE,
     /* S_ELECTION           ==> */ S_ELECTION,
     /* S_INTEGRATION        ==> */ S_INTEGRATION,
     /* S_FINALIZE_JOIN      ==> */ S_FINALIZE_JOIN,
     /* S_NOT_DC             ==> */ S_NOT_DC,
     /* S_POLICY_ENGINE      ==> */ S_POLICY_ENGINE,
     /* S_RECOVERY           ==> */ S_RECOVERY,
     /* S_RELEASE_DC         ==> */ S_RELEASE_DC,
     /* S_STARTING           ==> */ S_RECOVERY,
     /* S_PENDING            ==> */ S_PENDING,
     /* S_STOPPING           ==> */ S_STOPPING,
     /* S_TERMINATE          ==> */ S_TERMINATE,
     /* S_TRANSITION_ENGINE  ==> */ S_IDLE,
     /* S_HALT               ==> */ S_HALT,
     },

/* Got an I_ROUTER */
    {
     /* S_IDLE               ==> */ S_IDLE,
     /* S_ELECTION           ==> */ S_ELECTION,
     /* S_INTEGRATION        ==> */ S_INTEGRATION,
     /* S_FINALIZE_JOIN      ==> */ S_FINALIZE_JOIN,
     /* S_NOT_DC             ==> */ S_NOT_DC,
     /* S_POLICY_ENGINE      ==> */ S_POLICY_ENGINE,
     /* S_RECOVERY           ==> */ S_RECOVERY,
     /* S_RELEASE_DC         ==> */ S_RELEASE_DC,
     /* S_STARTING           ==> */ S_STARTING,
     /* S_PENDING            ==> */ S_PENDING,
     /* S_STOPPING           ==> */ S_STOPPING,
     /* S_TERMINATE          ==> */ S_TERMINATE,
     /* S_TRANSITION_ENGINE  ==> */ S_TRANSITION_ENGINE,
     /* S_HALT               ==> */ S_HALT,
     },

/* Got an I_SHUTDOWN */
    {
     /* S_IDLE               ==> */ S_POLICY_ENGINE,
     /* S_ELECTION           ==> */ S_ELECTION,
     /* S_INTEGRATION        ==> */ S_INTEGRATION,
     /* S_FINALIZE_JOIN      ==> */ S_FINALIZE_JOIN,
     /* S_NOT_DC             ==> */ S_NOT_DC,
     /* S_POLICY_ENGINE      ==> */ S_POLICY_ENGINE,
     /* S_RECOVERY           ==> */ S_STOPPING,
     /* S_RELEASE_DC         ==> */ S_RELEASE_DC,
     /* S_STARTING           ==> */ S_STOPPING,
     /* S_PENDING            ==> */ S_PENDING,
     /* S_STOPPING           ==> */ S_STOPPING,
     /* S_TERMINATE          ==> */ S_TERMINATE,
     /* S_TRANSITION_ENGINE  ==> */ S_POLICY_ENGINE,
     /* S_HALT               ==> */ S_ELECTION,
     },

/* Got an I_STOP */
    {
     /* S_IDLE               ==> */ S_STOPPING,
     /* S_ELECTION           ==> */ S_STOPPING,
     /* S_INTEGRATION        ==> */ S_STOPPING,
     /* S_FINALIZE_JOIN      ==> */ S_STOPPING,
     /* S_NOT_DC             ==> */ S_STOPPING,
     /* S_POLICY_ENGINE      ==> */ S_STOPPING,
     /* S_RECOVERY           ==> */ S_STOPPING,
     /* S_RELEASE_DC         ==> */ S_STOPPING,
     /* S_STARTING           ==> */ S_STOPPING,
     /* S_PENDING            ==> */ S_STOPPING,
     /* S_STOPPING           ==> */ S_STOPPING,
     /* S_TERMINATE          ==> */ S_TERMINATE,
     /* S_TRANSITION_ENGINE  ==> */ S_STOPPING,
     /* S_HALT               ==> */ S_STOPPING,
     },

/* Got an I_TERMINATE */
    {
     /* S_IDLE               ==> */ S_TERMINATE,
     /* S_ELECTION           ==> */ S_TERMINATE,
     /* S_INTEGRATION        ==> */ S_TERMINATE,
     /* S_FINALIZE_JOIN      ==> */ S_TERMINATE,
     /* S_NOT_DC             ==> */ S_TERMINATE,
     /* S_POLICY_ENGINE      ==> */ S_TERMINATE,
     /* S_RECOVERY           ==> */ S_TERMINATE,
     /* S_RELEASE_DC         ==> */ S_TERMINATE,
     /* S_STARTING           ==> */ S_TERMINATE,
     /* S_PENDING            ==> */ S_TERMINATE,
     /* S_STOPPING           ==> */ S_TERMINATE,
     /* S_TERMINATE          ==> */ S_TERMINATE,
     /* S_TRANSITION_ENGINE  ==> */ S_TERMINATE,
     /* S_HALT               ==> */ S_TERMINATE,
     },

/* Got an I_STARTUP */
    {
     /* S_IDLE               ==> */ S_RECOVERY,
     /* S_ELECTION           ==> */ S_RECOVERY,
     /* S_INTEGRATION        ==> */ S_RECOVERY,
     /* S_FINALIZE_JOIN      ==> */ S_RECOVERY,
     /* S_NOT_DC             ==> */ S_RECOVERY,
     /* S_POLICY_ENGINE      ==> */ S_RECOVERY,
     /* S_RECOVERY           ==> */ S_RECOVERY,
     /* S_RELEASE_DC         ==> */ S_RELEASE_DC,
     /* S_STARTING           ==> */ S_STARTING,
     /* S_PENDING            ==> */ S_PENDING,
     /* S_STOPPING           ==> */ S_STOPPING,
     /* S_TERMINATE          ==> */ S_TERMINATE,
     /* S_TRANSITION_ENGINE  ==> */ S_RECOVERY,
     /* S_HALT               ==> */ S_HALT,
     },

/* Got an I_PE_SUCCESS */
    {
     /* S_IDLE               ==> */ S_IDLE,
     /* S_ELECTION           ==> */ S_ELECTION,
     /* S_INTEGRATION        ==> */ S_INTEGRATION,
     /* S_FINALIZE_JOIN      ==> */ S_FINALIZE_JOIN,
     /* S_NOT_DC             ==> */ S_NOT_DC,
     /* S_POLICY_ENGINE      ==> */ S_TRANSITION_ENGINE,
     /* S_RECOVERY           ==> */ S_RECOVERY,
     /* S_RELEASE_DC         ==> */ S_RELEASE_DC,
     /* S_STARTING           ==> */ S_RECOVERY,
     /* S_PENDING            ==> */ S_PENDING,
     /* S_STOPPING           ==> */ S_STOPPING,
     /* S_TERMINATE          ==> */ S_TERMINATE,
     /* S_TRANSITION_ENGINE  ==> */ S_TRANSITION_ENGINE,
     /* S_HALT               ==> */ S_HALT,
     },

/* Got an I_JOIN_OFFER */
    {
     /* S_IDLE               ==> */ S_IDLE,
     /* S_ELECTION           ==> */ S_ELECTION,
     /* S_INTEGRATION        ==> */ S_INTEGRATION,
     /* S_FINALIZE_JOIN      ==> */ S_FINALIZE_JOIN,
     /* S_NOT_DC             ==> */ S_PENDING,
     /* S_POLICY_ENGINE      ==> */ S_POLICY_ENGINE,
     /* S_RECOVERY           ==> */ S_RECOVERY,
     /* S_RELEASE_DC         ==> */ S_RELEASE_DC,
     /* S_STARTING           ==> */ S_STARTING,
     /* S_PENDING            ==> */ S_PENDING,
     /* S_STOPPING           ==> */ S_STOPPING,
     /* S_TERMINATE          ==> */ S_TERMINATE,
     /* S_TRANSITION_ENGINE  ==> */ S_TRANSITION_ENGINE,
     /* S_HALT               ==> */ S_HALT,
     },

/* Got an I_JOIN_REQUEST */
    {
     /* S_IDLE               ==> */ S_INTEGRATION,
     /* S_ELECTION           ==> */ S_ELECTION,
     /* S_INTEGRATION        ==> */ S_INTEGRATION,
     /* S_FINALIZE_JOIN      ==> */ S_INTEGRATION,
     /* S_NOT_DC             ==> */ S_NOT_DC,
     /* S_POLICY_ENGINE      ==> */ S_INTEGRATION,
     /* S_RECOVERY           ==> */ S_RECOVERY,
     /* S_RELEASE_DC         ==> */ S_RELEASE_DC,
     /* S_STARTING           ==> */ S_STARTING,
     /* S_PENDING            ==> */ S_PENDING,
     /* S_STOPPING           ==> */ S_STOPPING,
     /* S_TERMINATE          ==> */ S_TERMINATE,
     /* S_TRANSITION_ENGINE  ==> */ S_INTEGRATION,
     /* S_HALT               ==> */ S_HALT,
     },

/* Got an I_JOIN_RESULT */
    {
     /* S_IDLE               ==> */ S_INTEGRATION,
     /* S_ELECTION           ==> */ S_ELECTION,
     /* S_INTEGRATION        ==> */ S_INTEGRATION,
     /* S_FINALIZE_JOIN      ==> */ S_FINALIZE_JOIN,
     /* S_NOT_DC             ==> */ S_PENDING,
     /* S_POLICY_ENGINE      ==> */ S_INTEGRATION,
     /* S_RECOVERY           ==> */ S_RECOVERY,
     /* S_RELEASE_DC         ==> */ S_RELEASE_DC,
     /* S_STARTING           ==> */ S_RECOVERY,
     /* S_PENDING            ==> */ S_PENDING,
     /* S_STOPPING           ==> */ S_STOPPING,
     /* S_TERMINATE          ==> */ S_TERMINATE,
     /* S_TRANSITION_ENGINE  ==> */ S_INTEGRATION,
     /* S_HALT               ==> */ S_HALT,
     },

/* Got an I_WAIT_FOR_EVENT */
    {
     /* S_IDLE               ==> */ S_IDLE,
     /* S_ELECTION           ==> */ S_ELECTION,
     /* S_INTEGRATION        ==> */ S_INTEGRATION,
     /* S_FINALIZE_JOIN      ==> */ S_FINALIZE_JOIN,
     /* S_NOT_DC             ==> */ S_NOT_DC,
     /* S_POLICY_ENGINE      ==> */ S_POLICY_ENGINE,
     /* S_RECOVERY           ==> */ S_RECOVERY,
     /* S_RELEASE_DC         ==> */ S_RELEASE_DC,
     /* S_STARTING           ==> */ S_STARTING,
     /* S_PENDING            ==> */ S_PENDING,
     /* S_STOPPING           ==> */ S_STOPPING,
     /* S_TERMINATE          ==> */ S_TERMINATE,
     /* S_TRANSITION_ENGINE  ==> */ S_TRANSITION_ENGINE,
     /* S_HALT               ==> */ S_HALT,
     },

/* Got an I_DC_HEARTBEAT */
    {
     /* S_IDLE               ==> */ S_IDLE,
     /* S_ELECTION           ==> */ S_ELECTION,
     /* S_INTEGRATION        ==> */ S_INTEGRATION,
     /* S_FINALIZE_JOIN      ==> */ S_FINALIZE_JOIN,
     /* S_NOT_DC             ==> */ S_NOT_DC,
     /* S_POLICY_ENGINE      ==> */ S_POLICY_ENGINE,
     /* S_RECOVERY           ==> */ S_RECOVERY,
     /* S_RELEASE_DC         ==> */ S_RELEASE_DC,
     /* S_STARTING           ==> */ S_STARTING,
     /* S_PENDING            ==> */ S_PENDING,
     /* S_STOPPING           ==> */ S_STOPPING,
     /* S_TERMINATE          ==> */ S_TERMINATE,
     /* S_TRANSITION_ENGINE  ==> */ S_TRANSITION_ENGINE,
     /* S_HALT               ==> */ S_HALT,
     },

/* Got an I_PENDING */
    {
     /* S_IDLE               ==> */ S_PENDING,
     /* S_ELECTION           ==> */ S_PENDING,
     /* S_INTEGRATION        ==> */ S_PENDING,
     /* S_FINALIZE_JOIN      ==> */ S_PENDING,
     /* S_NOT_DC             ==> */ S_PENDING,
     /* S_POLICY_ENGINE      ==> */ S_PENDING,
     /* S_RECOVERY           ==> */ S_RECOVERY,
     /* S_RELEASE_DC         ==> */ S_RELEASE_DC,
     /* S_STARTING           ==> */ S_PENDING,
     /* S_PENDING            ==> */ S_PENDING,
     /* S_STOPPING           ==> */ S_STOPPING,
     /* S_TERMINATE          ==> */ S_TERMINATE,
     /* S_TRANSITION_ENGINE  ==> */ S_PENDING,
     /* S_HALT               ==> */ S_HALT,
     },

/* Got an I_HALT */
    {
     /* S_IDLE               ==> */ S_HALT,
     /* S_ELECTION           ==> */ S_HALT,
     /* S_INTEGRATION        ==> */ S_HALT,
     /* S_FINALIZE_JOIN      ==> */ S_HALT,
     /* S_NOT_DC             ==> */ S_HALT,
     /* S_POLICY_ENGINE      ==> */ S_HALT,
     /* S_RECOVERY           ==> */ S_RECOVERY,
     /* S_RELEASE_DC         ==> */ S_RELEASE_DC,
     /* S_STARTING           ==> */ S_STARTING,
     /* S_PENDING            ==> */ S_HALT,
     /* S_STOPPING           ==> */ S_STOPPING,
     /* S_TERMINATE          ==> */ S_TERMINATE,
     /* S_TRANSITION_ENGINE  ==> */ S_HALT,
     /* S_HALT               ==> */ S_HALT,
     },
};

/*
 *	The action table.  Each entry is a set of actions to take or-ed
 *	together.  Like the state table, the rows are inputs, and
 *	the columns are states.
 */

/* NOTE: In the fsa, the actions are extracted then state is updated. */

static const uint64_t fsa_actions[MAXINPUT][MAXSTATE] = {

/* Got an I_NULL */
    {
     /* S_IDLE               ==> */ A_NOTHING,
     /* S_ELECTION           ==> */ A_NOTHING,
     /* S_INTEGRATION        ==> */ A_NOTHING,
     /* S_FINALIZE_JOIN      ==> */ A_NOTHING,
     /* S_NOT_DC             ==> */ A_NOTHING,
     /* S_POLICY_ENGINE      ==> */ A_NOTHING,
     /* S_RECOVERY           ==> */ A_NOTHING,
     /* S_RELEASE_DC         ==> */ A_NOTHING,
     /* S_STARTING           ==> */ A_NOTHING,
     /* S_PENDING            ==> */ A_NOTHING,
     /* S_STOPPING           ==> */ A_NOTHING,
     /* S_TERMINATE          ==> */ A_NOTHING,
     /* S_TRANSITION_ENGINE  ==> */ A_NOTHING,
     /* S_HALT               ==> */ A_NOTHING,
     },

/* Got an I_CIB_UPDATE */
    {
     /* S_IDLE               ==> */ A_LOG,
     /* S_ELECTION           ==> */ A_LOG,
     /* S_INTEGRATION        ==> */ A_WARN,
     /* S_FINALIZE_JOIN      ==> */ A_WARN,
     /* S_NOT_DC             ==> */ A_WARN,
     /* S_POLICY_ENGINE      ==> */ A_LOG,
     /* S_RECOVERY           ==> */ A_WARN,
     /* S_RELEASE_DC         ==> */ A_WARN,
     /* S_STARTING           ==> */ A_WARN,
     /* S_PENDING            ==> */ A_WARN,
     /* S_STOPPING           ==> */ A_WARN,
     /* S_TERMINATE          ==> */ A_WARN,
     /* S_TRANSITION_ENGINE  ==> */ A_LOG,
     /* S_HALT               ==> */ A_WARN,
     },

/* Got an I_DC_TIMEOUT */
    {
     /* S_IDLE               ==> */ A_WARN,
     /* S_ELECTION           ==> */ A_ELECTION_VOTE,
     /* S_INTEGRATION        ==> */ A_WARN,
     /* S_FINALIZE_JOIN      ==> */ A_WARN,
     /* S_NOT_DC             ==> */ A_ELECTION_VOTE | A_WARN,
     /* S_POLICY_ENGINE      ==> */ A_WARN,
     /* S_RECOVERY           ==> */ A_NOTHING,
     /* S_RELEASE_DC         ==> */ A_WARN,
     /* S_STARTING           ==> */ A_WARN,
     /* S_PENDING            ==> */ A_ELECTION_VOTE | A_WARN,
     /* S_STOPPING           ==> */ A_NOTHING,
     /* S_TERMINATE          ==> */ A_NOTHING,
     /* S_TRANSITION_ENGINE  ==> */ A_TE_CANCEL | A_WARN,
     /* S_HALT               ==> */ A_WARN,
     },

/* Got an I_ELECTION */
    {
     /* S_IDLE               ==> */ A_ELECTION_VOTE,
     /* S_ELECTION           ==> */ A_ELECTION_VOTE,
     /* S_INTEGRATION        ==> */ A_ELECTION_VOTE,
     /* S_FINALIZE_JOIN      ==> */ A_ELECTION_VOTE,
     /* S_NOT_DC             ==> */ A_ELECTION_VOTE,
     /* S_POLICY_ENGINE      ==> */ A_ELECTION_VOTE,
     /* S_RECOVERY           ==> */ A_LOG,
     /* S_RELEASE_DC         ==> */ A_LOG,
     /* S_STARTING           ==> */ A_WARN,
     /* S_PENDING            ==> */ A_ELECTION_VOTE,
     /* S_STOPPING           ==> */ A_LOG,
     /* S_TERMINATE          ==> */ A_LOG,
     /* S_TRANSITION_ENGINE  ==> */ A_ELECTION_VOTE,
     /* S_HALT               ==> */ A_ELECTION_VOTE,
     },

/* Got an I_PE_CALC */
    {
     /* S_IDLE               ==> */ A_PE_INVOKE,
     /* S_ELECTION           ==> */ A_NOTHING,
     /* S_INTEGRATION        ==> */ A_NOTHING,
     /* S_FINALIZE_JOIN      ==> */ A_NOTHING,
     /* S_NOT_DC             ==> */ A_WARN,
     /* S_POLICY_ENGINE      ==> */ A_PE_INVOKE,
     /* S_RECOVERY           ==> */ A_NOTHING,
     /* S_RELEASE_DC         ==> */ A_NOTHING,
     /* S_STARTING           ==> */ A_ERROR,
     /* S_PENDING            ==> */ A_WARN,
     /* S_STOPPING           ==> */ A_WARN,
     /* S_TERMINATE          ==> */ A_ERROR,
     /* S_TRANSITION_ENGINE  ==> */ A_PE_INVOKE,
     /* S_HALT               ==> */ A_ERROR,
     },

/* Got an I_RELEASE_DC */
    {
     /* S_IDLE               ==> */ O_RELEASE,
     /* S_ELECTION           ==> */ O_RELEASE,
     /* S_INTEGRATION        ==> */ O_RELEASE | A_WARN,
     /* S_FINALIZE_JOIN      ==> */ O_RELEASE | A_WARN,
     /* S_NOT_DC             ==> */ A_WARN,
     /* S_POLICY_ENGINE      ==> */ O_RELEASE | A_WARN,
     /* S_RECOVERY           ==> */ O_RELEASE,
     /* S_RELEASE_DC         ==> */ O_RELEASE | A_WARN,
     /* S_STARTING           ==> */ A_ERROR,
     /* S_PENDING            ==> */ A_WARN,
     /* S_STOPPING           ==> */ A_WARN,
     /* S_TERMINATE          ==> */ A_WARN,
     /* S_TRANSITION_ENGINE  ==> */ O_RELEASE | A_WARN,
     /* S_HALT               ==> */ A_WARN,
     },

/* Got an I_ELECTION_DC */
    {
     /* S_IDLE               ==> */ A_WARN | A_ELECTION_VOTE,
     /* S_ELECTION           ==> */
     A_LOG | A_DC_TAKEOVER | A_PE_START | A_TE_START | A_DC_JOIN_OFFER_ALL | A_DC_TIMER_STOP,
     /* S_INTEGRATION        ==> */ A_WARN | A_ELECTION_VOTE | A_DC_JOIN_OFFER_ALL,
     /* S_FINALIZE_JOIN      ==> */ A_WARN | A_ELECTION_VOTE | A_DC_JOIN_OFFER_ALL,
     /* S_NOT_DC             ==> */ A_LOG | A_ELECTION_VOTE,
     /* S_POLICY_ENGINE      ==> */ A_WARN | A_ELECTION_VOTE,
     /* S_RECOVERY           ==> */ A_WARN,
     /* S_RELEASE_DC         ==> */ A_WARN | A_ELECTION_VOTE,
     /* S_STARTING           ==> */ A_LOG | A_WARN,
     /* S_PENDING            ==> */ A_LOG | A_WARN,
     /* S_STOPPING           ==> */ A_WARN,
     /* S_TERMINATE          ==> */ A_WARN,
     /* S_TRANSITION_ENGINE  ==> */ A_WARN | A_ELECTION_VOTE,
     /* S_HALT               ==> */ A_WARN,
     },

/* Got an I_ERROR */
    {
     /* S_IDLE               ==> */ A_ERROR | A_RECOVER | O_RELEASE | A_ELECTION_START,
     /* S_ELECTION           ==> */ A_ERROR | A_RECOVER | O_RELEASE,
     /* S_INTEGRATION        ==> */ A_ERROR | A_RECOVER | O_RELEASE | A_ELECTION_START,
     /* S_FINALIZE_JOIN      ==> */ A_ERROR | A_RECOVER | O_RELEASE | A_ELECTION_START,
     /* S_NOT_DC             ==> */ A_ERROR | A_RECOVER,
     /* S_POLICY_ENGINE      ==> */ A_ERROR | A_RECOVER | O_RELEASE | A_ELECTION_START,
     /* S_RECOVERY           ==> */ A_ERROR | O_RELEASE,
     /* S_RELEASE_DC         ==> */ A_ERROR | A_RECOVER,
     /* S_STARTING           ==> */ A_ERROR | A_RECOVER,
     /* S_PENDING            ==> */ A_ERROR | A_RECOVER,
     /* S_STOPPING           ==> */ A_ERROR | A_EXIT_1,
     /* S_TERMINATE          ==> */ A_ERROR | A_EXIT_1,
     /* S_TRANSITION_ENGINE  ==> */ A_ERROR | A_RECOVER | O_RELEASE | A_ELECTION_START,
     /* S_HALT               ==> */ A_ERROR | A_RECOVER | O_RELEASE | A_ELECTION_START,
     },

/* Got an I_FAIL */
    {
     /* S_IDLE               ==> */ A_WARN,
     /* S_ELECTION           ==> */ A_WARN,
     /* S_INTEGRATION        ==> */ A_WARN | A_DC_JOIN_OFFER_ALL,
     /* S_FINALIZE_JOIN      ==> */ A_WARN | A_DC_JOIN_OFFER_ALL,
     /* S_NOT_DC             ==> */ A_WARN,
     /* S_POLICY_ENGINE      ==> */ A_WARN | A_DC_JOIN_OFFER_ALL | A_TE_CANCEL,
     /* S_RECOVERY           ==> */ A_WARN | O_RELEASE,
     /* S_RELEASE_DC         ==> */ A_WARN,
     /* S_STARTING           ==> */ A_WARN,
     /* S_PENDING            ==> */ A_WARN,
     /* S_STOPPING           ==> */ A_WARN,
     /* S_TERMINATE          ==> */ A_WARN | A_EXIT_1,
     /* S_TRANSITION_ENGINE  ==> */ A_WARN | O_LRM_RECONNECT | A_PE_INVOKE | A_TE_CANCEL,
     /* S_HALT               ==> */ A_WARN,
     },

/* Got an I_INTEGRATED */
    {
     /* S_IDLE               ==> */ A_NOTHING,
     /* S_ELECTION           ==> */ A_WARN,
     /* S_INTEGRATION        ==> */ A_DC_JOIN_FINALIZE,
     /* S_FINALIZE_JOIN      ==> */ A_WARN,
     /* S_NOT_DC             ==> */ A_WARN,
     /* S_POLICY_ENGINE      ==> */ A_NOTHING,
     /* S_RECOVERY           ==> */ A_WARN,
     /* S_RELEASE_DC         ==> */ A_WARN,
     /* S_STARTING           ==> */ A_WARN,
     /* S_PENDING            ==> */ A_WARN,
     /* S_STOPPING           ==> */ A_WARN,
     /* S_TERMINATE          ==> */ A_WARN,
     /* S_TRANSITION_ENGINE  ==> */ A_NOTHING,
     /* S_HALT               ==> */ A_WARN,
     },

/* Got an I_FINALIZED */
    {
     /* S_IDLE               ==> */ A_NOTHING,
     /* S_ELECTION           ==> */ A_WARN,
     /* S_INTEGRATION        ==> */ A_WARN,
     /* S_FINALIZE_JOIN      ==> */ A_DC_JOIN_FINAL | A_TE_CANCEL,
     /* S_NOT_DC             ==> */ A_WARN,
     /* S_POLICY_ENGINE      ==> */ A_NOTHING,
     /* S_RECOVERY           ==> */ A_WARN,
     /* S_RELEASE_DC         ==> */ A_WARN,
     /* S_STARTING           ==> */ A_WARN,
     /* S_PENDING            ==> */ A_WARN,
     /* S_STOPPING           ==> */ A_WARN,
     /* S_TERMINATE          ==> */ A_WARN,
     /* S_TRANSITION_ENGINE  ==> */ A_NOTHING,
     /* S_HALT               ==> */ A_WARN,
     },

/* Got an I_NODE_JOIN */
    {
     /* S_IDLE               ==> */ A_TE_HALT | A_DC_JOIN_OFFER_ONE,
     /* S_ELECTION           ==> */ A_WARN,
     /* S_INTEGRATION        ==> */ A_DC_JOIN_OFFER_ONE,
     /* S_FINALIZE_JOIN      ==> */ A_DC_JOIN_OFFER_ONE,
     /* S_NOT_DC             ==> */ A_WARN,
     /* S_POLICY_ENGINE      ==> */ A_DC_JOIN_OFFER_ONE,
     /* S_RECOVERY           ==> */ A_WARN,
     /* S_RELEASE_DC         ==> */ A_WARN,
     /* S_STARTING           ==> */ A_WARN,
     /* S_PENDING            ==> */ A_WARN,
     /* S_STOPPING           ==> */ A_WARN,
     /* S_TERMINATE          ==> */ A_WARN,
     /* S_TRANSITION_ENGINE  ==> */ A_TE_HALT | A_DC_JOIN_OFFER_ONE,
     /* S_HALT               ==> */ A_WARN,
     },

/* Got an I_NOT_DC */
    {
     /* S_IDLE               ==> */ A_WARN | O_RELEASE,
     /* S_ELECTION           ==> */ A_ERROR | A_ELECTION_START | A_DC_TIMER_STOP,
     /* S_INTEGRATION        ==> */ A_ERROR | O_RELEASE,
     /* S_FINALIZE_JOIN      ==> */ A_ERROR | O_RELEASE,
     /* S_NOT_DC             ==> */ A_LOG,
     /* S_POLICY_ENGINE      ==> */ A_ERROR | O_RELEASE,
     /* S_RECOVERY           ==> */ A_ERROR | O_RELEASE,
     /* S_RELEASE_DC         ==> */ A_ERROR | O_RELEASE,
     /* S_STARTING           ==> */ A_WARN,
     /* S_PENDING            ==> */ A_LOG | A_DC_TIMER_STOP,
     /* S_STOPPING           ==> */ A_WARN,
     /* S_TERMINATE          ==> */ A_WARN,
     /* S_TRANSITION_ENGINE  ==> */ A_ERROR | O_RELEASE,
     /* S_HALT               ==> */ A_WARN,
     },

/* Got an I_RECOVERED */
    {
     /* S_IDLE               ==> */ A_WARN,
     /* S_ELECTION           ==> */ A_ELECTION_VOTE,
     /* S_INTEGRATION        ==> */ A_WARN,
     /* S_FINALIZE_JOIN      ==> */ A_WARN,
     /* S_NOT_DC             ==> */ A_WARN,
     /* S_POLICY_ENGINE      ==> */ A_WARN,
     /* S_RECOVERY           ==> */ A_LOG,
     /* S_RELEASE_DC         ==> */ A_WARN,
     /* S_STARTING           ==> */ A_WARN,
     /* S_PENDING            ==> */ A_WARN,
     /* S_STOPPING           ==> */ A_WARN,
     /* S_TERMINATE          ==> */ A_WARN,
     /* S_TRANSITION_ENGINE  ==> */ A_WARN,
     /* S_HALT               ==> */ A_WARN,
     },

/* Got an I_RELEASE_FAIL */
    {
     /* S_IDLE               ==> */ A_WARN,
     /* S_ELECTION           ==> */ A_WARN,
     /* S_INTEGRATION        ==> */ A_WARN,
     /* S_FINALIZE_JOIN      ==> */ A_WARN,
     /* S_NOT_DC             ==> */ A_WARN,
     /* S_POLICY_ENGINE      ==> */ A_NOTHING,
     /* S_RECOVERY           ==> */ A_WARN | A_SHUTDOWN_REQ,
     /* S_RELEASE_DC         ==> */ A_NOTHING,
     /* S_STARTING           ==> */ A_WARN,
     /* S_PENDING            ==> */ A_WARN,
     /* S_STOPPING           ==> */ A_WARN,
     /* S_TERMINATE          ==> */ A_WARN,
     /* S_TRANSITION_ENGINE  ==> */ A_WARN,
     /* S_HALT               ==> */ A_WARN,
     },

/* Got an I_RELEASE_SUCCESS */
    {
     /* S_IDLE               ==> */ A_WARN,
     /* S_ELECTION           ==> */ A_WARN,
     /* S_INTEGRATION        ==> */ A_WARN,
     /* S_FINALIZE_JOIN      ==> */ A_WARN,
     /* S_NOT_DC             ==> */ A_WARN,
     /* S_POLICY_ENGINE      ==> */ A_WARN,
     /* S_RECOVERY           ==> */ A_WARN,
     /* S_RELEASE_DC         ==> */ A_LOG,
     /* S_STARTING           ==> */ A_WARN,
     /* S_PENDING            ==> */ A_LOG,
     /* S_STOPPING           ==> */ A_WARN,
     /* S_TERMINATE          ==> */ A_WARN,
     /* S_TRANSITION_ENGINE  ==> */ A_WARN,
     /* S_HALT               ==> */ A_WARN,
     },

/* Got an I_RESTART */
    {
     /* S_IDLE               ==> */ A_NOTHING,
     /* S_ELECTION           ==> */ A_LOG | A_ELECTION_VOTE,
     /* S_INTEGRATION        ==> */ A_LOG | A_DC_JOIN_OFFER_ALL,
     /* S_FINALIZE_JOIN      ==> */ A_LOG | A_DC_JOIN_FINALIZE,
     /* S_NOT_DC             ==> */ A_LOG | A_NOTHING,
     /* S_POLICY_ENGINE      ==> */ A_LOG | A_PE_INVOKE,
     /* S_RECOVERY           ==> */ A_LOG | A_RECOVER | O_RELEASE,
     /* S_RELEASE_DC         ==> */ A_LOG | O_RELEASE,
     /* S_STARTING           ==> */ A_LOG,
     /* S_PENDING            ==> */ A_LOG,
     /* S_STOPPING           ==> */ A_LOG,
     /* S_TERMINATE          ==> */ A_LOG,
     /* S_TRANSITION_ENGINE  ==> */ A_LOG | A_TE_INVOKE,
     /* S_HALT               ==> */ A_WARN,
     },

/* Got an I_TE_SUCCESS */
    {
     /* S_IDLE               ==> */ A_LOG,
     /* S_ELECTION           ==> */ A_WARN,
     /* S_INTEGRATION        ==> */ A_WARN,
     /* S_FINALIZE_JOIN      ==> */ A_WARN,
     /* S_NOT_DC             ==> */ A_ERROR,
     /* S_POLICY_ENGINE      ==> */ A_WARN,
     /* S_RECOVERY           ==> */ A_RECOVER | A_WARN,
     /* S_RELEASE_DC         ==> */ A_WARN,
     /* S_STARTING           ==> */ A_ERROR,
     /* S_PENDING            ==> */ A_ERROR,
     /* S_STOPPING           ==> */ A_WARN,
     /* S_TERMINATE          ==> */ A_WARN,
     /* S_TRANSITION_ENGINE  ==> */ A_LOG,
     /* S_HALT               ==> */ A_WARN,
     },

/* Got an I_ROUTER */
    {
     /* S_IDLE               ==> */ A_MSG_ROUTE,
     /* S_ELECTION           ==> */ A_MSG_ROUTE,
     /* S_INTEGRATION        ==> */ A_MSG_ROUTE,
     /* S_FINALIZE_JOIN      ==> */ A_MSG_ROUTE,
     /* S_NOT_DC             ==> */ A_MSG_ROUTE,
     /* S_POLICY_ENGINE      ==> */ A_MSG_ROUTE,
     /* S_RECOVERY           ==> */ A_MSG_ROUTE,
     /* S_RELEASE_DC         ==> */ A_MSG_ROUTE,
     /* S_STARTING           ==> */ A_MSG_ROUTE,
     /* S_PENDING            ==> */ A_MSG_ROUTE,
     /* S_STOPPING           ==> */ A_MSG_ROUTE,
     /* S_TERMINATE          ==> */ A_MSG_ROUTE,
     /* S_TRANSITION_ENGINE  ==> */ A_MSG_ROUTE,
     /* S_HALT               ==> */ A_WARN | A_MSG_ROUTE,
     },

/* Got an I_SHUTDOWN */
    {
     /* S_IDLE               ==> */ A_LOG | A_SHUTDOWN_REQ,
     /* S_ELECTION           ==> */ A_LOG | A_SHUTDOWN_REQ | A_ELECTION_VOTE,
     /* S_INTEGRATION        ==> */ A_LOG | A_SHUTDOWN_REQ,
     /* S_FINALIZE_JOIN      ==> */ A_LOG | A_SHUTDOWN_REQ,
     /* S_NOT_DC             ==> */ A_SHUTDOWN_REQ,
     /* S_POLICY_ENGINE      ==> */ A_LOG | A_SHUTDOWN_REQ,
     /* S_RECOVERY           ==> */ A_WARN | O_EXIT | O_RELEASE,
     /* S_RELEASE_DC         ==> */ A_WARN | A_SHUTDOWN_REQ,
     /* S_STARTING           ==> */ A_WARN | O_EXIT,
     /* S_PENDING            ==> */ A_SHUTDOWN_REQ,
     /* S_STOPPING           ==> */ A_LOG,
     /* S_TERMINATE          ==> */ A_LOG,
     /* S_TRANSITION_ENGINE  ==> */ A_WARN | A_SHUTDOWN_REQ,
     /* S_HALT               ==> */ A_WARN | A_ELECTION_START | A_SHUTDOWN_REQ,
     },

/* Got an I_STOP */
    {
     /* S_IDLE               ==> */ A_ERROR | O_RELEASE | O_EXIT,
     /* S_ELECTION           ==> */ O_RELEASE | O_EXIT,
     /* S_INTEGRATION        ==> */ A_WARN | O_RELEASE | O_EXIT,
     /* S_FINALIZE_JOIN      ==> */ A_ERROR | O_RELEASE | O_EXIT,
     /* S_NOT_DC             ==> */ O_EXIT,
     /* S_POLICY_ENGINE      ==> */ A_WARN | O_RELEASE | O_EXIT,
     /* S_RECOVERY           ==> */ A_ERROR | O_RELEASE | O_EXIT,
     /* S_RELEASE_DC         ==> */ A_ERROR | O_RELEASE | O_EXIT,
     /* S_STARTING           ==> */ O_EXIT,
     /* S_PENDING            ==> */ O_EXIT,
     /* S_STOPPING           ==> */ O_EXIT,
     /* S_TERMINATE          ==> */ A_ERROR | A_EXIT_1,
     /* S_TRANSITION_ENGINE  ==> */ A_LOG | O_RELEASE | O_EXIT,
     /* S_HALT               ==> */ O_RELEASE | O_EXIT | A_WARN,
     },

/* Got an I_TERMINATE */
    {
     /* S_IDLE               ==> */ A_ERROR | O_EXIT,
     /* S_ELECTION           ==> */ A_ERROR | O_EXIT,
     /* S_INTEGRATION        ==> */ A_ERROR | O_EXIT,
     /* S_FINALIZE_JOIN      ==> */ A_ERROR | O_EXIT,
     /* S_NOT_DC             ==> */ A_ERROR | O_EXIT,
     /* S_POLICY_ENGINE      ==> */ A_ERROR | O_EXIT,
     /* S_RECOVERY           ==> */ A_ERROR | O_EXIT,
     /* S_RELEASE_DC         ==> */ A_ERROR | O_EXIT,
     /* S_STARTING           ==> */ O_EXIT,
     /* S_PENDING            ==> */ A_ERROR | O_EXIT,
     /* S_STOPPING           ==> */ O_EXIT,
     /* S_TERMINATE          ==> */ O_EXIT,
     /* S_TRANSITION_ENGINE  ==> */ A_ERROR | O_EXIT,
     /* S_HALT               ==> */ A_ERROR | O_EXIT,
     },

/* Got an I_STARTUP */
    {
     /* S_IDLE               ==> */ A_WARN,
     /* S_ELECTION           ==> */ A_WARN,
     /* S_INTEGRATION        ==> */ A_WARN,
     /* S_FINALIZE_JOIN      ==> */ A_WARN,
     /* S_NOT_DC             ==> */ A_WARN,
     /* S_POLICY_ENGINE      ==> */ A_WARN,
     /* S_RECOVERY           ==> */ A_WARN,
     /* S_RELEASE_DC         ==> */ A_WARN,
     /* S_STARTING           ==> */
     A_LOG | A_STARTUP | A_CIB_START | A_LRM_CONNECT | A_HA_CONNECT | A_READCONFIG | A_STARTED,
     /* S_PENDING            ==> */ A_LOG,
     /* S_STOPPING           ==> */ A_WARN,
     /* S_TERMINATE          ==> */ A_WARN,
     /* S_TRANSITION_ENGINE  ==> */ A_WARN,
     /* S_HALT               ==> */ A_WARN,
     },

/* Got an I_PE_SUCCESS */
    {
     /* S_IDLE               ==> */ A_LOG,
     /* S_ELECTION           ==> */ A_WARN,
     /* S_INTEGRATION        ==> */ A_WARN,
     /* S_FINALIZE_JOIN      ==> */ A_WARN,
     /* S_NOT_DC             ==> */ A_NOTHING,
     /* S_POLICY_ENGINE      ==> */ A_TE_INVOKE,
     /* S_RECOVERY           ==> */ A_RECOVER | A_LOG,
     /* S_RELEASE_DC         ==> */ A_LOG,
     /* S_STARTING           ==> */ A_ERROR,
     /* S_PENDING            ==> */ A_LOG,
     /* S_STOPPING           ==> */ A_ERROR,
     /* S_TERMINATE          ==> */ A_ERROR,
     /* S_TRANSITION_ENGINE  ==> */ A_LOG,
     /* S_HALT               ==> */ A_WARN,
     },

/* Got an I_JOIN_OFFER */
    {
     /* S_IDLE               ==> */ A_WARN | A_CL_JOIN_REQUEST,
     /* S_ELECTION           ==> */ A_WARN | A_ELECTION_VOTE,
     /* S_INTEGRATION        ==> */ A_CL_JOIN_REQUEST,
     /* S_FINALIZE_JOIN      ==> */ A_CL_JOIN_REQUEST,
     /* S_NOT_DC             ==> */ A_CL_JOIN_REQUEST | A_DC_TIMER_STOP,
     /* S_POLICY_ENGINE      ==> */ A_WARN | A_CL_JOIN_REQUEST,
     /* S_RECOVERY           ==> */ A_WARN | A_CL_JOIN_REQUEST | A_DC_TIMER_STOP,
     /* S_RELEASE_DC         ==> */ A_WARN | A_CL_JOIN_REQUEST | A_DC_TIMER_STOP,
     /* S_STARTING           ==> */ A_LOG,
     /* S_PENDING            ==> */ A_CL_JOIN_REQUEST | A_DC_TIMER_STOP,
     /* S_STOPPING           ==> */ A_LOG,
     /* S_TERMINATE          ==> */ A_LOG,
     /* S_TRANSITION_ENGINE  ==> */ A_WARN | A_CL_JOIN_REQUEST,
     /* S_HALT               ==> */ A_WARN,
     },

/* Got an I_JOIN_REQUEST */
    {
     /* S_IDLE               ==> */ A_DC_JOIN_OFFER_ONE,
     /* S_ELECTION           ==> */ A_WARN,
     /* S_INTEGRATION        ==> */ A_DC_JOIN_PROCESS_REQ,
     /* S_FINALIZE_JOIN      ==> */ A_DC_JOIN_OFFER_ONE,
     /* S_NOT_DC             ==> */ A_WARN,
     /* S_POLICY_ENGINE      ==> */ A_DC_JOIN_OFFER_ONE,
     /* S_RECOVERY           ==> */ A_WARN,
     /* S_RELEASE_DC         ==> */ A_WARN,
     /* S_STARTING           ==> */ A_WARN,
     /* S_PENDING            ==> */ A_WARN,
     /* S_STOPPING           ==> */ A_WARN,
     /* S_TERMINATE          ==> */ A_WARN,
     /* S_TRANSITION_ENGINE  ==> */ A_DC_JOIN_OFFER_ONE,
     /* S_HALT               ==> */ A_WARN,
     },

/* Got an I_JOIN_RESULT */
    {
     /* S_IDLE               ==> */ A_ERROR | A_TE_HALT | A_DC_JOIN_OFFER_ALL,
     /* S_ELECTION           ==> */ A_LOG,
     /* S_INTEGRATION        ==> */ A_LOG | A_CL_JOIN_RESULT  | A_DC_JOIN_PROCESS_ACK,
     /* S_FINALIZE_JOIN      ==> */ A_CL_JOIN_RESULT | A_DC_JOIN_PROCESS_ACK,
     /* S_NOT_DC             ==> */ A_ERROR | A_CL_JOIN_ANNOUNCE,
     /* S_POLICY_ENGINE      ==> */ A_ERROR | A_TE_HALT | A_DC_JOIN_OFFER_ALL,
     /* S_RECOVERY           ==> */ A_LOG,
     /* S_RELEASE_DC         ==> */ A_LOG,
     /* S_STARTING           ==> */ A_ERROR,
     /* S_PENDING            ==> */ A_CL_JOIN_RESULT,
     /* S_STOPPING           ==> */ A_ERROR,
     /* S_TERMINATE          ==> */ A_ERROR,
     /* S_TRANSITION_ENGINE  ==> */ A_ERROR | A_TE_HALT | A_DC_JOIN_OFFER_ALL,
     /* S_HALT               ==> */ A_WARN,
     },

/* Got an I_WAIT_FOR_EVENT */
    {
     /* S_IDLE               ==> */ A_LOG,
     /* S_ELECTION           ==> */ A_LOG,
     /* S_INTEGRATION        ==> */ A_LOG,
     /* S_FINALIZE_JOIN      ==> */ A_LOG,
     /* S_NOT_DC             ==> */ A_LOG,
     /* S_POLICY_ENGINE      ==> */ A_LOG,
     /* S_RECOVERY           ==> */ A_LOG,
     /* S_RELEASE_DC         ==> */ A_LOG,
     /* S_STARTING           ==> */ A_LOG,
     /* S_PENDING            ==> */ A_LOG,
     /* S_STOPPING           ==> */ A_LOG,
     /* S_TERMINATE          ==> */ A_LOG,
     /* S_TRANSITION_ENGINE  ==> */ A_LOG,
     /* S_HALT               ==> */ A_WARN,
     },

/* Got an I_DC_HEARTBEAT */
    {
     /* S_IDLE               ==> */ A_ERROR,
     /* S_ELECTION           ==> */ A_WARN | A_ELECTION_VOTE,
     /* S_INTEGRATION        ==> */ A_ERROR,
     /* S_FINALIZE_JOIN      ==> */ A_ERROR,
     /* S_NOT_DC             ==> */ A_NOTHING,
     /* S_POLICY_ENGINE      ==> */ A_ERROR,
     /* S_RECOVERY           ==> */ A_NOTHING,
     /* S_RELEASE_DC         ==> */ A_LOG,
     /* S_STARTING           ==> */ A_LOG,
     /* S_PENDING            ==> */ A_LOG | A_CL_JOIN_ANNOUNCE,
     /* S_STOPPING           ==> */ A_NOTHING,
     /* S_TERMINATE          ==> */ A_NOTHING,
     /* S_TRANSITION_ENGINE  ==> */ A_ERROR,
     /* S_HALT               ==> */ A_WARN,
     },

/* For everyone ending up in S_PENDING, (re)start the DC timer and wait for I_JOIN_OFFER or I_NOT_DC */
/* Got an I_PENDING */
    {
     /* S_IDLE               ==> */ O_RELEASE | O_DC_TIMER_RESTART,
     /* S_ELECTION           ==> */ O_RELEASE | O_DC_TIMER_RESTART,
     /* S_INTEGRATION        ==> */ O_RELEASE | O_DC_TIMER_RESTART,
     /* S_FINALIZE_JOIN      ==> */ O_RELEASE | O_DC_TIMER_RESTART,
     /* S_NOT_DC             ==> */ A_LOG | O_DC_TIMER_RESTART,
     /* S_POLICY_ENGINE      ==> */ O_RELEASE | O_DC_TIMER_RESTART,
     /* S_RECOVERY           ==> */ A_WARN,
     /* S_RELEASE_DC         ==> */ A_WARN | O_DC_TIMER_RESTART,
     /* S_STARTING           ==> */ A_LOG | A_DC_TIMER_START | A_CL_JOIN_QUERY,
     /* S_PENDING            ==> */ A_LOG | O_DC_TIMER_RESTART,
     /* S_STOPPING           ==> */ A_WARN,
     /* S_TERMINATE          ==> */ A_WARN,
     /* S_TRANSITION_ENGINE  ==> */ O_RELEASE | O_DC_TIMER_RESTART,
     /* S_HALT               ==> */ A_WARN,
     },

/* Got an I_HALT */
    {
     /* S_IDLE               ==> */ A_WARN,
     /* S_ELECTION           ==> */ A_WARN,
     /* S_INTEGRATION        ==> */ A_WARN,
     /* S_FINALIZE_JOIN      ==> */ A_WARN,
     /* S_NOT_DC             ==> */ A_WARN,
     /* S_POLICY_ENGINE      ==> */ A_WARN,
     /* S_RECOVERY           ==> */ A_WARN,
     /* S_RELEASE_DC         ==> */ A_WARN,
     /* S_STARTING           ==> */ A_WARN,
     /* S_PENDING            ==> */ A_WARN,
     /* S_STOPPING           ==> */ A_WARN,
     /* S_TERMINATE          ==> */ A_WARN,
     /* S_TRANSITION_ENGINE  ==> */ A_WARN,
     /* S_HALT               ==> */ A_WARN,
     },
};

/*!
 * \internal
 * \brief Get the next FSA state given an input and the current state
 *
 * \param[in] input  FSA input
 *
 * \return The next FSA state
 */
enum crmd_fsa_state
controld_fsa_get_next_state(enum crmd_fsa_input input)
{
    return fsa_next_states[input][controld_globals.fsa_state];
}

/*!
 * \internal
 * \brief Get the appropriate FSA action given an input and the current state
 *
 * \param[in] input  FSA input
 *
 * \return The appropriate FSA action
 */
uint64_t
controld_fsa_get_action(enum crmd_fsa_input input)
{
    return fsa_actions[input][controld_globals.fsa_state];
}
