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

#ifndef XML_FSA_MATRIX__H
#define XML_FSA_MATRIX__H

/*
 *	The state transition table.  The rows are inputs, and
 *	the columns are states.
 */
const enum crmd_fsa_state crmd_fsa_state [MAXINPUT][MAXSTATE] = 
{
/* Got an I_NULL */
	{
		/* S_IDLE		==> */	S_IDLE,
		/* S_ELECTION		==> */	S_ELECTION,
		/* S_INTEGRATION	==> */	S_INTEGRATION,
		/* S_NOT_DC		==> */	S_NOT_DC,
		/* S_POLICY_ENGINE	==> */	S_POLICY_ENGINE,
		/* S_RECOVERY		==> */	S_RECOVERY,
		/* S_RECOVERY_DC	==> */	S_RECOVERY_DC,
		/* S_RELEASE_DC		==> */	S_RELEASE_DC,
		/* S_PENDING		==> */	S_PENDING,
		/* S_STOPPING		==> */	S_STOPPING,
		/* S_TERMINATE		==> */	S_TERMINATE,
		/* S_TRANSITION_ENGINE	==> */	S_TRANSITION_ENGINE,
	},

/* Got an I_CCM_EVENT */
	{
		/* S_IDLE		==> */	S_IDLE,
		/* S_ELECTION		==> */	S_ELECTION,
		/* S_INTEGRATION	==> */	S_INTEGRATION,
		/* S_NOT_DC		==> */	S_NOT_DC,
		/* S_POLICY_ENGINE	==> */	S_POLICY_ENGINE,
		/* S_RECOVERY		==> */	S_RECOVERY,
		/* S_RECOVERY_DC	==> */	S_RECOVERY_DC,
		/* S_RELEASE_DC		==> */	S_RELEASE_DC,
		/* S_PENDING		==> */	S_PENDING,
		/* S_STOPPING		==> */	S_STOPPING,
		/* S_TERMINATE		==> */	S_TERMINATE,
		/* S_TRANSITION_ENGINE	==> */	S_TRANSITION_ENGINE,
	},

/* Got an I_CIB_OP */
	{
		/* S_IDLE		==> */	S_IDLE,
		/* S_ELECTION		==> */	S_ELECTION,
		/* S_INTEGRATION	==> */	S_INTEGRATION,
		/* S_NOT_DC		==> */	S_NOT_DC,
		/* S_POLICY_ENGINE	==> */	S_POLICY_ENGINE,
		/* S_RECOVERY		==> */	S_RECOVERY,
		/* S_RECOVERY_DC	==> */	S_RECOVERY_DC,
		/* S_RELEASE_DC		==> */	S_RELEASE_DC,
		/* S_PENDING		==> */	S_PENDING,
		/* S_STOPPING		==> */	S_STOPPING,
		/* S_TERMINATE		==> */	S_TERMINATE,
		/* S_TRANSITION_ENGINE	==> */	S_TRANSITION_ENGINE,
	},

/* Got an I_CIB_UPDATE */
	{
		/* S_IDLE		==> */	S_IDLE,
		/* S_ELECTION		==> */	S_ELECTION,
		/* S_INTEGRATION	==> */	S_INTEGRATION,
		/* S_NOT_DC		==> */	S_RECOVERY,
		/* S_POLICY_ENGINE	==> */	S_POLICY_ENGINE,
		/* S_RECOVERY		==> */	S_RECOVERY,
		/* S_RECOVERY_DC	==> */	S_RECOVERY_DC,
		/* S_RELEASE_DC		==> */	S_RELEASE_DC,
		/* S_PENDING		==> */	S_RECOVERY,
		/* S_STOPPING		==> */	S_STOPPING,
		/* S_TERMINATE		==> */	S_TERMINATE,
		/* S_TRANSITION_ENGINE	==> */	S_TRANSITION_ENGINE,
	},

/* Got an I_DC_TIMEOUT */
	{
		/* S_IDLE		==> */	S_RECOVERY,
		/* S_ELECTION		==> */	S_ELECTION,
		/* S_INTEGRATION	==> */	S_RECOVERY,
		/* S_NOT_DC		==> */	S_ELECTION,
		/* S_POLICY_ENGINE	==> */	S_RECOVERY,
		/* S_RECOVERY		==> */	S_RECOVERY,
		/* S_RECOVERY_DC	==> */	S_RECOVERY_DC,
		/* S_RELEASE_DC		==> */	S_RECOVERY,
		/* S_PENDING		==> */	S_ELECTION,
		/* S_STOPPING		==> */	S_STOPPING,
		/* S_TERMINATE		==> */	S_TERMINATE,
		/* S_TRANSITION_ENGINE	==> */	S_RECOVERY,
	},

/* Got an I_ELECTION */
	{
		/* S_IDLE		==> */	S_ELECTION,
		/* S_ELECTION		==> */	S_ELECTION,
		/* S_INTEGRATION	==> */	S_ELECTION,
		/* S_NOT_DC		==> */	S_ELECTION,
		/* S_POLICY_ENGINE	==> */	S_ELECTION,
		/* S_RECOVERY		==> */	S_RECOVERY,
		/* S_RECOVERY_DC	==> */	S_RECOVERY,
		/* S_RELEASE_DC		==> */	S_RELEASE_DC,
		/* S_PENDING		==> */	S_ELECTION,
		/* S_STOPPING		==> */	S_STOPPING,
		/* S_TERMINATE		==> */	S_TERMINATE,
		/* S_TRANSITION_ENGINE	==> */	S_ELECTION,
	},

/* Got an I_PE_CALC */
	{
		/* S_IDLE		==> */	S_POLICY_ENGINE,
		/* S_ELECTION		==> */	S_ELECTION,
		/* S_INTEGRATION	==> */	S_POLICY_ENGINE,
		/* S_NOT_DC		==> */	S_RECOVERY,
		/* S_POLICY_ENGINE	==> */	S_POLICY_ENGINE,
		/* S_RECOVERY		==> */	S_RECOVERY,
		/* S_RECOVERY_DC	==> */	S_RECOVERY_DC,
		/* S_RELEASE_DC		==> */	S_RELEASE_DC,
		/* S_PENDING		==> */	S_RECOVERY,
		/* S_STOPPING		==> */	S_STOPPING,
		/* S_TERMINATE		==> */	S_TERMINATE,
		/* S_TRANSITION_ENGINE	==> */	S_POLICY_ENGINE,
	},

/* Got an I_RELEASE_DC */
	{
		/* S_IDLE		==> */	S_RECOVERY,
		/* S_ELECTION		==> */	S_RELEASE_DC,
		/* S_INTEGRATION	==> */	S_RECOVERY,
		/* S_NOT_DC		==> */	S_NOT_DC,
		/* S_POLICY_ENGINE	==> */	S_RECOVERY,
		/* S_RECOVERY		==> */	S_RECOVERY,
		/* S_RECOVERY_DC	==> */	S_RECOVERY,
		/* S_RELEASE_DC		==> */	S_RELEASE_DC,
		/* S_PENDING		==> */	S_PENDING,
		/* S_STOPPING		==> */	S_STOPPING,
		/* S_TERMINATE		==> */	S_TERMINATE,
		/* S_TRANSITION_ENGINE	==> */	S_RELEASE_DC,
	},

/* Got an I_ELECTION_DC */
	{
		/* S_IDLE		==> */	S_INTEGRATION,
		/* S_ELECTION		==> */	S_INTEGRATION,
		/* S_INTEGRATION	==> */	S_INTEGRATION,
		/* S_NOT_DC		==> */	S_INTEGRATION,
		/* S_POLICY_ENGINE	==> */	S_INTEGRATION,
		/* S_RECOVERY		==> */	S_RECOVERY_DC,
		/* S_RECOVERY_DC	==> */	S_RECOVERY_DC,
		/* S_RELEASE_DC		==> */	S_RELEASE_DC,
		/* S_PENDING		==> */	S_INTEGRATION,
		/* S_STOPPING		==> */	S_STOPPING,
		/* S_TERMINATE		==> */	S_TERMINATE,
		/* S_TRANSITION_ENGINE	==> */	S_INTEGRATION,
	},

/* Got an I_ERROR */
	{
		/* S_IDLE		==> */	S_RECOVERY_DC,
		/* S_ELECTION		==> */	S_RELEASE_DC,
		/* S_INTEGRATION	==> */	S_INTEGRATION,
		/* S_NOT_DC		==> */	S_RECOVERY,
		/* S_POLICY_ENGINE	==> */	S_RECOVERY_DC,
		/* S_RECOVERY		==> */	S_RECOVERY,
		/* S_RECOVERY_DC	==> */	S_RELEASE_DC,
		/* S_RELEASE_DC		==> */	S_STOPPING,
		/* S_PENDING		==> */	S_STOPPING,
		/* S_STOPPING		==> */	S_TERMINATE,
		/* S_TERMINATE		==> */	S_TERMINATE,
		/* S_TRANSITION_ENGINE	==> */	S_RECOVERY_DC,
	},

/* Got an I_FAIL */
	{
		/* S_IDLE		==> */	S_RECOVERY_DC,
		/* S_ELECTION		==> */	S_RELEASE_DC,
		/* S_INTEGRATION	==> */	S_INTEGRATION,
		/* S_NOT_DC		==> */	S_RECOVERY,
		/* S_POLICY_ENGINE	==> */	S_INTEGRATION,
		/* S_RECOVERY		==> */	S_RECOVERY,
		/* S_RECOVERY_DC	==> */	S_RECOVERY_DC,
		/* S_RELEASE_DC		==> */	S_RELEASE_DC,
		/* S_PENDING		==> */	S_STOPPING,
		/* S_STOPPING		==> */	S_STOPPING,
		/* S_TERMINATE		==> */	S_TERMINATE,
		/* S_TRANSITION_ENGINE	==> */	S_POLICY_ENGINE,
	},

/* Got an I_INTEGRATION_TIMEOUT */
	{
		/* S_IDLE		==> */	S_IDLE,
		/* S_ELECTION		==> */	S_ELECTION,
		/* S_INTEGRATION	==> */	S_POLICY_ENGINE,
		/* S_NOT_DC		==> */	S_NOT_DC,
		/* S_POLICY_ENGINE	==> */	S_POLICY_ENGINE,
		/* S_RECOVERY		==> */	S_RECOVERY,
		/* S_RECOVERY_DC	==> */	S_RECOVERY_DC,
		/* S_RELEASE_DC		==> */	S_RELEASE_DC,
		/* S_PENDING		==> */	S_PENDING,
		/* S_STOPPING		==> */	S_STOPPING,
		/* S_TERMINATE		==> */	S_TERMINATE,
		/* S_TRANSITION_ENGINE	==> */	S_TRANSITION_ENGINE,
	},

/* Got an I_NODE_JOIN */
	{
		/* S_IDLE		==> */	S_INTEGRATION,
		/* S_ELECTION		==> */	S_ELECTION,
		/* S_INTEGRATION	==> */	S_INTEGRATION,
		/* S_NOT_DC		==> */	S_NOT_DC,
		/* S_POLICY_ENGINE	==> */	S_INTEGRATION,
		/* S_RECOVERY		==> */	S_RECOVERY,
		/* S_RECOVERY_DC	==> */	S_RECOVERY_DC,
		/* S_RELEASE_DC		==> */	S_RELEASE_DC,
		/* S_PENDING		==> */	S_PENDING,
		/* S_STOPPING		==> */	S_STOPPING,
		/* S_TERMINATE		==> */	S_TERMINATE,
		/* S_TRANSITION_ENGINE	==> */	S_INTEGRATION,
	},

/* Got an I_NODE_LEFT */
	{
		/* S_IDLE		==> */	S_POLICY_ENGINE,
		/* S_ELECTION		==> */	S_ELECTION,
		/* S_INTEGRATION	==> */	S_INTEGRATION,
		/* S_NOT_DC		==> */	S_NOT_DC,
		/* S_POLICY_ENGINE	==> */	S_POLICY_ENGINE,
		/* S_RECOVERY		==> */	S_RECOVERY,
		/* S_RECOVERY_DC	==> */	S_RECOVERY_DC,
		/* S_RELEASE_DC		==> */	S_RELEASE_DC,
		/* S_PENDING		==> */	S_PENDING,
		/* S_STOPPING		==> */	S_STOPPING,
		/* S_TERMINATE		==> */	S_TERMINATE,
		/* S_TRANSITION_ENGINE	==> */	S_POLICY_ENGINE,
	},
	
/* Got an I_NOT_DC */
	{
		/* S_IDLE		==> */	S_RECOVERY,
		/* S_ELECTION		==> */	S_PENDING,
		/* S_INTEGRATION	==> */	S_RECOVERY,
		/* S_NOT_DC		==> */	S_NOT_DC,
		/* S_POLICY_ENGINE	==> */	S_RECOVERY,
		/* S_RECOVERY		==> */	S_RECOVERY,
		/* S_RECOVERY_DC	==> */	S_RECOVERY,
		/* S_RELEASE_DC		==> */	S_RELEASE_DC,
		/* S_PENDING		==> */	S_PENDING,
		/* S_STOPPING		==> */	S_STOPPING,
		/* S_TERMINATE		==> */	S_TERMINATE,
		/* S_TRANSITION_ENGINE	==> */	S_RECOVERY,
	},

/* Got an I_RECOVERED */
	{
		/* S_IDLE		==> */	S_IDLE,
		/* S_ELECTION		==> */	S_ELECTION,
		/* S_INTEGRATION	==> */	S_INTEGRATION,
		/* S_NOT_DC		==> */	S_NOT_DC,
		/* S_POLICY_ENGINE	==> */	S_POLICY_ENGINE,
		/* S_RECOVERY		==> */	S_PENDING,
		/* S_RECOVERY_DC	==> */	S_INTEGRATION,
		/* S_RELEASE_DC		==> */	S_RELEASE_DC,
		/* S_PENDING		==> */	S_PENDING,
		/* S_STOPPING		==> */	S_STOPPING,
		/* S_TERMINATE		==> */	S_TERMINATE,
		/* S_TRANSITION_ENGINE	==> */	S_TRANSITION_ENGINE,
	},

/* Got an I_RELEASE_FAIL */
	{
		/* S_IDLE		==> */	S_STOPPING,
		/* S_ELECTION		==> */	S_STOPPING,
		/* S_INTEGRATION	==> */	S_STOPPING,
		/* S_NOT_DC		==> */	S_NOT_DC,
		/* S_POLICY_ENGINE	==> */	S_STOPPING,
		/* S_RECOVERY		==> */	S_STOPPING,
		/* S_RECOVERY_DC	==> */	S_STOPPING,
		/* S_RELEASE_DC		==> */	S_STOPPING,
		/* S_PENDING		==> */	S_PENDING,
		/* S_STOPPING		==> */	S_STOPPING,
		/* S_TERMINATE		==> */	S_TERMINATE,
		/* S_TRANSITION_ENGINE	==> */	S_STOPPING,
	},

/* Got an I_RELEASE_SUCCESS */
	{
		/* S_IDLE		==> */	S_RECOVERY,
		/* S_ELECTION		==> */	S_ELECTION,
		/* S_INTEGRATION	==> */	S_RECOVERY,
		/* S_NOT_DC		==> */	S_NOT_DC,
		/* S_POLICY_ENGINE	==> */	S_RECOVERY,
		/* S_RECOVERY		==> */	S_RECOVERY,
		/* S_RECOVERY_DC	==> */	S_RECOVERY,
		/* S_RELEASE_DC		==> */	S_PENDING,
		/* S_PENDING		==> */	S_PENDING,
		/* S_STOPPING		==> */	S_STOPPING,
		/* S_TERMINATE		==> */	S_TERMINATE,
		/* S_TRANSITION_ENGINE	==> */	S_RECOVERY,
	},

/* Got an I_RESTART */
	{
		/* S_IDLE		==> */	S_IDLE,
		/* S_ELECTION		==> */	S_ELECTION,
		/* S_INTEGRATION	==> */	S_INTEGRATION,
		/* S_NOT_DC		==> */	S_NOT_DC,
		/* S_POLICY_ENGINE	==> */	S_POLICY_ENGINE,
		/* S_RECOVERY		==> */	S_RECOVERY,
		/* S_RECOVERY_DC	==> */	S_RECOVERY_DC,
		/* S_RELEASE_DC		==> */	S_RELEASE_DC,
		/* S_PENDING		==> */	S_PENDING,
		/* S_STOPPING		==> */	S_STOPPING,
		/* S_TERMINATE		==> */	S_TERMINATE,
		/* S_TRANSITION_ENGINE	==> */	S_TRANSITION_ENGINE,
	},

/* Got an I_REQUEST */
	{
		/* S_IDLE		==> */	S_IDLE,
		/* S_ELECTION		==> */	S_ELECTION,
		/* S_INTEGRATION	==> */	S_INTEGRATION,
		/* S_NOT_DC		==> */	S_NOT_DC,
		/* S_POLICY_ENGINE	==> */	S_POLICY_ENGINE,
		/* S_RECOVERY		==> */	S_RECOVERY,
		/* S_RECOVERY_DC	==> */	S_RECOVERY_DC,
		/* S_RELEASE_DC		==> */	S_RELEASE_DC,
		/* S_PENDING		==> */	S_PENDING,
		/* S_STOPPING		==> */	S_STOPPING,
		/* S_TERMINATE		==> */	S_TERMINATE,
		/* S_TRANSITION_ENGINE	==> */	S_TRANSITION_ENGINE,
	},

/* Got an I_ROUTER */
	{
		/* S_IDLE		==> */	S_IDLE,
		/* S_ELECTION		==> */	S_ELECTION,
		/* S_INTEGRATION	==> */	S_INTEGRATION,
		/* S_NOT_DC		==> */	S_NOT_DC,
		/* S_POLICY_ENGINE	==> */	S_POLICY_ENGINE,
		/* S_RECOVERY		==> */	S_RECOVERY,
		/* S_RECOVERY_DC	==> */	S_RECOVERY_DC,
		/* S_RELEASE_DC		==> */	S_RELEASE_DC,
		/* S_PENDING		==> */	S_PENDING,
		/* S_STOPPING		==> */	S_STOPPING,
		/* S_TERMINATE		==> */	S_TERMINATE,
		/* S_TRANSITION_ENGINE	==> */	S_TRANSITION_ENGINE,
	},

/* Got an I_SHUTDOWN */
	{
		/* S_IDLE		==> */	S_RELEASE_DC,
		/* S_ELECTION		==> */	S_RELEASE_DC,
		/* S_INTEGRATION	==> */	S_RELEASE_DC,
		/* S_NOT_DC		==> */	S_NOT_DC,
		/* S_POLICY_ENGINE	==> */	S_RELEASE_DC,
		/* S_RECOVERY		==> */	S_PENDING,
		/* S_RECOVERY_DC	==> */	S_PENDING,
		/* S_RELEASE_DC		==> */	S_RELEASE_DC,
		/* S_PENDING		==> */	S_PENDING,
		/* S_STOPPING		==> */	S_STOPPING,
		/* S_TERMINATE		==> */	S_TERMINATE,
		/* S_TRANSITION_ENGINE	==> */	S_RELEASE_DC,
	},

/* Got an I_TERMINATE */
	{
		/* S_IDLE		==> */	S_RELEASE_DC,
		/* S_ELECTION		==> */	S_RELEASE_DC,
		/* S_INTEGRATION	==> */	S_RELEASE_DC,
		/* S_NOT_DC		==> */	S_STOPPING,
		/* S_POLICY_ENGINE	==> */	S_RELEASE_DC,
		/* S_RECOVERY		==> */	S_STOPPING,
		/* S_RECOVERY_DC	==> */	S_STOPPING,
		/* S_RELEASE_DC		==> */	S_RELEASE_DC,
		/* S_PENDING		==> */	S_STOPPING,
		/* S_STOPPING		==> */	S_STOPPING,
		/* S_TERMINATE		==> */	S_TERMINATE,
		/* S_TRANSITION_ENGINE	==> */	S_RELEASE_DC,
	},

/* Got an I_STARTUP */
	{
		/* S_IDLE		==> */	S_IDLE,
		/* S_ELECTION		==> */	S_ELECTION,
		/* S_INTEGRATION	==> */	S_INTEGRATION,
		/* S_NOT_DC		==> */	S_NOT_DC,
		/* S_POLICY_ENGINE	==> */	S_POLICY_ENGINE,
		/* S_RECOVERY		==> */	S_RECOVERY,
		/* S_RECOVERY_DC	==> */	S_RECOVERY_DC,
		/* S_RELEASE_DC		==> */	S_RELEASE_DC,
		/* S_PENDING		==> */	S_PENDING,
		/* S_STOPPING		==> */	S_STOPPING,
		/* S_TERMINATE		==> */	S_TERMINATE,
		/* S_TRANSITION_ENGINE	==> */	S_TRANSITION_ENGINE,
	},

/* Got an I_SUCCESS */
	{
		/* S_IDLE		==> */	S_IDLE,
		/* S_ELECTION		==> */	S_ELECTION,
		/* S_INTEGRATION	==> */	S_POLICY_ENGINE,
		/* S_NOT_DC		==> */	S_NOT_DC,
		/* S_POLICY_ENGINE	==> */	S_TRANSITION_ENGINE,
		/* S_RECOVERY		==> */	S_RECOVERY,
		/* S_RECOVERY_DC	==> */	S_RECOVERY_DC,
		/* S_RELEASE_DC		==> */	S_RELEASE_DC,
		/* S_PENDING		==> */	S_PENDING,
		/* S_STOPPING		==> */	S_TERMINATE,
		/* S_TERMINATE		==> */	S_TERMINATE,
		/* S_TRANSITION_ENGINE	==> */	S_IDLE,
	},

/* Got an I_WELCOME */
	{
		/* S_IDLE		==> */	S_RELEASE_DC,
		/* S_ELECTION		==> */	S_RELEASE_DC,
		/* S_INTEGRATION	==> */	S_RELEASE_DC,
		/* S_NOT_DC		==> */	S_NOT_DC,
		/* S_POLICY_ENGINE	==> */	S_RELEASE_DC,
		/* S_RECOVERY		==> */	S_RECOVERY,
		/* S_RECOVERY_DC	==> */	S_RELEASE_DC,
		/* S_RELEASE_DC		==> */	S_RELEASE_DC,
		/* S_PENDING		==> */	S_NOT_DC,
		/* S_STOPPING		==> */	S_STOPPING,
		/* S_TERMINATE		==> */	S_TERMINATE,
		/* S_TRANSITION_ENGINE	==> */	S_RELEASE_DC,
	},

/* Got an I_WELCOME_ACK */
	{
		/* S_IDLE		==> */	S_IDLE,
		/* S_ELECTION		==> */	S_ELECTION,
		/* S_INTEGRATION	==> */	S_INTEGRATION,
		/* S_NOT_DC		==> */	S_NOT_DC,
		/* S_POLICY_ENGINE	==> */	S_POLICY_ENGINE,
		/* S_RECOVERY		==> */	S_RECOVERY,
		/* S_RECOVERY_DC	==> */	S_RECOVERY_DC,
		/* S_RELEASE_DC		==> */	S_RELEASE_DC,
		/* S_PENDING		==> */	S_PENDING,
		/* S_STOPPING		==> */	S_STOPPING,
		/* S_TERMINATE		==> */	S_TERMINATE,
		/* S_TRANSITION_ENGINE	==> */	S_TRANSITION_ENGINE,
	},

/* Got an I_WAIT_FOR_EVENT */
	{
		/* S_IDLE		==> */	S_IDLE,
		/* S_ELECTION		==> */	S_ELECTION,
		/* S_INTEGRATION	==> */	S_INTEGRATION,
		/* S_NOT_DC		==> */	S_NOT_DC,
		/* S_POLICY_ENGINE	==> */	S_POLICY_ENGINE,
		/* S_RECOVERY		==> */	S_RECOVERY,
		/* S_RECOVERY_DC	==> */	S_RECOVERY_DC,
		/* S_RELEASE_DC		==> */	S_RELEASE_DC,
		/* S_PENDING		==> */	S_PENDING,
		/* S_STOPPING		==> */	S_STOPPING,
		/* S_TERMINATE		==> */	S_TERMINATE,
		/* S_TRANSITION_ENGINE	==> */	S_TRANSITION_ENGINE,
	},

/* Got an I_DC_HEARTBEAT */
	{
		/* S_IDLE		==> */	S_ELECTION,
		/* S_ELECTION		==> */	S_ELECTION,
		/* S_INTEGRATION	==> */	S_ELECTION,
		/* S_NOT_DC		==> */	S_NOT_DC,
		/* S_POLICY_ENGINE	==> */	S_ELECTION,
		/* S_RECOVERY		==> */	S_RECOVERY,
		/* S_RECOVERY_DC	==> */	S_RECOVERY,
		/* S_RELEASE_DC		==> */	S_RELEASE_DC,
		/* S_PENDING		==> */	S_PENDING,
		/* S_STOPPING		==> */	S_STOPPING,
		/* S_TERMINATE		==> */	S_TERMINATE,
		/* S_TRANSITION_ENGINE	==> */	S_ELECTION,
	},

/* Got an I_LRM_EVENT */
	{
		/* S_IDLE		==> */	S_IDLE,
		/* S_ELECTION		==> */	S_ELECTION,
		/* S_INTEGRATION	==> */	S_INTEGRATION,
		/* S_NOT_DC		==> */	S_NOT_DC,
		/* S_POLICY_ENGINE	==> */	S_POLICY_ENGINE,
		/* S_RECOVERY		==> */	S_RECOVERY,
		/* S_RECOVERY_DC	==> */	S_RECOVERY_DC,
		/* S_RELEASE_DC		==> */	S_RELEASE_DC,
		/* S_PENDING		==> */	S_PENDING,
		/* S_STOPPING		==> */	S_STOPPING,
		/* S_TERMINATE		==> */	S_TERMINATE,
		/* S_TRANSITION_ENGINE	==> */	S_TRANSITION_ENGINE,
	},
};

		

/*
 *	The action table.  Each entry is a set of actions to take or-ed
 *	together.  Like the state table, the rows are inputs, and
 *	the columns are states.
 */
const long long crmd_fsa_actions [MAXINPUT][MAXSTATE] = {

/* Got an I_NULL */
	{
		/* S_IDLE		==> */	A_NOTHING,
		/* S_ELECTION		==> */	A_NOTHING,
		/* S_INTEGRATION	==> */	A_NOTHING,
		/* S_NOT_DC		==> */	A_NOTHING,
		/* S_POLICY_ENGINE	==> */	A_NOTHING,
		/* S_RECOVERY		==> */	A_RECOVER,
		/* S_RECOVERY_DC	==> */	A_RECOVER,
		/* S_RELEASE_DC		==> */	A_NOTHING,
		/* S_PENDING		==> */	A_NOTHING,
		/* S_STOPPING		==> */	A_NOTHING,
		/* S_TERMINATE		==> */	A_NOTHING,
		/* S_TRANSITION_ENGINE	==> */	A_NOTHING,
	},

/* Got an I_CCM_EVENT */
	{
		/* S_IDLE		==> */	A_CCM_EVENT|A_CCM_UPDATE_CACHE,
		/* S_ELECTION		==> */	A_CCM_EVENT|A_CCM_UPDATE_CACHE,
		/* S_INTEGRATION	==> */	A_CCM_EVENT|A_CCM_UPDATE_CACHE,
		/* S_NOT_DC		==> */	A_CCM_EVENT|A_CCM_UPDATE_CACHE,
		/* S_POLICY_ENGINE	==> */	A_CCM_EVENT|A_CCM_UPDATE_CACHE,
		/* S_RECOVERY		==> */	A_CCM_EVENT|A_CCM_UPDATE_CACHE,
		/* S_RECOVERY_DC	==> */	A_CCM_EVENT|A_CCM_UPDATE_CACHE,
		/* S_RELEASE_DC		==> */	A_CCM_EVENT|A_CCM_UPDATE_CACHE,
		/* S_PENDING		==> */	A_CCM_EVENT|A_CCM_UPDATE_CACHE,
		/* S_STOPPING		==> */	A_NOTHING,
		/* S_TERMINATE		==> */	A_NOTHING,
		/* S_TRANSITION_ENGINE	==> */	A_CCM_EVENT|A_CCM_UPDATE_CACHE,
	},

/* Got an I_CIB_OP */
	{
		/* S_IDLE		==> */	A_CIB_INVOKE,
		/* S_ELECTION		==> */	A_CIB_INVOKE,
		/* S_INTEGRATION	==> */	A_CIB_INVOKE, 
		/* S_NOT_DC		==> */	A_CIB_INVOKE,
		/* S_POLICY_ENGINE	==> */	A_CIB_INVOKE,
		/* S_RECOVERY		==> */	A_CIB_INVOKE,
		/* S_RECOVERY_DC	==> */	A_CIB_INVOKE,
		/* S_RELEASE_DC		==> */	A_CIB_INVOKE,
		/* S_PENDING		==> */	A_CIB_INVOKE,
		/* S_STOPPING		==> */	A_CIB_INVOKE,
		/* S_TERMINATE		==> */	A_CIB_INVOKE,
		/* S_TRANSITION_ENGINE	==> */	A_CIB_INVOKE,
	},

/* Got an I_CIB_UPDATE */
	{
		/* S_IDLE		==> */	A_CIB_BUMPGEN|A_TE_COPYTO,
		/* S_ELECTION		==> */	A_LOG,
		/* S_INTEGRATION	==> */	A_CIB_BUMPGEN|A_TE_COPYTO, 
		/* S_NOT_DC		==> */	A_WARN,
		/* S_POLICY_ENGINE	==> */	A_CIB_BUMPGEN|A_TE_COPYTO,
		/* S_RECOVERY		==> */	A_WARN,
		/* S_RECOVERY_DC	==> */	A_CIB_BUMPGEN|A_TE_COPYTO,
		/* S_RELEASE_DC		==> */	A_WARN,
		/* S_PENDING		==> */	A_WARN,
		/* S_STOPPING		==> */	A_WARN,
		/* S_TERMINATE		==> */	A_WARN,
		/* S_TRANSITION_ENGINE	==> */	A_CIB_BUMPGEN|A_TE_COPYTO,
	},

/* Got an I_DC_TIMEOUT */
	{
		/* S_IDLE		==> */	A_ELECTION_VOTE|A_ELECT_TIMER_START,
		/* S_ELECTION		==> */	A_ELECTION_VOTE|A_ELECT_TIMER_START,
		/* S_INTEGRATION	==> */	A_ELECTION_VOTE|A_ELECT_TIMER_START,
		/* S_NOT_DC		==> */	A_ELECTION_VOTE|A_ELECT_TIMER_START,
		/* S_POLICY_ENGINE	==> */	A_ELECTION_VOTE|A_ELECT_TIMER_START,
		/* S_RECOVERY		==> */	A_NOTHING,
		/* S_RECOVERY_DC	==> */	A_NOTHING,
		/* S_RELEASE_DC		==> */	A_ELECTION_VOTE|A_ELECT_TIMER_START,
		/* S_PENDING		==> */	A_ELECTION_VOTE|A_ELECT_TIMER_START,
		/* S_STOPPING		==> */	A_NOTHING,
		/* S_TERMINATE		==> */	A_NOTHING,
		/* S_TRANSITION_ENGINE	==> */	A_ELECTION_VOTE|A_ELECT_TIMER_START,
	},

/* Got an I_ELECTION */
	{
		/* S_IDLE		==> */	A_ELECTION_COUNT,
		/* S_ELECTION		==> */	A_ELECTION_COUNT,
		/* S_INTEGRATION	==> */	A_ELECTION_COUNT,
		/* S_NOT_DC		==> */	A_ELECTION_COUNT,
		/* S_POLICY_ENGINE	==> */	A_ELECTION_COUNT,
		/* S_RECOVERY		==> */	A_LOG,
		/* S_RECOVERY_DC	==> */	A_LOG,
		/* S_RELEASE_DC		==> */	A_LOG,
		/* S_PENDING		==> */	A_ELECTION_COUNT,
		/* S_STOPPING		==> */	A_LOG,
		/* S_TERMINATE		==> */	A_LOG,
		/* S_TRANSITION_ENGINE	==> */	A_ELECTION_COUNT,
	},

/* Got an I_PE_CALC */
	{
		/* S_IDLE		==> */	A_PE_INVOKE,
		/* S_ELECTION		==> */	A_WARN,
		/* S_INTEGRATION	==> */	A_PE_INVOKE,
		/* S_NOT_DC		==> */	A_ERROR,
		/* S_POLICY_ENGINE	==> */	A_PE_INVOKE,
		/* S_RECOVERY		==> */	A_ERROR,
		/* S_RECOVERY_DC	==> */	A_PE_INVOKE,
		/* S_RELEASE_DC		==> */	A_WARN,
		/* S_PENDING		==> */	A_ERROR,
		/* S_STOPPING		==> */	A_WARN,
		/* S_TERMINATE		==> */	A_WARN,
		/* S_TRANSITION_ENGINE	==> */	A_PE_INVOKE|A_TE_CANCEL,
	},
	
/* Got an I_RELEASE_DC */
	{
		/* S_IDLE		==> */	O_RELEASE|A_ERROR,
		/* S_ELECTION		==> */	O_RELEASE,
		/* S_INTEGRATION	==> */	O_RELEASE|A_ERROR,
		/* S_NOT_DC		==> */	A_ERROR,
		/* S_POLICY_ENGINE	==> */	O_RELEASE|A_ERROR,
		/* S_RECOVERY		==> */	O_RELEASE,
		/* S_RECOVERY_DC	==> */	O_RELEASE|A_ERROR,
		/* S_RELEASE_DC		==> */	O_RELEASE|A_ERROR,
		/* S_PENDING		==> */	A_ERROR,
		/* S_STOPPING		==> */	A_WARN,
		/* S_TERMINATE		==> */	A_WARN,
		/* S_TRANSITION_ENGINE	==> */	O_RELEASE|A_ERROR,
	},

/* Got an I_ELECTION_DC */
	{
		/* S_IDLE		==> */	A_WARN|A_ELECTION_VOTE,
		/* S_ELECTION		==> */	A_LOG|A_DC_TAKEOVER|A_PE_START|A_TE_START|A_JOIN_WELCOME_ALL|A_ELECT_TIMER_STOP|A_ELECTION_VOTE|A_UPDATE_NODESTATUS,
		/* S_INTEGRATION	==> */	A_WARN|A_ELECTION_VOTE,
		/* S_NOT_DC		==> */	A_LOG|A_ELECTION_VOTE|A_UPDATE_NODESTATUS,
		/* S_POLICY_ENGINE	==> */	A_WARN|A_ELECTION_VOTE,
		/* S_RECOVERY		==> */	A_WARN|A_ELECTION_VOTE,
		/* S_RECOVERY_DC	==> */	A_LOG|A_ELECTION_VOTE,
		/* S_RELEASE_DC		==> */	A_WARN|A_ELECTION_VOTE,
		/* S_PENDING		==> */	A_LOG|A_ELECTION_VOTE|A_UPDATE_NODESTATUS,
		/* S_STOPPING		==> */	A_WARN,
		/* S_TERMINATE		==> */	A_WARN,
		/* S_TRANSITION_ENGINE	==> */	A_WARN|A_ELECTION_VOTE,
	},

/* Got an I_ERROR */
	{
		/* S_IDLE		==> */	A_DC_TIMER_STOP|A_RECOVER,
		/* S_ELECTION		==> */	A_DC_TIMER_STOP|A_RECOVER,
		/* S_INTEGRATION	==> */	A_DC_TIMER_STOP|A_RECOVER,
		/* S_NOT_DC		==> */	A_DC_TIMER_STOP|A_RECOVER,
		/* S_POLICY_ENGINE	==> */	A_DC_TIMER_STOP|O_PE_RESTART|A_RECOVER,
		/* S_RECOVERY		==> */	A_DC_TIMER_STOP|O_SHUTDOWN,
		/* S_RECOVERY_DC	==> */	A_DC_TIMER_STOP|O_SHUTDOWN|O_RELEASE,
		/* S_RELEASE_DC		==> */	A_DC_TIMER_STOP|O_SHUTDOWN,
		/* S_PENDING		==> */	A_DC_TIMER_STOP|O_SHUTDOWN,
		/* S_STOPPING		==> */	A_DC_TIMER_STOP|A_EXIT_1,
		/* S_TERMINATE		==> */	A_DC_TIMER_STOP|A_EXIT_1,
		/* S_TRANSITION_ENGINE	==> */	A_DC_TIMER_STOP|O_TE_RESTART|A_RECOVER,
	},

/* Got an I_FAIL */
	{
		/* S_IDLE		==> */	A_WARN,
		/* S_ELECTION		==> */	A_DC_TIMER_STOP|A_WARN,
		/* S_INTEGRATION	==> */	A_WARN|A_JOIN_WELCOME_ALL,
		/* S_NOT_DC		==> */	A_ELECT_TIMER_STOP|A_WARN,
		/* S_POLICY_ENGINE	==> */	A_WARN|A_JOIN_WELCOME_ALL|A_PE_INVOKE,
		/* S_RECOVERY		==> */	A_WARN|O_SHUTDOWN,
		/* S_RECOVERY_DC	==> */	A_WARN|O_SHUTDOWN|O_RELEASE,
		/* S_RELEASE_DC		==> */	A_WARN|O_SHUTDOWN,
		/* S_PENDING		==> */	A_ELECT_TIMER_STOP|A_WARN|O_SHUTDOWN,
		/* S_STOPPING		==> */	A_WARN,
		/* S_TERMINATE		==> */	A_WARN|A_EXIT_1,
		/* S_TRANSITION_ENGINE	==> */	A_WARN|O_TE_RESTART|A_RECOVER,
	},
	
/* Got an I_INTEGRATION_TIMEOUT */
	{
		/* S_IDLE		==> */	A_NOTHING,
		/* S_ELECTION		==> */	A_WARN,
		/* S_INTEGRATION	==> */	A_PE_INVOKE,
		/* S_NOT_DC		==> */	A_WARN,
		/* S_POLICY_ENGINE	==> */	A_NOTHING,
		/* S_RECOVERY		==> */	A_WARN,
		/* S_RECOVERY_DC	==> */	A_WARN,
		/* S_RELEASE_DC		==> */	A_WARN,
		/* S_PENDING		==> */	A_WARN,
		/* S_STOPPING		==> */	A_WARN,
		/* S_TERMINATE		==> */	A_WARN,
		/* S_TRANSITION_ENGINE	==> */	A_NOTHING,
	},

/* Got an I_NODE_JOIN */
	{
		/* S_IDLE		==> */	A_TE_CANCEL|A_JOIN_WELCOME,
		/* S_ELECTION		==> */	A_WARN,
		/* S_INTEGRATION	==> */	A_TE_CANCEL|A_JOIN_WELCOME,
		/* S_NOT_DC		==> */	A_WARN,
		/* S_POLICY_ENGINE	==> */	A_TE_CANCEL|A_JOIN_WELCOME,
		/* S_RECOVERY		==> */	A_WARN,
		/* S_RECOVERY_DC	==> */	A_TE_CANCEL|A_JOIN_WELCOME,
		/* S_RELEASE_DC		==> */	A_WARN,
		/* S_PENDING		==> */	A_WARN,
		/* S_STOPPING		==> */	A_WARN,
		/* S_TERMINATE		==> */	A_WARN,
		/* S_TRANSITION_ENGINE	==> */	A_TE_CANCEL|A_JOIN_WELCOME,
	},

/* Got an I_NODE_LEFT */
	{
		/* S_IDLE		==> */	A_LOG,
		/* S_ELECTION		==> */	A_WARN,
		/* S_INTEGRATION	==> */	A_LOG,
		/* S_NOT_DC		==> */	A_WARN,
		/* S_POLICY_ENGINE	==> */	A_LOG,
		/* S_RECOVERY		==> */	A_WARN,
		/* S_RECOVERY_DC	==> */	A_LOG,
		/* S_RELEASE_DC		==> */	A_WARN,
		/* S_PENDING		==> */	A_WARN,
		/* S_STOPPING		==> */	A_WARN,
		/* S_TERMINATE		==> */	A_WARN,
		/* S_TRANSITION_ENGINE	==> */	A_LOG,
	},

/* Got an I_NOT_DC */
	{
		/* S_IDLE		==> */	O_RELEASE|A_DC_TIMER_START,
		/* S_ELECTION		==> */	A_LOG|A_DC_TIMER_START,
		/* S_INTEGRATION	==> */	O_RELEASE|A_DC_TIMER_START,
		/* S_NOT_DC		==> */	A_WARN,
		/* S_POLICY_ENGINE	==> */	O_RELEASE|A_DC_TIMER_START,
		/* S_RECOVERY		==> */	A_WARN,
		/* S_RECOVERY_DC	==> */	O_RELEASE|A_DC_TIMER_START,
		/* S_RELEASE_DC		==> */	O_RELEASE|A_DC_TIMER_START,
		/* S_PENDING		==> */	A_WARN,
		/* S_STOPPING		==> */	A_WARN,
		/* S_TERMINATE		==> */	A_WARN,
		/* S_TRANSITION_ENGINE	==> */	O_RELEASE|A_DC_TIMER_START,
	},

/* Got an I_RECOVERED */
	{
		/* S_IDLE		==> */	A_WARN,
		/* S_ELECTION		==> */	A_ELECTION_VOTE,
		/* S_INTEGRATION	==> */	A_WARN,
		/* S_NOT_DC		==> */	A_WARN,
		/* S_POLICY_ENGINE	==> */	A_WARN,
		/* S_RECOVERY		==> */	A_DC_TIMER_START,
		/* S_RECOVERY_DC	==> */	A_JOIN_WELCOME_ALL|A_PE_INVOKE,
		/* S_RELEASE_DC		==> */	A_WARN,
		/* S_PENDING		==> */	A_WARN,
		/* S_STOPPING		==> */	A_WARN,
		/* S_TERMINATE		==> */	A_WARN,
		/* S_TRANSITION_ENGINE	==> */	A_WARN,
	},

/* Got an I_RELEASE_FAIL */
	{
		/* S_IDLE		==> */	A_WARN|O_SHUTDOWN,
		/* S_ELECTION		==> */	A_WARN|O_SHUTDOWN,
		/* S_INTEGRATION	==> */	A_WARN|O_SHUTDOWN,
		/* S_NOT_DC		==> */	A_WARN,
		/* S_POLICY_ENGINE	==> */	O_SHUTDOWN,
		/* S_RECOVERY		==> */	A_WARN,
		/* S_RECOVERY_DC	==> */	A_WARN|O_SHUTDOWN,
		/* S_RELEASE_DC		==> */	O_SHUTDOWN,
		/* S_PENDING		==> */	A_WARN,
		/* S_STOPPING		==> */	A_WARN|O_SHUTDOWN,
		/* S_TERMINATE		==> */	A_WARN|O_SHUTDOWN,
		/* S_TRANSITION_ENGINE	==> */	A_WARN|O_SHUTDOWN,
	},

/* Got an I_RELEASE_SUCCESS */
	{
		/* S_IDLE		==> */	A_WARN,
		/* S_ELECTION		==> */	A_WARN,
		/* S_INTEGRATION	==> */	A_WARN,
		/* S_NOT_DC		==> */	A_WARN,
		/* S_POLICY_ENGINE	==> */	A_WARN,
		/* S_RECOVERY		==> */	A_WARN,
		/* S_RECOVERY_DC	==> */	A_WARN,
		/* S_RELEASE_DC		==> */	A_LOG,
		/* S_PENDING		==> */	A_WARN,
		/* S_STOPPING		==> */	A_WARN,
		/* S_TERMINATE		==> */	A_WARN,
		/* S_TRANSITION_ENGINE	==> */	A_WARN,
	},

/* Got an I_RESTART */
	{
		/* S_IDLE		==> */	A_NOTHING,
		/* S_ELECTION		==> */	A_LOG|A_ELECTION_TIMEOUT|A_ELECTION_VOTE,
		/* S_INTEGRATION	==> */	A_LOG|A_JOIN_WELCOME_ALL|A_PE_INVOKE,
		/* S_NOT_DC		==> */	A_LOG|A_NOTHING,
		/* S_POLICY_ENGINE	==> */	A_LOG|A_PE_INVOKE,
		/* S_RECOVERY		==> */	A_LOG|A_RECOVER,
		/* S_RECOVERY_DC	==> */	A_LOG|A_RECOVER,
		/* S_RELEASE_DC		==> */	A_LOG|O_RELEASE,
		/* S_PENDING		==> */	A_LOG|A_STARTUP,
		/* S_STOPPING		==> */	A_LOG|O_SHUTDOWN,
		/* S_TERMINATE		==> */	A_LOG|O_SHUTDOWN,
		/* S_TRANSITION_ENGINE	==> */	A_LOG|A_TE_INVOKE,
	},

/* Got an I_REQUEST */
	{
		/* S_IDLE		==> */	A_MSG_PROCESS,
		/* S_ELECTION		==> */	A_MSG_PROCESS,
		/* S_INTEGRATION	==> */	A_MSG_PROCESS,
		/* S_NOT_DC		==> */	A_MSG_PROCESS,
		/* S_POLICY_ENGINE	==> */	A_MSG_PROCESS,
		/* S_RECOVERY		==> */	A_MSG_PROCESS,
		/* S_RECOVERY_DC	==> */	A_MSG_PROCESS,
		/* S_RELEASE_DC		==> */	A_MSG_PROCESS,
		/* S_PENDING		==> */	A_MSG_PROCESS,
		/* S_STOPPING		==> */	A_LOG|A_MSG_PROCESS,
		/* S_TERMINATE		==> */	A_LOG|A_MSG_PROCESS,
		/* S_TRANSITION_ENGINE	==> */	A_MSG_PROCESS,
	},

/* Got an I_ROUTER */
	{
		/* S_IDLE		==> */	A_MSG_ROUTE,
		/* S_ELECTION		==> */	A_MSG_ROUTE,
		/* S_INTEGRATION	==> */	A_MSG_ROUTE,
		/* S_NOT_DC		==> */	A_MSG_ROUTE,
		/* S_POLICY_ENGINE	==> */	A_MSG_ROUTE,
		/* S_RECOVERY		==> */	A_MSG_ROUTE,
		/* S_RECOVERY_DC	==> */	A_MSG_ROUTE,
		/* S_RELEASE_DC		==> */	A_MSG_ROUTE,
		/* S_PENDING		==> */	A_MSG_ROUTE,
		/* S_STOPPING		==> */	A_MSG_ROUTE,
		/* S_TERMINATE		==> */	A_MSG_ROUTE,
		/* S_TRANSITION_ENGINE	==> */	A_MSG_ROUTE,
	},

/* Got an I_SHUTDOWN */
	{
		/* S_IDLE		==> */	O_RELEASE,
		/* S_ELECTION		==> */	O_RELEASE,
		/* S_INTEGRATION	==> */	O_RELEASE,
		/* S_NOT_DC		==> */	A_ELECT_TIMER_STOP|A_SHUTDOWN_REQ,
		/* S_POLICY_ENGINE	==> */	O_RELEASE,
		/* S_RECOVERY		==> */	A_ELECT_TIMER_STOP|A_SHUTDOWN_REQ,
		/* S_RECOVERY_DC	==> */	O_RELEASE,
		/* S_RELEASE_DC		==> */	A_SHUTDOWN_REQ,
		/* S_PENDING		==> */	A_ELECT_TIMER_STOP|A_SHUTDOWN_REQ,
		/* S_STOPPING		==> */	A_SHUTDOWN_REQ,
		/* S_TERMINATE		==> */	A_SHUTDOWN_REQ,
		/* S_TRANSITION_ENGINE	==> */	O_RELEASE,
	},

/* Got an I_TERMINATE */
	{
		/* S_IDLE		==> */	A_DC_TIMER_STOP|O_SHUTDOWN|O_RELEASE,
		/* S_ELECTION		==> */	A_DC_TIMER_STOP|O_SHUTDOWN|O_RELEASE,
		/* S_INTEGRATION	==> */	A_DC_TIMER_STOP|O_SHUTDOWN|O_RELEASE,
		/* S_NOT_DC		==> */	O_SHUTDOWN,
		/* S_POLICY_ENGINE	==> */	A_DC_TIMER_STOP|O_SHUTDOWN|O_RELEASE,
		/* S_RECOVERY		==> */	O_SHUTDOWN,
		/* S_RECOVERY_DC	==> */	A_DC_TIMER_STOP|O_SHUTDOWN|O_RELEASE,
		/* S_RELEASE_DC		==> */	A_DC_TIMER_STOP|O_SHUTDOWN,
		/* S_PENDING		==> */	O_SHUTDOWN,
		/* S_STOPPING		==> */	O_SHUTDOWN,
		/* S_TERMINATE		==> */	O_SHUTDOWN,
		/* S_TRANSITION_ENGINE	==> */	A_DC_TIMER_STOP|O_SHUTDOWN|O_RELEASE,
	},

/* Got an I_STARTUP */
	{
		/* S_IDLE		==> */	A_WARN,
		/* S_ELECTION		==> */	A_WARN,
		/* S_INTEGRATION	==> */	A_WARN,
		/* S_NOT_DC		==> */	A_WARN,
		/* S_POLICY_ENGINE	==> */	A_WARN,
		/* S_RECOVERY		==> */	A_WARN,
		/* S_RECOVERY_DC	==> */	A_WARN,
		/* S_RELEASE_DC		==> */	A_WARN,
		/* S_PENDING		==> */	A_LOG|A_STARTUP|A_CIB_START|A_LRM_CONNECT|A_CCM_CONNECT|A_HA_CONNECT|A_DC_TIMER_START|A_READCONFIG,
		/* S_STOPPING		==> */	A_WARN,
		/* S_TERMINATE		==> */	A_WARN,
		/* S_TRANSITION_ENGINE	==> */	A_WARN,
	},

/* Got an I_SUCCESS */
	{
		/* S_IDLE		==> */	A_LOG,
		/* S_ELECTION		==> */	A_WARN,
		/* S_INTEGRATION	==> */	A_LOG|A_CIB_INVOKE,
		/* S_NOT_DC		==> */	A_NOTHING,
		/* S_POLICY_ENGINE	==> */	A_LOG|A_TE_INVOKE,
		/* S_RECOVERY		==> */	A_RECOVER|A_LOG,
		/* S_RECOVERY_DC	==> */	A_RECOVER|A_LOG,
		/* S_RELEASE_DC		==> */	A_LOG,
		/* S_PENDING		==> */	A_LOG,
		/* S_STOPPING		==> */	A_LOG,
		/* S_TERMINATE		==> */	A_LOG,
		/* S_TRANSITION_ENGINE	==> */	A_LOG,
	},

/* Got an I_WELCOME */
	{
		/* S_IDLE		==> */	O_RELEASE|A_UPDATE_NODESTATUS|A_JOIN_ACK,
		/* S_ELECTION		==> */	O_RELEASE|A_UPDATE_NODESTATUS|A_JOIN_ACK,
		/* S_INTEGRATION	==> */	O_RELEASE|A_UPDATE_NODESTATUS|A_JOIN_ACK,
		/* S_NOT_DC		==> */	O_DC_TICKLE|A_UPDATE_NODESTATUS|A_JOIN_ACK,
		/* S_POLICY_ENGINE	==> */	O_RELEASE|A_UPDATE_NODESTATUS|A_JOIN_ACK,
		/* S_RECOVERY		==> */	A_UPDATE_NODESTATUS|A_JOIN_ACK,
		/* S_RECOVERY_DC	==> */	O_RELEASE|A_UPDATE_NODESTATUS|A_JOIN_ACK,
		/* S_RELEASE_DC		==> */	A_UPDATE_NODESTATUS|A_JOIN_ACK,
		/* S_PENDING		==> */	O_DC_TICKLE|A_UPDATE_NODESTATUS|A_JOIN_ACK|A_STARTED|A_UPDATE_NODESTATUS,
		/* S_STOPPING		==> */	A_LOG,
		/* S_TERMINATE		==> */	A_LOG,
		/* S_TRANSITION_ENGINE	==> */	O_RELEASE|A_UPDATE_NODESTATUS|A_JOIN_ACK,
	},

/* Got an I_WELCOME_ACK */
	{
		/* S_IDLE		==> */	A_JOIN_PROCESS_ACK,
		/* S_ELECTION		==> */	A_WARN,
		/* S_INTEGRATION	==> */	A_JOIN_PROCESS_ACK,
		/* S_NOT_DC		==> */	A_WARN,
		/* S_POLICY_ENGINE	==> */	A_JOIN_PROCESS_ACK,
		/* S_RECOVERY		==> */	A_WARN,
		/* S_RECOVERY_DC	==> */	A_JOIN_PROCESS_ACK,
		/* S_RELEASE_DC		==> */	A_WARN,
		/* S_PENDING		==> */	A_WARN,
		/* S_STOPPING		==> */	A_WARN,
		/* S_TERMINATE		==> */	A_WARN,
		/* S_TRANSITION_ENGINE	==> */	A_JOIN_PROCESS_ACK,
	},

/* Got an I_WAIT_FOR_EVENT */
	{
		/* S_IDLE		==> */	A_LOG,
		/* S_ELECTION		==> */	A_LOG,
		/* S_INTEGRATION	==> */	A_LOG,
		/* S_NOT_DC		==> */	A_LOG,
		/* S_POLICY_ENGINE	==> */	A_LOG,
		/* S_RECOVERY		==> */	A_LOG,
		/* S_RECOVERY_DC	==> */	A_LOG,
		/* S_RELEASE_DC		==> */	A_LOG,
		/* S_PENDING		==> */	A_LOG,
		/* S_STOPPING		==> */	A_LOG,
		/* S_TERMINATE		==> */	A_LOG,
		/* S_TRANSITION_ENGINE	==> */	A_LOG,
	},

/* Got an I_DC_HEARTBEAT */
	{
		/* S_IDLE		==> */	A_WARN|A_ELECTION_VOTE,
		/* S_ELECTION		==> */	A_WARN|A_ELECTION_VOTE,
		/* S_INTEGRATION	==> */	A_WARN|A_ELECTION_VOTE,
		/* S_NOT_DC		==> */	O_DC_TICKLE,
		/* S_POLICY_ENGINE	==> */	A_WARN|A_ELECTION_VOTE,
		/* S_RECOVERY		==> */	A_NOTHING|O_DC_TICKLE,
		/* S_RECOVERY_DC	==> */	A_WARN|O_RELEASE|A_DC_TIMER_START,
		/* S_RELEASE_DC		==> */	A_LOG|A_DC_TIMER_START,
		/* S_PENDING		==> */	A_LOG|O_DC_TICKLE|A_ANNOUNCE,
		/* S_STOPPING		==> */	A_NOTHING,
		/* S_TERMINATE		==> */	A_NOTHING,
		/* S_TRANSITION_ENGINE	==> */	A_WARN|A_ELECTION_VOTE,
	},

/* Got an I_LRM_EVENT */
	{
		/* S_IDLE		==> */	A_LRM_EVENT,
		/* S_ELECTION		==> */	A_LRM_EVENT,
		/* S_INTEGRATION	==> */	A_LRM_EVENT,
		/* S_NOT_DC		==> */	A_LRM_EVENT,
		/* S_POLICY_ENGINE	==> */	A_LRM_EVENT,
		/* S_RECOVERY		==> */	A_LRM_EVENT,
		/* S_RECOVERY_DC	==> */	A_LRM_EVENT,
		/* S_RELEASE_DC		==> */	A_LRM_EVENT,
		/* S_PENDING		==> */	A_LRM_EVENT,
		/* S_STOPPING		==> */	A_LRM_EVENT,
		/* S_TERMINATE		==> */	A_LRM_EVENT,
		/* S_TRANSITION_ENGINE	==> */	A_LRM_EVENT,
	},
};

#endif
