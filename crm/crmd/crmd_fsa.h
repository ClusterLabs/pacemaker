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

/*======================================
 *	States the DC/CRMd can be in
 *======================================*/
enum crmd_fsa_state {
	S_STARTING = 0,	/* we are just starting out */
	S_NOT_DC,	/* we are in crmd/slave mode */
	S_CIB_DISCOVER,	/* we are in the process of calculating the
			 * most up-to-date CIB
			 */
	S_RESOURCES,	/* Processing resources */
	S_IDLE,		/* Nothing happening */
	S_STOPPING,	/* We are trying to shutdown */
	S_AUDIT,	/* Check everything is ok before continuing
			 * Attempt to recover if required
			 */
	/*  ------------- Last input found in table is above -------------- */
	S_ILLEGAL,	/* This is an illegal FSA state */
			/* (must be last) */
};
#define MAXSTATE	S_ILLEGAL
/*
   <Starting>
      |
      |
      V
    Not DC <--> Audit <--> Cib discovery  
      |		/  A		|
      |        /   |            |
      |       /    |            |
      |      |     \            |
      V      V      \           V
      Shutdown <--> Idle <--> Resources
*/

/*======================================
 * 	Inputs/Events/Stimuli to be given to the finite state machine
 *======================================*/
enum crmd_fsa_input {
	I_NULL,		/* Nothing happened */
	I_SYS_DISCON,	/* A required sub-system "dissappeared" */
	I_DC_MSG,	/* We recieved a message from "a" DC */

	I_AM_DC,	/* Switch into DC mode */
	I_SHUTDOWN,	/* We would like to shutdown please */
	
	I_AUDIT_FAILED, /* The self-audit FAILED */
	I_AUDIT_NOT_DC, /* The self-audit passed, but we are not the DC */
	I_AUDIT_PASSED, /* The self-audit passed, any problems were rectified */

	I_CIB_DONE,	/* CIB Calculations complete... lets rock and roll */
	I_CIB_FAILED,	/* Could not gather a consistent view of the CIB */

	I_CCM_EVENT,	/* The a node left/joined or something generally changed */
	I_REQUEST,	/* Some non-resource, non-ccm action is required of us,
			   eg. ping */
	I_RESOURCE,	/* Some resource actions are required */
	I_ROUTER,	/* Do our job as router and forward this to the
			   right place */

	I_PE_DONE,	/* The Policy Engine has computed the next cluster state */
	I_TE_DONE,	/* The Transitioner has completed its current batch of work */
	
	/*  ------------- Last input found in table is above -------------- */
	I_ILLEGAL,	/* This is an illegal value for an FSA input */
			/* (must be last) */
};
#define MAXINPUT	I_ILLEGAL


/*======================================
 * actions
 *======================================*/

/* -- initialization actions -- */
#define A_CIB_CONNECT	0x00000001  /* Connect to the CIB */
#define A_HA_CONNECT	0x00000002  /* Connect to Heartbeat */
#define A_CCM_CONNECT	0x00000004  /* Connect to the CCM */
#define	A_AUDIT		0x00000008  /* Audit the state of the cluster */

/* -- startup / join protocol actions -- */
#define A_CCM_EVENT	0x00000010  /* Process whatever it is the CCM is
				       trying to tell us */
#define A_INIT_AS_DC	0x00000020  /* */
#define	A_CALC_CIB	0x00000040  /* Calculate the most up to date CIB */
#define	A_WELCOME_SEND	0x00000080  /* Send a welcome message to new node(s) */
#define	A_WELCOME_ACK	0x00000100  /* Acknowledge the DC as our overlord */
#define	A_SEND_CIB	0x00000200  /* Distribute the CIB */
#define A_STORE_CIB	0x00000400  /* Store the CIB as sent by the DC */
/* #define	A_	0x00000800  /\* Unused *\/ */

/* -- operational actions -- */
#define	A_ROUTE_MSG	0x00001000  /* Send the message to the correct
				       recipient */
#define	A_STORE_REQ	0x00002000  /* Put the request into a queue
				       for processing */
#define	A_ADD_BLOCK	0x00004000  /* Add a system generate "block" so that
				       resources arent moved to or are
				       activly moved away from the affected
				       node.  This way we can return quickly
				       even if busy with other things. */
/* #define	A_	0x00008000  /\* Unused *\/ */

/* -- DC resource actions -- */
#define	A_PROCESS_REQ	0x00010000  /* Process the queue of requests */
#define	A_INVOKE_PE	0x00020000  /* Calculate the next state for the
				       cluster */
#define	A_INVOKE_TE	0x00040000  /* Attempt to reach the newly calculated
				       cluster state */
/* #define	A_	0x00080000  /\* Unused *\/ */

/* -- Cleanup/shutdown actions -- */
#define	A_GIVEUP_DC	0x00000040  /* Give up DC status */
#define	A_SHUTDOWN	0x00000020  /* Shutdown the CRM */



/*======================================
 * "register" contents
 *======================================*/
#define	R_THE_DC	0x00000001 /* Are we the DC */
#define	R_STARTING	0x00000002 /* Are we starting up */
#define	R_SHUTDOWN	0x00000004 /* Are we trying to shut down */
#define	R_CIB_DONE	0x00000008 /* have we calculated the CIB */


#define	R_INVOKE_PE	0x00000010 /* Does the PE needed to be invoked at
				      the next appropriate point */
/* #define	R_	0x00000020 /\* Unused *\/ */
/* #define	R_	0x00000040 /\* Unused *\/  */
/* #define	R_	0x00000080 /\* Unused *\/ */

#define	R_CIB_CONNECTED	0x00000100 /* Is the CIB connected */
#define	R_PE_CONNECTED	0x00000200 /* Is the Policy Engine connected */
#define	R_TE_CONNECTED	0x00000400 /* Is the Transition Engine connected */
#define	R_LRM_CONNECTED	0x00000800 /* Is the Local Resource Manager
				      connected */

#define	R_REQ_PEND	0x00001000 /* Are there Requests waiting
				      processing */
#define	R_PE_PEND	0x00002000 /* Has the PE been invoked and we're
				      awaiting a reply */
#define	R_TE_PEND	0x00004000 /* Has the TE been invoked and we're
				      awaiting completion */ 
#define	R_RESP_PEND	0x00008000 /* Do we have clients waiting on a
				      response */


