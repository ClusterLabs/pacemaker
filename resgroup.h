#ifndef __RESGROUP_H
#define __RESGROUP_H

#include <pthread.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <errno.h>


/* Requests */
#define RG_SUCCESS	  0
#define RG_FAIL		  1
#define RG_START	  2
#define RG_STOP		  3
#define RG_STATUS	  4
#define RG_DISABLE	  5
#define RG_STOP_RECOVER	  6
#define RG_START_RECOVER  7
#define RG_RESTART	  8
#define RG_EXITING	  9 
#define RG_INIT		  10
#define RG_ENABLE	  11
#define RG_STATUS_NODE	  12
#define RG_RELOCATE	  13
#define RG_CONDSTOP	  14
#define RG_CONDSTART	  15
#define RG_START_REMOTE   16	/* Part of a relocate */
#define RG_STOP_USER	  17	/* User-stop request */
#define RG_STOP_EXITING	  18	/* Exiting. */
#define RG_LOCK		  19
#define RG_UNLOCK	  20
#define RG_QUERY_LOCK	  21
#define RG_MIGRATE	  22
#define RG_FREEZE	  23
#define RG_UNFREEZE	  24
#define RG_STATUS_INQUIRY 25
#define RG_CONVALESCE	  26
#define RG_NONE		  999


/* Resource group states (for now) */
#define RG_STATE_BASE			110
#define RG_STATE_STOPPED		110	/** Resource group is stopped */
#define RG_STATE_STARTING		111	/** Resource is starting */
#define RG_STATE_STARTED		112	/** Resource is started */
#define RG_STATE_STOPPING		113	/** Resource is stopping */
#define RG_STATE_FAILED			114	/** Resource has failed */
#define RG_STATE_UNINITIALIZED		115	/** Thread not running yet */
#define RG_STATE_CHECK			116	/** Checking status */
#define RG_STATE_ERROR			117	/** Recoverable error */
#define RG_STATE_RECOVER		118	/** Pending recovery */
#define RG_STATE_DISABLED		119	/** Resource not allowd to run */
#define RG_STATE_MIGRATE		120	/** Resource migrating */

#define DEFAULT_CHECK_INTERVAL		10

/* Resource group flags (for now) */
#define RG_FLAG_FROZEN			(1<<0)	/** Resource frozen */
#define RG_FLAG_PARTIAL			(1<<1)	/** One or more non-critical
						    resources offline */

/* Return codes */
#define RG_EEXCL	-16		/* Service not runnable due to
					   the fact that it is tagged 
					   exclusive and there are no
					   empty nodes. */
#define RG_EDOMAIN	-15		/* Service not runnable given the
					   set of nodes and its failover
					   domain */
#define RG_ESCRIPT	-14		/* S/Lang script failed */
#define RG_EFENCE	-13		/* Fencing operation pending */
#define RG_ENODE	-12		/* Node is dead/nonexistent */
#define RG_EFROZEN	-11		/* Forward compat. with -HEAD */
#define RG_ERUN		-10		/* Service is already running */
#define RG_EQUORUM	-9		/* Operation requires quorum */
#define RG_EINVAL	-8		/* Invalid operation for resource */
#define RG_EDEPEND 	-7		/* Operation violates dependency */
#define RG_EAGAIN	-6		/* Try again */
#define RG_EDEADLCK	-5		/* Aborted - would deadlock */
#define RG_ENOSERVICE	-4		/* Service does not exist */
#define RG_EFORWARD	-3		/* Service not mastered locally */
#define RG_EABORT	-2		/* Abort; service unrecoverable */
#define RG_EFAIL	-1		/* Generic failure */
#define RG_ESUCCESS	0
#define RG_YES		1
#define RG_NO		2


const char *rg_strerror(int val);


/*
 * Fail-over domain states
 */
#define FOD_ILLEGAL		0
#define FOD_GOOD		1
#define FOD_BETTER		2
#define FOD_BEST		3

/* 
   Fail-over domain flags
 */
#define FOD_ORDERED		(1<<0)
#define FOD_RESTRICTED		(1<<1)
#define FOD_NOFAILBACK		(1<<2)

/*
   Status tree flags
 */
#define SFL_FAILURE		(1<<0)
#define SFL_RECOVERABLE		(1<<1)
#define SFL_PARTIAL		(1<<2)

#endif
