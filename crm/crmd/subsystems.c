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
#include <crm/crm.h>
#include <crmd_fsa.h>

#include <sys/types.h>
#include <sys/wait.h>

#include <unistd.h>			/* for access */
#include <clplumbing/cl_signal.h>
#include <clplumbing/realtime.h>
#include <sys/types.h>	/* for calls to open */
#include <sys/stat.h>	/* for calls to open */
#include <fcntl.h>	/* for calls to open */
#include <pwd.h>	/* for getpwuid */
#include <grp.h>	/* for initgroups */

#include <sys/time.h>	/* for getrlimit */
#include <sys/resource.h>/* for getrlimit */

#include <errno.h>

#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crmd_messages.h>
#include <crmd_callbacks.h>

#include <crm/cib.h>
#include <crmd.h>

#include <crm/dmalloc_wrapper.h>

gboolean
stop_subsystem(struct crm_subsystem_s*	the_subsystem)
{
	crm_verbose("Stopping sub-system \"%s\"", the_subsystem->name);
	if (the_subsystem->pid <= 0) {
		crm_err("Client %s not running yet", the_subsystem->name);

	} else if(! is_set(fsa_input_register, the_subsystem->flag) ) {
		/* running but not yet connected */
		crm_warn("Stopping %s before it had connected",
			 the_subsystem->name);
		
		kill(the_subsystem->pid, -9);
		the_subsystem->pid = -1;
		
	} else {
		crm_info("Sending quit message to %s.", the_subsystem->name);
		send_request(NULL,NULL, CRM_OP_QUIT, NULL,
			     the_subsystem->name, NULL);
	}
	
	return TRUE;
}


gboolean
start_subsystem(struct crm_subsystem_s*	the_subsystem)
{
	pid_t       pid;
	struct stat buf;
	int         s_res;
	unsigned int	j;
	struct rlimit	oflimits;
	const char 	*devnull = "/dev/null";
	

	crm_debug("Starting sub-system \"%s\"", the_subsystem->name);

	if (the_subsystem->pid > 0) {
		crm_warn("Client %s already running as pid %d",
			the_subsystem->name, (int) the_subsystem->pid);

		/* starting a started X is not an error */
		return TRUE;
	}

	/*
	 * We want to ensure that the exec will succeed before
	 * we bother forking.
	 */

	if (access(the_subsystem->path, F_OK|X_OK) != 0) {
		cl_perror("Cannot (access) exec %s", the_subsystem->path);
		return FALSE;
	}

	s_res = stat(the_subsystem->command, &buf);
	if(s_res != 0) {
		cl_perror("Cannot (stat) exec %s", the_subsystem->command);
		return FALSE;
	}
	
	/* We need to fork so we can make child procs not real time */
	switch(pid=fork()) {
		case -1:
			crm_err("Cannot fork.");
			return FALSE;

		default:	/* Parent */
			the_subsystem->pid = pid;
			return TRUE;

		case 0:		/* Child */
			break;
	}

	crm_info("Executing \"%s %s\" (pid %d)",
		 the_subsystem->command, the_subsystem->args, (int) getpid());

	/* A precautionary measure */
	getrlimit(RLIMIT_NOFILE, &oflimits);
	for (j=0; j < oflimits.rlim_cur; ++j) {
		close(j);
	}
	
	(void)open(devnull, O_RDONLY);	/* Stdin:  fd 0 */
	(void)open(devnull, O_WRONLY);	/* Stdout: fd 1 */
	(void)open(devnull, O_WRONLY);	/* Stderr: fd 2 */
	
	{
		char* const start_args[] = {
			crm_strdup(the_subsystem->args),
			NULL
		};
		
		(void)execv(the_subsystem->command, start_args);
	}
	
	/* Should not happen */
	cl_perror("FATAL: Cannot exec %s %s",
		  the_subsystem->command, the_subsystem->args);

	exit(100); /* Suppress respawning */
	return TRUE; /* never reached */
}


void
cleanup_subsystem(struct crm_subsystem_s *the_subsystem)
{
	int pid_status = -1;
	the_subsystem->ipc = NULL;
	clear_bit_inplace(fsa_input_register, the_subsystem->flag);

	/* Forcing client to die */
	kill(the_subsystem->pid, -9);
	
	/* cleanup the ps entry */
	waitpid(the_subsystem->pid, &pid_status, WNOHANG);
	the_subsystem->pid = -1;

	if(is_set(fsa_input_register, R_THE_DC)) {
		/* this wasnt supposed to happen */
		crm_err("The %s subsystem terminated unexpectedly",
			the_subsystem->name);
		
		register_fsa_input(C_IPC_MESSAGE, I_ERROR, NULL);
		s_crmd_fsa(C_IPC_MESSAGE);
	}
}



