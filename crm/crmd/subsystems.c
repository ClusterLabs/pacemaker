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
#include <crm/crm.h>
#include <crmd_fsa.h>

#include <sys/types.h>
#include <sys/wait.h>

#include <unistd.h>			// for access
#include <clplumbing/cl_signal.h>
#include <clplumbing/realtime.h>
#include <sys/types.h>	// for calls to open
#include <sys/stat.h>	// for calls to open
#include <fcntl.h>	// for calls to open
#include <pwd.h>	// for getpwuid
#include <grp.h>	// for initgroups

#include <sys/time.h>	// for getrlimit
#include <sys/resource.h>// for getrlimit

#include <crm/common/ipcutils.h>
#include <crm/msg_xml.h>
#include <crm/common/xmlutils.h>


#include <crm/cib.h>

#include <crmd.h>
#include <crmd_messages.h>
#include <string.h>
#include <errno.h>

#include <crm/dmalloc_wrapper.h>

#define CLIENT_EXIT_WAIT 10

static gboolean stop_subsystem (struct crm_subsystem_s *centry);
static gboolean start_subsystem(struct crm_subsystem_s *centry);
static gboolean run_command    (struct crm_subsystem_s *centry,
				const char *options,
				gboolean update_pid);

gboolean crmd_authorize_message(xmlNodePtr root_xml_node,
				IPC_Message *client_msg,
				crmd_client_t *curr_client);

struct crm_subsystem_s *cib_subsystem = NULL;
struct crm_subsystem_s *te_subsystem  = NULL;
struct crm_subsystem_s *pe_subsystem  = NULL;

void
cleanup_subsystem(struct crm_subsystem_s *the_subsystem)
{
	int pid_status = -1;
	the_subsystem->ipc = NULL;
	clear_bit_inplace(&fsa_input_register,
			  the_subsystem->flag);

	/* Forcing client to die */
	kill(the_subsystem->pid, -9);
	
	// cleanup the ps entry
	waitpid(the_subsystem->pid, &pid_status, WNOHANG);
	the_subsystem->pid = -1;
}

/*	 A_CIB_STOP, A_CIB_START, A_CIB_RESTART,	*/
enum crmd_fsa_input
do_cib_control(long long action,
	       enum crmd_fsa_cause cause,
	       enum crmd_fsa_state cur_state,
	       enum crmd_fsa_input current_input,
	       void *data)
{
	enum crmd_fsa_input result = I_NULL;
	struct crm_subsystem_s *this_subsys = cib_subsystem;
	
	long long stop_actions = A_CIB_STOP;
	long long start_actions = A_CIB_START;

	FNIN();
	
	if(action & stop_actions) {
		// dont do anything, its embedded now
	}

	if(action & start_actions) {

		if(cur_state != S_STOPPING) {
			if(startCib(CIB_FILENAME) == FALSE)
				result = I_FAIL;

		} else {
			cl_log(LOG_INFO,
			       "Ignoring request to start %s after shutdown",
			       this_subsys->command);
		}
	}
	
	FNRET(result);
}

/*	 A_CIB_INVOKE, A_CIB_BUMPGEN, A_UPDATE_NODESTATUS	*/
enum crmd_fsa_input
do_cib_invoke(long long action,
	      enum crmd_fsa_cause cause,
	      enum crmd_fsa_state cur_state,
	      enum crmd_fsa_input current_input,
	      void *data)
{
	xmlNodePtr cib_msg = NULL;
	FNIN();

	if(data != NULL)
		cib_msg = (xmlNodePtr)data;

	
	if(action & A_CIB_INVOKE) {
		set_xml_property_copy(cib_msg, XML_ATTR_SYSTO, "cib");
		xmlNodePtr answer = process_cib_message(cib_msg, TRUE);
		if(relay_message(answer, TRUE) == FALSE) {
			cl_log(LOG_ERR, "Confused what to do with cib result");
			xml_message_debug(answer, "Couldnt route: ");
		}

		// check the answer, see if we are interested in it also
#if 0
		if(interested in reply) {
			put_message(answer);
			FN_RET(I_REQUEST);
		}
		
#endif

		free_xml(answer);

		/* experimental */
/* 	} else if(action & A_CIB_INVOKE_LOCAL) { */
/* 		xmlNodePtr answer = process_cib_message(cib_msg, TRUE); */
/* 		put_message(answer); */
/* 		FN_RET(I_REQUEST); */

	} else if(action & A_CIB_BUMPGEN) {  
 		// check if the response was ok before next bit

		const char *section = get_xml_attr(cib_msg, XML_TAG_OPTIONS,
						   XML_ATTR_FILTER_TYPE, FALSE);
		
		/* set the section so that we dont always send the
		 * whole thing
		 */
		xmlNodePtr new_options =
			set_xml_attr(NULL, XML_TAG_OPTIONS,
				     XML_ATTR_FILTER_TYPE, section, TRUE);
		
		xmlNodePtr answer = process_cib_request(CRM_OPERATION_BUMP,
							new_options, NULL);

		send_request(NULL, answer, CRM_OPERATION_STORE,
			     NULL, CRM_SYSTEM_CRMD);

		free_xml(answer);
		free_xml(new_options);

  	} else if(action & A_UPDATE_NODESTATUS) {

		/* build our status */
		/* save to message list CIB */
		/* return I_MESSAGE */
		
	} else {
		cl_log(LOG_ERR, "Unexpected action %s",
		       fsa_action2string(action));
	}
	
	
	FNRET(I_NULL);
}


/*	 A_PE_START, A_PE_STOP, A_TE_RESTART	*/
enum crmd_fsa_input
do_pe_control(long long action,
	      enum crmd_fsa_cause cause,
	      enum crmd_fsa_state cur_state,
	      enum crmd_fsa_input current_input,
	      void *data)
{
	enum crmd_fsa_input result = I_NULL;
	struct crm_subsystem_s *this_subsys = pe_subsystem;

	long long stop_actions = A_PE_STOP;
	long long start_actions = A_PE_START;
	
	FNIN();

	if(action & stop_actions) {
		if(stop_subsystem(this_subsys) == FALSE)
			result = I_FAIL;
		else  if(this_subsys->pid > 0){
			int lpc = CLIENT_EXIT_WAIT;
			int pid_status = -1;
			while(lpc-- > 0
			      && this_subsys->pid > 0
			      && CL_PID_EXISTS(this_subsys->pid)) {

				sleep(1);
				waitpid(this_subsys->pid, &pid_status, WNOHANG);
			}
			
			if(CL_PID_EXISTS(this_subsys->pid)) {
				cl_log(LOG_ERR,
				       "Process %s is still active with pid=%d",
				       this_subsys->command, this_subsys->pid);
				result = I_FAIL;
			} 
		}

		cleanup_subsystem(this_subsys);
	}

	if(action & start_actions) {

		if(cur_state != S_STOPPING) {
			if(start_subsystem(this_subsys) == FALSE) {
				result = I_FAIL;
				cleanup_subsystem(this_subsys);
			}
		} else {
			cl_log(LOG_INFO,
			       "Ignoring request to start %s while shutting down",
			       this_subsys->command);
		}
	}
	
	FNRET(result);
}

/*	 A_PE_INVOKE	*/
enum crmd_fsa_input
do_pe_invoke(long long action,
	     enum crmd_fsa_cause cause,
	     enum crmd_fsa_state cur_state,
	     enum crmd_fsa_input current_input,
	     void *data)
{
	FNIN();

	stopTimer(integration_timer);
	cl_log(LOG_ERR, "Action %s (%.16llx) not supported\n",
	       fsa_action2string(action), action);
	
	FNRET(I_NULL);
}

/*	 A_TE_START, A_TE_STOP, A_TE_RESTART	*/
enum crmd_fsa_input
do_te_control(long long action,
	      enum crmd_fsa_cause cause,
	      enum crmd_fsa_state cur_state,
	      enum crmd_fsa_input current_input,
	      void *data)
{
	enum crmd_fsa_input result = I_NULL;
	struct crm_subsystem_s *this_subsys = te_subsystem;
	
	long long stop_actions = A_TE_STOP;
	long long start_actions = A_TE_START;
	
	FNIN();

/* 		if(action & stop_actions && cur_state != S_STOPPING */
/* 		   && is_set(fsa_input_register, R_TE_PEND)) { */
/* 			result = I_WAIT_FOR_EVENT; */
/* 			FNRET(result); */
/* 		} */
	
	if(action & stop_actions) {
		if(stop_subsystem(this_subsys) == FALSE)
			result = I_FAIL;
		else if(this_subsys->pid > 0){
			int lpc = CLIENT_EXIT_WAIT;
			int pid_status = -1;
			while(lpc-- > 0
			      && this_subsys->pid > 0
			      && CL_PID_EXISTS(this_subsys->pid)) {

				sleep(1);
				waitpid(this_subsys->pid, &pid_status, WNOHANG);
			}
			
			if(CL_PID_EXISTS(this_subsys->pid)) {
				cl_log(LOG_ERR,
				       "Process %s is still active with pid=%d",
				       this_subsys->command, this_subsys->pid);
				result = I_FAIL;
			} 
		}

		cleanup_subsystem(this_subsys);
	}

	if(action & start_actions) {

		if(cur_state != S_STOPPING) {
			if(start_subsystem(this_subsys) == FALSE) {
				result = I_FAIL;
				cleanup_subsystem(this_subsys);
			}
		} else {
			cl_log(LOG_INFO,
			       "Ignoring request to start %s while shutting down",
			       this_subsys->command);
		}
	}

	FNRET(result);
}

/*	 A_TE_INVOKE	*/
enum crmd_fsa_input
do_te_invoke(long long action,
	     enum crmd_fsa_cause cause,
	     enum crmd_fsa_state cur_state,
	     enum crmd_fsa_input current_input,
	     void *data)
{
	FNIN();

	cl_log(LOG_ERR, "Action %s (%.16llx) not supported\n",
	       fsa_action2string(action), action);
	
	FNRET(I_NULL);
}

gboolean
crmd_client_connect(IPC_Channel *client_channel, gpointer user_data)
{
	FNIN();

	CRM_DEBUG("A client tried to connect... and there was much rejoicing.");

	if (client_channel == NULL) {
		cl_log(LOG_ERR, "Channel was NULL");
	} else if (client_channel->ch_status == IPC_DISCONNECT) {
		cl_log(LOG_ERR, "Channel was disconnected");
	} else {
		crmd_client_t *blank_client =
			(crmd_client_t *)ha_malloc(sizeof(crmd_client_t));
	
		if (blank_client == NULL) {
			cl_log(LOG_ERR,
			       "Could not allocate memory for a blank crmd_client_t");
			FNRET(FALSE);
		}
		client_channel->ops->set_recv_qlen(client_channel, 100);
		client_channel->ops->set_send_qlen(client_channel, 100);
	
		blank_client->client_channel = client_channel;
		blank_client->sub_sys   = NULL;
		blank_client->uuid       = NULL;
		blank_client->table_key = NULL;
	
		CRM_DEBUG("Adding IPC Channel to main thread.");
		blank_client->client_source =
			G_main_add_IPC_Channel(G_PRIORITY_LOW,
					       client_channel,
					       FALSE, 
					       crmd_ipc_input_callback,
					       blank_client,
					       default_ipc_input_destroy);
	}
    
	FNRET(TRUE);
}

static gboolean
stop_subsystem(struct crm_subsystem_s*	centry)
{
	cl_log(LOG_INFO, "Stopping sub-system \"%s\"", centry->command);
	if (centry->pid <= 0) {
		cl_log(LOG_ERR,
		       "OOPS! client %s not running yet",
		       centry->command);
	} else {
#if 0
		return run_command(centry, "-k", FALSE);
#else
		send_request(NULL, NULL, "quit", NULL, centry->name);
#endif
	}
	
	return TRUE;
}


static gboolean
start_subsystem(struct crm_subsystem_s*	centry)
{
	cl_log(LOG_INFO, "Starting sub-system \"%s\"", centry->command);

	if (centry->pid != 0) {
		cl_log(LOG_ERR, "OOPS! client %s already running as pid %d"
		       ,	centry->command, (int) centry->pid);
	}

	return run_command(centry, "-r", TRUE);
}


static gboolean
run_command(struct crm_subsystem_s *centry,
	    const char *options,
	    gboolean update_pid)
{
	pid_t			pid;

	/*
	 * We need to ensure that the exec will succeed before
	 * we bother forking.  We don't want to respawn something that
	 * won't exec in the first place.
	 */

	if (access(centry->path, F_OK|X_OK) != 0) {
		cl_perror("Cannot (access) exec %s", centry->path);
		return FALSE;
	}

	struct stat buf;
	int s_res = stat(centry->command, &buf);
	if(s_res != 0) {
		cl_perror("Cannot (stat) exec %s", centry->command);
		return FALSE;
	}
	

	/* We need to fork so we can make child procs not real time */
	switch(pid=fork()) {

		case -1:	cl_log(LOG_ERR
				       ,	"start_a_child_client: Cannot fork.");
			return FALSE;

		default:	/* Parent */
#if 0
			NewTrackedProc(pid, 1, PT_LOGVERBOSE
				       ,	centry, &ManagedChildTrackOps);
#else
			if(update_pid)
				centry->pid = pid;
#endif
			return TRUE;

		case 0:		/* Child */
			break;
	}

	/* Child process:  start the managed child */
	cl_make_normaltime();
	setpgid(0,0);

	/* Limit peak resource usage, maximize success chances */
	if (centry->shortrcount > 0) {
		alarm(0);
		sleep(1);
	}

	char *cmd_with_options = NULL;
	int size = strlen(options);
	size += strlen(centry->command);
	size += 2; // ' ' + \0
	
	cmd_with_options = ha_malloc((1+size)*sizeof(char));
	sprintf(cmd_with_options, "%s %s", centry->command, options);
	cmd_with_options[size] = 0;
	

	cl_log(LOG_INFO, "Executing \"%s\" (pid %d)",
	       cmd_with_options, (int) getpid());

	if(CL_SIGINTERRUPT(SIGALRM, 0) < 0) {
		cl_perror("Cannot set interrupt for child process %s",
			  cmd_with_options);
	}else{
		const char *	devnull = "/dev/null";
		unsigned int	j;
		struct rlimit		oflimits;
		CL_SIGNAL(SIGCHLD, SIG_DFL);
		alarm(0);
		CL_IGNORE_SIG(SIGALRM);

		/* A precautionary measure */
		getrlimit(RLIMIT_NOFILE, &oflimits);
		for (j=0; j < oflimits.rlim_cur; ++j) {
			close(j);
		}
		(void)devnull;
		
		(void)open(devnull, O_RDONLY);	/* Stdin:  fd 0 */
		(void)open(devnull, O_WRONLY);	/* Stdout: fd 1 */
		(void)open(devnull, O_WRONLY);	/* Stderr: fd 2 */

		(void)execl("/bin/sh", "sh", "-c", cmd_with_options, (const char *)NULL);

		/* Should not happen */
		cl_perror("Cannot exec %s", cmd_with_options);
	}
	/* Suppress respawning */
	exit(100);

	// never reached
	return TRUE;
}
