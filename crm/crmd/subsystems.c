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
#include <portability.h>
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

#include <crm/common/crmutils.h>
#include <crm/common/ipcutils.h>
#include <crm/common/msgutils.h>

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

struct crm_subsystem_s *cib_subsystem = NULL;
struct crm_subsystem_s *te_subsystem  = NULL;
struct crm_subsystem_s *pe_subsystem  = NULL;


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
	xmlNodePtr answer = NULL;
	xmlNodePtr new_options = NULL;
	const char *section = NULL;

	FNIN();

	if(data != NULL) {
		cib_msg = (xmlNodePtr)data;
	}
	
	
	if(action & A_CIB_INVOKE) {

		const char *op = get_xml_attr(cib_msg, XML_TAG_OPTIONS,
					      XML_ATTR_OP, TRUE);

		xml_message_debug(cib_msg, "[CIB] Invoking with");
		if(cib_msg == NULL) {
			cl_log(LOG_ERR, "No message for CIB command");
			FNRET(I_NULL); // I_ERROR
		}

		set_xml_property_copy(cib_msg, XML_ATTR_SYSTO, "cib");
		answer = process_cib_message(cib_msg, TRUE);
		if(relay_message(answer, TRUE) == FALSE) {
			cl_log(LOG_ERR, "Confused what to do with cib result");
			xml_message_debug(answer, "Couldnt route: ");
		}


		if(op != NULL && AM_I_DC
		   && (strcmp(op, CRM_OP_CREATE) == 0
		       || strcmp(op, CRM_OP_UPDATE) == 0
		       || strcmp(op, CRM_OP_DELETE) == 0
		       || strcmp(op, CRM_OP_REPLACE) == 0
		       || strcmp(op, CRM_OP_WELCOME) == 0
		       || strcmp(op, CRM_OP_SHUTDOWN_REQ) == 0
		       || strcmp(op, CRM_OP_ERASE) == 0)) {
			FNRET(I_CIB_UPDATE);	
		}

		if(op == NULL) {
			xml_message_debug(cib_msg, "Invalid CIB Message");
		}
		
	
		
		// check the answer, see if we are interested in it also
#if 0
		if(interested in reply) {
			put_message(answer);
			FNRET(I_REQUEST);
		}
#endif

		free_xml(answer);

		/* experimental */
	} else if(action & A_CIB_INVOKE_LOCAL) {
		xml_message_debug(cib_msg, "[CIB] Invoking with");
		if(cib_msg == NULL) {
			cl_log(LOG_ERR, "No message for CIB command");
			FNRET(I_NULL); // I_ERROR
		}
		
		answer = process_cib_message(cib_msg, TRUE);
		put_message(answer);
		FNRET(I_REQUEST);

	} else if(action & A_CIB_BUMPGEN) {  
 		// check if the response was ok before next bit

		section = get_xml_attr(cib_msg, XML_TAG_OPTIONS,
				       XML_ATTR_FILTER_TYPE, FALSE);
		
		/* set the section so that we dont always send the
		 * whole thing
		 */

		if(section != NULL) {
			new_options = set_xml_attr(NULL, XML_TAG_OPTIONS,
						   XML_ATTR_FILTER_TYPE,
						   section, TRUE);
		}
		
		answer = process_cib_request(CRM_OP_BUMP,
					     new_options, NULL);

		free_xml(new_options);

		if(answer == NULL) {
			cl_log(LOG_ERR, "Result of BUMP in %s was NULL",
			       __FUNCTION__);
			FNRET(I_FAIL);
		}

		send_request(NULL, answer, CRM_OP_REPLACE,
			     NULL, CRM_SYSTEM_CRMD, NULL);
		
		free_xml(answer);

	} else {
		cl_log(LOG_ERR, "Unexpected action %s in %s",
		       fsa_action2string(action), __FUNCTION__);
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

char *fsa_pe_ref = NULL;

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

	if(is_set(fsa_input_register, R_PE_CONNECTED) == FALSE){
		
		cl_log(LOG_INFO, "Waiting for the PE to connect");
		FNRET(I_WAIT_FOR_EVENT);
		
	}
	
	xmlNodePtr local_cib = get_cib_copy();

	CRM_DEBUG("Invoking %s with %p", CRM_SYSTEM_PENGINE, local_cib);

	if(fsa_pe_ref) {
		crm_free(fsa_pe_ref);
		fsa_pe_ref = NULL;
	}

	send_request(NULL, local_cib, CRM_OP_PECALC,
		     NULL, CRM_SYSTEM_PENGINE, &fsa_pe_ref);

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

static xmlNodePtr te_last_input = NULL;
static xmlNodePtr te_lastcc = NULL;

/*	 A_TE_COPYTO	*/
enum crmd_fsa_input
do_te_copyto(long long action,
	     enum crmd_fsa_cause cause,
	     enum crmd_fsa_state cur_state,
	     enum crmd_fsa_input current_input,
	     void *data)
{
	xmlNodePtr message  = NULL;
	xmlNodePtr opts     = NULL;
	const char *true_op = NULL;
	
	FNIN();

	if(data != NULL) {
		message  = copy_xml_node_recursive((xmlNodePtr)data);
		opts  = find_xml_node(message, XML_TAG_OPTIONS);
		true_op = xmlGetProp(opts, XML_ATTR_OP);
		
		set_xml_property_copy(opts, XML_ATTR_OP, CRM_OP_EVENTCC);
		set_xml_property_copy(opts, XML_ATTR_TRUEOP, true_op);

		set_xml_property_copy(message,
				      XML_ATTR_SYSTO,
				      CRM_SYSTEM_TENGINE);
	}

	if(is_set(fsa_input_register, R_TE_CONNECTED) == FALSE){
		cl_log(LOG_INFO, "Waiting for the TE to connect");
		if(data != NULL) {
			free_xml(te_lastcc);
			te_lastcc = message;
		}
		FNRET(I_WAIT_FOR_EVENT);

	}

	if(message == NULL) {
		message = te_lastcc;
		te_lastcc = NULL;
		
	} else {
		free_xml(te_lastcc);
	}
	
	relay_message(message, FALSE);

	// only free it if it was a local copy
	if(data == NULL) {
		free_xml(message);
	}
	
	FNRET(I_NULL);
}


/*	 A_TE_INVOKE, A_TE_CANCEL	*/
enum crmd_fsa_input
do_te_invoke(long long action,
	     enum crmd_fsa_cause cause,
	     enum crmd_fsa_state cur_state,
	     enum crmd_fsa_input current_input,
	     void *data)
{
	xmlNodePtr graph = NULL;
	xmlNodePtr msg = (xmlNodePtr)data;
	FNIN();

	if(is_set(fsa_input_register, R_TE_CONNECTED) == FALSE){
		cl_log(LOG_INFO, "Waiting for the TE to connect");
		if(data != NULL) {
			free_xml(te_last_input);
			te_last_input = copy_xml_node_recursive(msg);
		}
		FNRET(I_WAIT_FOR_EVENT);

	}

	if(msg == NULL) {
		msg = te_last_input;
		te_last_input = NULL;
		
	} else {
		free_xml(te_last_input);
	}
	
	if(action & A_TE_INVOKE) {
		graph = find_xml_node(msg, "transition_graph");
		if(graph == NULL) {
			FNRET(I_FAIL);
		}
	
		send_request(NULL, graph, CRM_OP_TRANSITION,
			     NULL, CRM_SYSTEM_TENGINE, NULL);
	} else {
		send_request(NULL, graph, CRM_OP_ABORT,
			     NULL, CRM_SYSTEM_TENGINE, NULL);
	}

	// only free it if it was a local copy
	if(data == NULL) {
		free_xml(msg);
	}
	
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
			(crmd_client_t *)crm_malloc(sizeof(crmd_client_t));
	
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
	cl_log(LOG_INFO, "Stopping sub-system \"%s\"", centry->name);
	if (centry->pid <= 0) {
		cl_log(LOG_ERR,
		       "OOPS! client %s not running yet",
		       centry->command);

	} else {
		cl_log(LOG_INFO, "Sending quit message to %s.", centry->name);
		send_request(NULL, NULL, CRM_OP_QUIT, NULL, centry->name, NULL);

	}
	
	return TRUE;
}


static gboolean
start_subsystem(struct crm_subsystem_s*	centry)
{
	pid_t			pid;
	struct stat buf;
	int s_res;

	cl_log(LOG_INFO, "Starting sub-system \"%s\"", centry->command);

	if (centry->pid != 0) {
		cl_log(LOG_ERR, "OOPS! client %s already running as pid %d"
		       ,	centry->command, (int) centry->pid);
	}

	/*
	 * We need to ensure that the exec will succeed before
	 * we bother forking.  We don't want to respawn something that
	 * won't exec in the first place.
	 */

	if (access(centry->path, F_OK|X_OK) != 0) {
		cl_perror("Cannot (access) exec %s", centry->path);
		return FALSE;
	}

	s_res = stat(centry->command, &buf);
	if(s_res != 0) {
		cl_perror("Cannot (stat) exec %s", centry->command);
		return FALSE;
	}
	

	/* We need to fork so we can make child procs not real time */
	switch(pid=fork()) {

		case -1:
			cl_log(LOG_ERR, "start_a_child_client: Cannot fork.");
			return FALSE;

		default:	/* Parent */
			centry->pid = pid;
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

	cl_log(LOG_INFO, "Executing \"%s\" (pid %d)",
	       centry->command, (int) getpid());

	if(CL_SIGINTERRUPT(SIGALRM, 0) < 0) {
		cl_perror("Cannot set interrupt for child process %s",
			  centry->command);
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

		(void)execl("/bin/sh", "sh", "-c", centry->command, (const char *)NULL);

		/* Should not happen */
		cl_perror("Cannot exec %s", centry->command);
	}
	/* Suppress respawning */
	exit(100);

	// never reached
	return TRUE;
}



