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

	
	
	if(action & stop_actions) {
		/* dont do anything, its embedded now */
	}

	if(action & start_actions) {

		if(cur_state != S_STOPPING) {
			if(startCib(CIB_FILENAME) == FALSE)
				result = I_FAIL;

		} else {
			crm_info("Ignoring request to start %s after shutdown",
				 this_subsys->command);
		}
	}
	
	return result;
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
	enum crmd_fsa_input result = I_NULL;

	if(data != NULL) {
		cib_msg = (xmlNodePtr)data;
	}
	
	
	if(action & A_CIB_INVOKE || action & A_CIB_INVOKE_LOCAL) {
/*		gboolean is_update   = FALSE; */
		xmlNodePtr options   = find_xml_node(cib_msg, XML_TAG_OPTIONS);
		const char *sys_from = xmlGetProp(cib_msg, XML_ATTR_SYSFROM);
		const char *op       = xmlGetProp(options, XML_ATTR_OP);
		
		crm_xml_devel(cib_msg, "[CIB b4]");
		if(cib_msg == NULL) {
			crm_err("No message for CIB command");
			return I_NULL; /* I_ERROR */

		} else if(op == NULL) {
			crm_xml_devel(cib_msg, "Invalid CIB Message");
			return I_NULL; /* I_ERROR */

		}

		set_xml_property_copy(cib_msg, XML_ATTR_SYSTO, "cib");
		answer = process_cib_message(cib_msg, TRUE);

		if(action & A_CIB_INVOKE) {

			if(AM_I_DC == FALSE) {
				if(relay_message(answer, TRUE) == FALSE) {
					crm_err("Confused what to do with cib result");
					crm_xml_devel(answer, "Couldnt route: ");
					result = I_ERROR;
				}
				
			} else if(strcmp(op, CRM_OP_CREATE) == 0
			   || strcmp(op, CRM_OP_UPDATE) == 0
			   || strcmp(op, CRM_OP_DELETE) == 0
			   || strcmp(op, CRM_OP_REPLACE) == 0
			   || strcmp(op, CRM_OP_WELCOME) == 0
			   || strcmp(op, CRM_OP_SHUTDOWN_REQ) == 0) {
				result = I_CIB_UPDATE;	
				
			} else if(strcmp(op, CRM_OP_ERASE) == 0) {
				/* regenerate everyone's state and our node entry */
				result = I_ELECTION_DC;	
			}
			
			/* the TENGINE will get CC'd by other means. */
			if(AM_I_DC
			   && sys_from != NULL
			   && safe_str_neq(sys_from, CRM_SYSTEM_TENGINE) 
			   && safe_str_neq(sys_from, CRM_SYSTEM_CRMD)
			   && safe_str_neq(sys_from, CRM_SYSTEM_DC)
			   && relay_message(answer, TRUE) == FALSE) {
				crm_err("Confused what to do with cib result");
				crm_xml_devel(answer, "Couldnt route: ");
				result = I_ERROR;
				
			}
			
/* 		} else { */
/* 			put_message(answer); */
/* 			return I_REQUEST; */
			
		}

		crm_xml_devel(cib_msg, "[CIB after]");
		return result;

	} else if(action & A_CIB_BUMPGEN) {
/*		xmlNodePtr options   = find_xml_node(cib_msg, XML_TAG_OPTIONS); */
/*		const char *op       = xmlGetProp(options, XML_ATTR_OP); */

		if(AM_I_DC == FALSE) {
			return I_NULL;
		}

 		/* check if the response was ok before next bit */

/*		if(safe_str_neq(op, CRM_OP_WELCOME)) { */
			/* set the section so that we dont always send the
			 * whole thing
			 */
		section = get_xml_attr(
			cib_msg, XML_TAG_OPTIONS,
			XML_ATTR_FILTER_TYPE, FALSE);
/*		} */
		
		if(section != NULL) {
			new_options = set_xml_attr(
				NULL, XML_TAG_OPTIONS, XML_ATTR_FILTER_TYPE,
				section, TRUE);
		}
		
		answer = process_cib_request(
			CRM_OP_BUMP, new_options, NULL);

		free_xml(new_options);

		if(answer == NULL) {
			crm_err("Result of BUMP in %s was NULL",
			       __FUNCTION__);
			return I_FAIL;
		}

		send_request(NULL, answer, CRM_OP_REPLACE,
			     NULL, CRM_SYSTEM_CRMD, NULL);
		
		free_xml(answer);

	} else {
		crm_err("Unexpected action %s in %s",
		       fsa_action2string(action), __FUNCTION__);
	}
	
	
	return I_NULL;
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
				crm_err("Process %s is still active with pid=%d",
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
			crm_info("Ignoring request to start %s while shutting down",
			       this_subsys->command);
		}
	}
	
	return result;
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
	xmlNodePtr local_cib = NULL;

	stopTimer(integration_timer);

	if(is_set(fsa_input_register, R_PE_CONNECTED) == FALSE){
		
		crm_info("Waiting for the PE to connect");
		return I_WAIT_FOR_EVENT;
		
	}
	
	local_cib = get_cib_copy();

	crm_verbose("Invoking %s with %p", CRM_SYSTEM_PENGINE, local_cib);

	if(fsa_pe_ref) {
		crm_free(fsa_pe_ref);
		fsa_pe_ref = NULL;
	}

	send_request(NULL, local_cib, CRM_OP_PECALC,
		     NULL, CRM_SYSTEM_PENGINE, &fsa_pe_ref);

	return I_NULL;
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
	int lpc, pid_status;
	
/* 		if(action & stop_actions && cur_state != S_STOPPING */
/* 		   && is_set(fsa_input_register, R_TE_PEND)) { */
/* 			result = I_WAIT_FOR_EVENT; */
/* 			return result; */
/* 		} */
	
	if(action & stop_actions) {
		if(stop_subsystem(this_subsys) == FALSE)
			result = I_FAIL;
		else if(this_subsys->pid > 0){
			lpc = CLIENT_EXIT_WAIT;
			pid_status = -1;
			while(lpc-- > 0
			      && this_subsys->pid > 0
			      && CL_PID_EXISTS(this_subsys->pid)) {

				sleep(1);
				waitpid(this_subsys->pid, &pid_status, WNOHANG);
			}
			
			if(CL_PID_EXISTS(this_subsys->pid)) {
				crm_err("Process %s is still active with pid=%d",
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
			crm_info("Ignoring request to start %s while shutting down",
				 this_subsys->command);
		}
	}

	return result;
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
	
	

	if(data != NULL) {
		crm_xml_devel(data, "[TE imput]");
		message  = copy_xml_node_recursive((xmlNodePtr)data);
		opts  = find_xml_node(message, XML_TAG_OPTIONS);
		true_op = xmlGetProp(opts, XML_ATTR_OP);
		
		set_xml_property_copy(opts, XML_ATTR_OP, CRM_OP_EVENTCC);
		set_xml_property_copy(opts, XML_ATTR_TRUEOP, true_op);

		set_xml_property_copy(
			message, XML_ATTR_SYSTO, CRM_SYSTEM_TENGINE);
	}

	if(is_set(fsa_input_register, R_TE_CONNECTED) == FALSE){
		crm_info("Waiting for the TE to connect");
		if(data != NULL) {
			free_xml(te_lastcc);
			te_lastcc = message;
		}
		return I_WAIT_FOR_EVENT;

	}

	if(message == NULL) {
		message = te_lastcc;
		te_lastcc = NULL;
		
	} else {
		free_xml(te_lastcc);
	}
	
	relay_message(message, FALSE);

	/* only free it if it was a local copy */
	if(data == NULL) {
		free_xml(message);
	}
	
	return I_NULL;
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
	

	if(is_set(fsa_input_register, R_TE_CONNECTED) == FALSE){
		crm_info("Waiting for the TE to connect");
		if(data != NULL) {
			free_xml(te_last_input);
			te_last_input = copy_xml_node_recursive(msg);
		}
		return I_WAIT_FOR_EVENT;

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
			return I_FAIL;
		}
	
		send_request(NULL, graph, CRM_OP_TRANSITION,
			     NULL, CRM_SYSTEM_TENGINE, NULL);
	} else {
		send_request(NULL, graph, CRM_OP_ABORT,
			     NULL, CRM_SYSTEM_TENGINE, NULL);
	}

	/* only free it if it was a local copy */
	if(data == NULL) {
		free_xml(msg);
	}
	
	return I_NULL;
}

gboolean
crmd_client_connect(IPC_Channel *client_channel, gpointer user_data)
{
	

	if (client_channel == NULL) {
		crm_err("Channel was NULL");
	} else if (client_channel->ch_status == IPC_DISCONNECT) {
		crm_err("Channel was disconnected");
	} else {
		crmd_client_t *blank_client =
			(crmd_client_t *)crm_malloc(sizeof(crmd_client_t));
	
		if (blank_client == NULL) {
			crm_err("Could not allocate memory for a blank crmd_client_t");
			return FALSE;
		}
		client_channel->ops->set_recv_qlen(client_channel, 100);
		client_channel->ops->set_send_qlen(client_channel, 100);
	
		blank_client->client_channel = client_channel;
		blank_client->sub_sys   = NULL;
		blank_client->uuid      = NULL;
		blank_client->table_key = NULL;
	
		blank_client->client_source =
			G_main_add_IPC_Channel(G_PRIORITY_LOW,
					       client_channel,
					       FALSE, 
					       crmd_ipc_input_callback,
					       blank_client,
					       default_ipc_input_destroy);
	}
    
	return TRUE;
}

static gboolean
stop_subsystem(struct crm_subsystem_s*	centry)
{
	crm_info("Stopping sub-system \"%s\"", centry->name);
	if (centry->pid <= 0) {
		crm_err("OOPS! client %s not running yet",
			centry->command);

	} else {
		crm_info("Sending quit message to %s.", centry->name);
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

	crm_info("Starting sub-system \"%s\"", centry->command);

	if (centry->pid > 0) {
		crm_err("OOPS! client %s already running as pid %d"
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
			crm_err("start_a_child_client: Cannot fork.");
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

	crm_info("Executing \"%s\" (pid %d)",
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

	/* never reached */
	return TRUE;
}



