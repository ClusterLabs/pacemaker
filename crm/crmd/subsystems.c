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
static gboolean run_command    (struct crm_subsystem_s *centry,
				const char *options,
				gboolean update_pid);

xmlNodePtr do_lrm_query(void);

GHashTable *xml2list(xmlNodePtr parent, const char **attr_path, int depth);

gboolean lrm_dispatch(int fd, gpointer user_data);

void do_update_resource(lrm_rsc_t *rsc, int status, int rc, const char *op_type);

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

		const char *op = xmlGetProp(cib_msg, XML_ATTR_OP);
		if(safe_str_eq(op, CRM_OPERATION_SHUTDOWN_REQ)){
			// create update section
			xmlNodePtr tmp1 = NULL;
			xmlNodePtr tmp2 =
				create_xml_node(NULL, XML_CIB_TAG_STATE);
			const char *req_from =
				xmlGetProp(cib_msg, XML_ATTR_HOSTFROM);
			
			set_xml_property_copy(tmp1, "id", req_from);
			set_xml_property_copy(tmp1, "exp_state", "shutdown");

			// create fragment
			tmp1 = create_cib_fragment(tmp2, NULL);
			
			// add to cib_msg
			add_node_copy(cib_msg, tmp1);

			free_xml(tmp2);
			free_xml(tmp1);
		}

		set_xml_property_copy(cib_msg, XML_ATTR_SYSTO, "cib");
		xmlNodePtr answer = process_cib_message(cib_msg, TRUE);
		if(relay_message(answer, TRUE) == FALSE) {
			cl_log(LOG_ERR, "Confused what to do with cib result");
			xml_message_debug(answer, "Couldnt route: ");
		}


		if(AM_I_DC && (strcmp(op, CRM_OPERATION_CREATE) == 0
			       || strcmp(op, CRM_OPERATION_UPDATE) == 0
			       || strcmp(op, CRM_OPERATION_DELETE) == 0
			       || strcmp(op, CRM_OPERATION_REPLACE) == 0
			       || strcmp(op, CRM_OPERATION_WELCOME) == 0
			       || strcmp(op, CRM_OPERATION_SHUTDOWN_REQ) == 0
			       || strcmp(op, CRM_OPERATION_ERASE) == 0)) {
			FNRET(I_CIB_UPDATE);	
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
		xmlNodePtr answer = process_cib_message(cib_msg, TRUE);
		put_message(answer);
		FNRET(I_REQUEST);

	} else if(action & A_CIB_BUMPGEN) {  
 		// check if the response was ok before next bit

		const char *section = get_xml_attr(cib_msg, XML_TAG_OPTIONS,
						   XML_ATTR_FILTER_TYPE, FALSE);
		
		/* set the section so that we dont always send the
		 * whole thing
		 */
		xmlNodePtr new_options = NULL;

		if(section != NULL) {
			new_options = set_xml_attr(NULL, XML_TAG_OPTIONS,
						   XML_ATTR_FILTER_TYPE,
						   section, TRUE);
		}
		
		xmlNodePtr answer = process_cib_request(CRM_OPERATION_BUMP,
							new_options, NULL);

		free_xml(new_options);

		if(answer == NULL) {
			cl_log(LOG_ERR, "Result of BUMP in %s was NULL",
			       __FUNCTION__);
			FNRET(I_FAIL);
		}

		send_request(NULL, answer, CRM_OPERATION_REPLACE,
			     NULL, CRM_SYSTEM_CRMD);
		
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
			(crmd_client_t *)cl_malloc(sizeof(crmd_client_t));
	
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
		send_request(NULL, NULL, "quit", NULL, centry->name);

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
	
	cmd_with_options = cl_malloc((1+size)*sizeof(char));
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


/*	 A_LRM_CONNECT	*/
enum crmd_fsa_input
do_lrm_control(long long action,
		enum crmd_fsa_cause cause,
		enum crmd_fsa_state cur_state,
		enum crmd_fsa_input current_input,
		void *data)
{
	enum crmd_fsa_input failed = I_NULL;//I_FAIL;
	int ret = HA_OK;
	FNIN();

	if(action & A_LRM_DISCONNECT) {
		fsa_lrm_conn->lrm_ops->signoff(fsa_lrm_conn);
	}

	if(action & A_LRM_CONNECT) {
	
		CRM_DEBUG("LRM: connect...");
		fsa_lrm_conn = ll_lrm_new("lrm");	
		if(NULL == fsa_lrm_conn) {
			return failed;
		}
		
		CRM_DEBUG("LRM: sigon...");
		ret = fsa_lrm_conn->lrm_ops->signon(fsa_lrm_conn,
						    "crmd");
		
		if(ret != HA_OK) {
			cl_log(LOG_ERR, "Failed to sign on to the LRM");
			return failed;
		}
		
		CRM_DEBUG("LRM: set_lrm_callback...");
		ret = fsa_lrm_conn->lrm_ops->set_lrm_callback(fsa_lrm_conn,
							      lrm_op_callback,
							      lrm_monitor_callback);
		
		if(ret != HA_OK) {
			cl_log(LOG_ERR, "Failed to set LRM callbacks");
			return failed;
		}

		/* TODO: create a destroy handler that causes
		 * some recovery to happen
		 */
		G_main_add_fd(G_PRIORITY_LOW,
			      fsa_lrm_conn->lrm_ops->inputfd(fsa_lrm_conn),
			      FALSE,
			      lrm_dispatch, fsa_lrm_conn,
			      default_ipc_input_destroy);
	}	

	if(action & ~(A_LRM_CONNECT|A_LRM_DISCONNECT)) {
		cl_log(LOG_ERR, "Unexpected action %s in %s",
		       fsa_action2string(action), __FUNCTION__);
	}
		
	
	FNRET(I_NULL);
}

gboolean lrm_dispatch(int fd, gpointer user_data)
{
	ll_lrm_t *lrm = (ll_lrm_t*)user_data;
	lrm->lrm_ops->rcvmsg(lrm, FALSE);
	return TRUE;
}

xmlNodePtr
do_lrm_query(void)
{
	GList* lrm_list = NULL;
	xmlNodePtr data = create_xml_node(NULL, "lrm");
	xmlNodePtr agent_list = create_xml_node(data, "lrm_agents");
	
	lrm_list = fsa_lrm_conn->lrm_ops->get_ra_supported(fsa_lrm_conn);
	if (NULL != lrm_list) {
		GList* element = g_list_first(lrm_list);
		while (NULL != element) {
			char *rsc_type = (char*)element->data;
			
			xmlNodePtr agent =
				create_xml_node(agent_list, "lrm_agent");
			
			set_xml_property_copy(agent, "class",   rsc_type);

			/* we dont have these yet */
			set_xml_property_copy(agent, "type",    NULL);
			set_xml_property_copy(agent, "version", NULL);
			
			element = g_list_next(element);
		}
	}
	
	g_list_free(lrm_list);
	lrm_list = fsa_lrm_conn->lrm_ops->get_all_rscs(fsa_lrm_conn);

	xmlNodePtr rsc_list = create_xml_node(data, "lrm_resources");
	GList* element = NULL;

	if (NULL != lrm_list) {
		element = g_list_first(lrm_list);
	}
	
	while (NULL != element) {
		lrm_rsc_t *the_rsc = (lrm_rsc_t*)element->data;
		
/* 				const char*	ra_type; */
/* 				GHashTable* 	params; */
		
		xmlNodePtr xml_rsc = create_xml_node(rsc_list, "rsc_state");
		
		set_xml_property_copy(xml_rsc, "id",     the_rsc->id);
		set_xml_property_copy(xml_rsc, "rsc_id", the_rsc->name);
		set_xml_property_copy(xml_rsc, "node_id",fsa_our_uname);
		
		state_flag_t cur_state = 0;
		
		CRM_DEBUG("get_cur_state...");
		
		GList* op_list = the_rsc->ops->get_cur_state(the_rsc,
							     &cur_state);
		CRM_DEBUG2("\tcurrent state:%s\n",
			   cur_state==LRM_RSC_IDLE?"Idel":"Busy");
		
		const char *this_op = NULL;
		GList* node = g_list_first(op_list);
		
		while(NULL != node){
			lrm_op_t* op = (lrm_op_t*)node->data;
			this_op = op->op_type;
			if(this_op == NULL
			   || strcmp(this_op, "status") != 0){
				
				const char *status_text = "<unknown>";
				switch(op->status) {
					case LRM_OP_DONE:
						status_text = "done";
						break;
					case LRM_OP_CANCELLED:
						status_text = "cancelled";
						break;
					case LRM_OP_TIMEOUT:
						status_text = "timeout";
						break;
					case LRM_OP_NOTSUPPORTED:
						status_text = "not suported";
						break;
					case LRM_OP_ERROR:
						status_text = "error";
						break;
				}
				
				
				set_xml_property_copy(xml_rsc,
						      "op_result",
						      status_text);
				
				set_xml_property_copy(xml_rsc,
						      "rsc_op",
						      this_op);
				
				// we only want the last one
				break;
			}
			
			node = g_list_next(node);
		}
		
		element = g_list_next(element);
	}

	if (NULL != lrm_list) {
		g_list_free(lrm_list);
	}
	
	return data;
}


/*	 A_LRM_INVOKE	*/
enum crmd_fsa_input
do_lrm_invoke(long long action,
	     enum crmd_fsa_cause cause,
	     enum crmd_fsa_state cur_state,
	     enum crmd_fsa_input current_input,
	     void *data)
{
	enum crmd_fsa_input next_input = I_NULL;
	FNIN();


	if(action & A_UPDATE_NODESTATUS) {

		xmlNodePtr data = do_lrm_query();
		set_xml_property_copy(data, "replace_lrm", "true");

		xmlNodePtr fragment, tmp1;
	
		tmp1 = create_xml_node(NULL, XML_CIB_TAG_STATE);
		set_xml_property_copy(tmp1, XML_ATTR_ID, fsa_our_uname);
		fragment = create_cib_fragment(tmp1, NULL);

		set_xml_property_copy(data, "replace_lrm", "true");
		add_node_copy(tmp1, data);

		send_request(NULL, fragment, CRM_OPERATION_UPDATE,
			     NULL, CRM_SYSTEM_DC);

		free_xml(fragment);
		free_xml(tmp1);
		free_xml(data);

		FNRET(next_input);
	}
	

	
	cl_log(LOG_ERR, "Action %s (%.16llx) not supported\n",
	       fsa_action2string(action), action);


	xmlNodePtr msg = (xmlNodePtr)data;
	const char *rsc_path[] = 
		{
			"msg_data",
			"rsc_op",
			"resource",
			"instance_attributes",
			"parameters"
		};
		
	const char *operation = get_xml_attr_nested(msg,
						    rsc_path,
						    DIMOF(rsc_path) -3,
						    "operation", TRUE);

	rsc_id_t rid;
	
	const char *id_from_cib = get_xml_attr_nested(msg,
						      rsc_path,
						      DIMOF(rsc_path) -2,
						      "id",
						      TRUE);
	// only the first 16 chars are used by the LRM
	strncpy(rid, id_from_cib, 16);
	

	const char *crm_op = get_xml_attr(msg, XML_TAG_OPTIONS, "operation", TRUE);

	lrm_rsc_t *rsc = fsa_lrm_conn->lrm_ops->get_rsc(
		fsa_lrm_conn, rid);
	
	if(crm_op != NULL && strcmp(crm_op, "lrm_query") == 0) {

		xmlNodePtr data, tmp1, tmp2, reply;

		tmp1 = create_xml_node(NULL, XML_CIB_TAG_STATE);
		set_xml_property_copy(tmp1, XML_ATTR_ID, fsa_our_uname);
		
		data = create_cib_fragment(tmp1, NULL);

		tmp2 = do_lrm_query();
		add_node_copy(tmp1, tmp2);

		reply = create_reply(msg, data);

		relay_message(reply, TRUE);

		free_xml(data);
		free_xml(reply);
		free_xml(tmp2);
		free_xml(tmp1);

	} else if(operation != NULL && strcmp(operation, "monitor") == 0) {
		if(rsc == NULL) {
			cl_log(LOG_ERR, "Could not find resource to monitor");
			FNRET(I_FAIL);
		}
		
		lrm_mon_t* mon = g_new(lrm_mon_t, 1);
		mon->op_type = "status";
		mon->params = NULL;
		mon->timeout = 0;
		mon->user_data = rsc;
		mon->mode = LRM_MONITOR_SET;
		mon->interval = 2;
		mon->target = 1;
		rsc->ops->set_monitor(rsc,mon);
		mon = g_new(lrm_mon_t, 1);

	} else if(operation != NULL) {
		if(rsc == NULL) {
			// add it to the list
			CRM_DEBUG("add_rsc...");
			fsa_lrm_conn->lrm_ops->add_rsc(
				fsa_lrm_conn, rid,
				get_xml_attr_nested(msg, 
						    rsc_path,
						    DIMOF(rsc_path) -2,
						    "class", TRUE),
				get_xml_attr_nested(msg, 
						    rsc_path,
						    DIMOF(rsc_path) -2,
						    "type", TRUE),
				NULL);
			
			rsc = fsa_lrm_conn->lrm_ops->get_rsc(
				fsa_lrm_conn, rid);
		}

		if(rsc == NULL) {
			cl_log(LOG_ERR, "Could not add resource to LRM");
			FNRET(I_FAIL);
		}
		
		// now do the op
		CRM_DEBUG2("performing op %s...", operation);
		lrm_op_t* op = g_new(lrm_op_t, 1);
		op->op_type = operation;
		op->params = xml2list(msg, rsc_path, DIMOF(rsc_path));
		op->timeout = 0;
		op->user_data = rsc;
		rsc->ops->perform_op(rsc, op);
	}

	FNRET(next_input);
}

GHashTable *
xml2list(xmlNodePtr parent, const char**attr_path, int depth)
{
	xmlNodePtr node_iter = NULL;

	GHashTable   *nvpair_hash =
		g_hash_table_new(&g_str_hash, &g_str_equal);

	xmlNodePtr nvpair_list =
		find_xml_node_nested(parent, attr_path, depth);
	
	if(nvpair_list != NULL){
		node_iter = nvpair_list->children;
		while(node_iter != NULL) {
			
			const char *key = xmlGetProp(node_iter, "name");
			const char *value = xmlGetProp(node_iter, "value");
			
			CRM_DEBUG3("Added %s=%s", key, value);
			
			g_hash_table_insert (nvpair_hash,
					     cl_strdup(key),
					     cl_strdup(value));
			
			node_iter = node_iter->next;
		}
	}
	
	return nvpair_hash;
}


void
do_update_resource(lrm_rsc_t *rsc, int status, int rc, const char *op_type)
{
/*
<status>
    <nodes_status id=uname>
        <lrm>
	   <lrm_resources>
	       <lrm_resource id=>
	   </...>
*/
	xmlNodePtr update, iter;
	
	update = create_xml_node(NULL, "node_state");
	set_xml_property_copy(update, XML_ATTR_ID, fsa_our_uname);
	iter = create_xml_node(update, "lrm");
	iter = create_xml_node(iter, "lrm_resources");
	iter = create_xml_node(iter, "lrm_resource");
	
	set_xml_property_copy(iter, XML_ATTR_ID, rsc->id);
	set_xml_property_copy(iter, "last_op", op_type);
	
	char *tmp = crm_itoa(status);
	set_xml_property_copy(iter, "op_status", tmp);
	cl_free(tmp);
	
	tmp = crm_itoa(rc);
	set_xml_property_copy(iter, "op_code", tmp);
	cl_free(tmp);

	
	xmlNodePtr fragment, tmp1;
	
	tmp1 = create_xml_node(NULL, XML_CIB_TAG_STATE);
	set_xml_property_copy(tmp1, XML_ATTR_ID, fsa_our_uname);
	add_node_copy(tmp1, update);

	fragment = create_cib_fragment(tmp1, NULL);

	send_request(NULL, fragment, CRM_OPERATION_UPDATE,
		     NULL, CRM_SYSTEM_DCIB);

	free_xml(fragment);
	free_xml(update);
	free_xml(tmp1);
}

enum crmd_fsa_input
do_lrm_event(long long action,
	     enum crmd_fsa_cause cause,
	     enum crmd_fsa_state cur_state,
	     enum crmd_fsa_input cur_input,
	     void *data)
{
	FNIN();
	if(cause == C_LRM_MONITOR_CALLBACK) {
		lrm_mon_t* monitor = (lrm_mon_t*)data;
		lrm_rsc_t* rsc = monitor->rsc;
		

		switch(monitor->status) {
			case LRM_OP_DONE:
				CRM_DEBUG("An LRM monitor operation passed");
				FNRET(I_NULL);
				break;

			case LRM_OP_CANCELLED:
			case LRM_OP_TIMEOUT:
			case LRM_OP_NOTSUPPORTED:
			case LRM_OP_ERROR:
				cl_log(LOG_ERR,
				       "An LRM monitor operation failed"
				       " or was aborted");

				do_update_resource(rsc,
						   monitor->status,
						   monitor->rc,
						   monitor->op_type);
				break;
		}	

	} else if(cause == C_LRM_OP_CALLBACK) {
		lrm_op_t* op = (lrm_op_t*)data;
		lrm_rsc_t* rsc = op->rsc;

		switch(op->status) {
			case LRM_OP_CANCELLED:
			case LRM_OP_TIMEOUT:
			case LRM_OP_NOTSUPPORTED:
			case LRM_OP_ERROR:
				cl_log(LOG_ERR,
				       "An LRM operation failed"
				       " or was aborted");
				// keep going
			case LRM_OP_DONE:

				do_update_resource(rsc,
						   op->status,
						   op->rc,
						   op->op_type);

				break;
		}
		
	} else {

		FNRET(I_FAIL);
	}
	
	FNRET(I_NULL);
}


