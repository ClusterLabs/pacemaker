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
#include <crm/common/crm.h>
#include <crmd_fsa.h>

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
#include <crmd.h>
#include <crmd_messages.h>

static gboolean start_a_child_client(gpointer childentry, gpointer pidtable);
gboolean crmd_authorize_message(xmlNodePtr root_xml_node,
				IPC_Message *client_msg,
				crmd_client_t *curr_client);

struct crm_subsystem_s *cib_subsystem = NULL;
struct crm_subsystem_s *te_subsystem  = NULL;
struct crm_subsystem_s *pe_subsystem  = NULL;

/*	 A_CIB_STOP, A_CIB_START, A_CIB_RESTART,	*/
enum crmd_fsa_input
do_cib_control(long long action,
	       enum crmd_fsa_state cur_state,
	       enum crmd_fsa_input current_input,
	       void *data)
{
	enum crmd_fsa_input result = I_NULL;
	
	FNIN();
	
	if(action & A_CIB_STOP || action & A_CIB_RESTART) {
		if(cib_subsystem != NULL) {
			clear_bit_inplace(&fsa_input_register,R_CIB_CONNECTED);
			
			// make sure we do a shutdown
			if(cib_subsystem->command != NULL)
				ha_free(cib_subsystem->command);
			cib_subsystem->command = ha_strdup("cib/cib -k");
			
			start_a_child_client(cib_subsystem, NULL);
		} // else we havent been started yet
	}
	
	if(action & A_CIB_START || action & A_CIB_RESTART) {
		if(cib_subsystem == NULL) {
			cib_subsystem = (struct crm_subsystem_s*)
				ha_malloc(sizeof(struct crm_subsystem_s));
			
			cib_subsystem->pid = 0;	
			cib_subsystem->respawn = 1;	
			cib_subsystem->command = NULL;
			cib_subsystem->u_runas = -1;	 
			cib_subsystem->g_runas = -1;	 
			cib_subsystem->path = ha_strdup(BIN_DIR);	
		}
		
		// make sure we always do a (re)start here
		if(cib_subsystem->command != NULL)
			ha_free(cib_subsystem->command);
		cib_subsystem->command = ha_strdup("cib/cib -r");	
		if(start_a_child_client(cib_subsystem, NULL) == FALSE)
			result = I_FAIL;
	}
	
	FNRET(result);
}

/*	 A_CIB_INVOKE	*/
enum crmd_fsa_input
do_cib_invoke(long long action,
	      enum crmd_fsa_state cur_state,
	      enum crmd_fsa_input current_input,
	      void *data)
{
	FNIN();
	
	FNRET(I_NULL);
}

/*	 A_PE_START	*/
enum crmd_fsa_input
do_pe_control(long long action,
	    enum crmd_fsa_state cur_state,
	    enum crmd_fsa_input current_input,
	    void *data)
{
	enum crmd_fsa_input result = I_NULL;
	
	FNIN();

	if(action & A_PE_STOP || action & A_PE_RESTART) {
		if(pe_subsystem != NULL) {
			clear_bit_inplace(&fsa_input_register, R_PE_CONNECTED);
			
			// make sure we do a shutdown
			if(pe_subsystem->command != NULL)
				ha_free(pe_subsystem->command);
			pe_subsystem->command = ha_strdup("pengine -k");

			start_a_child_client(pe_subsystem, NULL);
		} // else we havent been started yet
	}
	
	if(action & A_PE_START || action & A_PE_RESTART) {
		if(pe_subsystem == NULL) {
			pe_subsystem = (struct crm_subsystem_s*)
				ha_malloc(sizeof(struct crm_subsystem_s));
			
			pe_subsystem->pid = 0;	
			pe_subsystem->respawn = 1;	
			pe_subsystem->command = NULL;
			pe_subsystem->u_runas = -1;	 
			pe_subsystem->g_runas = -1;	 
			pe_subsystem->path = ha_strdup(BIN_DIR);	
		}
		
		// make sure we always do a (re)start here
		if(pe_subsystem->command != NULL)
			ha_free(pe_subsystem->command);
		pe_subsystem->command = ha_strdup("pengine -r");	
		if(start_a_child_client(pe_subsystem, NULL) == FALSE)
			result = I_FAIL;
	}
	
	FNRET(result);
}

/*	 A_PE_INVOKE	*/
enum crmd_fsa_input
do_pe_invoke(long long action,
	     enum crmd_fsa_state cur_state,
	     enum crmd_fsa_input current_input,
	     void *data)
{
	FNIN();
	
	FNRET(I_NULL);
}

/*	 A_TE_START	*/
enum crmd_fsa_input
do_te_control(long long action,
	    enum crmd_fsa_state cur_state,
	    enum crmd_fsa_input current_input,
	    void *data)
{
	enum crmd_fsa_input result = I_NULL;
	
	FNIN();

	if(action & A_TE_STOP || action & A_TE_RESTART) {
		if(te_subsystem != NULL) {
			clear_bit_inplace(&fsa_input_register, R_TE_CONNECTED);
			
			// make sure we do a shutdown
			if(te_subsystem->command != NULL)
				ha_free(te_subsystem->command);
			te_subsystem->command = ha_strdup("tengine -k");

			start_a_child_client(te_subsystem, NULL);
		} // else we havent been started yet
	}
	
	if(action & A_TE_START || action & A_TE_RESTART) {
		if(te_subsystem == NULL) {
			te_subsystem = (struct crm_subsystem_s*)
				ha_malloc(sizeof(struct crm_subsystem_s));
			
			te_subsystem->pid = 0;	
			te_subsystem->respawn = 1;	
			te_subsystem->command = NULL;
			te_subsystem->u_runas = -1;	 
			te_subsystem->g_runas = -1;	 
			te_subsystem->path = ha_strdup(BIN_DIR);	
		}
		
		// make sure we always do a (re)start here
		if(te_subsystem->command != NULL)
			ha_free(te_subsystem->command);
		te_subsystem->command = ha_strdup("tengine -r");	
		if(start_a_child_client(te_subsystem, NULL) == FALSE)
			result = I_FAIL;
	}
	
	FNRET(result);
}

/*	 A_TE_INVOKE	*/
enum crmd_fsa_input
do_te_invoke(long long action,
	     enum crmd_fsa_state cur_state,
	     enum crmd_fsa_input current_input,
	     void *data)
{
	FNIN();
	
	FNRET(I_NULL);
}

gboolean
crmd_client_connect(IPC_Channel *client_channel, gpointer user_data)
{
	FNIN();
	// assign the client to be something, or put in a hashtable
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
	
		blank_client->client_channel = client_channel;
		blank_client->sub_sys = NULL;
		blank_client->uid = NULL;
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


/*
 * Why re-invent the wheel? Steal the start_a_child_client from heartbeat.c,
 *
 * Only minor modifications have been made, so it should be possible to just
 * drop in verbatum any changes made there
 */
static gboolean
start_a_child_client(gpointer childentry, gpointer pidtable)
{
	struct crm_subsystem_s*	centry = childentry;
	pid_t			pid;
	struct passwd*		pwent;

	cl_log(LOG_INFO, "Starting child client \"%s\" (%d,%d)"
	,	centry->command, (int) centry->u_runas
	,	(int) centry->g_runas);

	if (centry->pid != 0) {
		cl_log(LOG_ERR, "OOPS! client %s already running as pid %d"
		,	centry->command, (int) centry->pid);
	}

	/*
	 * We need to ensure that the exec will succeed before
	 * we bother forking.  We don't want to respawn something that
	 * won't exec in the first place.
	 */

	if (access(centry->path, F_OK|X_OK) < 0) {
		cl_perror("Cannot exec %s", centry->command);
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

	cl_log(LOG_INFO, "Starting \"%s\" as uid %d  gid %d (pid %d)"
	,	centry->command, (int) centry->u_runas
	,	(int) centry->g_runas, (int) getpid());

	if(((int)centry->g_runas >= 0) && ((int)centry->u_runas >= 0)) {
		if ((pwent = getpwuid(centry->u_runas)) == NULL
		    || initgroups(pwent->pw_name, centry->g_runas) < 0
		    || setgid(centry->g_runas) < 0
		    || setuid(centry->u_runas) < 0) {
			cl_perror("Cannot setup uid/gid for child process %s", centry->command);
		}
	}
	
	if(CL_SIGINTERRUPT(SIGALRM, 0) < 0) {
		cl_perror("Cannot set interrupt for child process %s", centry->command);
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

		(void)open(devnull, O_RDONLY);	/* Stdin:  fd 0 */
		(void)open(devnull, O_WRONLY);	/* Stdout: fd 1 */
		(void)open(devnull, O_WRONLY);	/* Stderr: fd 2 */
		(void)execl("/bin/sh", "sh", "-c", centry->command
		,	(const char *)NULL);

		/* Should not happen */
		cl_perror("Cannot exec %s", centry->command);
	}
	/* Suppress respawning */
	exit(100);

	// never reached
	return TRUE;
}
