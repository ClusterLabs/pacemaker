/* $Id: crmutils.c,v 1.15 2004/05/12 14:27:16 andrew Exp $ */
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

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>

#include <apphb.h>

#include <clplumbing/cl_log.h>
#include <clplumbing/Gmain_timeout.h>

#include <crmutils.h>
#include <xmlutils.h>
#include <crm/dmalloc_wrapper.h>


static int  wdt_interval_ms = 10000;

gboolean
tickle_apphb_template(gpointer data)
{
	char	app_instance[APPNAME_LEN];
	int     rc = 0;
	sprintf(app_instance, "%s_%ld", "our_system_name", (long)getpid());

	rc = apphb_hb();
	if (rc < 0) {
		cl_perror("%s apphb_hb failure", app_instance);

		exit(3);
	}
	return TRUE;
}


void
register_pid(const char *pid_file,
	     gboolean do_fork,
	     void (*shutdown)(int nsig))
{
	int	j;
	long	pid;
	FILE *	lockfd;

	if (do_fork) {
		pid = fork();
		
		if (pid < 0) {
			cl_log(LOG_CRIT, "cannot start daemon");
			exit(LSB_EXIT_GENERIC);
		}else if (pid > 0) {
			exit(LSB_EXIT_OK);
		}
	}
    
	lockfd = fopen(pid_file, "w");
	if (lockfd == NULL) {
		cl_log(LOG_CRIT, "cannot create pid file: %s", pid_file);
		exit(LSB_EXIT_GENERIC);
	}else{
		pid = getpid();
		fprintf(lockfd, "%ld\n", pid);
		fclose(lockfd);
	}

	umask(022);

	for (j=0; j < 3; ++j) {
		close(j);
		(void)open("/dev/null", j == 0 ? O_RDONLY : O_RDONLY);
	}
//	CL_IGNORE_SIG(SIGINT);
//	CL_IGNORE_SIG(SIGHUP);
	CL_SIGNAL(SIGTERM, shutdown);
}

long
get_running_pid(const char *pid_file, gboolean* anypidfile)
{
	long    pid;
	FILE *  lockfd;
	lockfd = fopen(pid_file, "r");

	if (anypidfile) {
		*anypidfile = (lockfd != NULL);
	}

	if (lockfd != NULL
	    &&      fscanf(lockfd, "%ld", &pid) == 1 && pid > 0) {
		if (CL_PID_EXISTS((pid_t)pid)) {
			fclose(lockfd);
			return(pid);
		}
	}
	if (lockfd != NULL) {
		fclose(lockfd);
	}
	return(-1L);
}

int
init_stop(const char *pid_file)
{
	long	pid;
	int	rc = LSB_EXIT_OK;

	FNIN();
	
	if (pid_file == NULL) {
		cl_log(LOG_ERR, "No pid file specified to kill process");
		return LSB_EXIT_GENERIC;
	}
	pid =	get_running_pid(pid_file, NULL);
	
	if (pid > 0) {
		if (CL_KILL((pid_t)pid, SIGTERM) < 0) {
			rc = (errno == EPERM
			      ?	LSB_EXIT_EPERM : LSB_EXIT_GENERIC);
			fprintf(stderr, "Cannot kill pid %ld\n", pid);
		}else{
			cl_log(LOG_INFO,
			       "Signal sent to pid=%ld,"
			       " waiting for process to exit",
			       pid);
			
			while (CL_PID_EXISTS(pid)) {
				sleep(1);
			}
		}
	}
	FNRET(rc);
}
int
init_status(const char *pid_file, const char *client_name)
{
	gboolean	anypidfile;
	long	pid =	get_running_pid(pid_file, &anypidfile);

	if (pid > 0) {
		fprintf(stderr, "%s is running [pid: %ld]\n"
			,	client_name, pid);
		return LSB_STATUS_OK;
	}
	if (anypidfile) {
		fprintf(stderr, "%s is stopped [pidfile exists]\n"
			,	client_name);
		return LSB_STATUS_VAR_PID;
	}
	fprintf(stderr, "%s is stopped.\n", client_name);
	return LSB_STATUS_STOPPED;
}


gboolean
register_with_ha(ll_cluster_t *hb_cluster, const char *client_name,
		 gboolean (*dispatch_method)(int fd, gpointer user_data),
		 void (*message_callback)(const struct ha_msg* msg,
					  void* private_data),
		 GDestroyNotify cleanup_method)
{
	const char* ournode = NULL;

	cl_log(LOG_INFO, "Signing in with Heartbeat");
	if (hb_cluster->llc_ops->signon(hb_cluster, client_name)!= HA_OK) {
		cl_log(LOG_ERR, "Cannot sign on with heartbeat");
		cl_log(LOG_ERR,
		       "REASON: %s",
		       hb_cluster->llc_ops->errmsg(hb_cluster));
		return FALSE;
	}
  
	cl_log(LOG_DEBUG, "Finding our node name");
	if ((ournode =
	     hb_cluster->llc_ops->get_mynodeid(hb_cluster)) == NULL) {
		cl_log(LOG_ERR, "get_mynodeid() failed");
		return FALSE;
	}
	cl_log(LOG_INFO, "hostname: %s", ournode);
	
	cl_log(LOG_DEBUG, "Be informed of CRM messages");
	if (hb_cluster->llc_ops->set_msg_callback(hb_cluster,
						  "CRM",
						  message_callback,
						  hb_cluster)
	    !=HA_OK){
		cl_log(LOG_ERR, "Cannot set CRM message callback");
		cl_log(LOG_ERR,
		       "REASON: %s",
		       hb_cluster->llc_ops->errmsg(hb_cluster));
		return FALSE;
	}


	G_main_add_fd(G_PRIORITY_HIGH, 
		      hb_cluster->llc_ops->inputfd(hb_cluster),
		      FALSE, 
		      dispatch_method, 
		      hb_cluster,  // usrdata 
		      cleanup_method);

	/* it seems we need to poke the message receiving stuff in order for it to
	 *    start seeing messages.  Its like it gets blocked or something.
	 */
	dispatch_method(0, hb_cluster);

	return TRUE;
    
}

void
register_with_apphb(const char *client_name,
		    gboolean(*tickle_fn)(gpointer data))
{
	char	app_instance[APPNAME_LEN];
	int     hb_intvl_ms = wdt_interval_ms * 2;
	int     rc = 0;

	// Register with apphb
	cl_log(LOG_INFO, "Signing in with AppHb");
	sprintf(app_instance, "%s_%ld", client_name, (long)getpid());
  
	cl_log(LOG_INFO, "Client %s registering with apphb", app_instance);

	rc = apphb_register(client_name, app_instance);
    
	if (rc < 0) {
		cl_perror("%s registration failure", app_instance);
		exit(1);
	}
  
	cl_log(LOG_DEBUG, "Client %s registered with apphb", app_instance);
  
	cl_log(LOG_INFO, 
	       "Client %s setting %d ms apphb heartbeat interval"
	       , app_instance, hb_intvl_ms);
	rc = apphb_setinterval(hb_intvl_ms);
	if (rc < 0) {
		cl_perror("%s setinterval failure", app_instance);
		exit(2);
	}
  
	// regularly tell apphb that we are alive
	cl_log(LOG_INFO, "Setting up AppHb Heartbeat");
	Gmain_timeout_add(wdt_interval_ms, tickle_fn, NULL);
}


char *
crm_itoa(int an_int)
{
	int len = 32;
	char *buffer = cl_malloc(sizeof(char)*(len+1));
	snprintf(buffer, len, "%d", an_int);

	return buffer;
}


gboolean
subsystem_input_dispatch(IPC_Channel *sender, void *user_data)
{
	int lpc = 0;
	char *buffer = NULL;
	xmlDocPtr doc = NULL;
	IPC_Message *msg = NULL;
	gboolean all_is_well = TRUE;
	xmlNodePtr answer = NULL, root_xml_node = NULL;
	const char *sys_to;
	const char *type;

	
	FNIN();

	while(sender->ops->is_message_pending(sender)) {
		if (sender->ch_status == IPC_DISCONNECT) {
			/* The message which was pending for us is that
			 * the IPC status is now IPC_DISCONNECT */
			break;
		}
		if (sender->ops->recv(sender, &msg) != IPC_OK) {
			perror("Receive failure:");
			FNRET(!all_is_well);
		}
		if (msg == NULL) {
			cl_log(LOG_ERR, "No message this time");
			continue;
		}

		lpc++;

		/* the docs say only do this once, but in their code
		 * they do it every time!
		 */
//		xmlInitParser();

		buffer = (char*)msg->msg_body;
		cl_log(LOG_DEBUG, "Message %d [text=%s]", lpc, buffer);
		doc = xmlParseMemory(cl_strdup(buffer), strlen(buffer));

		if(doc == NULL) {
			cl_log(LOG_INFO,
			       "XML Buffer was not valid...\n Buffer: (%s)",
			       buffer);
		}

		root_xml_node = xmlDocGetRootElement(doc);

		sys_to= xmlGetProp(root_xml_node, XML_ATTR_SYSTO);
		type  = xmlGetProp(root_xml_node, XML_ATTR_MSGTYPE);
		if (root_xml_node == NULL) {
			cl_log(LOG_ERR, "Root node was NULL!!");

		} else if(sys_to == NULL) {
			cl_log(LOG_ERR, "Value of %s was NULL!!",
			       XML_ATTR_SYSTO);
			
		} else if(type == NULL) {
			cl_log(LOG_ERR, "Value of %s was NULL!!",
			       XML_ATTR_MSGTYPE);
			
		} else if(strcmp(type, XML_ATTR_REQUEST) != 0) {
			cl_log(LOG_INFO,
			       "Message was a response not a request."
			       "  Discarding");

		} else {
			gboolean (*process_function)(xmlNodePtr msg, IPC_Channel *sender) = NULL;
			process_function = user_data;
			
			if(process_function(root_xml_node, sender) == FALSE) {
				cl_log(LOG_WARNING,
				       "Received a message destined for %s"
				       " by mistake", sys_to);
			}
			
		}
		
		if(answer != NULL)
			free_xml(answer);
		answer = NULL;
		
		msg->msg_done(msg);
		msg = NULL;
	}

	// clean up after a break
	if(msg != NULL)
		msg->msg_done(msg);

	if(root_xml_node != NULL)
		free_xml(root_xml_node);

	CRM_DEBUG("Processed %d messages", lpc);
	if (sender->ch_status == IPC_DISCONNECT) {
		cl_log(LOG_ERR, "The server has left us: Shutting down...NOW");

		exit(1); // shutdown properly later
		
		FNRET(!all_is_well);
	}
	FNRET(all_is_well);
}

