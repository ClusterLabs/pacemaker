/* $Id: ctrl.c,v 1.1 2004/06/02 11:45:28 andrew Exp $ */
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
#include <crm/common/ctrl.h>

#include <apphb.h>

#include <clplumbing/cl_log.h>
#include <clplumbing/Gmain_timeout.h>

#include <crm/dmalloc_wrapper.h>


static int  wdt_interval_ms = 10000;


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
