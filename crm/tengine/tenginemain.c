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

#include <portability.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <hb_api.h>
#include <apphb.h>

#include <clplumbing/ipc.h>
#include <clplumbing/Gmain_timeout.h>
#include <clplumbing/cl_log.h>
#include <clplumbing/cl_signal.h>
#include <clplumbing/lsb_exitcodes.h>
#include <clplumbing/uids.h>
#include <clplumbing/realtime.h>
#include <clplumbing/GSource.h>
#include <clplumbing/cl_poll.h>

#include <crm/common/ipcutils.h>

#define IPC_COMMS        1
#define FORK_CHILD       1

#define OPTARGS	"skrh"
#define PID_FILE     WORKING_DIR "/transitioner.pid"
#define DAEMON_LOG   "/var/log/transitioner.log"
#define DAEMON_DEBUG "/var/log/transitioner.debug"
//#define DAEMON_FIFO  WORKING_DIR "/transitioner.fifo"
#define APPNAME_LEN 256

GMainLoop*  mainloop = NULL;
const char* daemon_name = "transitioner";


void usage(const char* cmd, int exit_status);
int init_start(void);
int init_stop(void);
int init_status(void);
void register_pid(void);
long get_running_pid(gboolean* anypidfile);
void shutdown(int nsig);
void register_with_apphb(void);
gboolean tickle_apphb(gpointer data);
int ha_register(void);

int
main(int argc, char ** argv)
{

    cl_log_set_entity(daemon_name);
    cl_log_enable_stderr(TRUE);
    cl_log_set_facility(LOG_USER);
    
    int	req_restart = FALSE;
    int	req_status = FALSE;
    int	req_stop = FALSE;
    int	argerr = 0;
    int flag;

    if(0)
    {
	send_ipc_message(NULL, NULL);
    }
    
    
    while ((flag = getopt(argc, argv, OPTARGS)) != EOF) {
	switch(flag) {
	    case 's':		/* Status */
		req_status = TRUE;
		break;
	    case 'k':		/* Stop (kill) */
		req_stop = TRUE;
		break;
	    case 'r':		/* Restart */
		req_restart = TRUE;
		break;
	    case 'h':		/* Help message */
		usage(daemon_name, LSB_EXIT_OK);
		break;
	    default:
		++argerr;
		break;
	}
    }
    
    if (optind > argc) {
	++argerr;
    }
    
    if (argerr) {
	usage(daemon_name,LSB_EXIT_GENERIC);
    }
    
    // read local config file
    
    if (req_status){
	return init_status();
    }
  
    if (req_stop){
	return init_stop();
    }
  
    if (req_restart) { 
	init_stop();
    }

    return init_start();

}


int
init_start(void)
{
    long pid;

    if ((pid = get_running_pid(NULL)) > 0) {
	cl_log(LOG_CRIT, "already running: [pid %ld].", pid);
	exit(LSB_EXIT_OK);
    }
  
    cl_log_set_logfile(DAEMON_LOG);
//    if (crm_debug()) {
    cl_log_set_debugfile(DAEMON_DEBUG);
//    }

    (void)_ha_msg_h_Id;
    
    /* change the logging facility to the one used by heartbeat daemon */
    ll_cluster_t*	hb_fd = ll_cluster_new("heartbeat");
    
    //	(void)_heartbeat_h_Id;
    
    int facility;
    cl_log(LOG_INFO, "Switching to Heartbeat logger");
    if ((facility = hb_fd->llc_ops->get_logfacility(hb_fd))>0) {
	cl_log_set_facility(facility);
    }
    
    cl_log(LOG_INFO, "Register PID");
    register_pid();

    IPC_Channel *crm_ch = init_client_ipc_comms("crmd", clntCh_input_dispatch);

    IPC_Message        *msg;
    char	       str[256];
    snprintf(str, sizeof(str)-1, "I am the transitioner with pid: %ld", (long int)getpid());

    msg = create_simple_message(str, crm_ch);
    send_ipc_message(crm_ch, msg);

    /* Create the mainloop and run it... */
    mainloop = g_main_new(FALSE);
    cl_log(LOG_INFO, "Starting %s", daemon_name);

    G_main_add_IPC_Channel(G_PRIORITY_LOW,
			   crm_ch,
			   FALSE, 
			   clntCh_input_dispatch,
			   crm_ch, 
			   clntCh_input_destroy);

    
    
#ifdef REALTIME_SUPPORT
static int  crm_realtime = 1;
    if (crm_realtime == 1){
	cl_enable_realtime();
    }else if (crm_realtime == 0){
	cl_disable_realtime();
    }
    cl_make_realtime(SCHED_RR, 5, 64, 64);
#endif

    g_main_run(mainloop);
    return_to_orig_privs();
  
    if (unlink(PID_FILE) == 0) {
	cl_log(LOG_INFO, "[%s] stopped", daemon_name);
    }
    return 0;
}


#ifdef APPHB_SUPPORT
static int  wdt_interval_ms = 10000;
void
register_with_apphb(void)
{
    // Register with apphb
    cl_log(LOG_INFO, "Signing in with AppHb");
    char	app_instance[APPNAME_LEN];
    int     hb_intvl_ms = wdt_interval_ms * 2;
    int     rc = 0;
    sprintf(app_instance, "%s_%ld", daemon_name, (long)getpid());
  
    cl_log(LOG_INFO, "Client %s registering with apphb", app_instance);

    rc = apphb_register(daemon_name, app_instance);
    
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
    Gmain_timeout_add(wdt_interval_ms, tickle_apphb, NULL);
}

#else

void
register_with_apphb(void)
{
}

#endif


void
register_pid(void)
{
    int	j;
    long	pid;
    FILE *	lockfd;

#ifdef FORK_CHILD
    pid = fork();

    if (pid < 0) {
	cl_log(LOG_CRIT, "cannot start daemon.\n");
	exit(LSB_EXIT_GENERIC);
    }else if (pid > 0) {
	exit(LSB_EXIT_OK);
    }
#endif

    lockfd = fopen(PID_FILE, "w");
    if (lockfd == NULL) {
	cl_log(LOG_CRIT, "cannot create pid file" PID_FILE);
	exit(LSB_EXIT_GENERIC);
    }else{
	pid = getpid();
	fprintf(lockfd, "%ld\n", pid);
	fclose(lockfd);
    }

    umask(022);
    getsid(0);
/*     if (!crm_debug()) { */
/* 	cl_log_enable_stderr(FALSE); */
/*     } */

    for (j=0; j < 3; ++j) {
	close(j);
	(void)open("/dev/null", j == 0 ? O_RDONLY : O_RDONLY);
    }
    CL_IGNORE_SIG(SIGINT);
    CL_IGNORE_SIG(SIGHUP);
    CL_SIGNAL(SIGTERM, shutdown);
}

long
get_running_pid(gboolean* anypidfile)
{
    long    pid;
    FILE *  lockfd;
    lockfd = fopen(PID_FILE, "r");

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
init_stop(void)
{
    long	pid;
    int	rc = LSB_EXIT_OK;
    pid =	get_running_pid(NULL);

    if (pid > 0) {
	if (CL_KILL((pid_t)pid, SIGTERM) < 0) {
	    rc = (errno == EPERM
		  ?	LSB_EXIT_EPERM : LSB_EXIT_GENERIC);
	    fprintf(stderr, "Cannot kill pid %ld\n", pid);
	}else{
	    while (CL_PID_EXISTS(pid)) {
		sleep(1);
	    }
	}
    }
    return rc;
}
int
init_status(void)
{
    gboolean	anypidfile;
    long	pid =	get_running_pid(&anypidfile);

    if (pid > 0) {
	fprintf(stderr, "%s is running [pid: %ld]\n"
		,	daemon_name, pid);
	return LSB_STATUS_OK;
    }
    if (anypidfile) {
	fprintf(stderr, "%s is stopped [pidfile exists]\n"
		,	daemon_name);
	return LSB_STATUS_VAR_PID;
    }
    fprintf(stderr, "%s is stopped.\n", daemon_name);
    return LSB_STATUS_STOPPED;
}


void
usage(const char* cmd, int exit_status)
{
    FILE* stream;

    stream = exit_status ? stderr : stdout;

    fprintf(stream, "usage: %s [-srkh]"
	    "[-c configure file]\n", cmd);
/* 	fprintf(stream, "\t-d\tsets debug level\n"); */
/* 	fprintf(stream, "\t-s\tgets daemon status\n"); */
/* 	fprintf(stream, "\t-r\trestarts daemon\n"); */
/* 	fprintf(stream, "\t-k\tstops daemon\n"); */
/* 	fprintf(stream, "\t-h\thelp message\n"); */
    fflush(stream);

    exit(exit_status);
}

void
shutdown(int nsig)
{
    static int	shuttingdown = 0;
    CL_SIGNAL(nsig, shutdown);
  
    if (!shuttingdown) {
	shuttingdown = 1;
    }
    if (mainloop != NULL && g_main_is_running(mainloop)) {
	g_main_quit(mainloop);
    }else{
	exit(LSB_EXIT_OK);
    }
}

// keep the compiler happy
gboolean
waitCh_client_connect(IPC_Channel *newclient, gpointer user_data)
{
    return TRUE;
}
