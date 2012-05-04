/* 
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <crm_internal.h>

#include <unistd.h>             /* for access */
#include <sys/types.h>          /* for calls to open */
#include <sys/stat.h>           /* for calls to open */
#include <fcntl.h>              /* for calls to open */
#include <pwd.h>                /* for getpwuid */
#include <grp.h>                /* for initgroups */
#include <errno.h>

#include <sys/wait.h>
#include <sys/time.h>           /* for getrlimit */
#include <sys/param.h>
#include <sys/types.h>
#include <sys/resource.h>       /* for getrlimit */

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/cib.h>

#include <crmd_fsa.h>
#include <crmd_messages.h>
#include <crmd_callbacks.h>

#include <crmd.h>
#include <crm/common/util.h>

static void
crmdManagedChildDied(GPid pid, gint status, gpointer user_data)
{
    struct crm_subsystem_s *the_subsystem = user_data;

    if(WIFSIGNALED(status)) {
        int signo = WTERMSIG(status);
        int core = WCOREDUMP(status);
        crm_notice("Child process %s terminated with signal %d (pid=%d, core=%d)",
                   the_subsystem->name, signo, the_subsystem->pid, core);

    } else if(WIFEXITED(status)) {
        int exitcode = WEXITSTATUS(status);
        do_crm_log(exitcode == 0 ? LOG_INFO : LOG_ERR,
                   "Child process %s exited (pid=%d, rc=%d)", the_subsystem->name, the_subsystem->pid, exitcode);

    } else {
        crm_err("Process %s:[%d] exited?", the_subsystem->name, the_subsystem->pid);
    }

#if 0
    /* everything below is now handled in pe_connection_destroy() */
    the_subsystem->pid = -1;
    the_subsystem->ipc = NULL;
    clear_bit_inplace(fsa_input_register, the_subsystem->flag_connected);

    crm_trace("Triggering FSA: %s", __FUNCTION__);
    mainloop_set_trigger(fsa_source);

    if (is_set(fsa_input_register, the_subsystem->flag_required)) {
        /* this wasnt supposed to happen */
        crm_warn("The %s subsystem terminated unexpectedly", the_subsystem->name);

        if (the_subsystem->flag_connected == R_PE_CONNECTED) {
            int rc = cib_ok;
            char *pid = crm_itoa(the_subsystem->pid);

            /* the PE died...
             * save the current CIB so that we have a chance of
             * figuring out what killed it
             */
            rc = fsa_cib_conn->cmds->query(fsa_cib_conn, NULL, NULL, cib_scope_local);
            add_cib_op_callback(fsa_cib_conn, rc, TRUE, pid, save_cib_contents);
        }

        register_fsa_input_before(C_FSA_INTERNAL, I_ERROR, NULL);
    }
#endif
}

gboolean
stop_subsystem(struct crm_subsystem_s *the_subsystem, gboolean force_quit)
{
    int quit_signal = SIGTERM;

    crm_trace("Stopping sub-system \"%s\"", the_subsystem->name);
    clear_bit_inplace(fsa_input_register, the_subsystem->flag_required);

    if (the_subsystem->pid <= 0) {
        crm_trace("Client %s not running", the_subsystem->name);
        return FALSE;

    }

    if (is_set(fsa_input_register, the_subsystem->flag_connected) == FALSE) {
        /* running but not yet connected */
        crm_debug("Stopping %s before it had connected", the_subsystem->name);
    }
/*
	if(force_quit && the_subsystem->sent_kill == FALSE) {
		quit_signal = SIGKILL;

	} else if(force_quit) {
		crm_debug("Already sent -KILL to %s: [%d]",
			  the_subsystem->name, the_subsystem->pid);
	}
*/
    errno = 0;
    if (kill(the_subsystem->pid, quit_signal) == 0) {
        crm_info("Sent -TERM to %s: [%d]", the_subsystem->name, the_subsystem->pid);
        the_subsystem->sent_kill = TRUE;

    } else {
        crm_perror(LOG_ERR, "Sent -TERM to %s: [%d]", the_subsystem->name, the_subsystem->pid);
    }

    return TRUE;
}

gboolean
start_subsystem(struct crm_subsystem_s * the_subsystem)
{
    pid_t pid;
    struct stat buf;
    int s_res;
    unsigned int j;
    struct rlimit oflimits;
    const char *devnull = "/dev/null";

    crm_info("Starting sub-system \"%s\"", the_subsystem->name);

    if (the_subsystem->pid > 0) {
        crm_warn("Client %s already running as pid %d",
                 the_subsystem->name, (int)the_subsystem->pid);

        /* starting a started X is not an error */
        return TRUE;
    }

    /*
     * We want to ensure that the exec will succeed before
     * we bother forking.
     */

    if (access(the_subsystem->path, F_OK | X_OK) != 0) {
        crm_perror(LOG_ERR, "Cannot (access) exec %s", the_subsystem->path);
        return FALSE;
    }

    s_res = stat(the_subsystem->command, &buf);
    if (s_res != 0) {
        crm_perror(LOG_ERR, "Cannot (stat) exec %s", the_subsystem->command);
        return FALSE;
    }

    /* We need to fork so we can make child procs not real time */
    switch (pid = fork()) {
        case -1:
            crm_err("Cannot fork.");
            return FALSE;

        default:               /* Parent */
            g_child_watch_add(pid, crmdManagedChildDied, the_subsystem);
            crm_trace("Client %s is has pid: %d", the_subsystem->name, pid);
            the_subsystem->pid = pid;
            return TRUE;

        case 0:                /* Child */
            /* create a new process group to avoid
             * being interupted by heartbeat
             */
            setpgid(0, 0);
            break;
    }

    crm_debug("Executing \"%s (%s)\" (pid %d)",
              the_subsystem->command, the_subsystem->name, (int)getpid());

    /* A precautionary measure */
    getrlimit(RLIMIT_NOFILE, &oflimits);
    for (j = 0; j < oflimits.rlim_cur; ++j) {
        close(j);
    }

    (void)open(devnull, O_RDONLY);      /* Stdin:  fd 0 */
    (void)open(devnull, O_WRONLY);      /* Stdout: fd 1 */
    (void)open(devnull, O_WRONLY);      /* Stderr: fd 2 */

    {
        char *opts[] = { crm_strdup(the_subsystem->command), NULL };
        (void)execvp(the_subsystem->command, opts);
    }

    /* Should not happen */
    crm_perror(LOG_ERR, "FATAL: Cannot exec %s", the_subsystem->command);

    exit(100);                  /* Suppress respawning */
    return TRUE;                /* never reached */
}
