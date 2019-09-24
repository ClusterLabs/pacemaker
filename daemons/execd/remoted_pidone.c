/*
 * Copyright 2017-2019 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <crm/crm.h>
#include "pacemaker-execd.h"

static pid_t main_pid = 0;

static void
sigdone(void)
{
    exit(CRM_EX_OK);
}

static void
sigreap(void)
{
    pid_t pid = 0;
    int status;

    do {
        /*
         * Opinions seem to differ as to what to put here:
         *  -1, any child process
         *  0,  any child process whose process group ID is equal to that of the calling process
         */
        pid = waitpid(-1, &status, WNOHANG);
        if (pid == main_pid) {
            /* Exit when pacemaker-remote exits and use the same return code */
            if (WIFEXITED(status)) {
                exit(WEXITSTATUS(status));
            }
            exit(CRM_EX_ERROR);
        }
    } while (pid > 0);
}

static struct {
    int sig;
    void (*handler)(void);
} sigmap[] = {
    { SIGCHLD, sigreap },
    { SIGINT,  sigdone },
};

void
remoted_spawn_pidone(int argc, char **argv, char **envp)
{
    sigset_t set;

    if (getpid() != 1) {
        return;
    }

    /* Containers can be expected to have /var/log, but they may not have
     * /var/log/pacemaker, so use a different default if no value has been
     * explicitly configured in the container's environment.
     */
    if (daemon_option("logfile") == NULL) {
        set_daemon_option("logfile", "/var/log/pcmk-init.log");
    }

    sigfillset(&set);
    sigprocmask(SIG_BLOCK, &set, 0);

    main_pid = fork();
    switch (main_pid) {
        case 0:
            sigprocmask(SIG_UNBLOCK, &set, NULL);
            setsid();
            setpgid(0, 0);

            // Child remains as pacemaker-remoted
            return;
        case -1:
            perror("fork");
    }

    /* Parent becomes the reaper of zombie processes */
    /* Safe to initialize logging now if needed */

#ifdef HAVE___PROGNAME
    /* Differentiate ourselves in the 'ps' output */
    {
        char *p;
        int i, maxlen;
        char *LastArgv = NULL;
        const char *name = "pcmk-init";

        for (i = 0; i < argc; i++) {
            if (!i || (LastArgv + 1 == argv[i]))
                LastArgv = argv[i] + strlen(argv[i]);
        }

        for (i = 0; envp[i] != NULL; i++) {
            if ((LastArgv + 1) == envp[i]) {
                LastArgv = envp[i] + strlen(envp[i]);
            }
        }

        maxlen = (LastArgv - argv[0]) - 2;

        i = strlen(name);

        /* We can overwrite individual argv[] arguments */
        snprintf(argv[0], maxlen, "%s", name);

        /* Now zero out everything else */
        p = &argv[0][i];
        while (p < LastArgv) {
            *p++ = '\0';
        }
        argv[1] = NULL;
    }
#endif /* HAVE___PROGNAME */

    while (1) {
        int sig;
        size_t i;

        sigwait(&set, &sig);
        for (i = 0; i < DIMOF(sigmap); i++) {
            if (sigmap[i].sig == sig) {
                sigmap[i].handler();
                break;
            }
        }
    }
}
