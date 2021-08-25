/*
 * Copyright 2017-2020 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
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

/*!
 * \internal
 * \brief Check a line of text for a valid environment variable name
 *
 * \param[in]  line  Text to check
 * \param[out] first  First character of valid name if found, NULL otherwise
 * \param[out] last   Last character of valid name if found, NULL otherwise
 *
 * \return TRUE if valid name found, FALSE otherwise
 * \note It's reasonable to impose limitations on environment variable names
 *       beyond what C or setenv() does: We only allow names that contain only
 *       [a-zA-Z0-9_] characters and do not start with a digit.
 */
static bool
find_env_var_name(char *line, char **first, char **last)
{
    // Skip leading whitespace
    *first = line;
    while (isspace(**first)) {
        ++*first;
    }

    if (isalpha(**first) || (**first == '_')) { // Valid first character
        *last = *first;
        while (isalnum(*(*last + 1)) || (*(*last + 1) == '_')) {
            ++*last;
        }
        return TRUE;
    }

    *first = *last = NULL;
    return FALSE;
}

static void
load_env_vars(const char *filename)
{
    /* We haven't forked or initialized logging yet, so don't leave any file
     * descriptors open, and don't log -- silently ignore errors.
     */
    FILE *fp = fopen(filename, "r");

    if (fp != NULL) {
        char line[LINE_MAX] = { '\0', };

        while (fgets(line, LINE_MAX, fp) != NULL) {
            char *name = NULL;
            char *end = NULL;
            char *value = NULL;
            char *quote = NULL;

            // Look for valid name immediately followed by equals sign
            if (find_env_var_name(line, &name, &end) && (*++end == '=')) {

                // Null-terminate name, and advance beyond equals sign
                *end++ = '\0';

                // Check whether value is quoted
                if ((*end == '\'') || (*end == '"')) {
                    quote = end++;
                }
                value = end;

                if (quote) {
                    /* Value is remaining characters up to next non-backslashed
                     * matching quote character.
                     */
                    while (((*end != *quote) || (*(end - 1) == '\\'))
                           && (*end != '\0')) {
                        end++;
                    }
                    if (*end == *quote) {
                        // Null-terminate value, and advance beyond close quote
                        *end++ = '\0';
                    } else {
                        // Matching closing quote wasn't found
                        value = NULL;
                    }

                } else {
                    /* Value is remaining characters up to next non-backslashed
                     * whitespace.
                     */
                    while ((!isspace(*end) || (*(end - 1) == '\\'))
                           && (*end != '\0')) {
                        ++end;
                    }

                    if (end == (line + LINE_MAX - 1)) {
                        // Line was too long
                        value = NULL;
                    }
                    // Do NOT null-terminate value (yet)
                }

                /* We have a valid name and value, and end is now the character
                 * after the closing quote or the first whitespace after the
                 * unquoted value. Make sure the rest of the line is just
                 * whitespace or a comment.
                 */
                if (value) {
                    char *value_end = end;

                    while (isspace(*end) && (*end != '\n')) {
                        ++end;
                    }
                    if ((*end == '\n') || (*end == '#')) {
                        if (quote == NULL) {
                            // Now we can null-terminate an unquoted value
                            *value_end = '\0';
                        }

                        // Don't overwrite (bundle options take precedence)
                        setenv(name, value, 0);

                    } else {
                        value = NULL;
                    }
                }
            }

            if ((value == NULL) && (strchr(line, '\n') == NULL)) {
                // Eat remainder of line beyond LINE_MAX
                if (fscanf(fp, "%*[^\n]\n") == EOF) {
                    value = NULL; // Don't care, make compiler happy
                }
            }
        }
        fclose(fp);
    }
}

void
remoted_spawn_pidone(int argc, char **argv, char **envp)
{
    sigset_t set;

    /* This environment variable exists for two purposes:
     * - For testing, setting it to "full" enables full PID 1 behavior even
     *   when PID is not 1
     * - Setting to "vars" enables just the loading of environment variables
     *   from /etc/pacemaker/pcmk-init.env, which could be useful for testing or
     *   containers with a custom PID 1 script that launches pacemaker-remoted.
     */
    const char *pid1 = (getpid() == 1)? "full" : getenv("PCMK_remote_pid1");

    if (pid1 == NULL) {
        return;
    }

    /* When a container is launched, it may be given specific environment
     * variables, which for Pacemaker bundles are given in the bundle
     * configuration. However, that does not allow for host-specific values.
     * To allow for that, look for a special file containing a shell-like syntax
     * of name/value pairs, and export those into the environment.
     */
    load_env_vars("/etc/pacemaker/pcmk-init.env");

    if (strcmp(pid1, "full")) {
        return;
    }

    /* Containers can be expected to have /var/log, but they may not have
     * /var/log/pacemaker, so use a different default if no value has been
     * explicitly configured in the container's environment.
     */
    if (pcmk__env_option(PCMK__ENV_LOGFILE) == NULL) {
        pcmk__set_env_option(PCMK__ENV_LOGFILE, "/var/log/pcmk-init.log");
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

#  ifdef HAVE___PROGNAME
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
#  endif // HAVE___PROGNAME

    while (1) {
        int sig;
        size_t i;

        sigwait(&set, &sig);
        for (i = 0; i < PCMK__NELEM(sigmap); i++) {
            if (sigmap[i].sig == sig) {
                sigmap[i].handler();
                break;
            }
        }
    }
}
