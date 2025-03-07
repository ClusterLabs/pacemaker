/*
 * Copyright 2017-2025 the Pacemaker project contributors
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
    crm_exit(CRM_EX_OK);
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
                crm_exit(WEXITSTATUS(status));
            }
            crm_exit(CRM_EX_ERROR);
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
 * \param[in] line  Text to check
 *
 * \return Last character of valid name if found, or \c NULL otherwise
 * \note It's reasonable to impose limitations on environment variable names
 *       beyond what C or setenv() does: We only allow names that contain only
 *       [a-zA-Z0-9_] characters and do not start with a digit.
 */
static char *
find_env_var_name(char *line)
{
    if (!isalpha(*line) && (*line != '_')) {
        // Invalid first character
        return NULL;
    }
    for (line++; isalnum(*line) || (*line == '_'); line++);
    return line;
}

#define CONTAINER_ENV_FILE "/etc/pacemaker/pcmk-init.env"

static void
load_env_vars(void)
{
    /* We haven't forked or initialized logging yet, so don't leave any file
     * descriptors open, and don't log -- silently ignore errors.
     */
    FILE *fp = fopen(CONTAINER_ENV_FILE, "r");
    char *line = NULL;
    size_t buf_size = 0;

    if (fp == NULL) {
        return;
    }

    while (getline(&line, &buf_size, fp) != -1) {
        char *name = NULL;
        char *end = NULL;
        char *value = NULL;
        char *value_end = NULL;
        char *quote = NULL;

        // Strip leading and trailing whitespace
        g_strstrip(line);

        // Look for valid name immediately followed by equals sign
        end = find_env_var_name(line);
        if ((end == NULL) || (*++end != '=')) {
            goto cleanup_loop;
        }
        name = line;

        // Null-terminate name, and advance beyond equals sign
        *end++ = '\0';

        // Check whether value is quoted
        if ((*end == '\'') || (*end == '"')) {
            quote = end++;
        }
        value = end;

        if (quote != NULL) {
            /* Value is remaining characters up to next non-backslashed matching
             * quote character.
             */
            while (((*end != *quote) || (*(end - 1) == '\\'))
                   && (*end != '\0')) {
                end++;
            }
            if (*end != *quote) {
                // Matching closing quote wasn't found
                goto cleanup_loop;
            }
            // Null-terminate value, and advance beyond close quote
            *end++ = '\0';

        } else {
            /* Value is remaining characters up to next non-backslashed
             * whitespace.
             */
            while ((!isspace(*end) || (*(end - 1) == '\\'))
                   && (*end != '\0')) {
                end++;
            }
            // Do NOT null-terminate value (yet)
        }

        /* We have a valid name and value, and end is now the character after
         * the closing quote or the first whitespace after the unquoted value.
         * Make sure the rest of the line, if any, is just optional whitespace
         * followed by a comment.
         */
        value_end = end;

        while (isspace(*end)) {
            end++;
        }

        if ((*end != '\0') && (*end != '#')) {
            // Found garbage after value
            goto cleanup_loop;
        }

        if (quote == NULL) {
            // Now we can null-terminate an unquoted value
            *value_end = '\0';
        }

        // Don't overwrite (bundle options take precedence)
        // coverity[tainted_string] Can't easily be changed right now
        setenv(name, value, 0);

cleanup_loop:
        errno = 0;
    }

    // getline() returns -1 on EOF (expected) or error
    if (errno != 0) {
        int rc = errno;

        crm_err("Error while reading environment variables from "
                CONTAINER_ENV_FILE ": %s",
                pcmk_rc_str(rc));
    }
    fclose(fp);
    free(line);
}

void
remoted_spawn_pidone(int argc, char **argv)
{
    sigset_t set;

    /* This environment variable exists for two purposes:
     * - For testing, setting it to "full" enables full PID 1 behavior even
     *   when PID is not 1
     * - Setting to "vars" enables just the loading of environment variables
     *   from /etc/pacemaker/pcmk-init.env, which could be useful for testing or
     *   containers with a custom PID 1 script that launches the remote
     *   executor.
     */
    const char *pid1 = PCMK_VALUE_DEFAULT;

    if (getpid() != 1) {
        pid1 = pcmk__env_option(PCMK__ENV_REMOTE_PID1);
        if (!pcmk__str_any_of(pid1, "full", "vars", NULL)) {
            // Default, unset, or invalid
            return;
        }
    }

    /* When a container is launched, it may be given specific environment
     * variables, which for Pacemaker bundles are given in the bundle
     * configuration. However, that does not allow for host-specific values.
     * To allow for that, look for a special file containing a shell-like syntax
     * of name/value pairs, and export those into the environment.
     */
    load_env_vars();

    if (strcmp(pid1, "vars") == 0) {
        return;
    }

    /* Containers can be expected to have /var/log, but they may not have
     * /var/log/pacemaker, so use a different default if no value has been
     * explicitly configured in the container's environment.
     */
    if (pcmk__env_option(PCMK__ENV_LOGFILE) == NULL) {
        pcmk__set_env_option(PCMK__ENV_LOGFILE, "/var/log/pcmk-init.log", true);
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
            crm_err("fork failed: %s", pcmk_rc_str(errno));
    }

    /* Parent becomes the reaper of zombie processes */
    /* Safe to initialize logging now if needed */

    /* Differentiate the parent from the child, which does the real
     * pacemaker-remoted work, in the output of the `ps` command.
     *
     * strncpy() pads argv[0] with '\0' after copying "pcmk-init" if there is
     * more space to fill. In practice argv[0] should always be longer than
     * "pcmk-init", but use strlen() for safety to ensure null termination.
     *
     * Zero out the other argv members.
     */
    strncpy(argv[0], "pcmk-init", strlen(argv[0]));
    for (int i = 1; i < argc; i++) {
        memset(argv[i], '\0', strlen(argv[i]));
    }

    while (1) {
        int sig = 0;

        sigwait(&set, &sig);
        for (int i = 0; i < PCMK__NELEM(sigmap); i++) {
            if (sigmap[i].sig == sig) {
                sigmap[i].handler();
                break;
            }
        }
    }
}
