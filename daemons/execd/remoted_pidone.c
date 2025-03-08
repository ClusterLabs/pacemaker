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
 * \brief Check whether a string is a valid environment variable name
 *
 * \param[in] name  String to check
 *
 * \return \c true if \p name is a valid name, or \c false otherwise
 * \note It's reasonable to impose limitations on environment variable names
 *       beyond what C or setenv() does: We only allow names that contain only
 *       [a-zA-Z0-9_] characters and do not start with a digit.
 */
static bool
valid_env_var_name(const gchar *name)
{
    if (!isalpha(*name) && (*name != '_')) {
        // Invalid first character
        return false;
    }

    // The rest of the characters must be alphanumeric or underscores
    for (name++; isalnum(*name) || (*name == '_'); name++);
    return *name == '\0';
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
        gchar *name = NULL;
        gchar *value = NULL;
        gchar *end = NULL;
        gchar *comment = NULL;

        // Strip leading and trailing whitespace
        g_strstrip(line);

        if ((pcmk__scan_nvpair(line, &name, &value) != pcmk_rc_ok)
            || !valid_env_var_name(name)) {
            goto cleanup_loop;
        }

        if ((*value == '\'') || (*value == '"')) {
            char quote = *value;

            // Strip the leading quote
            *value = ' ';
            g_strchug(value);

            /* Value is remaining characters up to next non-backslashed matching
             * quote character.
             */
            for (end = value;
                 (*end != '\0') && ((*end != quote) || (*(end - 1) == '\\'));
                 end++);

            if (*end != quote) {
                // Matching closing quote wasn't found
                goto cleanup_loop;
            }

            // Discard closing quote and advance to check for trailing garbage
            *end++ = '\0';

        } else {
            /* Value is remaining characters up to next non-backslashed
             * whitespace.
             */
            for (end = value;
                 (*end != '\0') && (!isspace(*end) || (*(end - 1) == '\\'));
                 end++);
        }

        /* We have a valid name and value, and end is now the character after
         * the closing quote or the first whitespace after the unquoted value.
         * Make sure the rest of the line, if any, is just optional whitespace
         * followed by a comment.
         */

        // Strip trailing comment beginning with '#'
        comment = strchr(end, '#');
        if (comment != NULL) {
            *comment = '\0';
        }

        // Strip any remaining trailing whitespace from value
        g_strchomp(end);

        if (*end != '\0') {
            // Found garbage after value
            goto cleanup_loop;
        }

        // Don't overwrite (bundle options take precedence)
        setenv(name, value, 0);

cleanup_loop:
        g_free(name);
        g_free(value);
        errno = 0;
    }

    // getline() returns -1 on EOF or error
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
remoted_spawn_pidone(int argc, char **argv, char **envp)
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

#  ifdef HAVE_PROGNAME
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
#  endif // HAVE_PROGNAME

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
