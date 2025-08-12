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

/*!
 * \internal
 * \brief Read one environment variable assignment and set the value
 *
 * Empty lines and trailing comments are ignored. This function handles
 * backslashes, single quotes, and double quotes in a manner similar to a POSIX
 * shell.
 *
 * This function has at least two limitations compared to a shell:
 * * An assignment must be contained within a single line.
 * * Only one assignment per line is supported.
 *
 * It would be possible to get rid of these limitations, but it doesn't seem
 * worth the trouble of implementation and testing.
 *
 * \param[in] line  Line containing an environment variable assignment statement
 */
static void
load_env_var_line(const char *line)
{
    gint argc = 0;
    gchar **argv = NULL;
    GError *error = NULL;

    gchar *name = NULL;
    gchar *value = NULL;

    int rc = pcmk_rc_ok;
    const char *reason = NULL;
    const char *value_to_set = NULL;

    /* g_shell_parse_argv() does the following in a manner similar to the shell:
     * * tokenizes the value
     * * strips a trailing '#' comment if one exists
     * * handles backslashes, single quotes, and double quotes
     */

    // Ensure the line contains zero or one token besides an optional comment
    if (!g_shell_parse_argv(line, &argc, NULL, &error)) {
        // Empty line (or only space/comment) means nothing to do and no error
        if (!g_error_matches(error, G_SHELL_ERROR,
                             G_SHELL_ERROR_EMPTY_STRING)) {
            reason = error->message;
        }
        goto done;
    }
    if (argc != 1) {
        // "argc != 1" for sanity; should imply "argc > 1" by now
        reason = "line contains garbage";
        goto done;
    }

    rc = pcmk__scan_nvpair(line, &name, &value);
    if (rc != pcmk_rc_ok) {
        reason = pcmk_rc_str(rc);
        goto done;
    }

    // Leading whitespace is allowed and ignored. A quoted name is invalid.
    g_strchug(name);
    if (!valid_env_var_name(name)) {
        reason = "invalid environment variable name";
        goto done;
    }

    /* Parse the value as the shell would do (stripping outermost quotes, etc.).
     * Also sanity-check that the value either is empty or consists of one
     * token. Anything malformed should have been caught by now.
     */
    if (!g_shell_parse_argv(value, &argc, &argv, &error)) {
        // Parse error should mean value is empty
        CRM_CHECK(g_error_matches(error, G_SHELL_ERROR,
                                  G_SHELL_ERROR_EMPTY_STRING),
                  goto done);
        value_to_set = "";

    } else {
        // value wasn't empty, so it should contain one token
        CRM_CHECK(argc == 1, goto done);
        value_to_set = argv[0];
    }

    // Don't overwrite (bundle options take precedence)
    setenv(name, value_to_set, 0);

done:
    if (reason != NULL) {
        crm_warn("Failed to perform environment variable assignment '%s': %s",
                 line, reason);
    }
    g_strfreev(argv);
    g_clear_error(&error);
    g_free(name);
    g_free(value);
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
        load_env_var_line(line);
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
