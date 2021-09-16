/*
 * Copyright 2010-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>
#include <unistd.h>
#include <dirent.h>
#include <grp.h>
#include <string.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "crm/crm.h"
#include "crm/common/mainloop.h"
#include "crm/services.h"

#include "services_private.h"

static void close_pipe(int fildes[]);

/* We have two alternative ways of handling SIGCHLD when synchronously waiting
 * for spawned processes to complete. Both rely on polling a file descriptor to
 * discover SIGCHLD events.
 *
 * If sys/signalfd.h is available (e.g. on Linux), we call signalfd() to
 * generate the file descriptor. Otherwise, we use the "self-pipe trick"
 * (opening a pipe and writing a byte to it when SIGCHLD is received).
 */
#ifdef HAVE_SYS_SIGNALFD_H

// signalfd() implementation

#include <sys/signalfd.h>

// Everything needed to manage SIGCHLD handling
struct sigchld_data_s {
    sigset_t mask;      // Signals to block now (including SIGCHLD)
    sigset_t old_mask;  // Previous set of blocked signals
};

// Initialize SIGCHLD data and prepare for use
static bool
sigchld_setup(struct sigchld_data_s *data)
{
    sigemptyset(&(data->mask));
    sigaddset(&(data->mask), SIGCHLD);

    sigemptyset(&(data->old_mask));

    // Block SIGCHLD (saving previous set of blocked signals to restore later)
    if (sigprocmask(SIG_BLOCK, &(data->mask), &(data->old_mask)) < 0) {
        crm_err("Wait for child process completion failed: %s "
                CRM_XS " source=sigprocmask", pcmk_strerror(errno));
        return false;
    }
    return true;
}

// Get a file descriptor suitable for polling for SIGCHLD events
static int
sigchld_open(struct sigchld_data_s *data)
{
    int fd;

    CRM_CHECK(data != NULL, return -1);

    fd = signalfd(-1, &(data->mask), SFD_NONBLOCK);
    if (fd < 0) {
        crm_err("Wait for child process completion failed: %s "
                CRM_XS " source=signalfd", pcmk_strerror(errno));
    }
    return fd;
}

// Close a file descriptor returned by sigchld_open()
static void
sigchld_close(int fd)
{
    if (fd > 0) {
        close(fd);
    }
}

// Return true if SIGCHLD was received from polled fd
static bool
sigchld_received(int fd)
{
    struct signalfd_siginfo fdsi;
    ssize_t s;

    if (fd < 0) {
        return false;
    }
    s = read(fd, &fdsi, sizeof(struct signalfd_siginfo));
    if (s != sizeof(struct signalfd_siginfo)) {
        crm_err("Wait for child process completion failed: %s "
                CRM_XS " source=read", pcmk_strerror(errno));

    } else if (fdsi.ssi_signo == SIGCHLD) {
        return true;
    }
    return false;
}

// Do anything needed after done waiting for SIGCHLD
static void
sigchld_cleanup(struct sigchld_data_s *data)
{
    // Restore the original set of blocked signals
    if ((sigismember(&(data->old_mask), SIGCHLD) == 0)
        && (sigprocmask(SIG_UNBLOCK, &(data->mask), NULL) < 0)) {
        crm_warn("Could not clean up after child process completion: %s",
                 pcmk_strerror(errno));
    }
}

#else // HAVE_SYS_SIGNALFD_H not defined

// Self-pipe implementation (see above for function descriptions)

struct sigchld_data_s {
    int pipe_fd[2];             // Pipe file descriptors
    struct sigaction sa;        // Signal handling info (with SIGCHLD)
    struct sigaction old_sa;    // Previous signal handling info
};

// We need a global to use in the signal handler
volatile struct sigchld_data_s *last_sigchld_data = NULL;

static void
sigchld_handler()
{
    // We received a SIGCHLD, so trigger pipe polling
    if ((last_sigchld_data != NULL)
        && (last_sigchld_data->pipe_fd[1] >= 0)
        && (write(last_sigchld_data->pipe_fd[1], "", 1) == -1)) {
        crm_err("Wait for child process completion failed: %s "
                CRM_XS " source=write", pcmk_strerror(errno));
    }
}

static bool
sigchld_setup(struct sigchld_data_s *data)
{
    int rc;

    data->pipe_fd[0] = data->pipe_fd[1] = -1;

    if (pipe(data->pipe_fd) == -1) {
        crm_err("Wait for child process completion failed: %s "
                CRM_XS " source=pipe", pcmk_strerror(errno));
        return false;
    }

    rc = pcmk__set_nonblocking(data->pipe_fd[0]);
    if (rc != pcmk_rc_ok) {
        crm_warn("Could not set pipe input non-blocking: %s " CRM_XS " rc=%d",
                 pcmk_rc_str(rc), rc);
    }
    rc = pcmk__set_nonblocking(data->pipe_fd[1]);
    if (rc != pcmk_rc_ok) {
        crm_warn("Could not set pipe output non-blocking: %s " CRM_XS " rc=%d",
                 pcmk_rc_str(rc), rc);
    }

    // Set SIGCHLD handler
    data->sa.sa_handler = sigchld_handler;
    data->sa.sa_flags = 0;
    sigemptyset(&(data->sa.sa_mask));
    if (sigaction(SIGCHLD, &(data->sa), &(data->old_sa)) < 0) {
        crm_err("Wait for child process completion failed: %s "
                CRM_XS " source=sigaction", pcmk_strerror(errno));
    }

    // Remember data for use in signal handler
    last_sigchld_data = data;
    return true;
}

static int
sigchld_open(struct sigchld_data_s *data)
{
    CRM_CHECK(data != NULL, return -1);
    return data->pipe_fd[0];
}

static void
sigchld_close(int fd)
{
    // Pipe will be closed in sigchld_cleanup()
    return;
}

static bool
sigchld_received(int fd)
{
    char ch;

    if (fd < 0) {
        return false;
    }

    // Clear out the self-pipe
    while (read(fd, &ch, 1) == 1) /*omit*/;
    return true;
}

static void
sigchld_cleanup(struct sigchld_data_s *data)
{
    // Restore the previous SIGCHLD handler
    if (sigaction(SIGCHLD, &(data->old_sa), NULL) < 0) {
        crm_warn("Could not clean up after child process completion: %s",
                 pcmk_strerror(errno));
    }

    close_pipe(data->pipe_fd);
}

#endif

/*!
 * \internal
 * \brief Close the two file descriptors of a pipe
 *
 * \param[in] fildes  Array of file descriptors opened by pipe()
 */
static void
close_pipe(int fildes[])
{
    if (fildes[0] >= 0) {
        close(fildes[0]);
        fildes[0] = -1;
    }
    if (fildes[1] >= 0) {
        close(fildes[1]);
        fildes[1] = -1;
    }
}

static gboolean
svc_read_output(int fd, svc_action_t * op, bool is_stderr)
{
    char *data = NULL;
    int rc = 0, len = 0;
    char buf[500];
    static const size_t buf_read_len = sizeof(buf) - 1;


    if (fd < 0) {
        crm_trace("No fd for %s", op->id);
        return FALSE;
    }

    if (is_stderr && op->stderr_data) {
        len = strlen(op->stderr_data);
        data = op->stderr_data;
        crm_trace("Reading %s stderr into offset %d", op->id, len);

    } else if (is_stderr == FALSE && op->stdout_data) {
        len = strlen(op->stdout_data);
        data = op->stdout_data;
        crm_trace("Reading %s stdout into offset %d", op->id, len);

    } else {
        crm_trace("Reading %s %s into offset %d", op->id, is_stderr?"stderr":"stdout", len);
    }

    do {
        rc = read(fd, buf, buf_read_len);
        if (rc > 0) {
            buf[rc] = 0;
            crm_trace("Got %d chars: %.80s", rc, buf);
            data = pcmk__realloc(data, len + rc + 1);
            len += sprintf(data + len, "%s", buf);

        } else if (errno != EINTR) {
            /* error or EOF
             * Cleanup happens in pipe_done()
             */
            rc = FALSE;
            break;
        }

    } while (rc == buf_read_len || rc < 0);

    if (is_stderr) {
        op->stderr_data = data;
    } else {
        op->stdout_data = data;
    }

    return rc;
}

static int
dispatch_stdout(gpointer userdata)
{
    svc_action_t *op = (svc_action_t *) userdata;

    return svc_read_output(op->opaque->stdout_fd, op, FALSE);
}

static int
dispatch_stderr(gpointer userdata)
{
    svc_action_t *op = (svc_action_t *) userdata;

    return svc_read_output(op->opaque->stderr_fd, op, TRUE);
}

static void
pipe_out_done(gpointer user_data)
{
    svc_action_t *op = (svc_action_t *) user_data;

    crm_trace("%p", op);

    op->opaque->stdout_gsource = NULL;
    if (op->opaque->stdout_fd > STDOUT_FILENO) {
        close(op->opaque->stdout_fd);
    }
    op->opaque->stdout_fd = -1;
}

static void
pipe_err_done(gpointer user_data)
{
    svc_action_t *op = (svc_action_t *) user_data;

    op->opaque->stderr_gsource = NULL;
    if (op->opaque->stderr_fd > STDERR_FILENO) {
        close(op->opaque->stderr_fd);
    }
    op->opaque->stderr_fd = -1;
}

static struct mainloop_fd_callbacks stdout_callbacks = {
    .dispatch = dispatch_stdout,
    .destroy = pipe_out_done,
};

static struct mainloop_fd_callbacks stderr_callbacks = {
    .dispatch = dispatch_stderr,
    .destroy = pipe_err_done,
};

static void
set_ocf_env(const char *key, const char *value, gpointer user_data)
{
    if (setenv(key, value, 1) != 0) {
        crm_perror(LOG_ERR, "setenv failed for key:%s and value:%s", key, value);
    }
}

static void
set_ocf_env_with_prefix(gpointer key, gpointer value, gpointer user_data)
{
    char buffer[500];

    snprintf(buffer, sizeof(buffer), strcmp(key, "OCF_CHECK_LEVEL") != 0 ? "OCF_RESKEY_%s" : "%s", (char *)key);
    set_ocf_env(buffer, value, user_data);
}

static void
set_alert_env(gpointer key, gpointer value, gpointer user_data)
{
    int rc;

    if (value != NULL) {
        rc = setenv(key, value, 1);
    } else {
        rc = unsetenv(key);
    }

    if (rc < 0) {
        crm_perror(LOG_ERR, "setenv %s=%s",
                  (char*)key, (value? (char*)value : ""));
    } else {
        crm_trace("setenv %s=%s", (char*)key, (value? (char*)value : ""));
    }
}

/*!
 * \internal
 * \brief Add environment variables suitable for an action
 *
 * \param[in] op  Action to use
 */
static void
add_action_env_vars(const svc_action_t *op)
{
    void (*env_setter)(gpointer, gpointer, gpointer) = NULL;
    if (op->agent == NULL) {
        env_setter = set_alert_env;  /* we deal with alert handler */

    } else if (pcmk__str_eq(op->standard, PCMK_RESOURCE_CLASS_OCF, pcmk__str_casei)) {
        env_setter = set_ocf_env_with_prefix;
    }

    if (env_setter != NULL && op->params != NULL) {
        g_hash_table_foreach(op->params, env_setter, NULL);
    }

    if (env_setter == NULL || env_setter == set_alert_env) {
        return;
    }

    set_ocf_env("OCF_RA_VERSION_MAJOR", PCMK_OCF_MAJOR_VERSION, NULL);
    set_ocf_env("OCF_RA_VERSION_MINOR", PCMK_OCF_MINOR_VERSION, NULL);
    set_ocf_env("OCF_ROOT", OCF_ROOT_DIR, NULL);
    set_ocf_env("OCF_EXIT_REASON_PREFIX", PCMK_OCF_REASON_PREFIX, NULL);

    if (op->rsc) {
        set_ocf_env("OCF_RESOURCE_INSTANCE", op->rsc, NULL);
    }

    if (op->agent != NULL) {
        set_ocf_env("OCF_RESOURCE_TYPE", op->agent, NULL);
    }

    /* Notes: this is not added to specification yet. Sept 10,2004 */
    if (op->provider != NULL) {
        set_ocf_env("OCF_RESOURCE_PROVIDER", op->provider, NULL);
    }
}

static void
pipe_in_single_parameter(gpointer key, gpointer value, gpointer user_data)
{
    svc_action_t *op = user_data;
    char *buffer = crm_strdup_printf("%s=%s\n", (char *)key, (char *) value);
    int ret, total = 0, len = strlen(buffer);

    do {
        errno = 0;
        ret = write(op->opaque->stdin_fd, buffer + total, len - total);
        if (ret > 0) {
            total += ret;
        }

    } while ((errno == EINTR) && (total < len));
    free(buffer);
}

/*!
 * \internal
 * \brief Pipe parameters in via stdin for action
 *
 * \param[in] op  Action to use
 */
static void
pipe_in_action_stdin_parameters(const svc_action_t *op)
{
    crm_debug("sending args");
    if (op->params) {
        g_hash_table_foreach(op->params, pipe_in_single_parameter, (gpointer) op);
    }
}

gboolean
recurring_action_timer(gpointer data)
{
    svc_action_t *op = data;

    crm_debug("Scheduling another invocation of %s", op->id);

    /* Clean out the old result */
    free(op->stdout_data);
    op->stdout_data = NULL;
    free(op->stderr_data);
    op->stderr_data = NULL;
    op->opaque->repeat_timer = 0;

    services_action_async(op, NULL);
    return FALSE;
}

/*!
 * \internal
 * \brief Finalize handling of an asynchronous operation
 *
 * Given a completed asynchronous operation, cancel or reschedule it as
 * appropriate if recurring, call its callback if registered, stop tracking it,
 * and clean it up.
 *
 * \param[in,out] op  Operation to finalize
 *
 * \return Standard Pacemaker return code
 * \retval EINVAL      Caller supplied NULL or invalid \p op
 * \retval EBUSY       Uncanceled recurring action has only been cleaned up
 * \retval pcmk_rc_ok  Action has been freed
 *
 * \note If the return value is not pcmk_rc_ok, the caller is responsible for
 *       freeing the action.
 */
int
services__finalize_async_op(svc_action_t *op)
{
    CRM_CHECK((op != NULL) && !(op->synchronous), return EINVAL);

    if (op->interval_ms != 0) {
        // Recurring operations must be either cancelled or rescheduled
        if (op->cancel) {
            op->status = PCMK_EXEC_CANCELLED;
            cancel_recurring_action(op);
        } else {
            op->opaque->repeat_timer = g_timeout_add(op->interval_ms,
                                                     recurring_action_timer,
                                                     (void *) op);
        }
    }

    if (op->opaque->callback != NULL) {
        op->opaque->callback(op);
    }

    // Stop tracking the operation (as in-flight or blocked)
    op->pid = 0;
    services_untrack_op(op);

    if ((op->interval_ms != 0) && !(op->cancel)) {
        // Do not free recurring actions (they will get freed when cancelled)
        services_action_cleanup(op);
        return EBUSY;
    }

    services_action_free(op);
    return pcmk_rc_ok;
}

static void
close_op_input(svc_action_t *op)
{
    if (op->opaque->stdin_fd >= 0) {
        close(op->opaque->stdin_fd);
    }
}

static void
finish_op_output(svc_action_t *op, bool is_stderr)
{
    mainloop_io_t **source;
    int fd;

    if (is_stderr) {
        source = &(op->opaque->stderr_gsource);
        fd = op->opaque->stderr_fd;
    } else {
        source = &(op->opaque->stdout_gsource);
        fd = op->opaque->stdout_fd;
    }

    if (op->synchronous || *source) {
        crm_trace("Finish reading %s[%d] %s",
                  op->id, op->pid, (is_stderr? "stdout" : "stderr"));
        svc_read_output(fd, op, is_stderr);
        if (op->synchronous) {
            close(fd);
        } else {
            mainloop_del_fd(*source);
            *source = NULL;
        }
    }
}

// Log an operation's stdout and stderr
static void
log_op_output(svc_action_t *op)
{
    char *prefix = crm_strdup_printf("%s[%d] error output", op->id, op->pid);

    crm_log_output(LOG_NOTICE, prefix, op->stderr_data);
    strcpy(prefix + strlen(prefix) - strlen("error output"), "output");
    crm_log_output(LOG_DEBUG, prefix, op->stdout_data);
    free(prefix);
}

/*!
 * \internal
 * \brief Process the completion of an asynchronous child process
 *
 * \param[in] p         Child process that completed
 * \param[in] pid       Process ID of child
 * \param[in] core      (unused)
 * \param[in] signo     Signal that interrupted child, if any
 * \param[in] exitcode  Exit status of child process
 */
static void
async_action_complete(mainloop_child_t *p, pid_t pid, int core, int signo,
                      int exitcode)
{
    svc_action_t *op = mainloop_child_userdata(p);

    mainloop_clear_child_userdata(p);
    CRM_CHECK(op->pid == pid,
              op->rc = services__generic_error(op);
              op->status = PCMK_EXEC_ERROR;
              return);

    /* Depending on the priority the mainloop gives the stdout and stderr
     * file descriptors, this function could be called before everything has
     * been read from them, so force a final read now.
     */
    finish_op_output(op, true);
    finish_op_output(op, false);

    close_op_input(op);

    if (signo == 0) {
        crm_debug("%s[%d] exited with status %d", op->id, op->pid, exitcode);
        op->status = PCMK_EXEC_DONE;
        op->rc = exitcode;

    } else if (mainloop_child_timeout(p)) {
        crm_warn("%s[%d] timed out after %dms", op->id, op->pid, op->timeout);
        op->status = PCMK_EXEC_TIMEOUT;
        op->rc = PCMK_OCF_TIMEOUT;

    } else if (op->cancel) {
        /* If an in-flight recurring operation was killed because it was
         * cancelled, don't treat that as a failure.
         */
        crm_info("%s[%d] terminated with signal: %s " CRM_XS " (%d)",
                 op->id, op->pid, strsignal(signo), signo);
        op->status = PCMK_EXEC_CANCELLED;
        op->rc = PCMK_OCF_OK;

    } else {
        crm_warn("%s[%d] terminated with signal: %s " CRM_XS " (%d)",
                 op->id, op->pid, strsignal(signo), signo);
        op->status = PCMK_EXEC_ERROR;
        op->rc = PCMK_OCF_UNKNOWN_ERROR;
    }

    log_op_output(op);
    services__finalize_async_op(op);
}

/*!
 * \internal
 * \brief Return agent standard's exit status for "generic error"
 *
 * When returning an internal error for an action, a value that is appropriate
 * to the action's agent standard must be used. This function returns a value
 * appropriate for errors in general.
 *
 * \param[in] op  Action that error is for
 *
 * \return Exit status appropriate to agent standard
 * \note Actions without a standard will get PCMK_OCF_UNKNOWN_ERROR.
 */
int
services__generic_error(svc_action_t *op)
{
    if ((op == NULL) || (op->standard == NULL)) {
        return PCMK_OCF_UNKNOWN_ERROR;
    }

    if (pcmk__str_eq(op->standard, PCMK_RESOURCE_CLASS_LSB, pcmk__str_casei)
        && pcmk__str_eq(op->action, "status", pcmk__str_casei)) {

        return PCMK_LSB_STATUS_UNKNOWN;
    }

#if SUPPORT_NAGIOS
    if (pcmk__str_eq(op->standard, PCMK_RESOURCE_CLASS_NAGIOS, pcmk__str_casei)) {
        return NAGIOS_STATE_UNKNOWN;
    }
#endif

    return PCMK_OCF_UNKNOWN_ERROR;
}

/*!
 * \internal
 * \brief Return agent standard's exit status for "not installed"
 *
 * When returning an internal error for an action, a value that is appropriate
 * to the action's agent standard must be used. This function returns a value
 * appropriate for "not installed" errors.
 *
 * \param[in] op  Action that error is for
 *
 * \return Exit status appropriate to agent standard
 * \note Actions without a standard will get PCMK_OCF_UNKNOWN_ERROR.
 */
int
services__not_installed_error(svc_action_t *op)
{
    if ((op == NULL) || (op->standard == NULL)) {
        return PCMK_OCF_UNKNOWN_ERROR;
    }

    if (pcmk__str_eq(op->standard, PCMK_RESOURCE_CLASS_LSB, pcmk__str_casei)
        && pcmk__str_eq(op->action, "status", pcmk__str_casei)) {

        return PCMK_LSB_STATUS_NOT_INSTALLED;
    }

#if SUPPORT_NAGIOS
    if (pcmk__str_eq(op->standard, PCMK_RESOURCE_CLASS_NAGIOS, pcmk__str_casei)) {
        return NAGIOS_NOT_INSTALLED;
    }
#endif

    return PCMK_OCF_NOT_INSTALLED;
}

/*!
 * \internal
 * \brief Return agent standard's exit status for "insufficient privileges"
 *
 * When returning an internal error for an action, a value that is appropriate
 * to the action's agent standard must be used. This function returns a value
 * appropriate for "insufficient privileges" errors.
 *
 * \param[in] op  Action that error is for
 *
 * \return Exit status appropriate to agent standard
 * \note Actions without a standard will get PCMK_OCF_UNKNOWN_ERROR.
 */
int
services__authorization_error(svc_action_t *op)
{
    if ((op == NULL) || (op->standard == NULL)) {
        return PCMK_OCF_UNKNOWN_ERROR;
    }

    if (pcmk__str_eq(op->standard, PCMK_RESOURCE_CLASS_LSB, pcmk__str_casei)
        && pcmk__str_eq(op->action, "status", pcmk__str_casei)) {

        return PCMK_LSB_STATUS_INSUFFICIENT_PRIV;
    }

#if SUPPORT_NAGIOS
    if (pcmk__str_eq(op->standard, PCMK_RESOURCE_CLASS_NAGIOS, pcmk__str_casei)) {
        return NAGIOS_INSUFFICIENT_PRIV;
    }
#endif

    return PCMK_OCF_INSUFFICIENT_PRIV;
}

/*!
 * \internal
 * \brief Set operation rc and status per errno from stat(), fork() or execvp()
 *
 * \param[in,out] op     Operation to set rc and status for
 * \param[in]     error  Value of errno after system call
 *
 * \return void
 */
void
services__handle_exec_error(svc_action_t * op, int error)
{
    switch (error) {   /* see execve(2), stat(2) and fork(2) */
        case ENOENT:   /* No such file or directory */
        case EISDIR:   /* Is a directory */
        case ENOTDIR:  /* Path component is not a directory */
        case EINVAL:   /* Invalid executable format */
        case ENOEXEC:  /* Invalid executable format */
            op->rc = services__not_installed_error(op);
            op->status = PCMK_EXEC_NOT_INSTALLED;
            break;
        case EACCES:   /* permission denied (various errors) */
        case EPERM:    /* permission denied (various errors) */
            op->rc = services__authorization_error(op);
            op->status = PCMK_EXEC_ERROR;
            break;
        default:
            op->rc = services__generic_error(op);
            op->status = PCMK_EXEC_ERROR;
    }
}

static void
action_launch_child(svc_action_t *op)
{
    /* SIGPIPE is ignored (which is different from signal blocking) by the gnutls library.
     * Depending on the libqb version in use, libqb may set SIGPIPE to be ignored as well. 
     * We do not want this to be inherited by the child process. By resetting this the signal
     * to the default behavior, we avoid some potential odd problems that occur during OCF
     * scripts when SIGPIPE is ignored by the environment. */
    signal(SIGPIPE, SIG_DFL);

#if defined(HAVE_SCHED_SETSCHEDULER)
    if (sched_getscheduler(0) != SCHED_OTHER) {
        struct sched_param sp;

        memset(&sp, 0, sizeof(sp));
        sp.sched_priority = 0;

        if (sched_setscheduler(0, SCHED_OTHER, &sp) == -1) {
            crm_perror(LOG_ERR, "Could not reset scheduling policy to SCHED_OTHER for %s", op->id);
        }
    }
#endif
    if (setpriority(PRIO_PROCESS, 0, 0) == -1) {
        crm_perror(LOG_ERR, "Could not reset process priority to 0 for %s", op->id);
    }

    /* Man: The call setpgrp() is equivalent to setpgid(0,0)
     * _and_ compiles on BSD variants too
     * need to investigate if it works the same too.
     */
    setpgid(0, 0);

    pcmk__close_fds_in_child(false);

#if SUPPORT_CIBSECRETS
    if (pcmk__substitute_secrets(op->rsc, op->params) != pcmk_rc_ok) {
        /* replacing secrets failed! */
        if (pcmk__str_eq(op->action, "stop", pcmk__str_casei)) {
            /* don't fail on stop! */
            crm_info("proceeding with the stop operation for %s", op->rsc);

        } else {
            crm_err("failed to get secrets for %s, "
                    "considering resource not configured", op->rsc);
            _exit(PCMK_OCF_NOT_CONFIGURED);
        }
    }
#endif

    add_action_env_vars(op);

    /* Become the desired user */
    if (op->opaque->uid && (geteuid() == 0)) {

        // If requested, set effective group
        if (op->opaque->gid && (setgid(op->opaque->gid) < 0)) {
            crm_perror(LOG_ERR, "Could not set child group to %d", op->opaque->gid);
            _exit(PCMK_OCF_NOT_CONFIGURED);
        }

        // Erase supplementary group list
        // (We could do initgroups() if we kept a copy of the username)
        if (setgroups(0, NULL) < 0) {
            crm_perror(LOG_ERR, "Could not set child groups");
            _exit(PCMK_OCF_NOT_CONFIGURED);
        }

        // Set effective user
        if (setuid(op->opaque->uid) < 0) {
            crm_perror(LOG_ERR, "setting user to %d", op->opaque->uid);
            _exit(PCMK_OCF_NOT_CONFIGURED);
        }
    }

    /* execute the RA */
    execvp(op->opaque->exec, op->opaque->args);

    /* Most cases should have been already handled by stat() */
    services__handle_exec_error(op, errno);

    _exit(op->rc);
}

/*!
 * \internal
 * \brief Wait for synchronous action to complete, and set its result
 *
 * \param[in] op    Action to wait for
 * \param[in] data  Child signal data
 */
static void
wait_for_sync_result(svc_action_t *op, struct sigchld_data_s *data)
{
    int status = 0;
    int timeout = op->timeout;
    time_t start = time(NULL);
    struct pollfd fds[3];
    int wait_rc = 0;

    fds[0].fd = op->opaque->stdout_fd;
    fds[0].events = POLLIN;
    fds[0].revents = 0;

    fds[1].fd = op->opaque->stderr_fd;
    fds[1].events = POLLIN;
    fds[1].revents = 0;

    fds[2].fd = sigchld_open(data);
    fds[2].events = POLLIN;
    fds[2].revents = 0;

    crm_trace("Waiting for %s[%d]", op->id, op->pid);
    do {
        int poll_rc = poll(fds, 3, timeout);

        if (poll_rc > 0) {
            if (fds[0].revents & POLLIN) {
                svc_read_output(op->opaque->stdout_fd, op, FALSE);
            }

            if (fds[1].revents & POLLIN) {
                svc_read_output(op->opaque->stderr_fd, op, TRUE);
            }

            if ((fds[2].revents & POLLIN) && sigchld_received(fds[2].fd)) {
                wait_rc = waitpid(op->pid, &status, WNOHANG);

                if ((wait_rc > 0) || ((wait_rc < 0) && (errno == ECHILD))) {
                    // Child process exited or doesn't exist
                    break;

                } else if (wait_rc < 0) {
                    crm_warn("Wait for completion of %s[%d] failed: %s "
                             CRM_XS " source=waitpid",
                             op->id, op->pid, pcmk_strerror(errno));
                    wait_rc = 0; // Act as if process is still running
                }
            }

        } else if (poll_rc == 0) {
            // Poll timed out with no descriptors ready
            timeout = 0;
            break;

        } else if ((poll_rc < 0) && (errno != EINTR)) {
            crm_err("Wait for completion of %s[%d] failed: %s "
                    CRM_XS " source=poll",
                    op->id, op->pid, pcmk_strerror(errno));
            break;
        }

        timeout = op->timeout - (time(NULL) - start) * 1000;

    } while ((op->timeout < 0 || timeout > 0));

    crm_trace("Stopped waiting for %s[%d]", op->id, op->pid);
    if (wait_rc <= 0) {

        if ((op->timeout > 0) && (timeout <= 0)) {
            op->rc = services__generic_error(op);
            op->status = PCMK_EXEC_TIMEOUT;
            crm_warn("%s[%d] timed out after %dms",
                     op->id, op->pid, op->timeout);

        } else {
            op->rc = services__generic_error(op);
            op->status = PCMK_EXEC_ERROR;
        }

        /* If only child hasn't been successfully waited for, yet.
           This is to limit killing wrong target a bit more. */
        if ((wait_rc == 0) && (waitpid(op->pid, &status, WNOHANG) == 0)) {
            if (kill(op->pid, SIGKILL)) {
                crm_warn("Could not kill rogue child %s[%d]: %s",
                         op->id, op->pid, pcmk_strerror(errno));
            }
            /* Safe to skip WNOHANG here as we sent non-ignorable signal. */
            while ((waitpid(op->pid, &status, 0) == (pid_t) -1)
                   && (errno == EINTR)) {
                /* keep waiting */;
            }
        }

    } else if (WIFEXITED(status)) {
        op->status = PCMK_EXEC_DONE;
        op->rc = WEXITSTATUS(status);
        crm_info("%s[%d] exited with status %d", op->id, op->pid, op->rc);

    } else if (WIFSIGNALED(status)) {
        int signo = WTERMSIG(status);

        op->rc = services__generic_error(op);
        op->status = PCMK_EXEC_ERROR;
        crm_err("%s[%d] terminated with signal: %s " CRM_XS " (%d)",
                op->id, op->pid, strsignal(signo), signo);

#ifdef WCOREDUMP
        if (WCOREDUMP(status)) {
            crm_warn("%s[%d] dumped core", op->id, op->pid);
        }
#endif

    } else {
        // Shouldn't be possible to get here
        op->rc = services__generic_error(op);
        op->status = PCMK_EXEC_ERROR;
    }

    finish_op_output(op, true);
    finish_op_output(op, false);
    close_op_input(op);
    sigchld_close(fds[2].fd);
}

/*!
 * \internal
 * \brief Execute an action whose standard uses executable files
 *
 * \param[in] op  Action to execute
 *
 * \return Standard Pacemaker return value
 * \retval EBUSY          Recurring operation could not be initiated
 * \retval pcmk_rc_error  Synchronous action failed
 * \retval pcmk_rc_ok     Synchronous action succeeded, or asynchronous action
 *                        should not be freed (because it already was or is
 *                        pending)
 *
 * \note If the return value for an asynchronous action is not pcmk_rc_ok, the
 *       caller is responsible for freeing the action.
 */
int
services__execute_file(svc_action_t *op)
{
    int stdout_fd[2];
    int stderr_fd[2];
    int stdin_fd[2] = {-1, -1};
    int rc;
    struct stat st;
    struct sigchld_data_s data;

    // Catch common failure conditions early
    if (stat(op->opaque->exec, &st) != 0) {
        rc = errno;
        crm_warn("Cannot execute '%s': %s " CRM_XS " stat rc=%d",
                 op->opaque->exec, pcmk_strerror(rc), rc);
        services__handle_exec_error(op, rc);
        goto done;
    }

    if (pipe(stdout_fd) < 0) {
        rc = errno;
        crm_err("Cannot execute '%s': %s " CRM_XS " pipe(stdout) rc=%d",
                op->opaque->exec, pcmk_strerror(rc), rc);
        services__handle_exec_error(op, rc);
        goto done;
    }

    if (pipe(stderr_fd) < 0) {
        rc = errno;

        close_pipe(stdout_fd);

        crm_err("Cannot execute '%s': %s " CRM_XS " pipe(stderr) rc=%d",
                op->opaque->exec, pcmk_strerror(rc), rc);
        services__handle_exec_error(op, rc);
        goto done;
    }

    if (pcmk_is_set(pcmk_get_ra_caps(op->standard), pcmk_ra_cap_stdin)) {
        if (pipe(stdin_fd) < 0) {
            rc = errno;

            close_pipe(stdout_fd);
            close_pipe(stderr_fd);

            crm_err("Cannot execute '%s': %s " CRM_XS " pipe(stdin) rc=%d",
                    op->opaque->exec, pcmk_strerror(rc), rc);
            services__handle_exec_error(op, rc);
            goto done;
        }
    }

    if (op->synchronous && !sigchld_setup(&data)) {
        close_pipe(stdin_fd);
        close_pipe(stdout_fd);
        close_pipe(stderr_fd);
        sigchld_cleanup(&data);
        op->rc = services__generic_error(op);
        op->status = PCMK_EXEC_ERROR;
        goto done;
    }

    op->pid = fork();
    switch (op->pid) {
        case -1:
            rc = errno;
            close_pipe(stdin_fd);
            close_pipe(stdout_fd);
            close_pipe(stderr_fd);

            crm_err("Cannot execute '%s': %s " CRM_XS " fork rc=%d",
                    op->opaque->exec, pcmk_strerror(rc), rc);
            services__handle_exec_error(op, rc);
            if (op->synchronous) {
                sigchld_cleanup(&data);
            }
            goto done;
            break;

        case 0:                /* Child */
            close(stdout_fd[0]);
            close(stderr_fd[0]);
            if (stdin_fd[1] >= 0) {
                close(stdin_fd[1]);
            }
            if (STDOUT_FILENO != stdout_fd[1]) {
                if (dup2(stdout_fd[1], STDOUT_FILENO) != STDOUT_FILENO) {
                    crm_warn("Can't redirect output from '%s': %s "
                             CRM_XS " errno=%d",
                             op->opaque->exec, pcmk_strerror(errno), errno);
                }
                close(stdout_fd[1]);
            }
            if (STDERR_FILENO != stderr_fd[1]) {
                if (dup2(stderr_fd[1], STDERR_FILENO) != STDERR_FILENO) {
                    crm_warn("Can't redirect error output from '%s': %s "
                             CRM_XS " errno=%d",
                             op->opaque->exec, pcmk_strerror(errno), errno);
                }
                close(stderr_fd[1]);
            }
            if ((stdin_fd[0] >= 0) &&
                (STDIN_FILENO != stdin_fd[0])) {
                if (dup2(stdin_fd[0], STDIN_FILENO) != STDIN_FILENO) {
                    crm_warn("Can't redirect input to '%s': %s "
                             CRM_XS " errno=%d",
                             op->opaque->exec, pcmk_strerror(errno), errno);
                }
                close(stdin_fd[0]);
            }

            if (op->synchronous) {
                sigchld_cleanup(&data);
            }

            action_launch_child(op);
            CRM_ASSERT(0);  /* action_launch_child is effectively noreturn */
    }

    /* Only the parent reaches here */
    close(stdout_fd[1]);
    close(stderr_fd[1]);
    if (stdin_fd[0] >= 0) {
        close(stdin_fd[0]);
    }

    op->opaque->stdout_fd = stdout_fd[0];
    rc = pcmk__set_nonblocking(op->opaque->stdout_fd);
    if (rc != pcmk_rc_ok) {
        crm_warn("Could not set '%s' output non-blocking: %s "
                 CRM_XS " rc=%d",
                 op->opaque->exec, pcmk_rc_str(rc), rc);
    }

    op->opaque->stderr_fd = stderr_fd[0];
    rc = pcmk__set_nonblocking(op->opaque->stderr_fd);
    if (rc != pcmk_rc_ok) {
        crm_warn("Could not set '%s' error output non-blocking: %s "
                 CRM_XS " rc=%d",
                 op->opaque->exec, pcmk_rc_str(rc), rc);
    }

    op->opaque->stdin_fd = stdin_fd[1];
    if (op->opaque->stdin_fd >= 0) {
        // using buffer behind non-blocking-fd here - that could be improved
        // as long as no other standard uses stdin_fd assume stonith
        rc = pcmk__set_nonblocking(op->opaque->stdin_fd);
        if (rc != pcmk_rc_ok) {
            crm_warn("Could not set '%s' input non-blocking: %s "
                    CRM_XS " fd=%d,rc=%d", op->opaque->exec,
                    pcmk_rc_str(rc), op->opaque->stdin_fd, rc);
        }
        pipe_in_action_stdin_parameters(op);
        // as long as we are handling parameters directly in here just close
        close(op->opaque->stdin_fd);
        op->opaque->stdin_fd = -1;
    }

    // after fds are setup properly and before we plug anything into mainloop
    if (op->opaque->fork_callback) {
        op->opaque->fork_callback(op);
    }

    if (op->synchronous) {
        wait_for_sync_result(op, &data);
        sigchld_cleanup(&data);
        goto done;
    }

    crm_trace("Waiting async for '%s'[%d]", op->opaque->exec, op->pid);
    mainloop_child_add_with_flags(op->pid, op->timeout, op->id, op,
                                  pcmk_is_set(op->flags, SVC_ACTION_LEAVE_GROUP)? mainloop_leave_pid_group : 0,
                                  async_action_complete);

    op->opaque->stdout_gsource = mainloop_add_fd(op->id,
                                                 G_PRIORITY_LOW,
                                                 op->opaque->stdout_fd, op,
                                                 &stdout_callbacks);
    op->opaque->stderr_gsource = mainloop_add_fd(op->id,
                                                 G_PRIORITY_LOW,
                                                 op->opaque->stderr_fd, op,
                                                 &stderr_callbacks);
    services_add_inflight_op(op);
    return pcmk_rc_ok;

done:
    if (op->synchronous) {
        return (op->rc == PCMK_OCF_OK)? pcmk_rc_ok : pcmk_rc_error;
    } else {
        return services__finalize_async_op(op);
    }
}

static GList *
services_os_get_single_directory_list(const char *root, gboolean files, gboolean executable)
{
    GList *list = NULL;
    struct dirent **namelist;
    int entries = 0, lpc = 0;
    char buffer[PATH_MAX];

    entries = scandir(root, &namelist, NULL, alphasort);
    if (entries <= 0) {
        return list;
    }

    for (lpc = 0; lpc < entries; lpc++) {
        struct stat sb;

        if ('.' == namelist[lpc]->d_name[0]) {
            free(namelist[lpc]);
            continue;
        }

        snprintf(buffer, sizeof(buffer), "%s/%s", root, namelist[lpc]->d_name);

        if (stat(buffer, &sb)) {
            continue;
        }

        if (S_ISDIR(sb.st_mode)) {
            if (files) {
                free(namelist[lpc]);
                continue;
            }

        } else if (S_ISREG(sb.st_mode)) {
            if (files == FALSE) {
                free(namelist[lpc]);
                continue;

            } else if (executable
                       && (sb.st_mode & S_IXUSR) == 0
                       && (sb.st_mode & S_IXGRP) == 0 && (sb.st_mode & S_IXOTH) == 0) {
                free(namelist[lpc]);
                continue;
            }
        }

        list = g_list_append(list, strdup(namelist[lpc]->d_name));

        free(namelist[lpc]);
    }

    free(namelist);
    return list;
}

GList *
services_os_get_directory_list(const char *root, gboolean files, gboolean executable)
{
    GList *result = NULL;
    char *dirs = strdup(root);
    char *dir = NULL;

    if (pcmk__str_empty(dirs)) {
        free(dirs);
        return result;
    }

    for (dir = strtok(dirs, ":"); dir != NULL; dir = strtok(NULL, ":")) {
        GList *tmp = services_os_get_single_directory_list(dir, files, executable);

        if (tmp) {
            result = g_list_concat(result, tmp);
        }
    }

    free(dirs);

    return result;
}

static GList *
services_os_get_directory_list_provider(const char *root, const char *provider, gboolean files, gboolean executable)
{
    GList *result = NULL;
    char *dirs = strdup(root);
    char *dir = NULL;
    char buffer[PATH_MAX];

    if (pcmk__str_empty(dirs)) {
        free(dirs);
        return result;
    }

    for (dir = strtok(dirs, ":"); dir != NULL; dir = strtok(NULL, ":")) {
        GList *tmp = NULL;

        sprintf(buffer, "%s/%s", dir, provider);
        tmp = services_os_get_single_directory_list(buffer, files, executable);

        if (tmp) {
            result = g_list_concat(result, tmp);
        }
    }

    free(dirs);

    return result;
}

GList *
resources_os_list_ocf_providers(void)
{
    return get_directory_list(OCF_RA_PATH, FALSE, TRUE);
}

GList *
resources_os_list_ocf_agents(const char *provider)
{
    GList *gIter = NULL;
    GList *result = NULL;
    GList *providers = NULL;

    if (provider) {
        return services_os_get_directory_list_provider(OCF_RA_PATH, provider, TRUE, TRUE);
    }

    providers = resources_os_list_ocf_providers();
    for (gIter = providers; gIter != NULL; gIter = gIter->next) {
        GList *tmp1 = result;
        GList *tmp2 = resources_os_list_ocf_agents(gIter->data);

        if (tmp2) {
            result = g_list_concat(tmp1, tmp2);
        }
    }
    g_list_free_full(providers, free);
    return result;
}

gboolean
services__ocf_agent_exists(const char *provider, const char *agent)
{
    gboolean rc = FALSE;
    struct stat st;
    char *dirs = strdup(OCF_RA_PATH);
    char *dir = NULL;
    char *buf = NULL;

    if (provider == NULL || agent == NULL || pcmk__str_empty(dirs)) {
        free(dirs);
        return rc;
    }

    for (dir = strtok(dirs, ":"); dir != NULL; dir = strtok(NULL, ":")) {
        buf = crm_strdup_printf("%s/%s/%s", dir, provider, agent);
        if (stat(buf, &st) == 0) {
            free(buf);
            rc = TRUE;
            break;
        }

        free(buf);
    }

    free(dirs);

    return rc;
}
