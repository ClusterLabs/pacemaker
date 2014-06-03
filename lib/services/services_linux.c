/*
 * Copyright (C) 2010 Andrew Beekhof <andrew@beekhof.net>
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
#include <fcntl.h>
#include <string.h>
#include <sys/time.h>
#include <sys/resource.h>

#ifdef HAVE_SYS_SIGNALFD_H
#include <sys/signalfd.h>
#endif

#include "crm/crm.h"
#include "crm/common/mainloop.h"
#include "crm/services.h"

#include "services_private.h"

#if SUPPORT_CIBSECRETS
#  include "crm/common/cib_secrets.h"
#endif

static inline void
set_fd_opts(int fd, int opts)
{
    int flag;

    if ((flag = fcntl(fd, F_GETFL)) >= 0) {
        if (fcntl(fd, F_SETFL, flag | opts) < 0) {
            crm_err("fcntl() write failed");
        }
    } else {
        crm_err("fcntl() read failed");
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
        crm_trace("Reading %s %s", op->id, is_stderr?"stderr":"stdout", len);
    }

    do {
        rc = read(fd, buf, buf_read_len);
        if (rc > 0) {
            crm_trace("Got %d characters starting with %.20s", rc, buf);
            buf[rc] = 0;
            data = realloc(data, len + rc + 1);
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

    snprintf(buffer, sizeof(buffer), "OCF_RESKEY_%s", (char *)key);
    set_ocf_env(buffer, value, user_data);
}

static void
add_OCF_env_vars(svc_action_t * op)
{
    if (!op->standard || strcasecmp("ocf", op->standard) != 0) {
        return;
    }

    if (op->params) {
        g_hash_table_foreach(op->params, set_ocf_env_with_prefix, NULL);
    }

    set_ocf_env("OCF_RA_VERSION_MAJOR", "1", NULL);
    set_ocf_env("OCF_RA_VERSION_MINOR", "0", NULL);
    set_ocf_env("OCF_ROOT", OCF_ROOT_DIR, NULL);

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

gboolean
recurring_action_timer(gpointer data)
{
    svc_action_t *op = data;

    crm_debug("Scheduling another invokation of %s", op->id);

    /* Clean out the old result */
    free(op->stdout_data);
    op->stdout_data = NULL;
    free(op->stderr_data);
    op->stderr_data = NULL;

    services_action_async(op, NULL);
    return FALSE;
}

/* Returns FALSE if 'op' should be free'd by the caller */
gboolean
operation_finalize(svc_action_t * op)
{
    int recurring = 0;

    if (op->interval) {
        if (op->cancel) {
            op->status = PCMK_LRM_OP_CANCELLED;
            cancel_recurring_action(op);
        } else {
            recurring = 1;
            op->opaque->repeat_timer = g_timeout_add(op->interval,
                                                     recurring_action_timer, (void *)op);
        }
    }

    if (op->opaque->callback) {
        op->opaque->callback(op);
    }

    op->pid = 0;

    if (!recurring) {
        /*
         * If this is a recurring action, do not free explicitly.
         * It will get freed whenever the action gets cancelled.
         */
        services_action_free(op);
        return TRUE;
    }
    return FALSE;
}

static void
operation_finished(mainloop_child_t * p, pid_t pid, int core, int signo, int exitcode)
{
    svc_action_t *op = mainloop_child_userdata(p);
    char *prefix = g_strdup_printf("%s:%d", op->id, op->pid);

    mainloop_clear_child_userdata(p);
    op->status = PCMK_LRM_OP_DONE;
    CRM_ASSERT(op->pid == pid);

    crm_trace("%s %p %p", prefix, op->opaque->stderr_gsource, op->opaque->stdout_gsource);
    if (op->opaque->stderr_gsource) {
        /* Make sure we have read everything from the buffer.
         * Depending on the priority mainloop gives the fd, operation_finished
         * could occur before all the reads are done.  Force the read now.*/
        crm_trace("%s dispatching stderr", prefix);
        dispatch_stderr(op);
        crm_trace("%s: %p", op->id, op->stderr_data);
        mainloop_del_fd(op->opaque->stderr_gsource);
        op->opaque->stderr_gsource = NULL;
    }

    if (op->opaque->stdout_gsource) {
        /* Make sure we have read everything from the buffer.
         * Depending on the priority mainloop gives the fd, operation_finished
         * could occur before all the reads are done.  Force the read now.*/
        crm_trace("%s dispatching stdout", prefix);
        dispatch_stdout(op);
        crm_trace("%s: %p", op->id, op->stdout_data);
        mainloop_del_fd(op->opaque->stdout_gsource);
        op->opaque->stdout_gsource = NULL;
    }

    if (signo) {
        if (mainloop_child_timeout(p)) {
            crm_warn("%s - timed out after %dms", prefix, op->timeout);
            op->status = PCMK_LRM_OP_TIMEOUT;
            op->rc = PCMK_OCF_TIMEOUT;

        } else {
            do_crm_log_unlikely((op->cancel) ? LOG_INFO : LOG_WARNING,
                                "%s - terminated with signal %d", prefix, signo);
            op->status = PCMK_LRM_OP_ERROR;
            op->rc = PCMK_OCF_SIGNAL;
        }

    } else {
        op->rc = exitcode;
        crm_debug("%s - exited with rc=%d", prefix, exitcode);
    }

    g_free(prefix);
    prefix = g_strdup_printf("%s:%d:stderr", op->id, op->pid);
    crm_log_output(LOG_NOTICE, prefix, op->stderr_data);

    g_free(prefix);
    prefix = g_strdup_printf("%s:%d:stdout", op->id, op->pid);
    crm_log_output(LOG_DEBUG, prefix, op->stdout_data);

    g_free(prefix);
    operation_finalize(op);
}

static void
services_handle_exec_error(svc_action_t * op, int error)
{
    op->rc = PCMK_OCF_EXEC_ERROR;
    op->status = PCMK_LRM_OP_ERROR;

    /* Need to mimic the return codes for each standard as thats what we'll convert back from in get_uniform_rc() */
    if (safe_str_eq(op->standard, "lsb") && safe_str_eq(op->action, "status")) {
        switch (error) {    /* see execve(2) */
            case ENOENT:   /* No such file or directory */
            case EISDIR:   /* Is a directory */
                op->rc = PCMK_LSB_STATUS_NOT_INSTALLED;
                op->status = PCMK_LRM_OP_NOT_INSTALLED;
                break;
            case EACCES:   /* permission denied (various errors) */
                /* LSB status ops don't support 'not installed' */
                break;
        }

#if SUPPORT_NAGIOS
    } else if (safe_str_eq(op->standard, "nagios")) {
        switch (error) {
            case ENOENT:   /* No such file or directory */
            case EISDIR:   /* Is a directory */
                op->rc = NAGIOS_NOT_INSTALLED;
                op->status = PCMK_LRM_OP_NOT_INSTALLED;
                break;
            case EACCES:   /* permission denied (various errors) */
                op->rc = NAGIOS_INSUFFICIENT_PRIV;
                break;
        }
#endif

    } else {
        switch (error) {
            case ENOENT:   /* No such file or directory */
            case EISDIR:   /* Is a directory */
                op->rc = PCMK_OCF_NOT_INSTALLED; /* Valid for LSB */
                op->status = PCMK_LRM_OP_NOT_INSTALLED;
                break;
            case EACCES:   /* permission denied (various errors) */
                op->rc = PCMK_OCF_INSUFFICIENT_PRIV; /* Valid for LSB */
                break;
        }
    }
}

/* Returns FALSE if 'op' should be free'd by the caller */
gboolean
services_os_action_execute(svc_action_t * op, gboolean synchronous)
{
    int lpc;
    int stdout_fd[2];
    int stderr_fd[2];
    sigset_t mask;
    sigset_t old_mask;
    struct stat st;

    if (pipe(stdout_fd) < 0) {
        crm_err("pipe() failed");
    }

    if (pipe(stderr_fd) < 0) {
        crm_err("pipe() failed");
    }

    /* Fail fast */
    if(stat(op->opaque->exec, &st) != 0) {
        int rc = errno;
        crm_warn("Cannot execute '%s': %s (%d)", op->opaque->exec, pcmk_strerror(rc), rc);
        services_handle_exec_error(op, rc);
        if (!synchronous) {
            return operation_finalize(op);
        }
        return FALSE;
    }

    if (synchronous) {
        sigemptyset(&mask);
        sigaddset(&mask, SIGCHLD);
        sigemptyset(&old_mask);

        if (sigprocmask(SIG_BLOCK, &mask, &old_mask) < 0) {
            crm_perror(LOG_ERR, "sigprocmask() failed");
        }
    }

    op->pid = fork();
    switch (op->pid) {
        case -1:
            {
                int rc = errno;

                close(stdout_fd[0]);
                close(stdout_fd[1]);
                close(stderr_fd[0]);
                close(stderr_fd[1]);

                crm_err("Could not execute '%s': %s (%d)", op->opaque->exec, pcmk_strerror(rc), rc);
                services_handle_exec_error(op, rc);
                if (!synchronous) {
                    return operation_finalize(op);
                }
                return FALSE;
            }
        case 0:                /* Child */
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
            close(stdout_fd[0]);
            close(stderr_fd[0]);
            if (STDOUT_FILENO != stdout_fd[1]) {
                if (dup2(stdout_fd[1], STDOUT_FILENO) != STDOUT_FILENO) {
                    crm_err("dup2() failed (stdout)");
                }
                close(stdout_fd[1]);
            }
            if (STDERR_FILENO != stderr_fd[1]) {
                if (dup2(stderr_fd[1], STDERR_FILENO) != STDERR_FILENO) {
                    crm_err("dup2() failed (stderr)");
                }
                close(stderr_fd[1]);
            }

            /* close all descriptors except stdin/out/err and channels to logd */
            for (lpc = getdtablesize() - 1; lpc > STDERR_FILENO; lpc--) {
                close(lpc);
            }

#if SUPPORT_CIBSECRETS
            if (replace_secret_params(op->rsc, op->params) < 0) {
                /* replacing secrets failed! */
                if (safe_str_eq(op->action,"stop")) {
                    /* don't fail on stop! */
                    crm_info("proceeding with the stop operation for %s", op->rsc);

                } else {
                    crm_err("failed to get secrets for %s, "
                            "considering resource not configured", op->rsc);
                    _exit(PCMK_OCF_NOT_CONFIGURED);
                }
            }
#endif
            /* Setup environment correctly */
            add_OCF_env_vars(op);

            /* execute the RA */
            execvp(op->opaque->exec, op->opaque->args);

            /* Most cases should have been already handled by stat() */
            services_handle_exec_error(op, errno);
            _exit(op->rc);
    }

    /* Only the parent reaches here */
    close(stdout_fd[1]);
    close(stderr_fd[1]);

    op->opaque->stdout_fd = stdout_fd[0];
    set_fd_opts(op->opaque->stdout_fd, O_NONBLOCK);

    op->opaque->stderr_fd = stderr_fd[0];
    set_fd_opts(op->opaque->stderr_fd, O_NONBLOCK);

    if (synchronous) {
#ifndef HAVE_SYS_SIGNALFD_H
        CRM_ASSERT(FALSE);
#else
        int status = 0;
        int timeout = op->timeout;
        int sfd = -1;
        time_t start = -1;
        struct pollfd fds[3];
        int wait_rc = 0;

        sfd = signalfd(-1, &mask, SFD_NONBLOCK);
        if (sfd < 0) {
            crm_perror(LOG_ERR, "signalfd() failed");
        }

        fds[0].fd = op->opaque->stdout_fd;
        fds[0].events = POLLIN;
        fds[0].revents = 0;

        fds[1].fd = op->opaque->stderr_fd;
        fds[1].events = POLLIN;
        fds[1].revents = 0;

        fds[2].fd = sfd;
        fds[2].events = POLLIN;
        fds[2].revents = 0;

        crm_trace("Waiting for %d", op->pid);
        start = time(NULL);
        do {
            int poll_rc = poll(fds, 3, timeout);

            if (poll_rc > 0) {
                if (fds[0].revents & POLLIN) {
                    svc_read_output(op->opaque->stdout_fd, op, FALSE);
                }

                if (fds[1].revents & POLLIN) {
                    svc_read_output(op->opaque->stderr_fd, op, TRUE);
                }

                if (fds[2].revents & POLLIN) {
                    struct signalfd_siginfo fdsi;
                    ssize_t s;

                    s = read(sfd, &fdsi, sizeof(struct signalfd_siginfo));
                    if (s != sizeof(struct signalfd_siginfo)) {
                        crm_perror(LOG_ERR, "Read from signal fd %d failed", sfd);

                    } else if (fdsi.ssi_signo == SIGCHLD) {
                        wait_rc = waitpid(op->pid, &status, WNOHANG);

                        if (wait_rc < 0){
                            crm_perror(LOG_ERR, "waitpid() for %d failed", op->pid);

                        } else if (wait_rc > 0) {
                            break;
                        }
                    }
                }

            } else if (poll_rc == 0) {
                timeout = 0;
                break;

            } else if (poll_rc < 0) {
                if (errno != EINTR) {
                    crm_perror(LOG_ERR, "poll() failed");
                    break;
                }
            }

            timeout = op->timeout - (time(NULL) - start) * 1000;

        } while ((op->timeout < 0 || timeout > 0));

        crm_trace("Child done: %d", op->pid);
        if (wait_rc <= 0) {
            int killrc = kill(op->pid, SIGKILL);

            op->rc = PCMK_OCF_UNKNOWN_ERROR;
            if (op->timeout > 0 && timeout <= 0) {
                op->status = PCMK_LRM_OP_TIMEOUT;
                crm_warn("%s:%d - timed out after %dms", op->id, op->pid, op->timeout);

            } else {
                op->status = PCMK_LRM_OP_ERROR;
            }

            if (killrc && errno != ESRCH) {
                crm_err("kill(%d, KILL) failed: %d", op->pid, errno);
            }
            /*
             * From sigprocmask(2):
             * It is not possible to block SIGKILL or SIGSTOP.  Attempts to do so are silently ignored.
             *
             * This makes it safe to skip WNOHANG here
             */
            waitpid(op->pid, &status, 0);

        } else if (WIFEXITED(status)) {
            op->status = PCMK_LRM_OP_DONE;
            op->rc = WEXITSTATUS(status);
            crm_info("Managed %s process %d exited with rc=%d", op->id, op->pid, op->rc);

        } else if (WIFSIGNALED(status)) {
            int signo = WTERMSIG(status);

            op->status = PCMK_LRM_OP_ERROR;
            crm_err("Managed %s process %d exited with signal=%d", op->id, op->pid, signo);
        }
#ifdef WCOREDUMP
        if (WCOREDUMP(status)) {
            crm_err("Managed %s process %d dumped core", op->id, op->pid);
        }
#endif

        svc_read_output(op->opaque->stdout_fd, op, FALSE);
        svc_read_output(op->opaque->stderr_fd, op, TRUE);

        close(op->opaque->stdout_fd);
        close(op->opaque->stderr_fd);
        close(sfd);

        if (sigismember(&old_mask, SIGCHLD) == 0) {
            if (sigprocmask(SIG_UNBLOCK, &mask, NULL) < 0) {
                crm_perror(LOG_ERR, "sigprocmask() to unblocked failed");
            }
        }
#endif

    } else {
        crm_trace("Async waiting for %d - %s", op->pid, op->opaque->exec);
        mainloop_child_add(op->pid, op->timeout, op->id, op, operation_finished);

        op->opaque->stdout_gsource = mainloop_add_fd(op->id,
                                                     G_PRIORITY_LOW,
                                                     op->opaque->stdout_fd, op, &stdout_callbacks);

        op->opaque->stderr_gsource = mainloop_add_fd(op->id,
                                                     G_PRIORITY_LOW,
                                                     op->opaque->stderr_fd, op, &stderr_callbacks);
    }

    return TRUE;
}

GList *
services_os_get_directory_list(const char *root, gboolean files, gboolean executable)
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
resources_os_list_lsb_agents(void)
{
    return get_directory_list(LSB_ROOT_DIR, TRUE, TRUE);
}

GList *
resources_os_list_ocf_providers(void)
{
    return get_directory_list(OCF_ROOT_DIR "/resource.d", FALSE, TRUE);
}

GList *
resources_os_list_ocf_agents(const char *provider)
{
    GList *gIter = NULL;
    GList *result = NULL;
    GList *providers = NULL;

    if (provider) {
        char buffer[500];

        snprintf(buffer, sizeof(buffer), "%s/resource.d/%s", OCF_ROOT_DIR, provider);
        return get_directory_list(buffer, TRUE, TRUE);
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

#if SUPPORT_NAGIOS
GList *
resources_os_list_nagios_agents(void)
{
    GList *plugin_list = NULL;
    GList *result = NULL;
    GList *gIter = NULL;

    plugin_list = get_directory_list(NAGIOS_PLUGIN_DIR, TRUE, TRUE);

    /* Make sure both the plugin and its metadata exist */
    for (gIter = plugin_list; gIter != NULL; gIter = gIter->next) {
        const char *plugin = gIter->data;
        char *metadata = g_strdup_printf(NAGIOS_METADATA_DIR "/%s.xml", plugin);
        struct stat st;

        if (stat(metadata, &st) == 0) {
            result = g_list_append(result, strdup(plugin));
        }

        g_free(metadata);
    }
    g_list_free_full(plugin_list, free);
    return result;
}
#endif
