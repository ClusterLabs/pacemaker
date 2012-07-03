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
#define _GNU_SOURCE
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <string.h>

#include "crm/crm.h"
#include "crm/common/mainloop.h"
#include "crm/services.h"

#include "services_private.h"

static inline void
set_fd_opts(int fd, int opts)
{
    int flag;
    if ((flag = fcntl(fd, F_GETFL)) >= 0) {
        if (fcntl(fd, F_SETFL, flag | opts) < 0) {
            crm_err( "fcntl() write failed");
        }
    } else {
        crm_err( "fcntl() read failed");
    }
}

static gboolean
read_output(int fd, svc_action_t *op)
{
    char *data = NULL;
    int rc = 0, len = 0;
    gboolean is_err = FALSE;
    char buf[500];
    static const size_t buf_read_len = sizeof(buf) - 1;

    crm_trace("%p", op);

    if (fd < 0) {
        return FALSE;
    }

    if (fd == op->opaque->stderr_fd) {
        is_err = TRUE;
        if (op->stderr_data) {
            len = strlen(op->stderr_data);
            data = op->stderr_data;
        }
    } else if (op->stdout_data) {
        len = strlen(op->stdout_data);
        data = op->stdout_data;
    }

    do {
        rc = read(fd, buf, buf_read_len);
        if (rc > 0) {
            buf[rc] = 0;
            data = realloc(data, len + rc + 1);
            sprintf(data + len, "%s", buf);
            len += rc;
        } else if (errno != EINTR) {
            /* error or EOF
             * Cleanup happens in pipe_done()
             */
            rc = FALSE;
            break;
        }

    } while (rc == buf_read_len || rc < 0);

    if (data != NULL && is_err) {
        op->stderr_data = data;
    } else if (data != NULL) {
        op->stdout_data = data;
    }

    return rc;
}

static int
dispatch_stdout(gpointer userdata)
{
    svc_action_t* op = (svc_action_t *) userdata;
    return read_output(op->opaque->stdout_fd, op);
}

static int
dispatch_stderr(gpointer userdata)
{
    svc_action_t* op = (svc_action_t *) userdata;
    return read_output(op->opaque->stderr_fd, op);
}

static void
pipe_out_done(gpointer user_data)
{
    svc_action_t* op = (svc_action_t *) user_data;

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
    svc_action_t* op = (svc_action_t *) user_data;
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
    snprintf(buffer, sizeof(buffer), "OCF_RESKEY_%s", (char *) key);
    set_ocf_env(buffer, value, user_data);
}

static void
add_OCF_env_vars(svc_action_t *op)
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

gboolean recurring_action_timer(gpointer data)
{
    svc_action_t *op = data;
    crm_debug("Scheduling another invokation of %s", op->id);

    /* Clean out the old result */
    free(op->stdout_data); op->stdout_data = NULL;
    free(op->stderr_data); op->stderr_data = NULL;

    services_action_async(op, NULL);
    return FALSE;
}

void
operation_finalize(svc_action_t *op)
{
    int recurring = 0;
    if (op->interval) {
        if (op->cancel) {
            op->status = PCMK_LRM_OP_CANCELLED;
            cancel_recurring_action(op);
        } else {
            recurring = 1;
            op->opaque->repeat_timer = g_timeout_add(op->interval,
                recurring_action_timer,
                (void *) op);
        }
    }

    if (op->opaque->callback) {
        op->opaque->callback(op);
    }

    if (!recurring) {
        /*
         * If this is a recurring action, do not free explicitly.
         * It will get freed whenever the action gets cancelled.
         */
        services_action_free(op);
    }
}

static void
operation_finished(mainloop_child_t *p, int status, int signo, int exitcode)
{
    char *next = NULL;
    char *offset = NULL;
    svc_action_t *op = mainloop_get_child_userdata(p);
    pid_t pid = mainloop_get_child_pid(p);

    mainloop_clear_child_userdata(p);
    op->status = PCMK_LRM_OP_DONE;
    CRM_ASSERT(op->pid == pid);

    if (op->opaque->stderr_gsource) {
        /* Make sure we have read everything from the buffer.
         * Depending on the priority mainloop gives the fd, operation_finished
         * could occur before all the reads are done.  Force the read now.*/
        dispatch_stderr(op);
    }

    if (op->opaque->stdout_gsource) {
        /* Make sure we have read everything from the buffer.
         * Depending on the priority mainloop gives the fd, operation_finished
         * could occur before all the reads are done.  Force the read now.*/
        dispatch_stdout(op);
    }

    if (signo) {
        if (mainloop_get_child_timeout(p)) {
            crm_warn("%s:%d - timed out after %dms", op->id, op->pid,
                    op->timeout);
            op->status = PCMK_LRM_OP_TIMEOUT;
            op->rc = PCMK_OCF_TIMEOUT;

        } else {
            crm_warn("%s:%d - terminated with signal %d", op->id, op->pid,
                    signo);
            op->status = PCMK_LRM_OP_ERROR;
            op->rc = PCMK_OCF_SIGNAL;
        }

    } else {
        op->rc = exitcode;
        crm_debug("%s:%d - exited with rc=%d", op->id, op->pid, exitcode);

        if (op->stdout_data) {
            next = op->stdout_data;
            do {
                offset = next;
                next = strchrnul(offset, '\n');
                crm_debug("%s:%d [ %.*s ]", op->id, op->pid,
                         (int) (next - offset), offset);
                if (next[0] != 0) {
                    next++;
                }

            } while (next != NULL && next[0] != 0);
        }

        if (op->stderr_data) {
            next = op->stderr_data;
            do {
                offset = next;
                next = strchrnul(offset, '\n');
                crm_notice("%s:%d [ %.*s ]", op->id, op->pid,
                          (int) (next - offset), offset);
                if (next[0] != 0) {
                    next++;
                }

            } while (next != NULL && next[0] != 0);
        }
    }

    op->pid = 0;
    operation_finalize(op);
}

gboolean
services_os_action_execute(svc_action_t* op, gboolean synchronous)
{
    int rc, lpc;
    int stdout_fd[2];
    int stderr_fd[2];

    if (pipe(stdout_fd) < 0) {
        crm_err( "pipe() failed");
    }

    if (pipe(stderr_fd) < 0) {
        crm_err( "pipe() failed");
    }

    op->pid = fork();
    switch (op->pid) {
    case -1:
        crm_err( "fork() failed");
        close(stdout_fd[0]);
        close(stdout_fd[1]);
        close(stderr_fd[0]);
        close(stderr_fd[1]);
        return FALSE;

    case 0:                /* Child */
        /* Man: The call setpgrp() is equivalent to setpgid(0,0)
         * _and_ compiles on BSD variants too
         * need to investigate if it works the same too.
         */
        setpgid(0, 0);
        close(stdout_fd[0]);
        close(stderr_fd[0]);
        if (STDOUT_FILENO != stdout_fd[1]) {
            if (dup2(stdout_fd[1], STDOUT_FILENO) != STDOUT_FILENO) {
                crm_err( "dup2() failed (stdout)");
            }
            close(stdout_fd[1]);
        }
        if (STDERR_FILENO != stderr_fd[1]) {
            if (dup2(stderr_fd[1], STDERR_FILENO) != STDERR_FILENO) {
                crm_err( "dup2() failed (stderr)");
            }
            close(stderr_fd[1]);
        }

        /* close all descriptors except stdin/out/err and channels to logd */
        for (lpc = getdtablesize() - 1; lpc > STDERR_FILENO; lpc--) {
            close(lpc);
        }

        /* Setup environment correctly */
        add_OCF_env_vars(op);

        /* execute the RA */
        execvp(op->opaque->exec, op->opaque->args);

        switch (errno) { /* see execve(2) */
        case ENOENT:  /* No such file or directory */
        case EISDIR:   /* Is a directory */
            rc = PCMK_OCF_NOT_INSTALLED;
            break;
        case EACCES:   /* permission denied (various errors) */
            rc = PCMK_OCF_INSUFFICIENT_PRIV;
            break;
        default:
            rc = PCMK_OCF_UNKNOWN_ERROR;
            break;
        }
        _exit(rc);
    }

    /* Only the parent reaches here */
    close(stdout_fd[1]);
    close(stderr_fd[1]);

    op->opaque->stdout_fd = stdout_fd[0];
    set_fd_opts(op->opaque->stdout_fd, O_NONBLOCK);

    op->opaque->stderr_fd = stderr_fd[0];
    set_fd_opts(op->opaque->stderr_fd, O_NONBLOCK);

    if (synchronous) {
        int status = 0;
        int timeout = (1 + op->timeout) / 1000;
        crm_trace("Waiting for %d", op->pid);
        while ((op->timeout < 0 || timeout > 0) && waitpid(op->pid, &status, WNOHANG) <= 0) {
            sleep(1);
            read_output(op->opaque->stdout_fd, op);
            read_output(op->opaque->stderr_fd, op);
            timeout--;
        }

        crm_trace("Child done: %d", op->pid);
        if (timeout == 0) {
            int killrc = kill(op->pid, 9 /*SIGKILL*/);

            op->rc = PCMK_OCF_UNKNOWN_ERROR;
            op->status = PCMK_LRM_OP_TIMEOUT;
            crm_warn("%s:%d - timed out after %dms", op->id, op->pid,
                    op->timeout);

            if (killrc && errno != ESRCH) {
                crm_err("kill(%d, KILL) failed: %d", op->pid, errno);
            }

        } else if (WIFEXITED(status)) {
            op->status = PCMK_LRM_OP_DONE;
            op->rc = WEXITSTATUS(status);
            crm_info("Managed %s process %d exited with rc=%d", op->id, op->pid,
                   op->rc);

        } else if (WIFSIGNALED(status)) {
            int signo = WTERMSIG(status);
            op->status = PCMK_LRM_OP_ERROR;
            crm_err("Managed %s process %d exited with signal=%d", op->id,
                   op->pid, signo);
        }
#ifdef WCOREDUMP
        if (WCOREDUMP(status)) {
            crm_err("Managed %s process %d dumped core", op->id, op->pid);
        }
#endif

        read_output(op->opaque->stdout_fd, op);
        read_output(op->opaque->stderr_fd, op);

    } else {
        crm_trace("Async waiting for %d - %s", op->pid, op->opaque->exec);
        mainloop_add_child(op->pid, op->timeout, op->id, op,
                           operation_finished);

        op->opaque->stdout_gsource = mainloop_add_fd(op->id,
            op->opaque->stdout_fd,
            op,
            &stdout_callbacks);

        op->opaque->stderr_gsource = mainloop_add_fd(op->id,
            op->opaque->stderr_fd,
            op,
            &stderr_callbacks);
    }

    return TRUE;
}

GList *
services_os_get_directory_list(const char *root, gboolean files)
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

            } else if ((sb.st_mode & S_IXUSR) == 0
                       && (sb.st_mode & S_IXGRP) == 0
                       && (sb.st_mode & S_IXOTH) == 0) {
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
    return get_directory_list(LSB_ROOT_DIR, TRUE);
}

GList *
resources_os_list_ocf_providers(void)
{
    return get_directory_list(OCF_ROOT_DIR "/resource.d", FALSE);
}

GList *
resources_os_list_ocf_agents(const char *provider)
{
    GList *gIter = NULL;
    GList *result = NULL;
    GList *providers = NULL;

    if (provider) {
        char buffer[500];
        snprintf(buffer, sizeof(buffer), "%s/resource.d/%s", OCF_ROOT_DIR,
                 provider);
        return get_directory_list(buffer, TRUE);
    }

    providers = resources_os_list_ocf_providers();
    for (gIter = providers; gIter != NULL; gIter = gIter->next) {
        GList *tmp1 = result;
        GList *tmp2 = resources_os_list_ocf_agents(gIter->data);
        if(tmp2) {
            result = g_list_concat(tmp1, tmp2);
        }
    }
    g_list_free_full(providers, free);
    return result;
}
