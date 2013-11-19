/*
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <crm_internal.h>

#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif

#include <stdlib.h>
#include <signal.h>
#include <errno.h>

#include <sys/wait.h>

#include <crm/crm.h>
#include <crm/common/xml.h>
#include <crm/common/mainloop.h>
#include <crm/common/ipcs.h>

struct mainloop_child_s {
    pid_t pid;
    char *desc;
    unsigned timerid;
    unsigned watchid;
    gboolean timeout;
    void *privatedata;

    /* Called when a process dies */
    void (*callback) (mainloop_child_t * p, pid_t pid, int core, int signo, int exitcode);
};

struct trigger_s {
    GSource source;
    gboolean running;
    gboolean trigger;
    void *user_data;
    guint id;

};

static gboolean
crm_trigger_prepare(GSource * source, gint * timeout)
{
    crm_trigger_t *trig = (crm_trigger_t *) source;

    /* cluster-glue's FD and IPC related sources make use of
     * g_source_add_poll() but do not set a timeout in their prepare
     * functions
     *
     * This means mainloop's poll() will block until an event for one
     * of these sources occurs - any /other/ type of source, such as
     * this one or g_idle_*, that doesn't use g_source_add_poll() is
     * S-O-L and wont be processed until there is something fd-based
     * happens.
     *
     * Luckily the timeout we can set here affects all sources and
     * puts an upper limit on how long poll() can take.
     *
     * So unconditionally set a small-ish timeout, not too small that
     * we're in constant motion, which will act as an upper bound on
     * how long the signal handling might be delayed for.
     */
    *timeout = 500;             /* Timeout in ms */

    return trig->trigger;
}

static gboolean
crm_trigger_check(GSource * source)
{
    crm_trigger_t *trig = (crm_trigger_t *) source;

    return trig->trigger;
}

static gboolean
crm_trigger_dispatch(GSource * source, GSourceFunc callback, gpointer userdata)
{
    int rc = TRUE;
    crm_trigger_t *trig = (crm_trigger_t *) source;

    if (trig->running) {
        /* Wait until the existing job is complete before starting the next one */
        return TRUE;
    }
    trig->trigger = FALSE;

    if (callback) {
        rc = callback(trig->user_data);
        if (rc < 0) {
            crm_trace("Trigger handler %p not yet complete", trig);
            trig->running = TRUE;
            rc = TRUE;
        }
    }
    return rc;
}

static void
crm_trigger_finalize(GSource * source)
{
    crm_trace("Trigger %p destroyed", source);
}

#if 0
struct _GSourceCopy
{
  gpointer callback_data;
  GSourceCallbackFuncs *callback_funcs;

  const GSourceFuncs *source_funcs;
  guint ref_count;

  GMainContext *context;

  gint priority;
  guint flags;
  guint source_id;

  GSList *poll_fds;
  
  GSource *prev;
  GSource *next;

  char    *name;

  void *priv;
};

static int
g_source_refcount(GSource * source)
{
    /* Duplicating the contents of private header files is a necessary evil */
    if (source) {
        struct _GSourceCopy *evil = (struct _GSourceCopy*)source;
        return evil->ref_count;
    }
    return 0;
}
#else
static int g_source_refcount(GSource * source)
{
    return 0;
}
#endif

static GSourceFuncs crm_trigger_funcs = {
    crm_trigger_prepare,
    crm_trigger_check,
    crm_trigger_dispatch,
    crm_trigger_finalize,
};

static crm_trigger_t *
mainloop_setup_trigger(GSource * source, int priority, int (*dispatch) (gpointer user_data),
                       gpointer userdata)
{
    crm_trigger_t *trigger = NULL;

    trigger = (crm_trigger_t *) source;

    trigger->id = 0;
    trigger->trigger = FALSE;
    trigger->user_data = userdata;

    if (dispatch) {
        g_source_set_callback(source, dispatch, trigger, NULL);
    }

    g_source_set_priority(source, priority);
    g_source_set_can_recurse(source, FALSE);

    crm_trace("Setup %p with ref-count=%u", source, g_source_refcount(source));
    trigger->id = g_source_attach(source, NULL);
    crm_trace("Attached %p with ref-count=%u", source, g_source_refcount(source));

    return trigger;
}

void
mainloop_trigger_complete(crm_trigger_t * trig)
{
    crm_trace("Trigger handler %p complete", trig);
    trig->running = FALSE;
}

/* If dispatch returns:
 *  -1: Job running but not complete
 *   0: Remove the trigger from mainloop
 *   1: Leave the trigger in mainloop
 */
crm_trigger_t *
mainloop_add_trigger(int priority, int (*dispatch) (gpointer user_data), gpointer userdata)
{
    GSource *source = NULL;

    CRM_ASSERT(sizeof(crm_trigger_t) > sizeof(GSource));
    source = g_source_new(&crm_trigger_funcs, sizeof(crm_trigger_t));
    CRM_ASSERT(source != NULL);

    return mainloop_setup_trigger(source, priority, dispatch, userdata);
}

void
mainloop_set_trigger(crm_trigger_t * source)
{
    if(source) {
        source->trigger = TRUE;
    }
}

gboolean
mainloop_destroy_trigger(crm_trigger_t * source)
{
    GSource *gs = NULL;

    if(source == NULL) {
        return TRUE;
    }

    gs = (GSource *)source;

    if(g_source_refcount(gs) > 2) {
        crm_info("Trigger %p is still referenced %u times", gs, g_source_refcount(gs));
    }

    g_source_destroy(gs); /* Remove from mainloop, ref_count-- */
    g_source_unref(gs); /* The caller no longer carries a reference to source
                         *
                         * At this point the source should be free'd,
                         * unless we're currently processing said
                         * source, in which case mainloop holds an
                         * additional reference and it will be free'd
                         * once our processing completes
                         */
    return TRUE;
}

typedef struct signal_s {
    crm_trigger_t trigger;      /* must be first */
    void (*handler) (int sig);
    int signal;

} crm_signal_t;

static crm_signal_t *crm_signals[NSIG];

static gboolean
crm_signal_dispatch(GSource * source, GSourceFunc callback, gpointer userdata)
{
    crm_signal_t *sig = (crm_signal_t *) source;

    if(sig->signal != SIGCHLD) {
        crm_info("Invoking handler for signal %d: %s", sig->signal, strsignal(sig->signal));
    }

    sig->trigger.trigger = FALSE;
    if (sig->handler) {
        sig->handler(sig->signal);
    }
    return TRUE;
}

static void
mainloop_signal_handler(int sig)
{
    if (sig > 0 && sig < NSIG && crm_signals[sig] != NULL) {
        mainloop_set_trigger((crm_trigger_t *) crm_signals[sig]);
    }
}

static GSourceFuncs crm_signal_funcs = {
    crm_trigger_prepare,
    crm_trigger_check,
    crm_signal_dispatch,
    crm_trigger_finalize,
};

gboolean
crm_signal(int sig, void (*dispatch) (int sig))
{
    sigset_t mask;
    struct sigaction sa;
    struct sigaction old;

    if (sigemptyset(&mask) < 0) {
        crm_perror(LOG_ERR, "Call to sigemptyset failed");
        return FALSE;
    }

    memset(&sa, 0, sizeof(struct sigaction));
    sa.sa_handler = dispatch;
    sa.sa_flags = SA_RESTART;
    sa.sa_mask = mask;

    if (sigaction(sig, &sa, &old) < 0) {
        crm_perror(LOG_ERR, "Could not install signal handler for signal %d", sig);
        return FALSE;
    }

    return TRUE;
}

gboolean
mainloop_add_signal(int sig, void (*dispatch) (int sig))
{
    GSource *source = NULL;
    int priority = G_PRIORITY_HIGH - 1;

    if (sig == SIGTERM) {
        /* TERM is higher priority than other signals,
         *   signals are higher priority than other ipc.
         * Yes, minus: smaller is "higher"
         */
        priority--;
    }

    if (sig >= NSIG || sig < 0) {
        crm_err("Signal %d is out of range", sig);
        return FALSE;

    } else if (crm_signals[sig] != NULL && crm_signals[sig]->handler == dispatch) {
        crm_trace("Signal handler for %d is already installed", sig);
        return TRUE;

    } else if (crm_signals[sig] != NULL) {
        crm_err("Different signal handler for %d is already installed", sig);
        return FALSE;
    }

    CRM_ASSERT(sizeof(crm_signal_t) > sizeof(GSource));
    source = g_source_new(&crm_signal_funcs, sizeof(crm_signal_t));

    crm_signals[sig] = (crm_signal_t *) mainloop_setup_trigger(source, priority, NULL, NULL);
    CRM_ASSERT(crm_signals[sig] != NULL);

    crm_signals[sig]->handler = dispatch;
    crm_signals[sig]->signal = sig;

    if (crm_signal(sig, mainloop_signal_handler) == FALSE) {
        crm_signal_t *tmp = crm_signals[sig];

        crm_signals[sig] = NULL;

        mainloop_destroy_trigger((crm_trigger_t *) tmp);
        return FALSE;
    }
#if 0
    /* If we want signals to interrupt mainloop's poll(), instead of waiting for
     * the timeout, then we should call siginterrupt() below
     *
     * For now, just enforce a low timeout
     */
    if (siginterrupt(sig, 1) < 0) {
        crm_perror(LOG_INFO, "Could not enable system call interruptions for signal %d", sig);
    }
#endif

    return TRUE;
}

gboolean
mainloop_destroy_signal(int sig)
{
    crm_signal_t *tmp = NULL;

    if (sig >= NSIG || sig < 0) {
        crm_err("Signal %d is out of range", sig);
        return FALSE;

    } else if (crm_signal(sig, NULL) == FALSE) {
        crm_perror(LOG_ERR, "Could not uninstall signal handler for signal %d", sig);
        return FALSE;

    } else if (crm_signals[sig] == NULL) {
        return TRUE;
    }

    crm_trace("Destroying signal %d", sig);
    tmp = crm_signals[sig];
    crm_signals[sig] = NULL;
    mainloop_destroy_trigger((crm_trigger_t *) tmp);
    return TRUE;
}

static qb_array_t *gio_map = NULL;

void
mainloop_cleanup(void) 
{
    if(gio_map) {
        qb_array_free(gio_map);
    }
}

/*
 * libqb...
 */
struct gio_to_qb_poll {
    int32_t is_used;
    guint source;
    int32_t events;
    void *data;
    qb_ipcs_dispatch_fn_t fn;
    enum qb_loop_priority p;
};

static gboolean
gio_read_socket(GIOChannel * gio, GIOCondition condition, gpointer data)
{
    struct gio_to_qb_poll *adaptor = (struct gio_to_qb_poll *)data;
    gint fd = g_io_channel_unix_get_fd(gio);

    crm_trace("%p.%d %d", data, fd, condition);

    if (condition & G_IO_NVAL) {
        crm_trace("Marking failed adaptor %p unused", adaptor);
        adaptor->is_used = QB_FALSE;
    }

    return (adaptor->fn(fd, condition, adaptor->data) == 0);
}

static void
gio_poll_destroy(gpointer data)
{
    struct gio_to_qb_poll *adaptor = (struct gio_to_qb_poll *)data;

    adaptor->is_used = QB_FALSE;
    adaptor->source = 0;
}

static int32_t
gio_poll_dispatch_add(enum qb_loop_priority p, int32_t fd, int32_t evts,
                      void *data, qb_ipcs_dispatch_fn_t fn)
{
    struct gio_to_qb_poll *adaptor;
    GIOChannel *channel;
    int32_t res = 0;

    res = qb_array_index(gio_map, fd, (void **)&adaptor);
    if (res < 0) {
        crm_err("Array lookup failed for fd=%d: %d", fd, res);
        return res;
    }

    crm_trace("Adding fd=%d to mainloop as adapater %p", fd, adaptor);
    if (adaptor->is_used) {
        crm_err("Adapter for descriptor %d is still in-use", fd);
        return -EEXIST;
    }

    /* channel is created with ref_count = 1 */
    channel = g_io_channel_unix_new(fd);
    if (!channel) {
        crm_err("No memory left to add fd=%d", fd);
        return -ENOMEM;
    }

    /* Because unlike the poll() API, glib doesn't tell us about HUPs by default */
    evts |= (G_IO_HUP | G_IO_NVAL | G_IO_ERR);

    adaptor->fn = fn;
    adaptor->events = evts;
    adaptor->data = data;
    adaptor->p = p;
    adaptor->is_used = QB_TRUE;
    adaptor->source =
        g_io_add_watch_full(channel, G_PRIORITY_DEFAULT, evts, gio_read_socket, adaptor,
                            gio_poll_destroy);

    /* Now that mainloop now holds a reference to channel,
     * thanks to g_io_add_watch_full(), drop ours from g_io_channel_unix_new().
     *
     * This means that channel will be free'd by:
     * g_main_context_dispatch()
     *  -> g_source_destroy_internal()
     *      -> g_source_callback_unref()
     * shortly after gio_poll_destroy() completes
     */
    g_io_channel_unref(channel);

    crm_trace("Added to mainloop with gsource id=%d", adaptor->source);
    if (adaptor->source > 0) {
        return 0;
    }

    return -EINVAL;
}

static int32_t
gio_poll_dispatch_mod(enum qb_loop_priority p, int32_t fd, int32_t evts,
                      void *data, qb_ipcs_dispatch_fn_t fn)
{
    return 0;
}

static int32_t
gio_poll_dispatch_del(int32_t fd)
{
    struct gio_to_qb_poll *adaptor;

    crm_trace("Looking for fd=%d", fd);
    if (qb_array_index(gio_map, fd, (void **)&adaptor) == 0) {
        crm_trace("Marking adaptor %p unused", adaptor);
        if (adaptor->source) {
            g_source_remove(adaptor->source);
            adaptor->source = 0;
        }
        adaptor->is_used = QB_FALSE;
    }
    return 0;
}

struct qb_ipcs_poll_handlers gio_poll_funcs = {
    .job_add = NULL,
    .dispatch_add = gio_poll_dispatch_add,
    .dispatch_mod = gio_poll_dispatch_mod,
    .dispatch_del = gio_poll_dispatch_del,
};

static enum qb_ipc_type
pick_ipc_type(enum qb_ipc_type requested)
{
    const char *env = getenv("PCMK_ipc_type");

    if (env && strcmp("shared-mem", env) == 0) {
        return QB_IPC_SHM;
    } else if (env && strcmp("socket", env) == 0) {
        return QB_IPC_SOCKET;
    } else if (env && strcmp("posix", env) == 0) {
        return QB_IPC_POSIX_MQ;
    } else if (env && strcmp("sysv", env) == 0) {
        return QB_IPC_SYSV_MQ;
    } else if (requested == QB_IPC_NATIVE) {
        /* We prefer shared memory because the server never blocks on
         * send.  If part of a message fits into the socket, libqb
         * needs to block until the remainder can be sent also.
         * Otherwise the client will wait forever for the remaining
         * bytes.
         */
        return QB_IPC_SHM;
    }
    return requested;
}

qb_ipcs_service_t *
mainloop_add_ipc_server(const char *name, enum qb_ipc_type type,
                        struct qb_ipcs_service_handlers * callbacks)
{
    int rc = 0;
    qb_ipcs_service_t *server = NULL;

    if (gio_map == NULL) {
        gio_map = qb_array_create_2(64, sizeof(struct gio_to_qb_poll), 1);
    }

    crm_client_init();
    server = qb_ipcs_create(name, 0, pick_ipc_type(type), callbacks);

#ifdef HAVE_IPCS_GET_BUFFER_SIZE
    /* All clients should use at least ipc_buffer_max as their buffer size */
    qb_ipcs_enforce_buffer_size(server, crm_ipc_default_buffer_size());
#endif

    qb_ipcs_poll_handlers_set(server, &gio_poll_funcs);

    rc = qb_ipcs_run(server);
    if (rc < 0) {
        crm_err("Could not start %s IPC server: %s (%d)", name, pcmk_strerror(rc), rc);
        return NULL;
    }

    return server;
}

void
mainloop_del_ipc_server(qb_ipcs_service_t * server)
{
    if (server) {
        qb_ipcs_destroy(server);
    }
}

struct mainloop_io_s {
    char *name;
    void *userdata;

    int fd;
    guint source;
    crm_ipc_t *ipc;
    GIOChannel *channel;

    int (*dispatch_fn_ipc) (const char *buffer, ssize_t length, gpointer userdata);
    int (*dispatch_fn_io) (gpointer userdata);
    void (*destroy_fn) (gpointer userdata);

};

static gboolean
mainloop_gio_callback(GIOChannel * gio, GIOCondition condition, gpointer data)
{
    gboolean keep = TRUE;
    mainloop_io_t *client = data;

    CRM_ASSERT(client->fd == g_io_channel_unix_get_fd(gio));

    if (condition & G_IO_IN) {
        if (client->ipc) {
            long rc = 0;
            int max = 10;

            do {
                rc = crm_ipc_read(client->ipc);
                if (rc <= 0) {
                    crm_trace("Message acquisition from %s[%p] failed: %s (%ld)",
                              client->name, client, pcmk_strerror(rc), rc);

                } else if (client->dispatch_fn_ipc) {
                    const char *buffer = crm_ipc_buffer(client->ipc);

                    crm_trace("New message from %s[%p] = %d", client->name, client, rc, condition);
                    if (client->dispatch_fn_ipc(buffer, rc, client->userdata) < 0) {
                        crm_trace("Connection to %s no longer required", client->name);
                        keep = FALSE;
                    }
                }

            } while (keep && rc > 0 && --max > 0);

        } else {
            crm_trace("New message from %s[%p] %u", client->name, client, condition);
            if (client->dispatch_fn_io) {
                if (client->dispatch_fn_io(client->userdata) < 0) {
                    crm_trace("Connection to %s no longer required", client->name);
                    keep = FALSE;
                }
            }
        }
    }

    if (client->ipc && crm_ipc_connected(client->ipc) == FALSE) {
        crm_err("Connection to %s[%p] closed (I/O condition=%d)", client->name, client, condition);
        keep = FALSE;

    } else if (condition & (G_IO_HUP | G_IO_NVAL | G_IO_ERR)) {
        crm_trace("The connection %s[%p] has been closed (I/O condition=%d)",
                  client->name, client, condition);
        keep = FALSE;

    } else if ((condition & G_IO_IN) == 0) {
        /*
           #define      GLIB_SYSDEF_POLLIN     =1
           #define      GLIB_SYSDEF_POLLPRI    =2
           #define      GLIB_SYSDEF_POLLOUT    =4
           #define      GLIB_SYSDEF_POLLERR    =8
           #define      GLIB_SYSDEF_POLLHUP    =16
           #define      GLIB_SYSDEF_POLLNVAL   =32

           typedef enum
           {
           G_IO_IN      GLIB_SYSDEF_POLLIN,
           G_IO_OUT     GLIB_SYSDEF_POLLOUT,
           G_IO_PRI     GLIB_SYSDEF_POLLPRI,
           G_IO_ERR     GLIB_SYSDEF_POLLERR,
           G_IO_HUP     GLIB_SYSDEF_POLLHUP,
           G_IO_NVAL    GLIB_SYSDEF_POLLNVAL
           } GIOCondition;

           A bitwise combination representing a condition to watch for on an event source.

           G_IO_IN      There is data to read.
           G_IO_OUT     Data can be written (without blocking).
           G_IO_PRI     There is urgent data to read.
           G_IO_ERR     Error condition.
           G_IO_HUP     Hung up (the connection has been broken, usually for pipes and sockets).
           G_IO_NVAL    Invalid request. The file descriptor is not open.
         */
        crm_err("Strange condition: %d", condition);
    }

    /* keep == FALSE results in mainloop_gio_destroy() being called
     * just before the source is removed from mainloop
     */
    return keep;
}

static void
mainloop_gio_destroy(gpointer c)
{
    mainloop_io_t *client = c;
    char *c_name = strdup(client->name);

    /* client->source is valid but about to be destroyed (ref_count == 0) in gmain.c
     * client->channel will still have ref_count > 0... should be == 1
     */
    crm_trace("Destroying client %s[%p]", c_name, c);

    if (client->ipc) {
        crm_ipc_close(client->ipc);
    }

    if (client->destroy_fn) {
        void (*destroy_fn) (gpointer userdata) = client->destroy_fn;

        client->destroy_fn = NULL;
        destroy_fn(client->userdata);
    }

    if (client->ipc) {
        crm_ipc_t *ipc = client->ipc;

        client->ipc = NULL;
        crm_ipc_destroy(ipc);
    }

    crm_trace("Destroyed client %s[%p]", c_name, c);

    free(client->name); client->name = NULL;
    free(client);

    free(c_name);
}

mainloop_io_t *
mainloop_add_ipc_client(const char *name, int priority, size_t max_size, void *userdata,
                        struct ipc_client_callbacks *callbacks)
{
    mainloop_io_t *client = NULL;
    crm_ipc_t *conn = crm_ipc_new(name, max_size);

    if (conn && crm_ipc_connect(conn)) {
        int32_t fd = crm_ipc_get_fd(conn);

        client = mainloop_add_fd(name, priority, fd, userdata, NULL);
        client->ipc = conn;
        client->destroy_fn = callbacks->destroy;
        client->dispatch_fn_ipc = callbacks->dispatch;
    }

    if (conn && client == NULL) {
        crm_trace("Connection to %s failed", name);
        crm_ipc_close(conn);
        crm_ipc_destroy(conn);
    }

    return client;
}

void
mainloop_del_ipc_client(mainloop_io_t * client)
{
    mainloop_del_fd(client);
}

crm_ipc_t *
mainloop_get_ipc_client(mainloop_io_t * client)
{
    if (client) {
        return client->ipc;
    }
    return NULL;
}

mainloop_io_t *
mainloop_add_fd(const char *name, int priority, int fd, void *userdata,
                struct mainloop_fd_callbacks * callbacks)
{
    mainloop_io_t *client = NULL;

    if (fd > 0) {
        client = calloc(1, sizeof(mainloop_io_t));
        client->name = strdup(name);
        client->userdata = userdata;

        if (callbacks) {
            client->destroy_fn = callbacks->destroy;
            client->dispatch_fn_io = callbacks->dispatch;
        }

        client->fd = fd;
        client->channel = g_io_channel_unix_new(fd);
        client->source =
            g_io_add_watch_full(client->channel, priority,
                                (G_IO_IN | G_IO_HUP | G_IO_NVAL | G_IO_ERR), mainloop_gio_callback,
                                client, mainloop_gio_destroy);

        /* Now that mainloop now holds a reference to channel,
         * thanks to g_io_add_watch_full(), drop ours from g_io_channel_unix_new().
         *
         * This means that channel will be free'd by:
         * g_main_context_dispatch() or g_source_remove()
         *  -> g_source_destroy_internal()
         *      -> g_source_callback_unref()
         * shortly after mainloop_gio_destroy() completes
         */
        g_io_channel_unref(client->channel);
        crm_trace("Added connection %d for %s[%p].%d", client->source, client->name, client, fd);
    }

    return client;
}

void
mainloop_del_fd(mainloop_io_t * client)
{
    if (client != NULL) {
        crm_trace("Removing client %s[%p]", client->name, client);
        if (client->source) {
            /* Results in mainloop_gio_destroy() being called just
             * before the source is removed from mainloop
             */
            g_source_remove(client->source);
        }
    }
}

pid_t
mainloop_child_pid(mainloop_child_t * child)
{
    return child->pid;
}

const char *
mainloop_child_name(mainloop_child_t * child)
{
    return child->desc;
}

int
mainloop_child_timeout(mainloop_child_t * child)
{
    return child->timeout;
}

void *
mainloop_child_userdata(mainloop_child_t * child)
{
    return child->privatedata;
}

void
mainloop_clear_child_userdata(mainloop_child_t * child)
{
    child->privatedata = NULL;
}

static gboolean
child_timeout_callback(gpointer p)
{
    mainloop_child_t *child = p;

    child->timerid = 0;
    if (child->timeout) {
        crm_crit("%s process (PID %d) will not die!", child->desc, (int)child->pid);
        return FALSE;
    }

    child->timeout = TRUE;
    crm_warn("%s process (PID %d) timed out", child->desc, (int)child->pid);

    if (kill(child->pid, SIGKILL) < 0) {
        if (errno == ESRCH) {
            /* Nothing left to do */
            return FALSE;
        }
        crm_perror(LOG_ERR, "kill(%d, KILL) failed", child->pid);
    }

    child->timerid = g_timeout_add(5000, child_timeout_callback, child);
    return FALSE;
}

static GListPtr child_list = NULL;

static void
child_death_dispatch(int signal)
{
    GListPtr iter = child_list;

    while(iter) {
        int rc = 0;
        int core = 0;
        int signo = 0;
        int status = 0;
        int exitcode = 0;

        GListPtr saved = NULL;
        mainloop_child_t *child = iter->data;

        rc = waitpid(child->pid, &status, WNOHANG);
        if(rc == 0) {
            iter = iter->next;
            continue;

        } else if(rc != child->pid) {
            signo = signal;
            exitcode = 1;
            status = 1;
            crm_perror(LOG_ERR, "Call to waitpid(%d) failed", child->pid);

        } else {
            crm_trace("Managed process %d exited: %p", child->pid, child);

            if (WIFEXITED(status)) {
                exitcode = WEXITSTATUS(status);
                crm_trace("Managed process %d (%s) exited with rc=%d", child->pid, child->desc, exitcode);

            } else if (WIFSIGNALED(status)) {
                signo = WTERMSIG(status);
                crm_trace("Managed process %d (%s) exited with signal=%d", child->pid, child->desc, signo);
            }
#ifdef WCOREDUMP
            if (WCOREDUMP(status)) {
                core = 1;
                crm_err("Managed process %d (%s) dumped core", child->pid, child->desc);
            }
#endif
        }

        if (child->callback) {
            child->callback(child, child->pid, core, signo, exitcode);
        }

        crm_trace("Removing process entry %p for %d", child, child->pid);

        saved = iter;
        iter = iter->next;

        child_list = g_list_remove_link(child_list, saved);
        g_list_free(saved);

        if (child->timerid != 0) {
            crm_trace("Removing timer %d", child->timerid);
            g_source_remove(child->timerid);
            child->timerid = 0;
        }
        free(child->desc);
        free(child);
    }
}

/* Create/Log a new tracked process
 * To track a process group, use -pid
 */
void
mainloop_child_add(pid_t pid, int timeout, const char *desc, void *privatedata,
                   void (*callback) (mainloop_child_t * p, pid_t pid, int core, int signo, int exitcode))
{
    static bool need_init = TRUE;
    mainloop_child_t *child = g_new(mainloop_child_t, 1);

    child->pid = pid;
    child->timerid = 0;
    child->timeout = FALSE;
    child->privatedata = privatedata;
    child->callback = callback;

    if(desc) {
        child->desc = strdup(desc);
    }

    if (timeout) {
        child->timerid = g_timeout_add(timeout, child_timeout_callback, child);
    }

    child_list = g_list_append(child_list, child);

    if(need_init) {
        need_init = FALSE;

        /* Do NOT use g_child_watch_add() and friends, they rely on pthreads */
        mainloop_add_signal(SIGCHLD, child_death_dispatch);

        /* In case they terminated before the signal handler was installed */
        child_death_dispatch(SIGCHLD);
    }
}


struct mainloop_timer_s {
        guint id;
        guint period_ms;
        bool repeat;
        char *name;
        GSourceFunc cb;
        void *userdata;
};

struct mainloop_timer_s mainloop;

static gboolean mainloop_timer_cb(gpointer user_data)
{
    int id = 0;
    bool repeat = FALSE;
    struct mainloop_timer_s *t = user_data;

    CRM_ASSERT(t != NULL);

    id = t->id;
    t->id = 0; /* Ensure its unset during callbacks so that
                * mainloop_timer_running() works as expected
                */

    if(t->cb) {
        crm_trace("Invoking callbacks for timer %s", t->name);
        repeat = t->repeat;
        if(t->cb(t->userdata) == FALSE) {
            crm_trace("Timer %s complete", t->name);
            repeat = FALSE;
        }
    }

    if(repeat) {
        /* Restore if repeating */
        t->id = id;
    }

    return repeat;
}

bool mainloop_timer_running(mainloop_timer_t *t)
{
    if(t && t->id != 0) {
        return TRUE;
    }
    return FALSE;
}

void mainloop_timer_start(mainloop_timer_t *t)
{
    mainloop_timer_stop(t);
    if(t && t->period_ms > 0) {
        crm_trace("Starting timer %s", t->name);
        t->id = g_timeout_add(t->period_ms, mainloop_timer_cb, t);
    }
}

void mainloop_timer_stop(mainloop_timer_t *t)
{
    if(t && t->id != 0) {
        crm_trace("Stopping timer %s", t->name);
        g_source_remove(t->id);
        t->id = 0;
    }
}

guint mainloop_timer_set_period(mainloop_timer_t *t, guint period_ms)
{
    guint last = 0;

    if(t) {
        last = t->period_ms;
        t->period_ms = period_ms;
    }

    if(t && t->id != 0 && last != t->period_ms) {
        mainloop_timer_start(t);
    }
    return last;
}


mainloop_timer_t *
mainloop_timer_add(const char *name, guint period_ms, bool repeat, GSourceFunc cb, void *userdata)
{
    mainloop_timer_t *t = calloc(1, sizeof(mainloop_timer_t));

    if(t) {
        if(name) {
            t->name = g_strdup_printf("%s-%u-%d", name, period_ms, repeat);
        } else {
            t->name = g_strdup_printf("%p-%u-%d", t, period_ms, repeat);
        }
        t->id = 0;
        t->period_ms = period_ms;
        t->repeat = repeat;
        t->cb = cb;
        t->userdata = userdata;
        crm_trace("Created timer %s with %p %p", t->name, userdata, t->userdata);
    }
    return t;
}

void
mainloop_timer_del(mainloop_timer_t *t)
{
    if(t) {
        crm_trace("Destroying timer %s", t->name);
        mainloop_timer_stop(t);
        free(t->name);
        free(t);
    }
}

