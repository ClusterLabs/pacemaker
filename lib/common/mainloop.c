/*
 * Copyright 2004-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>

#include <sys/wait.h>

#include <crm/crm.h>
#include <crm/common/xml.h>
#include <crm/common/mainloop.h>

#include <qb/qbarray.h>

struct trigger_s {
    GSource source;
    gboolean running;
    gboolean trigger;
    void *user_data;
    guint id;

};

struct mainloop_timer_s {
        guint id;
        guint period_ms;
        bool repeat;
        char *name;
        GSourceFunc cb;
        void *userdata;
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
     * S-O-L and won't be processed until there is something fd-based
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

/*!
 * \internal
 * \brief GSource dispatch function for crm_trigger_t
 *
 * \param[in] source        crm_trigger_t being dispatched
 * \param[in] callback      Callback passed at source creation
 * \param[in,out] userdata  User data passed at source creation
 *
 * \return G_SOURCE_REMOVE to remove source, G_SOURCE_CONTINUE to keep it
 */
static gboolean
crm_trigger_dispatch(GSource *source, GSourceFunc callback, gpointer userdata)
{
    gboolean rc = G_SOURCE_CONTINUE;
    crm_trigger_t *trig = (crm_trigger_t *) source;

    if (trig->running) {
        /* Wait until the existing job is complete before starting the next one */
        return G_SOURCE_CONTINUE;
    }
    trig->trigger = FALSE;

    if (callback) {
        int callback_rc = callback(trig->user_data);

        if (callback_rc < 0) {
            pcmk__trace("Trigger handler %p not yet complete", trig);
            trig->running = TRUE;
        } else if (callback_rc == 0) {
            rc = G_SOURCE_REMOVE;
        }
    }
    return rc;
}

static void
crm_trigger_finalize(GSource * source)
{
    pcmk__trace("Trigger %p destroyed", source);
}

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

    trigger->id = g_source_attach(source, NULL);
    return trigger;
}

void
mainloop_trigger_complete(crm_trigger_t * trig)
{
    pcmk__trace("Trigger handler %p complete", trig);
    trig->running = FALSE;
}

/*!
 * \brief Create a trigger to be used as a mainloop source
 *
 * \param[in] priority  Relative priority of source (lower number is higher priority)
 * \param[in] dispatch  Trigger dispatch function (should return 0 to remove the
 *                      trigger from the mainloop, -1 if the trigger should be
 *                      kept but the job is still running and not complete, and
 *                      1 if the trigger should be kept and the job is complete)
 * \param[in] userdata  Pointer to pass to \p dispatch
 *
 * \return Newly allocated mainloop source for trigger
 */
crm_trigger_t *
mainloop_add_trigger(int priority, int (*dispatch) (gpointer user_data),
                     gpointer userdata)
{
    GSource *source = NULL;

    pcmk__assert(sizeof(crm_trigger_t) > sizeof(GSource));
    source = g_source_new(&crm_trigger_funcs, sizeof(crm_trigger_t));

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

// Define a custom glib source for signal handling

// Data structure for custom glib source
typedef struct {
    crm_trigger_t trigger;      // trigger that invoked source (must be first)
    void (*handler) (int sig);  // signal handler
    int signal;                 // signal that was received
} crm_signal_t;

// Table to associate signal handlers with signal numbers
static crm_signal_t *crm_signals[NSIG];

/*!
 * \internal
 * \brief Dispatch an event from custom glib source for signals
 *
 * Given an signal event, clear the event trigger and call any registered
 * signal handler.
 *
 * \param[in] source    glib source that triggered this dispatch
 * \param[in] callback  (ignored)
 * \param[in] userdata  (ignored)
 */
static gboolean
crm_signal_dispatch(GSource *source, GSourceFunc callback, gpointer userdata)
{
    crm_signal_t *sig = (crm_signal_t *) source;

    if(sig->signal != SIGCHLD) {
        pcmk__notice("Caught '%s' signal " QB_XS " %d (%s handler)",
                     strsignal(sig->signal), sig->signal,
                     ((sig->handler != NULL)? "invoking" : "no"));
    }

    sig->trigger.trigger = FALSE;
    if (sig->handler) {
        sig->handler(sig->signal);
    }
    return TRUE;
}

/*!
 * \internal
 * \brief Handle a signal by setting a trigger for signal source
 *
 * \param[in] sig  Signal number that was received
 *
 * \note This is the true signal handler for the mainloop signal source, and
 *       must be async-safe.
 */
static void
mainloop_signal_handler(int sig)
{
    if (sig > 0 && sig < NSIG && crm_signals[sig] != NULL) {
        mainloop_set_trigger((crm_trigger_t *) crm_signals[sig]);
    }
}

// Functions implementing our custom glib source for signal handling
static GSourceFuncs crm_signal_funcs = {
    crm_trigger_prepare,
    crm_trigger_check,
    crm_signal_dispatch,
    crm_trigger_finalize,
};

/*!
 * \internal
 * \brief Set a true signal handler
 *
 * signal()-like interface to sigaction()
 *
 * \param[in] sig       Signal number to register handler for
 * \param[in] dispatch  Signal handler
 *
 * \return The previous value of the signal handler, or SIG_ERR on error
 * \note The dispatch function must be async-safe.
 */
sighandler_t
crm_signal_handler(int sig, sighandler_t dispatch)
{
    sigset_t mask;
    struct sigaction sa;
    struct sigaction old;

    if (sigemptyset(&mask) < 0) {
        pcmk__err("Could not %sset handler for signal %d: %s",
                  ((dispatch == NULL)? "un" : ""), sig, strerror(errno));
        return SIG_ERR;
    }

    memset(&sa, 0, sizeof(struct sigaction));
    sa.sa_handler = dispatch;
    sa.sa_flags = SA_RESTART;
    sa.sa_mask = mask;

    if (sigaction(sig, &sa, &old) < 0) {
        pcmk__err("Could not %sset handler for signal %d: %s",
                  ((dispatch == NULL)? "un" : ""), sig, strerror(errno));
        return SIG_ERR;
    }
    return old.sa_handler;
}

static void
mainloop_destroy_signal_entry(int sig)
{
    crm_signal_t *tmp = crm_signals[sig];

    if (tmp != NULL) {
        crm_signals[sig] = NULL;
        pcmk__trace("Unregistering mainloop handler for signal %d", sig);
        mainloop_destroy_trigger((crm_trigger_t *) tmp);
    }
}

/*!
 * \internal
 * \brief Add a signal handler to a mainloop
 *
 * \param[in] sig       Signal number to handle
 * \param[in] dispatch  Signal handler function (\c NULL to ignore the signal)
 *
 * \note The true signal handler merely sets a mainloop trigger to call this
 *       dispatch function via the mainloop. Therefore, the dispatch function
 *       does not need to be async-safe.
 */
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
        pcmk__err("Signal %d is out of range", sig);
        return FALSE;

    } else if (crm_signals[sig] != NULL && crm_signals[sig]->handler == dispatch) {
        pcmk__trace("Signal handler for %d is already installed", sig);
        return TRUE;

    } else if (crm_signals[sig] != NULL) {
        pcmk__err("Different signal handler for %d is already installed", sig);
        return FALSE;
    }

    pcmk__assert(sizeof(crm_signal_t) > sizeof(GSource));
    source = g_source_new(&crm_signal_funcs, sizeof(crm_signal_t));

    crm_signals[sig] = (crm_signal_t *) mainloop_setup_trigger(source, priority, NULL, NULL);
    pcmk__assert(crm_signals[sig] != NULL);

    crm_signals[sig]->handler = dispatch;
    crm_signals[sig]->signal = sig;

    if (crm_signal_handler(sig, mainloop_signal_handler) == SIG_ERR) {
        mainloop_destroy_signal_entry(sig);
        return FALSE;
    }

    return TRUE;
}

gboolean
mainloop_destroy_signal(int sig)
{
    if (sig >= NSIG || sig < 0) {
        pcmk__err("Signal %d is out of range", sig);
        return FALSE;

    } else if (crm_signal_handler(sig, NULL) == SIG_ERR) {
        // Error already logged
        return FALSE;

    } else if (crm_signals[sig] == NULL) {
        return TRUE;
    }
    mainloop_destroy_signal_entry(sig);
    return TRUE;
}

static qb_array_t *gio_map = NULL;

void
mainloop_cleanup(void) 
{
    if (gio_map != NULL) {
        qb_array_free(gio_map);
        gio_map = NULL;
    }

    for (int sig = 0; sig < NSIG; ++sig) {
        mainloop_destroy_signal_entry(sig);
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

    pcmk__trace("%p.%d %d", data, fd, condition);

    /* if this assert get's hit, then there is a race condition between
     * when we destroy a fd and when mainloop actually gives it up */
    pcmk__assert(adaptor->is_used > 0);

    return (adaptor->fn(fd, condition, adaptor->data) == 0);
}

static void
gio_poll_destroy(gpointer data)
{
    struct gio_to_qb_poll *adaptor = (struct gio_to_qb_poll *)data;

    adaptor->is_used--;
    pcmk__assert(adaptor->is_used >= 0);

    if (adaptor->is_used == 0) {
        pcmk__trace("Marking adaptor %p unused", adaptor);
        adaptor->source = 0;
    }
}

/*!
 * \internal
 * \brief Convert libqb's poll priority into GLib's one
 *
 * \param[in] prio  libqb's poll priority (#QB_LOOP_MED assumed as fallback)
 *
 * \return  best matching GLib's priority
 */
static gint
conv_prio_libqb2glib(enum qb_loop_priority prio)
{
    switch (prio) {
        case QB_LOOP_LOW:   return G_PRIORITY_LOW;
        case QB_LOOP_HIGH:  return G_PRIORITY_HIGH;
        default:            return G_PRIORITY_DEFAULT; // QB_LOOP_MED
    }
}

/*!
 * \internal
 * \brief Convert libqb's poll priority to rate limiting spec
 *
 * \param[in] prio  libqb's poll priority (#QB_LOOP_MED assumed as fallback)
 *
 * \return  best matching rate limiting spec
 * \note This is the inverse of libqb's qb_ipcs_request_rate_limit().
 */
static enum qb_ipcs_rate_limit
conv_libqb_prio2ratelimit(enum qb_loop_priority prio)
{
    switch (prio) {
        case QB_LOOP_LOW:   return QB_IPCS_RATE_SLOW;
        case QB_LOOP_HIGH:  return QB_IPCS_RATE_FAST;
        default:            return QB_IPCS_RATE_NORMAL; // QB_LOOP_MED
    }
}

static int32_t
gio_poll_dispatch_update(enum qb_loop_priority p, int32_t fd, int32_t evts,
                         void *data, qb_ipcs_dispatch_fn_t fn, int32_t add)
{
    struct gio_to_qb_poll *adaptor;
    GIOChannel *channel;
    int32_t res = 0;

    res = qb_array_index(gio_map, fd, (void **)&adaptor);
    if (res < 0) {
        pcmk__err("Array lookup failed for fd=%d: %d", fd, res);
        return res;
    }

    pcmk__trace("Adding fd=%d to mainloop as adaptor %p", fd, adaptor);

    if (add && adaptor->source) {
        pcmk__err("Adaptor for descriptor %d is still in-use", fd);
        return -EEXIST;
    }
    if (!add && !adaptor->is_used) {
        pcmk__err("Adaptor for descriptor %d is not in-use", fd);
        return -ENOENT;
    }

    /* channel is created with ref_count = 1 */
    channel = g_io_channel_unix_new(fd);
    if (!channel) {
        pcmk__err("No memory left to add fd=%d", fd);
        return -ENOMEM;
    }

    if (adaptor->source) {
        g_source_remove(adaptor->source);
        adaptor->source = 0;
    }

    /* Because unlike the poll() API, glib doesn't tell us about HUPs by default */
    evts |= (G_IO_HUP | G_IO_NVAL | G_IO_ERR);

    adaptor->fn = fn;
    adaptor->events = evts;
    adaptor->data = data;
    adaptor->p = p;
    adaptor->is_used++;
    adaptor->source =
        g_io_add_watch_full(channel, conv_prio_libqb2glib(p), evts,
                            gio_read_socket, adaptor, gio_poll_destroy);

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

    pcmk__trace("Added to mainloop with gsource id=%d", adaptor->source);
    if (adaptor->source > 0) {
        return 0;
    }

    return -EINVAL;
}

static int32_t
gio_poll_dispatch_add(enum qb_loop_priority p, int32_t fd, int32_t evts,
                      void *data, qb_ipcs_dispatch_fn_t fn)
{
    return gio_poll_dispatch_update(p, fd, evts, data, fn, QB_TRUE);
}

static int32_t
gio_poll_dispatch_mod(enum qb_loop_priority p, int32_t fd, int32_t evts,
                      void *data, qb_ipcs_dispatch_fn_t fn)
{
    return gio_poll_dispatch_update(p, fd, evts, data, fn, QB_FALSE);
}

static int32_t
gio_poll_dispatch_del(int32_t fd)
{
    struct gio_to_qb_poll *adaptor;

    pcmk__trace("Looking for fd=%d", fd);
    if (qb_array_index(gio_map, fd, (void **)&adaptor) == 0) {
        if (adaptor->source) {
            g_source_remove(adaptor->source);
            adaptor->source = 0;
        }
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
    const char *env = pcmk__env_option(PCMK__ENV_IPC_TYPE);

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
                        struct qb_ipcs_service_handlers *callbacks)
{
    return mainloop_add_ipc_server_with_prio(name, type, callbacks, QB_LOOP_MED);
}

qb_ipcs_service_t *
mainloop_add_ipc_server_with_prio(const char *name, enum qb_ipc_type type,
                                  struct qb_ipcs_service_handlers *callbacks,
                                  enum qb_loop_priority prio)
{
    int rc = 0;
    qb_ipcs_service_t *server = NULL;

    if (gio_map == NULL) {
        gio_map = qb_array_create_2(64, sizeof(struct gio_to_qb_poll), 1);
    }

    server = qb_ipcs_create(name, 0, pick_ipc_type(type), callbacks);

    if (server == NULL) {
        pcmk__err("Could not create %s IPC server: %s (%d)", name,
                  pcmk_rc_str(errno), errno);
        return NULL;
    }

    if (prio != QB_LOOP_MED) {
        qb_ipcs_request_rate_limit(server, conv_libqb_prio2ratelimit(prio));
    }

    // Enforce a minimum IPC buffer size on all clients
    qb_ipcs_enforce_buffer_size(server, crm_ipc_default_buffer_size());
    qb_ipcs_poll_handlers_set(server, &gio_poll_funcs);

    rc = qb_ipcs_run(server);
    if (rc < 0) {
        pcmk__err("Could not start %s IPC server: %s (%d)", name,
                  pcmk_strerror(rc), rc);
        return NULL; // qb_ipcs_run() destroys server on failure
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

/*!
 * \internal
 * \brief I/O watch callback function (GIOFunc)
 *
 * \param[in] gio        I/O channel being watched
 * \param[in] condition  I/O condition satisfied
 * \param[in] data       User data passed when source was created
 *
 * \return G_SOURCE_REMOVE to remove source, G_SOURCE_CONTINUE to keep it
 */
static gboolean
mainloop_gio_callback(GIOChannel *gio, GIOCondition condition, gpointer data)
{
    gboolean rc = G_SOURCE_CONTINUE;
    mainloop_io_t *client = data;

    pcmk__assert(client->fd == g_io_channel_unix_get_fd(gio));

    if (condition & G_IO_IN) {
        if (client->ipc) {
            long read_rc = 0L;
            int max = 10;

            do {
                read_rc = crm_ipc_read(client->ipc);
                if (read_rc <= 0) {
                    pcmk__trace("Could not read IPC message from %s: %s (%ld)",
                                client->name, pcmk_strerror(read_rc), read_rc);

                    if (read_rc == -EAGAIN) {
                        continue;
                    }

                } else if (client->dispatch_fn_ipc) {
                    const char *buffer = crm_ipc_buffer(client->ipc);

                    pcmk__trace("New %ld-byte IPC message from %s after I/O "
                                "condition %d",
                                read_rc, client->name, (int) condition);
                    if (client->dispatch_fn_ipc(buffer, read_rc, client->userdata) < 0) {
                        pcmk__trace("Connection to %s no longer required",
                                    client->name);
                        rc = G_SOURCE_REMOVE;
                    }
                }

                pcmk__ipc_free_client_buffer(client->ipc);

            } while ((rc == G_SOURCE_CONTINUE) && (--max > 0)
                      && ((read_rc > 0) || (read_rc == -EAGAIN)));

        } else {
            pcmk__trace("New I/O event for %s after I/O condition %d",
                        client->name, (int) condition);
            if (client->dispatch_fn_io) {
                if (client->dispatch_fn_io(client->userdata) < 0) {
                    pcmk__trace("Connection to %s no longer required",
                                client->name);
                    rc = G_SOURCE_REMOVE;
                }
            }
        }
    }

    if (client->ipc && !crm_ipc_connected(client->ipc)) {
        pcmk__err("Connection to %s closed " QB_XS " client=%p condition=%d",
                  client->name, client, condition);
        rc = G_SOURCE_REMOVE;

    } else if (condition & (G_IO_HUP | G_IO_NVAL | G_IO_ERR)) {
        pcmk__trace("The connection %s[%p] has been closed (I/O condition=%d)",
                    client->name, client, condition);
        rc = G_SOURCE_REMOVE;

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
        pcmk__err("Strange condition: %d", condition);
    }

    /* G_SOURCE_REMOVE results in mainloop_gio_destroy() being called
     * just before the source is removed from mainloop
     */
    return rc;
}

static void
mainloop_gio_destroy(gpointer c)
{
    mainloop_io_t *client = c;
    char *c_name = strdup(client->name);

    /* client->source is valid but about to be destroyed (ref_count == 0) in gmain.c
     * client->channel will still have ref_count > 0... should be == 1
     */
    pcmk__trace("Destroying client %s[%p]", c_name, c);

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

    pcmk__trace("Destroyed client %s[%p]", c_name, c);

    free(client->name); client->name = NULL;
    free(client);

    free(c_name);
}

/*!
 * \brief Connect to IPC and add it as a main loop source
 *
 * \param[in,out] ipc        IPC connection to add
 * \param[in]     priority   Event source priority to use for connection
 * \param[in]     userdata   Data to register with callbacks
 * \param[in]     callbacks  Dispatch and destroy callbacks for connection
 * \param[out]    source     Newly allocated event source
 *
 * \return Standard Pacemaker return code
 *
 * \note On failure, the caller is still responsible for ipc. On success, the
 *       caller should call mainloop_del_ipc_client() when source is no longer
 *       needed, which will lead to the disconnection of the IPC later in the
 *       main loop if it is connected. However the IPC disconnects,
 *       mainloop_gio_destroy() will free ipc and source after calling the
 *       destroy callback.
 */
int
pcmk__add_mainloop_ipc(crm_ipc_t *ipc, int priority, void *userdata,
                       const struct ipc_client_callbacks *callbacks,
                       mainloop_io_t **source)
{
    int rc = pcmk_rc_ok;
    int fd = -1;
    const char *ipc_name = NULL;

    CRM_CHECK((ipc != NULL) && (callbacks != NULL), return EINVAL);

    ipc_name = pcmk__s(crm_ipc_name(ipc), "Pacemaker");
    rc = pcmk__connect_generic_ipc(ipc);
    if (rc != pcmk_rc_ok) {
        pcmk__debug("Connection to %s failed: %s", ipc_name, pcmk_rc_str(rc));
        return rc;
    }

    rc = pcmk__ipc_fd(ipc, &fd);
    if (rc != pcmk_rc_ok) {
        pcmk__debug("Could not obtain file descriptor for %s IPC: %s", ipc_name,
                    pcmk_rc_str(rc));
        crm_ipc_close(ipc);
        return rc;
    }

    *source = mainloop_add_fd(ipc_name, priority, fd, userdata, NULL);
    if (*source == NULL) {
        rc = errno;
        crm_ipc_close(ipc);
        return rc;
    }

    (*source)->ipc = ipc;
    (*source)->destroy_fn = callbacks->destroy;
    (*source)->dispatch_fn_ipc = callbacks->dispatch;
    return pcmk_rc_ok;
}

/*!
 * \brief Get period for mainloop timer
 *
 * \param[in]  timer      Timer
 *
 * \return Period in ms
 */
guint
pcmk__mainloop_timer_get_period(const mainloop_timer_t *timer)
{
    if (timer) {
        return timer->period_ms;
    }
    return 0;
}

mainloop_io_t *
mainloop_add_ipc_client(const char *name, int priority, size_t max_size,
                        void *userdata, struct ipc_client_callbacks *callbacks)
{
    crm_ipc_t *ipc = crm_ipc_new(name, 0);
    mainloop_io_t *source = NULL;
    int rc = pcmk__add_mainloop_ipc(ipc, priority, userdata, callbacks,
                                    &source);

    if (rc != pcmk_rc_ok) {
        if (crm_log_level == PCMK__LOG_STDOUT) {
            fprintf(stderr, "Connection to %s failed: %s",
                    name, pcmk_rc_str(rc));
        }
        crm_ipc_destroy(ipc);
        if (rc > 0) {
            errno = rc;
        } else {
            errno = ENOTCONN;
        }
        return NULL;
    }
    return source;
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

    if (fd >= 0) {
        client = calloc(1, sizeof(mainloop_io_t));
        if (client == NULL) {
            return NULL;
        }
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
        pcmk__trace("Added connection %d for %s[%p].%d", client->source,
                    client->name, client, fd);
    } else {
        errno = EINVAL;
    }

    return client;
}

void
mainloop_del_fd(mainloop_io_t *client)
{
    if ((client == NULL) || (client->source == 0)) {
        return;
    }

    pcmk__trace("Removing client %s[%p]", client->name, client);

    // mainloop_gio_destroy() gets called during source removal
    g_source_remove(client->source);
}

static GList *child_list = NULL;

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

/* good function name */
static void
child_free(mainloop_child_t *child)
{
    if (child->timerid != 0) {
        pcmk__trace("Removing timer %d", child->timerid);
        g_source_remove(child->timerid);
        child->timerid = 0;
    }
    free(child->desc);
    free(child);
}

/* terrible function name */
static int
child_kill_helper(mainloop_child_t *child)
{
    int rc;
    if (child->flags & mainloop_leave_pid_group) {
        pcmk__debug("Killing PID %lld only. Leaving its process group intact.",
                    (long long) child->pid);
        rc = kill(child->pid, SIGKILL);
    } else {
        pcmk__debug("Killing PID %lld's entire process group",
                    (long long) child->pid);
        rc = kill(-child->pid, SIGKILL);
    }

    if (rc < 0) {
        if (errno != ESRCH) {
            pcmk__err("kill(%d, KILL) failed: %s", child->pid, strerror(errno));
        }
        return -errno;
    }
    return 0;
}

static gboolean
child_timeout_callback(gpointer p)
{
    mainloop_child_t *child = p;
    int rc = 0;

    child->timerid = 0;
    if (child->timeout) {
        pcmk__warn("%s process (PID %lld) will not die!", child->desc,
                   (long long) child->pid);
        return FALSE;
    }

    rc = child_kill_helper(child);
    if (rc == -ESRCH) {
        /* Nothing left to do. pid doesn't exist */
        return FALSE;
    }

    child->timeout = TRUE;
    pcmk__debug("%s process (PID %lld) timed out", child->desc,
                (long long) child->pid);

    child->timerid = pcmk__create_timer(5000, child_timeout_callback, child);
    return FALSE;
}

static bool
child_waitpid(mainloop_child_t *child, int flags)
{
    int rc = 0;
    int core = 0;
    int signo = 0;
    int status = 0;
    int exitcode = 0;
    bool callback_needed = true;

    rc = waitpid(child->pid, &status, flags);
    if (rc == 0) { // WNOHANG in flags, and child status is not available
        pcmk__trace("Child process %lld (%s) still active",
                    (long long) child->pid, child->desc);
        callback_needed = false;

    } else if (rc != child->pid) {
        /* According to POSIX, possible conditions:
         * - child->pid was non-positive (process group or any child),
         *   and rc is specific child
         * - errno ECHILD (pid does not exist or is not child)
         * - errno EINVAL (invalid flags)
         * - errno EINTR (caller interrupted by signal)
         *
         * @TODO Handle these cases more specifically.
         */
        signo = SIGCHLD;
        exitcode = 1;
        pcmk__notice("Wait for child process %d (%s) interrupted: %s",
                     child->pid, child->desc, pcmk_rc_str(errno));

    } else if (WIFEXITED(status)) {
        exitcode = WEXITSTATUS(status);
        pcmk__trace("Child process %lld (%s) exited with status %d",
                    (long long) child->pid, child->desc, exitcode);

    } else if (WIFSIGNALED(status)) {
        signo = WTERMSIG(status);
        pcmk__trace("Child process %lld (%s) exited with signal %d (%s)",
                    (long long) child->pid, child->desc, signo,
                    strsignal(signo));

#ifdef WCOREDUMP // AIX, SunOS, maybe others
    } else if (WCOREDUMP(status)) {
        core = 1;
        pcmk__err("Child process %d (%s) dumped core", child->pid, child->desc);
#endif

    } else { // flags must contain WUNTRACED and/or WCONTINUED to reach this
        pcmk__trace("Child process %lld (%s) stopped or continued",
                    (long long) child->pid, child->desc);
        callback_needed = false;
    }

    if (callback_needed && child->exit_fn) {
        child->exit_fn(child, core, signo, exitcode);
    }
    return callback_needed;
}

static void
child_death_dispatch(int signal)
{
    for (GList *iter = child_list; iter; ) {
        GList *saved = iter;
        mainloop_child_t *child = iter->data;

        iter = iter->next;
        if (child_waitpid(child, WNOHANG)) {
            pcmk__trace("Removing completed process %lld from child list",
                        (long long) child->pid);
            child_list = g_list_remove_link(child_list, saved);
            g_list_free(saved);
            child_free(child);
        }
    }
}

static gboolean
child_signal_init(gpointer p)
{
    pcmk__trace("Installed SIGCHLD handler");
    /* Do NOT use g_child_watch_add() and friends, they rely on pthreads */
    mainloop_add_signal(SIGCHLD, child_death_dispatch);

    /* In case they terminated before the signal handler was installed */
    child_death_dispatch(SIGCHLD);
    return FALSE;
}

gboolean
mainloop_child_kill(pid_t pid)
{
    GList *iter;
    mainloop_child_t *child = NULL;
    mainloop_child_t *match = NULL;
    /* It is impossible to block SIGKILL, this allows us to
     * call waitpid without WNOHANG flag.*/
    int waitflags = 0, rc = 0;

    for (iter = child_list; iter != NULL && match == NULL; iter = iter->next) {
        child = iter->data;
        if (pid == child->pid) {
            match = child;
        }
    }

    if (match == NULL) {
        return FALSE;
    }

    rc = child_kill_helper(match);
    if(rc == -ESRCH) {
        /* It's gone, but hasn't shown up in waitpid() yet. Wait until we get
         * SIGCHLD and let handler clean it up as normal (so we get the correct
         * return code/status). The blocking alternative would be to call
         * child_waitpid(match, 0).
         */
        pcmk__trace("Waiting for signal that child process %lld completed",
                    (long long) match->pid);
        return TRUE;

    } else if(rc != 0) {
        /* If KILL for some other reason set the WNOHANG flag since we
         * can't be certain what happened.
         */
        waitflags = WNOHANG;
    }

    if (!child_waitpid(match, waitflags)) {
        /* not much we can do if this occurs */
        return FALSE;
    }

    child_list = g_list_remove(child_list, match);
    child_free(match);
    return TRUE;
}

/* Create/Log a new tracked process
 * To track a process group, use -pid
 *
 * @TODO Using a non-positive pid (i.e. any child, or process group) would
 *       likely not be useful since we will free the child after the first
 *       completed process.
 */
void
mainloop_child_add_with_flags(pid_t pid, int timeout, const char *desc,
                              void *privatedata,
                              enum mainloop_child_flags flags,
                              pcmk__mainloop_child_exit_fn_t exit_fn)
{
    static bool need_init = TRUE;
    mainloop_child_t *child = pcmk__assert_alloc(1, sizeof(mainloop_child_t));

    child->pid = pid;
    child->timerid = 0;
    child->timeout = FALSE;
    child->privatedata = privatedata;
    child->exit_fn = exit_fn;
    child->flags = flags;
    child->desc = pcmk__str_copy(desc);

    if (timeout) {
        child->timerid = pcmk__create_timer(timeout, child_timeout_callback, child);
    }

    child_list = g_list_append(child_list, child);

    if(need_init) {
        need_init = FALSE;
        /* SIGCHLD processing has to be invoked from mainloop.
         * We do not want it to be possible to both add a child pid
         * to mainloop, and have the pid's exit callback invoked within
         * the same callstack. */
        pcmk__create_timer(1, child_signal_init, NULL);
    }
}

void
mainloop_child_add(pid_t pid, int timeout, const char *desc, void *privatedata,
                   pcmk__mainloop_child_exit_fn_t exit_fn)
{
    mainloop_child_add_with_flags(pid, timeout, desc, privatedata, 0, exit_fn);
}

static gboolean
mainloop_timer_cb(gpointer user_data)
{
    int id = 0;
    bool repeat = FALSE;
    struct mainloop_timer_s *t = user_data;

    pcmk__assert(t != NULL);

    id = t->id;
    t->id = 0; /* Ensure it's unset during callbacks so that
                * mainloop_timer_running() works as expected
                */

    if(t->cb) {
        pcmk__trace("Invoking callbacks for timer %s", t->name);
        repeat = t->repeat;
        if(t->cb(t->userdata) == FALSE) {
            pcmk__trace("Timer %s complete", t->name);
            repeat = FALSE;
        }
    }

    if(repeat) {
        /* Restore if repeating */
        t->id = id;
    }

    return repeat;
}

bool
mainloop_timer_running(mainloop_timer_t *t)
{
    if(t && t->id != 0) {
        return TRUE;
    }
    return FALSE;
}

void
mainloop_timer_start(mainloop_timer_t *t)
{
    mainloop_timer_stop(t);
    if(t && t->period_ms > 0) {
        pcmk__trace("Starting timer %s", t->name);
        t->id = pcmk__create_timer(t->period_ms, mainloop_timer_cb, t);
    }
}

void
mainloop_timer_stop(mainloop_timer_t *t)
{
    if(t && t->id != 0) {
        pcmk__trace("Stopping timer %s", t->name);
        g_source_remove(t->id);
        t->id = 0;
    }
}

guint
mainloop_timer_set_period(mainloop_timer_t *t, guint period_ms)
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
    mainloop_timer_t *t = pcmk__assert_alloc(1, sizeof(mainloop_timer_t));

    if (name != NULL) {
        t->name = pcmk__assert_asprintf("%s-%u-%d", name, period_ms, repeat);
    } else {
        t->name = pcmk__assert_asprintf("%p-%u-%d", t, period_ms, repeat);
    }
    t->id = 0;
    t->period_ms = period_ms;
    t->repeat = repeat;
    t->cb = cb;
    t->userdata = userdata;
    pcmk__trace("Created timer %s with %p %p", t->name, userdata, t->userdata);
    return t;
}

void
mainloop_timer_del(mainloop_timer_t *t)
{
    if(t) {
        pcmk__trace("Destroying timer %s", t->name);
        mainloop_timer_stop(t);
        free(t->name);
        free(t);
    }
}

/*
 * Helpers to make sure certain events aren't lost at shutdown
 */

static gboolean
drain_timeout_cb(gpointer user_data)
{
    bool *timeout_popped = (bool*) user_data;

    *timeout_popped = TRUE;
    return FALSE;
}

/*!
 * \brief Drain some remaining main loop events then quit it
 *
 * \param[in,out] mloop  Main loop to drain and quit
 * \param[in]     n      Drain up to this many pending events
 */
void
pcmk_quit_main_loop(GMainLoop *mloop, unsigned int n)
{
    if ((mloop != NULL) && g_main_loop_is_running(mloop)) {
        GMainContext *ctx = g_main_loop_get_context(mloop);

        /* Drain up to n events in case some memory clean-up is pending
         * (helpful to reduce noise in valgrind output).
         */
        for (int i = 0; (i < n) && g_main_context_pending(ctx); ++i) {
            g_main_context_dispatch(ctx);
        }
        g_main_loop_quit(mloop);
    }
}

/*!
 * \brief Process main loop events while a certain condition is met
 *
 * \param[in,out] mloop     Main loop to process
 * \param[in]     timer_ms  Don't process longer than this amount of time
 * \param[in]     check     Function that returns true if events should be
 *                          processed
 *
 * \note This function is intended to be called at shutdown if certain important
 *       events should not be missed. The caller would likely quit the main loop
 *       or exit after calling this function. The check() function will be
 *       passed the remaining timeout in milliseconds.
 */
void
pcmk_drain_main_loop(GMainLoop *mloop, guint timer_ms, bool (*check)(guint))
{
    bool timeout_popped = FALSE;
    guint timer = 0;
    GMainContext *ctx = NULL;

    CRM_CHECK(mloop && check, return);

    ctx = g_main_loop_get_context(mloop);
    if (ctx) {
        time_t start_time = time(NULL);

        timer = pcmk__create_timer(timer_ms, drain_timeout_cb, &timeout_popped);
        while (!timeout_popped
               && check(timer_ms - (time(NULL) - start_time) * 1000)) {
            g_main_context_iteration(ctx, TRUE);
        }
    }
    if (!timeout_popped && (timer > 0)) {
        g_source_remove(timer);
    }
}
