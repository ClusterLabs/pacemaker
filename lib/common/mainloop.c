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
    bool running;
    bool trigger;
    void *user_data;
    unsigned int id;
};

static GList *child_list = NULL;
static qb_array_t *gio_map = NULL;

static gboolean
crm_trigger_prepare(GSource *source, int *timeout)
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
crm_trigger_dispatch(GSource *source, GSourceFunc callback, void *userdata)
{
    gboolean rc = G_SOURCE_CONTINUE;
    crm_trigger_t *trig = (crm_trigger_t *) source;

    if (trig->running) {
        /* Wait until the existing job is complete before starting the next one */
        return G_SOURCE_CONTINUE;
    }
    trig->trigger = false;

    if (callback) {
        int callback_rc = callback(trig->user_data);

        if (callback_rc < 0) {
            pcmk__trace("Trigger handler %p not yet complete", trig);
            trig->running = true;
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
mainloop_setup_trigger(GSource * source, int priority,
                       int (*dispatch)(void *user_data), void *userdata)
{
    crm_trigger_t *trigger = NULL;

    trigger = (crm_trigger_t *) source;

    trigger->id = 0;
    trigger->trigger = false;
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
    trig->running = false;
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
mainloop_add_trigger(int priority, int (*dispatch) (void *user_data),
                     void *userdata)
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
        source->trigger = true;
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
crm_signal_dispatch(GSource *source, GSourceFunc callback, void *userdata)
{
    crm_signal_t *sig = (crm_signal_t *) source;

    if(sig->signal != SIGCHLD) {
        pcmk__notice("Caught '%s' signal " QB_XS " %d (%s handler)",
                     strsignal(sig->signal), sig->signal,
                     ((sig->handler != NULL)? "invoking" : "no"));
    }

    sig->trigger.trigger = false;
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
 * \note The added signal handler gets freed by \c mainloop_cleanup() if it is
 *       not freed manually using \c mainloop_destroy_signal().
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

/*
 * libqb...
 */
struct gio_to_qb_poll {
    int32_t is_used;
    unsigned int source;
    int32_t events;
    void *data;
    qb_ipcs_dispatch_fn_t fn;
    enum qb_loop_priority p;
};

static gboolean
gio_read_socket(GIOChannel * gio, GIOCondition condition, void *data)
{
    struct gio_to_qb_poll *adaptor = (struct gio_to_qb_poll *)data;
    int fd = g_io_channel_unix_get_fd(gio);

    pcmk__trace("%p.%d %d", data, fd, condition);

    /* if this assert get's hit, then there is a race condition between
     * when we destroy a fd and when mainloop actually gives it up */
    pcmk__assert(adaptor->is_used > 0);

    return (adaptor->fn(fd, condition, adaptor->data) == 0);
}

static void
gio_poll_destroy(void *data)
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
static int
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

    server = qb_ipcs_create(name, 0, QB_IPC_SHM, callbacks);

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
mainloop_gio_callback(GIOChannel *gio, GIOCondition condition, void *data)
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
mainloop_gio_destroy(void *c)
{
    mainloop_io_t *client = c;

    /* client->source is valid but about to be destroyed (ref_count == 0) in
     * gmain.c. client->channel will still have ref_count > 0 (should be == 1).
     */
    pcmk__trace("Destroying client %s[%p]", client->name, client);

    // @TODO Would it be safe to call this immediately before crm_ipc_destroy()?
    crm_ipc_close(client->ipc);

    if (client->destroy_fn != NULL) {
        client->destroy_fn(client->userdata);
    }

    crm_ipc_destroy(client->ipc);

    pcmk__trace("Destroyed client %s[%p]", client->name, client);

    /* This is the destructor corresponding to mainloop_add_fd(). There,
     * g_io_channel_unix_new() created client->channel and added a reference to
     * it, so we drop a reference here. The channel will be freed when the
     * reference count drops to zero.
     */
    g_io_channel_unref(client->channel);

    free(client->name);
    free(client);
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
    const GIOCondition condition = G_IO_IN|G_IO_HUP|G_IO_NVAL|G_IO_ERR;

    if (fd < 0) {
        errno = EINVAL;
        return NULL;
    }

    client = pcmk__assert_alloc(1, sizeof(mainloop_io_t));
    client->name = pcmk__str_copy(name);
    client->userdata = userdata;

    if (callbacks != NULL) {
        client->destroy_fn = callbacks->destroy;
        client->dispatch_fn_io = callbacks->dispatch;
    }

    client->fd = fd;
    client->channel = g_io_channel_unix_new(fd);
    client->source = g_io_add_watch_full(client->channel, priority, condition,
                                         mainloop_gio_callback, client,
                                         mainloop_gio_destroy);

    pcmk__trace("Added connection %d for %s[%p].%d", client->source,
                client->name, client, fd);
    return client;
}

void
mainloop_del_fd(mainloop_io_t *client)
{
    if ((client == NULL) || (client->source == 0)) {
        return;
    }

    pcmk__trace("Removing client %s[%p]", client->name, client);

    /* g_source_remove() marks the source as destroyed, unsets the source
     * callback (mainloop_gio_callback()), and destroys the callback data (the
     * client) via the notify function (mainloop_gio_destroy()). We can rely on
     * mainloop_gio_callback() not getting called again for this source, and on
     * the client being destroyed.
     */
    g_source_remove(client->source);
}

/*!
 * \internal
 * \brief Send \c SIGKILL to a main loop child process or its process group
 *
 * If \p child->kill_group is set, kill the child's entire process group.
 * Otherwise, kill only the child process itself.
 *
 * \param[in] child  Main loop child
 *
 * \return Standard Pacemaker return code (\c pcmk_rc_ok if \c kill() returns 0,
 *         or \c errno after calling \c kill() otherwise)
 */
static int
kill_child_pid(const pcmk__main_loop_child_t *child)
{
    const pid_t pid = (child->kill_group? -child->pid : child->pid);
    int rc = 0;

    pcmk__debug("Killing PID %lld", (long long) pid);

    rc = kill(pid, SIGKILL);
    if (rc == 0) {
        return pcmk_rc_ok;
    }

    rc = errno;
    if (rc == ESRCH) {
        return rc;
    }

    pcmk__err("kill(%lld, KILL) failed for child '%s': %s", (long long) pid,
              pcmk__s(child->desc, ""), strerror(rc));
    return rc;
}

/*!
 * \internal
 * \brief Kill a child process after its timeout has expired
 *
 * \param[in,out] user_data  Main loop child
 *                           (<tt>pcmk__main_loop_child_t *</tt>)
 *
 * \return \c G_SOURCE_REMOVE (to destroy the timeout that triggered this call)
 *
 * \note This is a \c GSourceFunc.
 */
static gboolean
child_timeout_callback(void *user_data)
{
    pcmk__main_loop_child_t *child = user_data;
    int rc = pcmk_rc_ok;
    const char *result_s = NULL;

    child->timer_id = 0;
    child->timed_out = true;

    rc = kill_child_pid(child);

    switch (rc) {
        case pcmk_rc_ok:
            result_s = "was successfully killed";
            break;

        case ESRCH:
            result_s = "has already terminated";
            break;

        default:
            result_s = "could not be killed";
            break;
    }

    pcmk__debug("%s process (PID %lld) timed out and %s", child->desc,
                (long long) child->pid, result_s);
    return G_SOURCE_REMOVE;
}

/*!
 * \internal
 * \brief Free a main loop child
 *
 * If the child has an associated timer, remove it.
 *
 * \param[in,out] data  Main loop child (<tt>pcmk__main_loop_child_t *</tt>)
 *
 * \note This does not free the child's \c user_data field.
 * \note This is a \c GDestroyNotify.
 */
static void
free_main_loop_child(void *data)
{
    pcmk__main_loop_child_t *child = data;

    if (child == NULL) {
        return;
    }

    if (child->timer_id != 0) {
        pcmk__trace("Removing timer %u", child->timer_id);
        g_source_remove(child->timer_id);
    }

    free(child->desc);
    free(child);
}

/*!
 * \internal
 * \brief Wait on a child process and free it if terminated
 *
 * If the child has terminated, call its exit callback if any, remove it from
 * \c child_list, and free it.
 *
 * Likely bug: If the child object's \c pid field is nonpositive, then we wait
 * on the corresponding process group as documented in the \c wait(2) man page.
 * On success, call the exit callback using that PID (not the PID of the actual
 * child process that changed state). Also remove the child object from
 * \c child_list and free the child object, even though there may still be other
 * child processes in the same process group that have not yet been waited on.
 * This seems incorrect. However, nothing internal creates a child object with
 * nonpositive PID, and the \c mainloop_child_add() documentation notes that
 * nonpositive PIDs are not expected to work correctly.
 *
 * \param[in,out] link     List element whose data is the child to wait for
 * \param[in]     no_hang  If \c true, use the \c waitpid() \c WNOHANG option
 *
 * \return \c true if the child process (or a child process in the specified
 *         process group) has terminated, or \c false if the child process is
 *         still active or its state changed in an unexpected way
 *
 * \note Taking the list link rather than the child as an argument allows us to
 *       delete a terminated child from \c child_list in constant time. If we
 *       took the child, \c g_list_remove() would have to find the child in the
 *       list again before removing it.
 */
static bool
child_waitpid(GList *link, bool no_hang)
{
    const int options = no_hang? WNOHANG : 0;

    pcmk__main_loop_child_t *child = NULL;
    pid_t rc = 0;
    int status = 0;

    int core = 0;
    int signo = 0;
    int exit_code = 0;

    pcmk__assert(link != NULL);
    child = link->data;

    rc = waitpid(child->pid, &status, options);

    if (rc == 0) {
        // WNOHANG was specified and child->pid exists and has not changed state
        pcmk__trace("Child process %lld (%s) still active",
                    (long long) child->pid, child->desc);
        return false;
    }

    if (rc == -1) {
        if (errno == ECHILD) {
            /* This situation should probably never happen in practice. Setting
             * exit_code to 1 is misleading in that it indicates the child
             * exited with code 1, and we don't know that to be true. We could
             * add a pcmk__main_loop_child_t flag to indicate this case, but it
             * doesn't seem worth it.
             */
            exit_code = 1;

            pcmk__err("Wait for child process %lld (%s) failed because process "
                      "does not exist or is not our child",
                      (long long) child->pid, child->desc);
            goto terminated;
        }

        if (errno == EINTR) {
            pcmk__notice("Wait for child process %lld (%s) was interrupted by "
                         "a signal", (long long) child->pid, child->desc);
            return false;
        }

        pcmk__err("Bug: Wait for child process %lld (%s) failed: %s (waitpid() "
                  "options: %#x)", (long long) child->pid, child->desc,
                  strerror(errno), options);
        return false;
    }

    /* At this point, rc is the PID of a child whose state changed. If
     * child->pid is positive, then rc == child->pid. Otherwise, rc is the PID
     * of one of the child processes in the process group with ID -child->pid.
     */

    if (rc != child->pid) {
        /* @COMPAT Nothing internal creates a nonpositive child->pid, and the
         * public Doxygen for mainloop_child_add() now notes that nonpositive
         * PIDs are not expected to work correctly.
         */
        pcmk__trace("Child process %lld from group %lld (%s) terminated",
                    (long long) rc, (long long) -child->pid, child->desc);
        goto terminated;
    }

    if (WIFEXITED(status)) {
        exit_code = WEXITSTATUS(status);
        pcmk__trace("Child process %lld (%s) exited with status %d",
                    (long long) child->pid, child->desc, exit_code);
        goto terminated;
    }

    if (WIFSIGNALED(status)) {
        signo = WTERMSIG(status);
        pcmk__trace("Child process %lld (%s) was terminated by signal %d (%s)",
                    (long long) child->pid, child->desc, signo,
                    strsignal(signo));

#ifdef WCOREDUMP
        if (WCOREDUMP(status)) {
            core = 1;
            pcmk__err("Child process %lld (%s) dumped core",
                      (long long) child->pid, child->desc);
        }
#endif  // defined(WCOREDUMP)

        goto terminated;
    }

    /* We're not using the WUNTRACED or WCONTINUED options. If the process
     * changed state, it should have either exited or been terminated by a
     * signal.
     */
    CRM_CHECK(false, return false);

terminated:
    if (child->callback != NULL) {
        child->callback(child, core, signo, exit_code);
    }

    pcmk__trace("Removing terminated process %lld from child list",
                (long long) child->pid);
    child_list = g_list_delete_link(child_list, link);
    free_main_loop_child(child);

    return true;
}

/*!
 * \internal
 * \brief Free all main loop children whose processes have terminated
 *
 * If a child object's process has terminated, remove the child from
 * \c child_list and free it.
 *
 * \param[in] signal  Ignored
 */
static void
free_terminated_children(int signal)
{
    GList *iter = child_list;

    while (iter != NULL) {
        GList *next = iter->next;

        child_waitpid(iter, true);
        iter = next;
    }
}

/*!
 * \internal
 * \brief Install the main loop \c SIGCHLD handler
 *
 * Install \c free_terminated_children() as the \c SIGCHLD handler, and call it
 * for any children that terminated before the handler was installed.
 *
 * \param[in] user_data  Ignored
 *
 * \return \c G_SOURCE_REMOVE (to destroy the timeout that triggered this call)
 *
 * \note This is a \c GSourceFunc.
 */
static gboolean
install_sigchld_handler(void *user_data)
{
    pcmk__trace("Installing SIGCHLD handler");

    // Do NOT use g_child_watch_add() and friends, since they rely on pthreads
    mainloop_add_signal(SIGCHLD, free_terminated_children);

    free_terminated_children(SIGCHLD);
    return G_SOURCE_REMOVE;
}

/*!
 * \internal
 * \brief Create a \c pcmk__main_loop_child_t object and add it to the main loop
 *
 * If the child process has not exited within \p timeout_ms, send it a
 * \c SIGKILL signal.
 *
 * \param[in] pid         Child PID
 * \param[in] desc        Description
 * \param[in] timeout_ms  Timeout in milliseconds
 * \param[in] user_data   User data
 * \param[in] kill group  If \c true, kill the child's entire process group on
 *                        timeout; otherwise, kill only the child process
 * \param[in] callback    Function to call when the child process terminates
 */
void
pcmk__main_loop_child_create(pid_t pid, const char *desc,
                             unsigned int timeout_ms, void *user_data,
                             bool kill_group,
                             pcmk__main_loop_child_cb_t callback)
{
    static bool need_init = true;

    pcmk__main_loop_child_t *child = NULL;

    pcmk__assert(pid > 0);

    child = pcmk__assert_alloc(1, sizeof(pcmk__main_loop_child_t));
    child->pid = pid;
    child->desc = pcmk__str_copy(desc);
    child->timer_id = pcmk__create_timer(timeout_ms, child_timeout_callback,
                                         child);
    child->user_data = user_data;
    child->kill_group = kill_group;
    child->callback = callback;

    child_list = g_list_append(child_list, child);

    if (need_init) {
        /* Invoke SIGCHLD processing from the main loop. This ensures that we
         * don't add a child to the main loop and have the exit callback invoked
         * for the child PID within the same call stack.
         *
         * @TODO Understand and document why this matters.
         */
        need_init = false;
        pcmk__create_timer(1, install_sigchld_handler, NULL);
    }
}

/*!
 * \internal
 * \brief Compare two mainloop child objects by PID
 *
 * \param[in] a  First child to compare
 *               (<tt>const pcmk__main_loop_child_t *</tt>)
 * \param[in] b  Second child to compare
 *               (<tt>const pcmk__main_loop_child_t *</tt>)
 *
 * \retval -1  if \p a->pid is less than \p b->pid
 * \retval  0  if \p a->pid is equal to \p b->pid
 * \retval  1  if \p a->pid is greater than \p b->pid
 *
 * \note This is a \c GCompareFunc.
 */
static int
compare_children_by_pid(const void *a, const void *b)
{
    const pcmk__main_loop_child_t *child1 = a;
    const pcmk__main_loop_child_t *child2 = b;

    if (child1->pid < child2->pid) {
        return -1;
    }

    if (child1->pid > child2->pid) {
        return 1;
    }

    return 0;
}

/*!
 * \internal
 * \brief Kill a child process tracked by the main loop
 *
 * If a process with PID \p pid is being tracked, send it a \c SIGKILL.
 *
 * If this function kills the child process successfully, remove the child from
 * the tracking data structure and free the child.
 *
 * If the process is being tracked but no longer exists, don't remove or free
 * the child yet. We will do this later when we receive a \c SIGCHLD for the
 * child process.
 *
 * \param[in] pid  Child PID
 *
 * \return \c true if the child with ID \p pid was being tracked and either this
 *         function killed the process successfully or the process has already
 *         terminated but we have not received a \c SIGCHLD for it; or \c false
 *         otherwise
 */
bool
pcmk__main_loop_child_kill(pid_t pid)
{
    const pcmk__main_loop_child_t cmp_data = { .pid = pid };
    GList *match = NULL;
    pcmk__main_loop_child_t *child = NULL;
    int rc = pcmk_rc_ok;
    bool no_hang = false;

    pcmk__assert(pid > 0);

    match = g_list_find_custom(child_list, &cmp_data, compare_children_by_pid);
    if (match == NULL) {
        return false;
    }

    child = match->data;

    rc = kill_child_pid(child);
    if (rc == ESRCH) {
        /* It's gone but hasn't shown up in waitpid() yet. Wait until we get
         * SIGCHLD and let handler clean it up as normal (so we get the correct
         * return code/status). The blocking alternative would be to call
         * child_waitpid(iter, false).
         */
        pcmk__trace("Waiting for signal that child process %lld completed",
                    (long long) child->pid);
        return true;
    }

    if (rc != pcmk_rc_ok) {
        /* If kill() failed for some other reason, set the WNOHANG flag, since
         * we can't be certain what happened.
         *
         * If kill() succeeded, we don't need the WNOHANG flag because SIGKILL
         * can't be blocked.
         */
        no_hang = true;
    }

    return child_waitpid(match, no_hang);
}

/*!
 * \internal
 * \brief Create a main loop timer
 *
 * \param[in] name         Timer name prefix (for logging only)
 * \param[in] interval_ms  Timer interval
 * \param[in] callback     Function to call after \p interval_ms expires
 * \param[in] user_data    User data for \p callback
 *
 * \return Newly allocated main loop timer (guaranteed not to be \c NULL)
 *
 * \note The new timer's \c name string starts with the \p name argument and
 *       includes the timer's interval and address.
 * \note The caller is responsible for freeing the return value using
 *       \c pcmk__main_loop_timer_free().
 */
pcmk__main_loop_timer_t *
pcmk__main_loop_timer_new(const char *name, unsigned int interval_ms,
                          GSourceFunc callback, void *user_data)
{
    pcmk__main_loop_timer_t *timer = NULL;
    pcmk__assert((name != NULL) && (callback != NULL));

    timer = pcmk__assert_alloc(1, sizeof(pcmk__main_loop_timer_t));
    timer->name = pcmk__assert_asprintf("%s-%u-%p", name, interval_ms, timer);
    timer->interval_ms = interval_ms;
    timer->cb = callback;
    timer->user_data = user_data;

    pcmk__trace("Created timer %s with data %p", timer->name, user_data);
    return timer;
}

/*!
 * \internal
 * \brief Check whether a main loop timer is running
 *
 * A timer is running if its \c id field is nonzero, meaning that it has an
 * active \c GSource with that ID associated with it.
 *
 * \param[in] timer  Main loop timer
 *
 * \return \c true if the timer is running, or \c false otherwise
 */
bool
pcmk__main_loop_timer_running(const pcmk__main_loop_timer_t *timer)
{
    CRM_CHECK(timer != NULL, return false);

    return (timer->source_id != 0);
}

/*!
 * \internal
 * \brief Stop a main loop timer
 *
 * Stopping a timer consists of removing its \c GSource and setting its \c id
 * field to 0 (to indicate that it has no associated \c GSource).
 *
 * \param[in,out] timer  Main loop timer
 */
void
pcmk__main_loop_timer_stop(pcmk__main_loop_timer_t *timer)
{
    if (!pcmk__main_loop_timer_running(timer)) {
        return;
    }

    pcmk__trace("Stopping timer %s", timer->name);
    g_source_remove(timer->source_id);
    timer->source_id = 0;
}

/*!
 * \internal
 * \brief Run a main loop timer's callback
 *
 * If the callback returns \c G_SOURCE_REMOVE, set \p timer->source_id to 0 to
 * indicate that the timer has no associated \c GSource.
 *
 * \param[in,out] user_data  Main loop timer
 *                           (<tt>pcmk__main_loop_timer_t *</tt>)
 *
 * \return The return value from \p timer->cb (\c G_SOURCE_CONTINUE to keep the
 *         timeout source, or \c G_SOURCE_REMOVE to remove it)
 *
 * \note This is a \c GSourceFunc.
 */
static gboolean
main_loop_timer_cb(void *user_data)
{
    int id = 0;
    pcmk__main_loop_timer_t *timer = user_data;

    pcmk__assert((timer != NULL) && (timer->cb != NULL));

    /* Ensure id is unset during callbacks so that
     * pcmk__main_loop_timer_running() works as expected.
     *
     * @TODO Why is this necessary or desirable?
     */
    id = timer->source_id;
    timer->source_id = 0;

    pcmk__trace("Invoking callbacks for timer %s", timer->name);

    // G_SOURCE_REMOVE is false; G_SOURCE_CONTINUE is true
    if (!timer->cb(timer->user_data)) {
        pcmk__trace("Timer %s complete", timer->name);
        return G_SOURCE_REMOVE;
    }

    timer->source_id = id;
    return G_SOURCE_CONTINUE;
}

/*!
 * \internal
 * \brief Start a main loop timer
 *
 * Starting a timer consists of:
 * 1. stopping the timer if it's already running (by removing the associated
 *    \c GSource)
 * 2. creating a new \c GSource using \p timer->interval_ms as the timeout (see
 *    \c pcmk__create_timer())
 * 3. assigning the new \c GSource ID to \p timer->source_id
 *
 * \param[in,out] timer  Main loop timer
 */
void
pcmk__main_loop_timer_start(pcmk__main_loop_timer_t *timer)
{
    CRM_CHECK((timer != NULL)
              && (timer->interval_ms > 0)
              && (timer->cb != NULL),
              return);

    pcmk__main_loop_timer_stop(timer);

    pcmk__trace("Starting timer %s", timer->name);
    timer->source_id = pcmk__create_timer(timer->interval_ms,
                                          main_loop_timer_cb, timer);
}

/*!
 * \internal
 * \brief Free a main loop timer
 *
 * \param[in,out] timer  Main loop timer
 */
void
pcmk__main_loop_timer_free(pcmk__main_loop_timer_t *timer)
{
    if (timer == NULL) {
        return;
    }

    pcmk__trace("Destroying timer %s", timer->name);
    pcmk__main_loop_timer_stop(timer);
    free(timer->name);
    free(timer);
}

static gboolean
mainloop_timer_cb(void *user_data)
{
    int id = 0;
    mainloop_timer_t *timer = user_data;

    pcmk__assert((timer != NULL) && (timer->cb != NULL));

    /* Ensure id is unset during callbacks so that
     * pcmk__main_loop_timer_running() works as expected
     */
    id = timer->source_id;
    timer->source_id = 0;

    pcmk__trace("Invoking callbacks for timer %s", timer->name);

    // G_SOURCE_REMOVE is false; G_SOURCE_CONTINUE is true
    if (!timer->cb(timer->user_data)) {
        pcmk__trace("Timer %s complete", timer->name);
        return G_SOURCE_REMOVE;
    }

    if (!timer->repeat) {
        return G_SOURCE_REMOVE;
    }

    timer->source_id = id;
    return G_SOURCE_CONTINUE;
}

bool
mainloop_timer_running(mainloop_timer_t *timer)
{
    return (timer != NULL) && (timer->source_id != 0);
}

void
mainloop_timer_start(mainloop_timer_t *timer)
{
    mainloop_timer_stop(timer);

    if ((timer == NULL) || (timer->interval_ms == 0) || (timer->cb == NULL)) {
        return;
    }

    pcmk__trace("Starting timer %s", timer->name);
    timer->source_id = pcmk__create_timer(timer->interval_ms, mainloop_timer_cb,
                                          timer);
}

void
mainloop_timer_stop(mainloop_timer_t *timer)
{
    if ((timer == NULL) || (timer->source_id == 0)) {
        return;
    }

    pcmk__trace("Stopping timer %s", timer->name);
    g_source_remove(timer->source_id);
    timer->source_id = 0;
}

unsigned int
mainloop_timer_set_period(mainloop_timer_t *timer, unsigned int interval_ms)
{
    unsigned int last = 0;

    if (timer == NULL) {
        return 0;
    }

    last = timer->interval_ms;
    timer->interval_ms = interval_ms;

    if ((timer->source_id != 0) && (timer->interval_ms != last)) {
        mainloop_timer_start(timer);
    }

    return last;
}

mainloop_timer_t *
mainloop_timer_add(const char *name, unsigned int interval_ms, bool repeat,
                   GSourceFunc cb, void *userdata)
{
    mainloop_timer_t *timer = pcmk__assert_alloc(1, sizeof(mainloop_timer_t));

    if (name != NULL) {
        timer->name = pcmk__assert_asprintf("%s-%u-%d", name, interval_ms,
                                            repeat);

    } else {
        timer->name = pcmk__assert_asprintf("%p-%u-%d", timer, interval_ms,
                                            repeat);
    }

    timer->interval_ms = interval_ms;
    timer->repeat = repeat;
    timer->cb = cb;
    timer->user_data = userdata;

    pcmk__trace("Created timer %s with %p", timer->name, userdata);
    return timer;
}

void
mainloop_timer_del(mainloop_timer_t *timer)
{
    if (timer == NULL) {
        return;
    }

    pcmk__trace("Destroying timer %s", timer->name);
    mainloop_timer_stop(timer);
    free(timer->name);
    free(timer);
}

/*
 * Helpers to make sure certain events aren't lost at shutdown
 */

static gboolean
drain_timeout_cb(void *user_data)
{
    bool *timeout_popped = (bool*) user_data;

    *timeout_popped = TRUE;
    return G_SOURCE_REMOVE;
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
pcmk_drain_main_loop(GMainLoop *mloop, unsigned int timer_ms,
                     bool (*check)(unsigned int))
{
    bool timeout_popped = FALSE;
    unsigned int timer = 0;
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

/*!
 * \internal
 * \brief Free data structures used for the mainloop
 *
 * \todo This is incomplete. Free other data structures created in this file.
 */
void
mainloop_cleanup(void)
{
    g_list_free_full(child_list, free_main_loop_child);
    child_list = NULL;

    g_clear_pointer(&gio_map, qb_array_free);

    for (int sig = 0; sig < NSIG; ++sig) {
        mainloop_destroy_signal_entry(sig);
    }
}

// Deprecated functions kept only for backward API compatibility
// LCOV_EXCL_START

#include <crm/common/mainloop_compat.h>

void
mainloop_child_add_with_flags(pid_t pid, int timeout_ms, const char *desc,
                              void *user_data,
                              enum mainloop_child_flags flags,
                              void (*callback)(mainloop_child_t *child, int core,
                                               int signo, int exit_code))
{
    static bool need_init = true;

    mainloop_child_t *child = pcmk__assert_alloc(1, sizeof(mainloop_child_t));

    child->pid = pid;
    child->desc = pcmk__str_copy(desc);
    child->user_data = user_data;
    child->kill_group = !pcmk__is_set(flags, mainloop_leave_pid_group);
    child->callback = callback;

    if (timeout_ms > 0) {
        child->timer_id = pcmk__create_timer(timeout_ms, child_timeout_callback,
                                             child);
    }

    child_list = g_list_append(child_list, child);

    if (need_init) {
        need_init = false;
        pcmk__create_timer(1, install_sigchld_handler, NULL);
    }
}

void
mainloop_child_add(pid_t pid, int timeout_ms, const char *desc, void *user_data,
                   void (*callback)(mainloop_child_t *child, int core,
                                    int signo, int exit_code))
{
    mainloop_child_add_with_flags(pid, timeout_ms, desc, user_data, 0, callback);
}

gboolean
mainloop_child_kill(pid_t pid)
{
    const mainloop_child_t cmp_data = { .pid = pid };
    GList *match = NULL;
    mainloop_child_t *child = NULL;
    int rc = pcmk_rc_ok;
    bool no_hang = false;

    match = g_list_find_custom(child_list, &cmp_data, compare_children_by_pid);
    if (match == NULL) {
        return FALSE;
    }

    child = match->data;

    rc = kill_child_pid(child);
    if (rc == ESRCH) {
        pcmk__trace("Waiting for signal that child process %lld completed",
                    (long long) child->pid);
        return TRUE;
    }

    if (rc != pcmk_rc_ok) {
        no_hang = true;
    }

    return child_waitpid(match, no_hang)? TRUE : FALSE;
}

pid_t
mainloop_child_pid(mainloop_child_t *child)
{
    return child->pid;
}

const char *
mainloop_child_name(mainloop_child_t *child)
{
    return child->desc;
}

int
mainloop_child_timeout(mainloop_child_t *child)
{
    return child->timed_out? TRUE : FALSE;
}

void *
mainloop_child_userdata(mainloop_child_t *child)
{
    return child->user_data;
}

void
mainloop_clear_child_userdata(mainloop_child_t *child)
{
    child->user_data = NULL;
}

// LCOV_EXCL_STOP
// End deprecated API
