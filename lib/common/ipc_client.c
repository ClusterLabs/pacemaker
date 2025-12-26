/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#if defined(HAVE_UCRED) || defined(HAVE_SOCKPEERCRED)
#include <sys/socket.h>
#elif defined(HAVE_GETPEERUCRED)
#include <ucred.h>
#endif

#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>
#include <errno.h>
#include <bzlib.h>

#include <crm/crm.h>   /* indirectly: pcmk_err_generic */
#include <crm/common/xml.h>
#include <crm/common/ipc.h>
#include "crmcommon_private.h"

static int is_ipc_provider_expected(qb_ipcc_connection_t *qb_ipc, int sock,
                                    uid_t refuid, gid_t refgid, pid_t *gotpid,
                                    uid_t *gotuid, gid_t *gotgid);

/*!
 * \brief Create a new object for using Pacemaker daemon IPC
 *
 * \param[out] api     Where to store new IPC object
 * \param[in]  server  Which Pacemaker daemon the object is for
 *
 * \return Standard Pacemaker result code
 *
 * \note The caller is responsible for freeing *api using pcmk_free_ipc_api().
 * \note This is intended to supersede crm_ipc_new() but currently only
 *       supports the controller, pacemakerd, and schedulerd IPC API.
 */
int
pcmk_new_ipc_api(pcmk_ipc_api_t **api, enum pcmk_ipc_server server)
{
    if (api == NULL) {
        return EINVAL;
    }

    *api = calloc(1, sizeof(pcmk_ipc_api_t));
    if (*api == NULL) {
        return errno;
    }

    (*api)->server = server;
    if (pcmk_ipc_name(*api, false) == NULL) {
        pcmk_free_ipc_api(*api);
        *api = NULL;
        return EOPNOTSUPP;
    }

    // Set server methods
    switch (server) {
        case pcmk_ipc_attrd:
            (*api)->cmds = pcmk__attrd_api_methods();
            break;

        case pcmk_ipc_based:
            break;

        case pcmk_ipc_controld:
            (*api)->cmds = pcmk__controld_api_methods();
            break;

        case pcmk_ipc_execd:
            break;

        case pcmk_ipc_fenced:
            break;

        case pcmk_ipc_pacemakerd:
            (*api)->cmds = pcmk__pacemakerd_api_methods();
            break;

        case pcmk_ipc_schedulerd:
            (*api)->cmds = pcmk__schedulerd_api_methods();
            break;

        default: // pcmk_ipc_unknown
            pcmk_free_ipc_api(*api);
            *api = NULL;
            return EINVAL;
    }
    if ((*api)->cmds == NULL) {
        pcmk_free_ipc_api(*api);
        *api = NULL;
        return ENOMEM;
    }

    (*api)->ipc = crm_ipc_new(pcmk_ipc_name(*api, false), 0);
    if ((*api)->ipc == NULL) {
        pcmk_free_ipc_api(*api);
        *api = NULL;
        return ENOMEM;
    }

    // If daemon API has its own data to track, allocate it
    if ((*api)->cmds->new_data != NULL) {
        if ((*api)->cmds->new_data(*api) != pcmk_rc_ok) {
            pcmk_free_ipc_api(*api);
            *api = NULL;
            return ENOMEM;
        }
    }
    pcmk__trace("Created %s API IPC object", pcmk_ipc_name(*api, true));
    return pcmk_rc_ok;
}

static void
free_daemon_specific_data(pcmk_ipc_api_t *api)
{
    if ((api != NULL) && (api->cmds != NULL)) {
        if ((api->cmds->free_data != NULL) && (api->api_data != NULL)) {
            api->cmds->free_data(api->api_data);
            api->api_data = NULL;
        }
        free(api->cmds);
        api->cmds = NULL;
    }
}

/*!
 * \internal
 * \brief Call an IPC API event callback, if one is registed
 *
 * \param[in,out] api         IPC API connection
 * \param[in]     event_type  The type of event that occurred
 * \param[in]     status      Event status
 * \param[in,out] event_data  Event-specific data
 */
void
pcmk__call_ipc_callback(pcmk_ipc_api_t *api, enum pcmk_ipc_event event_type,
                        crm_exit_t status, void *event_data)
{
    if ((api != NULL) && (api->cb != NULL)) {
        api->cb(api, event_type, status, event_data, api->user_data);
    }
}

/*!
 * \internal
 * \brief Clean up after an IPC disconnect
 *
 * \param[in,out] user_data  IPC API connection that disconnected
 *
 * \note This function can be used as a main loop IPC destroy callback.
 */
static void
ipc_post_disconnect(gpointer user_data)
{
    pcmk_ipc_api_t *api = user_data;

    pcmk__info("Disconnected from %s", pcmk_ipc_name(api, true));

    // Perform any daemon-specific handling needed
    if ((api->cmds != NULL) && (api->cmds->post_disconnect != NULL)) {
        api->cmds->post_disconnect(api);
    }

    // Call client's registered event callback
    pcmk__call_ipc_callback(api, pcmk_ipc_event_disconnect, CRM_EX_DISCONNECT,
                            NULL);

    /* If this is being called from a running main loop, mainloop_gio_destroy()
     * will free ipc and mainloop_io immediately after calling this function.
     * If this is called from a stopped main loop, these will leak, so the best
     * practice is to close the connection before stopping the main loop.
     */
    api->ipc = NULL;
    api->mainloop_io = NULL;

    if (api->free_on_disconnect) {
        /* pcmk_free_ipc_api() has already been called, but did not free api
         * or api->cmds because this function needed them. Do that now.
         */
        free_daemon_specific_data(api);
        pcmk__trace("Freeing IPC API object after disconnect");
        free(api);
    }
}

/*!
 * \brief Free the contents of an IPC API object
 *
 * \param[in,out] api  IPC API object to free
 */
void
pcmk_free_ipc_api(pcmk_ipc_api_t *api)
{
    bool free_on_disconnect = false;

    if (api == NULL) {
        return;
    }
    pcmk__debug("Releasing %s IPC API", pcmk_ipc_name(api, true));

    if (api->ipc != NULL) {
        if (api->mainloop_io != NULL) {
            /* We need to keep the api pointer itself around, because it is the
             * user data for the IPC client destroy callback. That will be
             * triggered by the pcmk_disconnect_ipc() call below, but it might
             * happen later in the main loop (if still running).
             *
             * This flag tells the destroy callback to free the object. It can't
             * do that unconditionally, because the application might call this
             * function after a disconnect that happened by other means.
             */
            free_on_disconnect = api->free_on_disconnect = true;
        }
        pcmk_disconnect_ipc(api); // Frees api if free_on_disconnect is true
    }
    if (!free_on_disconnect) {
        free_daemon_specific_data(api);
        pcmk__trace("Freeing IPC API object");
        free(api);
    }
}

/*!
 * \brief Get the IPC name used with an IPC API connection
 *
 * \param[in] api      IPC API connection
 * \param[in] for_log  If true, return human-friendly name instead of IPC name
 *
 * \return IPC API's human-friendly or connection name, or if none is available,
 *         "Pacemaker" if for_log is true and NULL if for_log is false
 */
const char *
pcmk_ipc_name(const pcmk_ipc_api_t *api, bool for_log)
{
    if (api == NULL) {
        return for_log? "Pacemaker" : NULL;
    }
    if (for_log) {
        const char *name = pcmk__server_log_name(api->server);

        return pcmk__s(name, "Pacemaker");
    }
    switch (api->server) {
        // These servers do not have pcmk_ipc_api_t implementations yet
        case pcmk_ipc_based:
        case pcmk_ipc_execd:
        case pcmk_ipc_fenced:
            return NULL;

        default:
            return pcmk__server_ipc_name(api->server);
    }
}

/*!
 * \brief Check whether an IPC API connection is active
 *
 * \param[in,out] api  IPC API connection
 *
 * \return true if IPC is connected, false otherwise
 */
bool
pcmk_ipc_is_connected(pcmk_ipc_api_t *api)
{
    return (api != NULL) && crm_ipc_connected(api->ipc);
}

/*!
 * \internal
 * \brief Call the daemon-specific API's dispatch function
 *
 * Perform daemon-specific handling of IPC reply dispatch. It is the daemon
 * method's responsibility to call the client's registered event callback, as
 * well as allocate and free any event data.
 *
 * \param[in,out] api      IPC API connection
 * \param[in,out] message  IPC reply XML to dispatch
 */
static bool
call_api_dispatch(pcmk_ipc_api_t *api, xmlNode *message)
{
    pcmk__log_xml_trace(message, "ipc-received");
    if ((api->cmds != NULL) && (api->cmds->dispatch != NULL)) {
        return api->cmds->dispatch(api, message);
    }

    return false;
}

/*!
 * \internal
 * \brief Dispatch previously read IPC data
 *
 * \param[in]     buffer  Data read from IPC
 * \param[in,out] api     IPC object
 *
 * \return Standard Pacemaker return code.  In particular:
 *
 * pcmk_rc_ok: There are no more messages expected from the server.  Quit
 *             reading.
 * EINPROGRESS: There are more messages expected from the server.  Keep reading.
 *
 * All other values indicate an error.
 */
static int
dispatch_ipc_data(const char *buffer, pcmk_ipc_api_t *api)
{
    bool more = false;
    xmlNode *msg;

    if (buffer == NULL) {
        pcmk__warn("Empty message received from %s IPC",
                   pcmk_ipc_name(api, true));
        return ENOMSG;
    }

    msg = pcmk__xml_parse(buffer);
    if (msg == NULL) {
        pcmk__warn("Malformed message received from %s IPC",
                   pcmk_ipc_name(api, true));
        return EPROTO;
    }

    more = call_api_dispatch(api, msg);
    pcmk__xml_free(msg);

    if (more) {
        return EINPROGRESS;
    } else {
        return pcmk_rc_ok;
    }
}

/*!
 * \internal
 * \brief Dispatch data read from IPC source
 *
 * \param[in]     buffer     Data read from IPC
 * \param[in]     length     Number of bytes of data in buffer (ignored)
 * \param[in,out] user_data  IPC object
 *
 * \return Always 0 (meaning connection is still required)
 *
 * \note This function can be used as a main loop IPC dispatch callback.
 */
static int
dispatch_ipc_source_data(const char *buffer, ssize_t length, gpointer user_data)
{
    pcmk_ipc_api_t *api = user_data;

    CRM_CHECK(api != NULL, return 0);
    dispatch_ipc_data(buffer, api);
    return 0;
}

/*!
 * \brief Check whether an IPC connection has data available (without main loop)
 *
 * \param[in]  api         IPC API connection
 * \param[in]  timeout_ms  If less than 0, poll indefinitely; if 0, poll once
 *                         and return immediately; otherwise, poll for up to
 *                         this many milliseconds
 *
 * \return Standard Pacemaker return code
 *
 * \note Callers of pcmk_connect_ipc() using pcmk_ipc_dispatch_poll should call
 *       this function to check whether IPC data is available. Return values of
 *       interest include pcmk_rc_ok meaning data is available, and EAGAIN
 *       meaning no data is available; all other values indicate errors.
 * \todo This does not allow the caller to poll multiple file descriptors at
 *       once. If there is demand for that, we could add a wrapper for
 *       pcmk__ipc_fd(api->ipc), so the caller can call poll() themselves.
 */
int
pcmk_poll_ipc(const pcmk_ipc_api_t *api, int timeout_ms)
{
    int rc;
    struct pollfd pollfd = { 0, };

    if ((api == NULL) || (api->dispatch_type != pcmk_ipc_dispatch_poll)) {
        return EINVAL;
    }

    rc = pcmk__ipc_fd(api->ipc, &(pollfd.fd));
    if (rc != pcmk_rc_ok) {
        pcmk__debug("Could not obtain file descriptor for %s IPC: %s",
                    pcmk_ipc_name(api, true), pcmk_rc_str(rc));
        return rc;
    }

    pollfd.events = POLLIN;
    rc = poll(&pollfd, 1, timeout_ms);
    if (rc < 0) {
        /* Some UNIX systems return negative and set EAGAIN for failure to
         * allocate memory; standardize the return code in that case
         */
        return (errno == EAGAIN)? ENOMEM : errno;
    } else if (rc == 0) {
        return EAGAIN;
    }
    return pcmk_rc_ok;
}

/*!
 * \brief Dispatch available messages on an IPC connection (without main loop)
 *
 * \param[in,out] api  IPC API connection
 *
 * \return Standard Pacemaker return code
 *
 * \note Callers of pcmk_connect_ipc() using pcmk_ipc_dispatch_poll should call
 *       this function when IPC data is available.
 */
void
pcmk_dispatch_ipc(pcmk_ipc_api_t *api)
{
    if (api == NULL) {
        return;
    }
    while (crm_ipc_ready(api->ipc) > 0) {
        if (crm_ipc_read(api->ipc) > 0) {
            dispatch_ipc_data(crm_ipc_buffer(api->ipc), api);
            pcmk__ipc_free_client_buffer(api->ipc);
        }
    }
}

// \return Standard Pacemaker return code
static int
connect_with_main_loop(pcmk_ipc_api_t *api)
{
    int rc;

    struct ipc_client_callbacks callbacks = {
        .dispatch = dispatch_ipc_source_data,
        .destroy = ipc_post_disconnect,
    };

    rc = pcmk__add_mainloop_ipc(api->ipc, G_PRIORITY_DEFAULT, api,
                                &callbacks, &(api->mainloop_io));
    if (rc != pcmk_rc_ok) {
        return rc;
    }
    pcmk__debug("Connected to %s IPC (attached to main loop)",
                pcmk_ipc_name(api, true));
    /* After this point, api->mainloop_io owns api->ipc, so api->ipc
     * should not be explicitly freed.
     */
    return pcmk_rc_ok;
}

// \return Standard Pacemaker return code
static int
connect_without_main_loop(pcmk_ipc_api_t *api)
{
    int rc = pcmk__connect_generic_ipc(api->ipc);

    if (rc != pcmk_rc_ok) {
        crm_ipc_close(api->ipc);
    } else {
        pcmk__debug("Connected to %s IPC (without main loop)",
                    pcmk_ipc_name(api, true));
    }
    return rc;
}

/*!
 * \internal
 * \brief Connect to a Pacemaker daemon via IPC (retrying after soft errors
 *        and ECONNREFUSED)
 *
 * \param[in,out] api            IPC API instance
 * \param[in]     dispatch_type  How IPC replies should be dispatched
 * \param[in]     attempts       How many times to try (in case of soft error)
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__connect_ipc_retry_conrefused(pcmk_ipc_api_t *api,
                                   enum pcmk_ipc_dispatch dispatch_type,
                                   int attempts)
{
    int remaining = attempts;
    int rc = pcmk_rc_ok;

    do {
        if (rc == ECONNREFUSED) {
            pcmk__sleep_ms((attempts - remaining) * 500);
        }
        rc = pcmk__connect_ipc(api, dispatch_type, remaining);
        remaining--;
    } while (rc == ECONNREFUSED && remaining >= 0);

    return rc;
}


/*!
 * \internal
 * \brief Connect to a Pacemaker daemon via IPC (retrying after soft errors)
 *
 * \param[in,out] api            IPC API instance
 * \param[in]     dispatch_type  How IPC replies should be dispatched
 * \param[in]     attempts       How many times to try (in case of soft error)
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__connect_ipc(pcmk_ipc_api_t *api, enum pcmk_ipc_dispatch dispatch_type,
                  int attempts)
{
    int rc = pcmk_rc_ok;

    if ((api == NULL) || (attempts < 1)) {
        return EINVAL;
    }

    if (api->ipc == NULL) {
        api->ipc = crm_ipc_new(pcmk_ipc_name(api, false), 0);
        if (api->ipc == NULL) {
            return ENOMEM;
        }
    }

    if (crm_ipc_connected(api->ipc)) {
        pcmk__trace("Already connected to %s", pcmk_ipc_name(api, true));
        return pcmk_rc_ok;
    }

    api->dispatch_type = dispatch_type;

    pcmk__debug("Attempting connection to %s (up to %d time%s)",
                pcmk_ipc_name(api, true), attempts, pcmk__plural_s(attempts));
    for (int remaining = attempts - 1; remaining >= 0; --remaining) {
        switch (dispatch_type) {
            case pcmk_ipc_dispatch_main:
                rc = connect_with_main_loop(api);
                break;

            case pcmk_ipc_dispatch_sync:
            case pcmk_ipc_dispatch_poll:
                rc = connect_without_main_loop(api);
                break;
        }

        if ((remaining == 0) || ((rc != EAGAIN) && (rc != EALREADY))) {
            break; // Result is final
        }

        // Retry after soft error (interrupted by signal, etc.)
        pcmk__sleep_ms((attempts - remaining) * 500);
        pcmk__debug("Re-attempting connection to %s (%d attempt%s remaining)",
                    pcmk_ipc_name(api, true), remaining,
                    pcmk__plural_s(remaining));
    }

    if (rc != pcmk_rc_ok) {
        return rc;
    }

    if ((api->cmds != NULL) && (api->cmds->post_connect != NULL)) {
        rc = api->cmds->post_connect(api);
        if (rc != pcmk_rc_ok) {
            crm_ipc_close(api->ipc);
        }
    }
    return rc;
}

/*!
 * \brief Connect to a Pacemaker daemon via IPC
 *
 * \param[in,out] api            IPC API instance
 * \param[in]     dispatch_type  How IPC replies should be dispatched
 *
 * \return Standard Pacemaker return code
 */
int
pcmk_connect_ipc(pcmk_ipc_api_t *api, enum pcmk_ipc_dispatch dispatch_type)
{
    int rc = pcmk__connect_ipc(api, dispatch_type, 2);

    if (rc != pcmk_rc_ok) {
        pcmk__err("Connection to %s failed: %s", pcmk_ipc_name(api, true),
                  pcmk_rc_str(rc));
    }
    return rc;
}

/*!
 * \brief Disconnect an IPC API instance
 *
 * \param[in,out] api  IPC API connection
 *
 * \return Standard Pacemaker return code
 *
 * \note If the connection is attached to a main loop, this function should be
 *       called before quitting the main loop, to ensure that all memory is
 *       freed.
 */
void
pcmk_disconnect_ipc(pcmk_ipc_api_t *api)
{
    if ((api == NULL) || (api->ipc == NULL)) {
        return;
    }
    switch (api->dispatch_type) {
        case pcmk_ipc_dispatch_main:
            {
                mainloop_io_t *mainloop_io = api->mainloop_io;

                // Make sure no code with access to api can use these again
                api->mainloop_io = NULL;
                api->ipc = NULL;

                mainloop_del_ipc_client(mainloop_io);
                // After this point api might have already been freed
            }
            break;

        case pcmk_ipc_dispatch_poll:
        case pcmk_ipc_dispatch_sync:
            {
                crm_ipc_t *ipc = api->ipc;

                // Make sure no code with access to api can use ipc again
                api->ipc = NULL;

                // This should always be the case already, but to be safe
                api->free_on_disconnect = false;

                crm_ipc_close(ipc);
                crm_ipc_destroy(ipc);
                ipc_post_disconnect(api);
            }
            break;
    }
}

/*!
 * \brief Register a callback for IPC API events
 *
 * \param[in,out] api       IPC API connection
 * \param[in]     callback  Callback to register
 * \param[in]     userdata  Caller data to pass to callback
 *
 * \note This function may be called multiple times to update the callback
 *       and/or user data. The caller remains responsible for freeing
 *       userdata in any case (after the IPC is disconnected, if the
 *       user data is still registered with the IPC).
 */
void
pcmk_register_ipc_callback(pcmk_ipc_api_t *api, pcmk_ipc_callback_t cb,
                           void *user_data)
{
    if (api == NULL) {
        return;
    }
    api->cb = cb;
    api->user_data = user_data;
}

/*!
 * \internal
 * \brief Send an XML request across an IPC API connection
 *
 * \param[in,out] api      IPC API connection
 * \param[in]     request  XML request to send
 *
 * \return Standard Pacemaker return code
 *
 * \note Daemon-specific IPC API functions should call this function to send
 *       requests, because it handles different dispatch types appropriately.
 */
int
pcmk__send_ipc_request(pcmk_ipc_api_t *api, const xmlNode *request)
{
    int rc;
    xmlNode *reply = NULL;
    enum crm_ipc_flags flags = crm_ipc_flags_none;

    if ((api == NULL) || (api->ipc == NULL) || (request == NULL)) {
        return EINVAL;
    }
    pcmk__log_xml_trace(request, "ipc-sent");

    // Synchronous dispatch requires waiting for a reply
    if ((api->dispatch_type == pcmk_ipc_dispatch_sync)
        && (api->cmds != NULL)
        && (api->cmds->reply_expected != NULL)
        && (api->cmds->reply_expected(api, request))) {
        flags = crm_ipc_client_response;
    }

    /* The 0 here means a default timeout of 5 seconds
     *
     * @TODO Maybe add a timeout_ms member to pcmk_ipc_api_t and a
     * pcmk_set_ipc_timeout() setter for it, then use it here.
     */
    rc = crm_ipc_send(api->ipc, request, flags, 0, &reply);

    if (rc < 0) {
        return pcmk_legacy2rc(rc);
    } else if (rc == 0) {
        return ENODATA;
    }

    // With synchronous dispatch, we dispatch any reply now
    if (reply != NULL) {
        bool more = call_api_dispatch(api, reply);

        pcmk__xml_free(reply);

        while (more) {
            rc = crm_ipc_read(api->ipc);

            if (rc == -EAGAIN) {
                continue;
            } else if (rc == -ENOMSG || rc == pcmk_ok) {
                return pcmk_rc_ok;
            } else if (rc < 0) {
                return -rc;
            }

            rc = dispatch_ipc_data(crm_ipc_buffer(api->ipc), api);
            pcmk__ipc_free_client_buffer(api->ipc);

            if (rc == pcmk_rc_ok) {
                more = false;
            } else if (rc == EINPROGRESS) {
                more = true;
            } else {
                continue;
            }
        }
    }
    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Create the XML for an IPC request to purge a node from the peer cache
 *
 * \param[in]  api        IPC API connection
 * \param[in]  node_name  If not NULL, name of node to purge
 * \param[in]  nodeid     If not 0, node ID of node to purge
 *
 * \return Newly allocated IPC request XML
 *
 * \note The controller, fencer, and pacemakerd use the same request syntax, but
 *       the attribute manager uses a different one. The CIB manager doesn't
 *       have any syntax for it. The executor and scheduler don't connect to the
 *       cluster layer and thus don't have or need any syntax for it.
 *
 * \todo Modify the attribute manager to accept the common syntax (as well
 *       as its current one, for compatibility with older clients). Modify
 *       the CIB manager to accept and honor the common syntax. Modify the
 *       executor and scheduler to accept the syntax (immediately returning
 *       success), just for consistency. Modify this function to use the
 *       common syntax with all daemons if their version supports it.
 */
static xmlNode *
create_purge_node_request(const pcmk_ipc_api_t *api, const char *node_name,
                          uint32_t nodeid)
{
    xmlNode *request = NULL;
    const char *client = crm_system_name? crm_system_name : "client";

    switch (api->server) {
        case pcmk_ipc_attrd:
            request = pcmk__xe_create(NULL, __func__);
            pcmk__xe_set(request, PCMK__XA_T, PCMK__VALUE_ATTRD);
            pcmk__xe_set(request, PCMK__XA_SRC, crm_system_name);
            pcmk__xe_set(request, PCMK_XA_TASK, PCMK__ATTRD_CMD_PEER_REMOVE);
            pcmk__xe_set_bool(request, PCMK__XA_REAP, true);
            pcmk__xe_set(request, PCMK__XA_ATTR_HOST, node_name);
            if (nodeid > 0) {
                pcmk__xe_set_int(request, PCMK__XA_ATTR_HOST_ID, nodeid);
            }
            break;

        case pcmk_ipc_controld:
        case pcmk_ipc_fenced:
        case pcmk_ipc_pacemakerd:
            request = pcmk__new_request(api->server, client, NULL,
                                        pcmk_ipc_name(api, false),
                                        CRM_OP_RM_NODE_CACHE, NULL);
            if (nodeid > 0) {
                pcmk__xe_set_ll(request, PCMK_XA_ID, (long long) nodeid);
            }
            pcmk__xe_set(request, PCMK_XA_UNAME, node_name);
            break;

        case pcmk_ipc_based:
        case pcmk_ipc_execd:
        case pcmk_ipc_schedulerd:
            break;

        default: // pcmk_ipc_unknown (shouldn't be possible)
            return NULL;
    }
    return request;
}

/*!
 * \brief Ask a Pacemaker daemon to purge a node from its peer cache
 *
 * \param[in,out] api        IPC API connection
 * \param[in]     node_name  If not NULL, name of node to purge
 * \param[in]     nodeid     If not 0, node ID of node to purge
 *
 * \return Standard Pacemaker return code
 *
 * \note At least one of node_name or nodeid must be specified.
 */
int
pcmk_ipc_purge_node(pcmk_ipc_api_t *api, const char *node_name, uint32_t nodeid)
{
    int rc = 0;
    xmlNode *request = NULL;

    if (api == NULL) {
        return EINVAL;
    }
    if ((node_name == NULL) && (nodeid == 0)) {
        return EINVAL;
    }

    request = create_purge_node_request(api, node_name, nodeid);
    if (request == NULL) {
        return EOPNOTSUPP;
    }
    rc = pcmk__send_ipc_request(api, request);
    pcmk__xml_free(request);

    pcmk__debug("%s peer cache purge of node %s[%" PRIu32 "]: rc=%d",
                pcmk_ipc_name(api, true), pcmk__s(node_name, "(unnamed)"),
                nodeid, rc);
    return rc;
}

/*
 * Generic IPC API (to eventually be deprecated as public API and made internal)
 */

struct crm_ipc_s {
    struct pollfd pfd;
    int need_reply;
    GByteArray *buffer;
    char *server_name;          // server IPC name being connected to
    qb_ipcc_connection_t *ipc;
};

/*!
 * \brief Create a new (legacy) object for using Pacemaker daemon IPC
 *
 * \param[in] name      IPC system name to connect to
 * \param[in] max_size  Use a maximum IPC buffer size of at least this size
 *
 * \return Newly allocated IPC object on success, NULL otherwise
 *
 * \note The caller is responsible for freeing the result using
 *       crm_ipc_destroy().
 * \note This should be considered deprecated for use with daemons supported by
 *       pcmk_new_ipc_api().
 * \note @COMPAT Since 3.0.1, \p max_size is ignored and the default given by
 *       \c crm_ipc_default_buffer_size() will be used instead.
 */
crm_ipc_t *
crm_ipc_new(const char *name, size_t max_size)
{
    crm_ipc_t *client = NULL;

    client = calloc(1, sizeof(crm_ipc_t));
    if (client == NULL) {
        pcmk__err("Could not create IPC connection: %s", strerror(errno));
        return NULL;
    }

    client->server_name = strdup(name);
    if (client->server_name == NULL) {
        pcmk__err("Could not create %s IPC connection: %s", name,
                  strerror(errno));
        free(client);
        return NULL;
    }

    client->buffer = NULL;
    client->pfd.fd = -1;
    client->pfd.events = POLLIN;
    client->pfd.revents = 0;

    return client;
}

/*!
 * \internal
 * \brief Connect a generic (not daemon-specific) IPC object
 *
 * \param[in,out] ipc  Generic IPC object to connect
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__connect_generic_ipc(crm_ipc_t *ipc)
{
    uid_t cl_uid = 0;
    gid_t cl_gid = 0;
    pid_t found_pid = 0;
    uid_t found_uid = 0;
    gid_t found_gid = 0;
    int rc = pcmk_rc_ok;

    if (ipc == NULL) {
        return EINVAL;
    }

    ipc->need_reply = FALSE;
    ipc->ipc = qb_ipcc_connect(ipc->server_name, crm_ipc_default_buffer_size());
    if (ipc->ipc == NULL) {
        return errno;
    }

    rc = qb_ipcc_fd_get(ipc->ipc, &ipc->pfd.fd);
    if (rc < 0) { // -errno
        crm_ipc_close(ipc);
        return -rc;
    }

    rc = pcmk__daemon_user(&cl_uid, &cl_gid);
    if (rc != pcmk_rc_ok) {
        crm_ipc_close(ipc);
        return rc;
    }

    rc = is_ipc_provider_expected(ipc->ipc, ipc->pfd.fd, cl_uid, cl_gid,
                                  &found_pid, &found_uid, &found_gid);
    if (rc != pcmk_rc_ok) {
        if (rc == pcmk_rc_ipc_unauthorized) {
            pcmk__info("%s IPC provider authentication failed: process %lld "
                       "has uid %lld (expected %lld) and gid %lld (expected "
                       "%lld)",
                       ipc->server_name,
                       (long long) PCMK__SPECIAL_PID_AS_0(found_pid),
                       (long long) found_uid, (long long) cl_uid,
                       (long long) found_gid, (long long) cl_gid);
        }
        crm_ipc_close(ipc);
        return rc;
    }

    return pcmk_rc_ok;
}

void
crm_ipc_close(crm_ipc_t * client)
{
    if (client) {
        if (client->ipc) {
            qb_ipcc_connection_t *ipc = client->ipc;

            client->ipc = NULL;
            qb_ipcc_disconnect(ipc);
        }
    }
}

void
crm_ipc_destroy(crm_ipc_t * client)
{
    if (client) {
        if (client->ipc && qb_ipcc_is_connected(client->ipc)) {
            pcmk__notice("Destroying active %s IPC connection",
                         client->server_name);
            /* The next line is basically unsafe
             *
             * If this connection was attached to mainloop and mainloop is active,
             *   the 'disconnected' callback will end up back here and we'll end
             *   up free'ing the memory twice - something that can still happen
             *   even without this if we destroy a connection and it closes before
             *   we call exit
             */
            /* crm_ipc_close(client); */
        } else {
            pcmk__trace("Destroying inactive %s IPC connection",
                        client->server_name);
        }

        if (client->buffer != NULL) {
            pcmk__ipc_free_client_buffer(client);
        }

        free(client->server_name);
        free(client);
    }
}

/*!
 * \internal
 * \brief Get the file descriptor for a generic IPC object
 *
 * \param[in,out] ipc  Generic IPC object to get file descriptor for
 * \param[out]    fd   Where to store file descriptor
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__ipc_fd(crm_ipc_t *ipc, int *fd)
{
    if ((ipc == NULL) || (fd == NULL)) {
        return EINVAL;
    }
    if ((ipc->ipc == NULL) || (ipc->pfd.fd < 0)) {
        return ENOTCONN;
    }
    *fd = ipc->pfd.fd;
    return pcmk_rc_ok;
}

int
crm_ipc_get_fd(crm_ipc_t * client)
{
    int fd = -1;

    if (pcmk__ipc_fd(client, &fd) != pcmk_rc_ok) {
        pcmk__err("Could not obtain file descriptor for %s IPC",
                  ((client == NULL)? "unspecified" : client->server_name));
        errno = EINVAL;
        return -EINVAL;
    }
    return fd;
}

bool
crm_ipc_connected(crm_ipc_t * client)
{
    bool rc = FALSE;

    if (client == NULL) {
        pcmk__trace("No client");
        return FALSE;

    } else if (client->ipc == NULL) {
        pcmk__trace("No connection");
        return FALSE;

    } else if (client->pfd.fd < 0) {
        pcmk__trace("Bad descriptor");
        return FALSE;
    }

    rc = qb_ipcc_is_connected(client->ipc);
    if (rc == FALSE) {
        client->pfd.fd = -EINVAL;
    }
    return rc;
}

/*!
 * \brief Check whether an IPC connection is ready to be read
 *
 * \param[in,out] client  Connection to check
 *
 * \return Positive value if ready to be read, 0 if not ready, -errno on error
 */
int
crm_ipc_ready(crm_ipc_t *client)
{
    int rc;

    pcmk__assert(client != NULL);

    if (!crm_ipc_connected(client)) {
        return -ENOTCONN;
    }

    client->pfd.revents = 0;
    rc = poll(&(client->pfd), 1, 0);
    return (rc < 0)? -errno : rc;
}

long
crm_ipc_read(crm_ipc_t *client)
{
    guint8 *buffer = NULL;
    long rc = -ENOMSG;

    pcmk__assert((client != NULL) && (client->ipc != NULL));
    buffer = g_malloc0(crm_ipc_default_buffer_size());

    do {
        pcmk__ipc_header_t *header = NULL;
        ssize_t bytes = qb_ipcc_event_recv(client->ipc, buffer,
                                           crm_ipc_default_buffer_size(), 0);

        header = (pcmk__ipc_header_t *)(void *) buffer;

        if (bytes <= 0) {
            pcmk__trace("No message received from %s IPC: %s",
                        client->server_name, strerror(-bytes));

            if (!crm_ipc_connected(client) || bytes == -ENOTCONN) {
                pcmk__err("Connection to %s IPC failed", client->server_name);
                rc = -ENOTCONN;
                pcmk__ipc_free_client_buffer(client);

            } else if (bytes == -EAGAIN) {
                rc = -EAGAIN;
            }

            goto done;
        }

        if (bytes != header->size + sizeof(pcmk__ipc_header_t)) {
            pcmk__err("Message size does not match header");
            rc = -EBADMSG;
            pcmk__ipc_free_client_buffer(client);
            goto done;
        }

        pcmk__trace("Received %s IPC event %" PRId32 " size=%" PRIu32 " rc=%zu",
                    client->server_name, header->qb.id, header->qb.size, bytes);

        rc = pcmk__ipc_msg_append(&client->buffer, buffer);

        if (rc == pcmk_rc_ok) {
            break;
        } else if (rc == pcmk_rc_ipc_more) {
            continue;
        } else {
            pcmk__ipc_free_client_buffer(client);
            rc = pcmk_rc2legacy(rc);
            goto done;
        }
    } while (true);

    if (client->buffer->len > 0) {
        /* Data length excluding the header */
        rc = client->buffer->len - sizeof(pcmk__ipc_header_t);
    }

done:
    g_free(buffer);
    return rc;
}

void
pcmk__ipc_free_client_buffer(crm_ipc_t *client)
{
    pcmk__assert(client != NULL);

    if (client->buffer != NULL) {
        g_byte_array_free(client->buffer, TRUE);
        client->buffer = NULL;
    }
}

const char *
crm_ipc_buffer(crm_ipc_t * client)
{
    pcmk__assert(client != NULL);
    CRM_CHECK(client->buffer != NULL, return NULL);
    return (const char *) (client->buffer->data + sizeof(pcmk__ipc_header_t));
}

uint32_t
crm_ipc_buffer_flags(crm_ipc_t * client)
{
    pcmk__ipc_header_t *header = NULL;

    pcmk__assert(client != NULL);
    if (client->buffer == NULL) {
        return 0;
    }

    header = (pcmk__ipc_header_t *)(void*) client->buffer->data;
    return header->flags;
}

const char *
crm_ipc_name(crm_ipc_t * client)
{
    pcmk__assert(client != NULL);
    return client->server_name;
}

// \return Standard Pacemaker return code
static int
internal_ipc_get_reply(crm_ipc_t *client, int request_id, int ms_timeout,
                       ssize_t *bytes, xmlNode **reply)
{
    guint8 *buffer = NULL;
    pcmk__ipc_header_t *hdr = NULL;
    time_t timeout = 0;
    int32_t qb_timeout = -1;
    int rc = pcmk_rc_ok;
    int reply_id = 0;

    if (ms_timeout > 0) {
        timeout = time(NULL) + 1 + pcmk__timeout_ms2s(ms_timeout);
        qb_timeout = 1000;
    }

    /* get the reply */
    pcmk__trace("Expecting reply to %s IPC message %d", client->server_name,
                request_id);

    buffer = g_malloc0(crm_ipc_default_buffer_size());

    do {
        guint8 *data = NULL;
        xmlNode *xml = NULL;

        *bytes = qb_ipcc_recv(client->ipc, buffer, crm_ipc_default_buffer_size(),
                              qb_timeout);

        hdr = (pcmk__ipc_header_t *) (void *) buffer;

        if (*bytes <= 0) {
            if (!crm_ipc_connected(client)) {
                pcmk__err("%s IPC provider disconnected while waiting for "
                          "message %d",
                          client->server_name, request_id);
                break;
            }

            continue;

        } else if (*bytes != hdr->size + sizeof(pcmk__ipc_header_t)) {
            pcmk__err("Message size does not match header");
            *bytes = -EBADMSG;
            break;
        }

        reply_id = hdr->qb.id;

        if (reply_id == request_id) {
            /* Got the reply we were expecting. */
            rc = pcmk__ipc_msg_append(&client->buffer, buffer);

            if (rc == pcmk_rc_ok) {
                break;
            } else if (rc == pcmk_rc_ipc_more) {
                continue;
            } else {
                goto done;
            }
        }

        data = buffer + sizeof(pcmk__ipc_header_t);
        xml = pcmk__xml_parse((const char *) data);

        if (reply_id < request_id) {
            pcmk__err("Discarding old reply %d (need %d)", reply_id,
                      request_id);
            pcmk__log_xml_notice(xml, "OldIpcReply");

        } else if (reply_id > request_id) {
            pcmk__err("Discarding newer reply %d (need %d)", reply_id,
                      request_id);
            pcmk__log_xml_notice(xml, "ImpossibleReply");
            pcmk__assert(hdr->qb.id <= request_id);
        }
    } while (time(NULL) < timeout || (timeout == 0 && *bytes == -EAGAIN));

    if (*bytes < 0) {
        rc = (int) -*bytes; // System errno
        pcmk__trace("%s reply to %s IPC %d: %s " QB_XS " rc=%d",
                    (client->buffer == NULL) ? "No" : "Incomplete",
                    client->server_name, request_id, pcmk_rc_str(rc), rc);
    } else if ((client->buffer != NULL) && (client->buffer->len > 0)) {
        pcmk__trace("Received %u-byte reply %d to %s IPC %d: %.100s",
                    client->buffer->len, reply_id, client->server_name,
                    request_id, crm_ipc_buffer(client));

        if (reply != NULL) {
            *reply = pcmk__xml_parse(crm_ipc_buffer(client));
        }
    }
    /* If bytes == 0, we'll return that to crm_ipc_send which will interpret
     * that as pcmk_rc_ok, log that the IPC request failed (since we did not
     * give it a valid reply), and return that 0 to its callers.  It's up to
     * the callers to take appropriate action after that.
     */

    /* Once we've parsed the client buffer as XML and saved it to reply,
     * there's no need to keep the client buffer around anymore.  Free it here
     * to avoid having to do this anywhere crm_ipc_send is called.
     */
done:
    pcmk__ipc_free_client_buffer(client);
    g_free(buffer);
    return rc;
}

static int
discard_old_replies(crm_ipc_t *client, int32_t ms_timeout)
{
    pcmk__ipc_header_t *header = NULL;
    int rc = pcmk_rc_ok;
    ssize_t qb_rc = 0;
    char *buffer = pcmk__assert_alloc(crm_ipc_default_buffer_size(),
                                      sizeof(char));

    qb_rc = qb_ipcc_recv(client->ipc, buffer, crm_ipc_default_buffer_size(),
                         ms_timeout);

    if (qb_rc < 0) {
        pcmk__warn("Sending %s IPC disabled until pending reply received",
                   client->server_name);
        rc = EALREADY;
        goto done;
    }

    header = (pcmk__ipc_header_t *)(void *) buffer;

    if (!pcmk__valid_ipc_header(header)) {
        rc = EBADMSG;

    } else if (!pcmk__is_set(header->flags, crm_ipc_multipart)
               || pcmk__is_set(header->flags, crm_ipc_multipart_end)) {

        pcmk__notice("Sending %s IPC re-enabled after pending reply received",
                     client->server_name);
        client->need_reply = FALSE;

    } else {
        pcmk__warn("Sending %s IPC disabled until multipart IPC message reply "
                   "received", client->server_name);
        rc = EALREADY;
    }

done:
    free(buffer);
    return rc;
}

/*!
 * \brief Send an IPC XML message
 *
 * \param[in,out] client      Connection to IPC server
 * \param[in]     message     XML message to send
 * \param[in]     flags       Bitmask of crm_ipc_flags
 * \param[in]     ms_timeout  Give up if not sent within this much time
 *                            (5 seconds if 0, or no timeout if negative)
 * \param[out]    reply       Reply from server (or NULL if none)
 *
 * \return Negative errno on error, otherwise size of reply received in bytes
 *         if reply was needed, otherwise number of bytes sent
 */
int
crm_ipc_send(crm_ipc_t *client, const xmlNode *message,
             enum crm_ipc_flags flags, int32_t ms_timeout, xmlNode **reply)
{
    int rc = 0;
    ssize_t bytes = 0;
    ssize_t sent_bytes = 0;
    struct iovec *iov = NULL;
    static uint32_t id = 0;
    pcmk__ipc_header_t *header;
    GString *iov_buffer = NULL;
    uint16_t index = 0;

    if (client == NULL) {
        pcmk__notice("Can't send IPC request without connection (bug?): %.100s",
                     message);
        return -ENOTCONN;

    } else if (!crm_ipc_connected(client)) {
        /* Don't even bother */
        pcmk__notice("Can't send %s IPC requests: Connection closed",
                     client->server_name);
        return -ENOTCONN;
    }

    if (ms_timeout == 0) {
        ms_timeout = 5000;
    }

    /* This block exists only to clear out any old replies that we haven't
     * yet read.  We don't care about their contents since it's too late to
     * do anything with them, so we just read and throw them away.
     */
    if (client->need_reply) {
        int discard_rc = discard_old_replies(client, ms_timeout);

        if (discard_rc != pcmk_rc_ok) {
            return pcmk_rc2legacy(discard_rc);
        }
    }

    id++;
    CRM_LOG_ASSERT(id != 0); /* Crude wrap-around detection */

    iov_buffer = g_string_sized_new(1024);
    pcmk__xml_string(message, 0, iov_buffer, 0);

    do {
        ssize_t qb_rc = 0;
        time_t timeout = 0;

        rc = pcmk__ipc_prepare_iov(id, iov_buffer, index, &iov, &bytes);

        if ((rc != pcmk_rc_ok) && (rc != pcmk_rc_ipc_more)) {
            pcmk__warn("Couldn't prepare %s IPC request: %s " QB_XS " rc=%d",
                       client->server_name, pcmk_rc_str(rc), rc);
            g_string_free(iov_buffer, TRUE);
            return pcmk_rc2legacy(rc);
        }

        header = iov[0].iov_base;
        pcmk__set_ipc_flags(header->flags, client->server_name, flags);

        if (pcmk__is_set(flags, crm_ipc_proxied)) {
            /* Don't look for a synchronous response */
            pcmk__clear_ipc_flags(flags, "client", crm_ipc_client_response);
        }

        if (pcmk__is_set(header->flags, crm_ipc_multipart)) {
            bool is_end = pcmk__is_set(header->flags, crm_ipc_multipart_end);

            pcmk__trace("Sending %s IPC request %" PRId32 " "
                        "(%spart %" PRIu16 ") of %" PRId32 " bytes "
                        "using %dms timeout",
                        client->server_name, header->qb.id,
                        (is_end ? "final " : ""), index, header->qb.size,
                        ms_timeout);
            pcmk__trace("Text = %s", (char *) iov[1].iov_base);

        } else {
            pcmk__trace("Sending %s IPC request %" PRId32 " "
                        "of %" PRId32 " bytes using %dms timeout",
                        client->server_name, header->qb.id, header->qb.size,
                        ms_timeout);
            pcmk__trace("Text = %s", (char *) iov[1].iov_base);
        }

        /* Send the IPC request, respecting any timeout we were passed */
        if (ms_timeout > 0) {
            timeout = time(NULL) + 1 + pcmk__timeout_ms2s(ms_timeout);
        }

        do {
            qb_rc = qb_ipcc_sendv(client->ipc, iov, 2);
        } while ((qb_rc == -EAGAIN) && ((timeout == 0) || (time(NULL) < timeout)));

        /* An error occurred when sending. */
        if (qb_rc <= 0) {
            rc = (int) qb_rc;   // Negative of system errno
            goto send_cleanup;
        }

        /* Sending succeeded.  The next action depends on whether this was a
         * multipart IPC message or not.
         */
        if (rc == pcmk_rc_ok) {
            /* This was either a standalone IPC message or the last part of
             * a multipart message.  Set the return value and break out of
             * this processing loop.
             */
            sent_bytes += qb_rc;
            rc = (int) sent_bytes;
            break;
        } else {
            /* There's no way to get here for any value other than rc == pcmk_rc_more
             * given the check right after pcmk__ipc_prepare_iov.
             *
             * This was a multipart message, loop to process the next chunk.
             */
            sent_bytes += qb_rc;
            index++;
        }

        pcmk_free_ipc_event(iov);
        iov = NULL;
    } while (true);

    /* If we should not wait for a response, bail now */
    if (!pcmk__is_set(flags, crm_ipc_client_response)) {
        pcmk__trace("Not waiting for reply to %s IPC request %d",
                    client->server_name, header->qb.id);
        goto send_cleanup;
    }

    pcmk__ipc_free_client_buffer(client);
    rc = internal_ipc_get_reply(client, header->qb.id, ms_timeout, &bytes, reply);
    if (rc == pcmk_rc_ok) {
        rc = (int) bytes; // Size of reply received
    } else {
        /* rc is either a positive system errno or a negative standard Pacemaker
         * return code.  If it's an errno, we need to convert it back to a
         * negative number for comparison and return at the end of this function.
         */
        rc = pcmk_rc2legacy(rc);

        if (ms_timeout > 0) {
            /* We didn't get the reply in time, so disable future sends for now.
             * The only alternative would be to close the connection since we
             * don't know how to detect and discard out-of-sequence replies.
             *
             * @TODO Implement out-of-sequence detection
             */
            client->need_reply = TRUE;
        }
    }

  send_cleanup:
    if (!crm_ipc_connected(client)) {
        pcmk__notice("Couldn't send %s IPC request %d: Connection closed "
                     QB_XS " rc=%d",
                     client->server_name, header->qb.id, rc);

    } else if (rc == -ETIMEDOUT) {
        pcmk__warn("%s IPC request %d failed: %s after %dms " QB_XS " rc=%d",
                   client->server_name, header->qb.id, pcmk_strerror(rc),
                   ms_timeout, rc);
        crm_write_blackbox(0, NULL);

    } else if (rc <= 0) {
        pcmk__warn("%s IPC request %d failed: %s " QB_XS " rc=%d",
                   client->server_name, header->qb.id,
                   ((rc == 0)? "No bytes sent" : pcmk_strerror(rc)), rc);
    }

    g_string_free(iov_buffer, TRUE);
    pcmk_free_ipc_event(iov);
    // coverity[return_overflow]
    return rc;
}

/*!
 * \brief Ensure an IPC provider has expected user or group
 *
 * \param[in]  qb_ipc  libqb client connection if available
 * \param[in]  sock    Connected Unix socket for IPC
 * \param[in]  refuid  Expected user ID
 * \param[in]  refgid  Expected group ID
 * \param[out] gotpid  If not NULL, where to store provider's actual process ID
 *                     (or 1 on platforms where ID is not available)
 * \param[out] gotuid  If not NULL, where to store provider's actual user ID
 * \param[out] gotgid  If not NULL, where to store provider's actual group ID
 *
 * \return Standard Pacemaker return code
 * \note An actual user ID of 0 (root) will always be considered authorized,
 *       regardless of the expected values provided. The caller can use the
 *       output arguments to be stricter than this function.
 */
static int
is_ipc_provider_expected(qb_ipcc_connection_t *qb_ipc, int sock,
                         uid_t refuid, gid_t refgid,
                         pid_t *gotpid, uid_t *gotuid, gid_t *gotgid)
{
    int rc = EOPNOTSUPP;
    pid_t found_pid = 0;
    uid_t found_uid = 0;
    gid_t found_gid = 0;

#ifdef HAVE_QB_IPCC_AUTH_GET
    if (qb_ipc != NULL) {
        rc = qb_ipcc_auth_get(qb_ipc, &found_pid, &found_uid, &found_gid);
        rc = -rc; // libqb returns 0 or -errno
        if (rc == pcmk_rc_ok) {
            goto found;
        }
    }
#endif

#ifdef HAVE_UCRED
    {
        struct ucred ucred;
        socklen_t ucred_len = sizeof(ucred);

        if (getsockopt(sock, SOL_SOCKET, SO_PEERCRED, &ucred, &ucred_len) < 0) {
            rc = errno;
        } else if (ucred_len != sizeof(ucred)) {
            rc = EOPNOTSUPP;
        } else {
            found_pid = ucred.pid;
            found_uid = ucred.uid;
            found_gid = ucred.gid;
            goto found;
        }
    }
#endif

#ifdef HAVE_SOCKPEERCRED
    {
        struct sockpeercred sockpeercred;
        socklen_t sockpeercred_len = sizeof(sockpeercred);

        if (getsockopt(sock, SOL_SOCKET, SO_PEERCRED,
                       &sockpeercred, &sockpeercred_len) < 0) {
            rc = errno;
        } else if (sockpeercred_len != sizeof(sockpeercred)) {
            rc = EOPNOTSUPP;
        } else {
            found_pid = sockpeercred.pid;
            found_uid = sockpeercred.uid;
            found_gid = sockpeercred.gid;
            goto found;
        }
    }
#endif

#ifdef HAVE_GETPEEREID // For example, FreeBSD
    if (getpeereid(sock, &found_uid, &found_gid) < 0) {
        rc = errno;
    } else {
        found_pid = PCMK__SPECIAL_PID;
        goto found;
    }
#endif

#ifdef HAVE_GETPEERUCRED
    {
        ucred_t *ucred = NULL;

        if (getpeerucred(sock, &ucred) < 0) {
            rc = errno;
        } else {
            found_pid = ucred_getpid(ucred);
            found_uid = ucred_geteuid(ucred);
            found_gid = ucred_getegid(ucred);
            ucred_free(ucred);
            goto found;
        }
    }
#endif

    return rc; // If we get here, nothing succeeded

found:
    if (gotpid != NULL) {
        *gotpid = found_pid;
    }
    if (gotuid != NULL) {
        *gotuid = found_uid;
    }
    if (gotgid != NULL) {
        *gotgid = found_gid;
    }
    if ((found_uid != 0) && (found_uid != refuid) && (found_gid != refgid)) {
        return pcmk_rc_ipc_unauthorized;
    }
    return pcmk_rc_ok;
}

int
crm_ipc_is_authentic_process(int sock, uid_t refuid, gid_t refgid,
                             pid_t *gotpid, uid_t *gotuid, gid_t *gotgid)
{
    int ret = is_ipc_provider_expected(NULL, sock, refuid, refgid,
                                       gotpid, gotuid, gotgid);

    /* The old function had some very odd return codes*/
    if (ret == 0) {
        return 1;
    } else if (ret == pcmk_rc_ipc_unauthorized) {
        return 0;
    } else {
        return pcmk_rc2legacy(ret);
    }
}

int
pcmk__ipc_is_authentic_process_active(const char *name, uid_t refuid,
                                      gid_t refgid, pid_t *gotpid)
{
    static char last_asked_name[PATH_MAX / 2] = "";  /* log spam prevention */
    int fd;
    int rc = pcmk_rc_ipc_unresponsive;
    int auth_rc = 0;
    int32_t qb_rc;
    pid_t found_pid = 0; uid_t found_uid = 0; gid_t found_gid = 0;
    qb_ipcc_connection_t *c;
#ifdef HAVE_QB_IPCC_CONNECT_ASYNC
    struct pollfd pollfd = { 0, };
    int poll_rc;

    c = qb_ipcc_connect_async(name, 0,
                              &(pollfd.fd));
#else
    c = qb_ipcc_connect(name, 0);
#endif
    if (c == NULL) {
        pcmk__info("Could not connect to %s IPC: %s", name, strerror(errno));
        rc = pcmk_rc_ipc_unresponsive;
        goto bail;
    }
#ifdef HAVE_QB_IPCC_CONNECT_ASYNC
    pollfd.events = POLLIN;
    do {
        poll_rc = poll(&pollfd, 1, 5000);
    } while ((poll_rc == -1) && (errno == EINTR));

    /* If poll() failed, given that disconnect function is not registered yet,
     * qb_ipcc_disconnect() won't clean up the socket. In any case, call
     * qb_ipcc_connect_continue() here so that it may fail and do the cleanup
     * for us.
     */
    if (qb_ipcc_connect_continue(c) != 0) {
        pcmk__info("Could not connect to %s IPC: %s", name,
                   ((poll_rc == 0)? "timeout" :strerror(errno)));
        rc = pcmk_rc_ipc_unresponsive;
        c = NULL; // qb_ipcc_connect_continue cleaned up for us
        goto bail;
    }
#endif

    qb_rc = qb_ipcc_fd_get(c, &fd);
    if (qb_rc != 0) {
        rc = (int) -qb_rc; // System errno
        pcmk__err("Could not get fd from %s IPC: %s " QB_XS " rc=%d",
                  name, pcmk_rc_str(rc), rc);
        goto bail;
    }

    auth_rc = is_ipc_provider_expected(c, fd, refuid, refgid,
                                       &found_pid, &found_uid, &found_gid);
    if (auth_rc == pcmk_rc_ipc_unauthorized) {
        pcmk__err("Daemon (IPC %s) effectively blocked with unauthorized "
                  "process %lld (uid: %lld, gid: %lld)",
                  name, (long long) PCMK__SPECIAL_PID_AS_0(found_pid),
                  (long long) found_uid, (long long) found_gid);
        rc = pcmk_rc_ipc_unauthorized;
        goto bail;
    }

    if (auth_rc != pcmk_rc_ok) {
        rc = auth_rc;
        pcmk__err("Could not get peer credentials from %s IPC: %s "
                  QB_XS " rc=%d",
                  name, pcmk_rc_str(rc), rc);
        goto bail;
    }

    if (gotpid != NULL) {
        *gotpid = found_pid;
    }

    rc = pcmk_rc_ok;
    if (((found_uid != refuid) || (found_gid != refgid))
        && !pcmk__str_eq(name, last_asked_name, pcmk__str_none)) {

        if ((found_uid == 0) && (refuid != 0)) {
            pcmk__warn("Daemon (IPC %s) runs as root, whereas the expected "
                       "credentials are %lld:%lld, hazard of violating the "
                       "least privilege principle",
                       name, (long long) refuid, (long long) refgid);
        } else {
            pcmk__notice("Daemon (IPC %s) runs as %lld:%lld, whereas the "
                         "expected credentials are %lld:%lld, which may "
                         "mean a different set of privileges than expected",
                         name, (long long) found_uid, (long long) found_gid,
                         (long long) refuid, (long long) refgid);
        }
        memccpy(last_asked_name, name, '\0', sizeof(last_asked_name));
    }

bail:
    if (c != NULL) {
        qb_ipcc_disconnect(c);
    }
    return rc;
}

// Deprecated functions kept only for backward API compatibility
// LCOV_EXCL_START

#include <crm/common/ipc_client_compat.h>

bool
crm_ipc_connect(crm_ipc_t *client)
{
    int rc = pcmk__connect_generic_ipc(client);

    if (rc == pcmk_rc_ok) {
        return true;
    }
    if ((client != NULL) && (client->ipc == NULL)) {
        errno = (rc > 0)? rc : ENOTCONN;
        pcmk__debug("Could not establish %s IPC connection: %s (%d)",
                    client->server_name, pcmk_rc_str(errno), errno);
    } else if (rc == pcmk_rc_ipc_unauthorized) {
        pcmk__err("%s IPC provider authentication failed",
                  (client == NULL)? "Pacemaker" : client->server_name);
        errno = ECONNABORTED;
    } else {
        pcmk__err("Could not verify authenticity of %s IPC provider",
                  (client == NULL)? "Pacemaker" : client->server_name);
        errno = ENOTCONN;
    }
    return false;
}

// LCOV_EXCL_STOP
// End deprecated API
