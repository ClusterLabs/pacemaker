/*
 * Copyright 2004-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#if defined(US_AUTH_PEERCRED_UCRED) || defined(US_AUTH_PEERCRED_SOCKPEERCRED)
#  ifdef US_AUTH_PEERCRED_UCRED
#    ifndef _GNU_SOURCE
#      define _GNU_SOURCE
#    endif
#  endif
#  include <sys/socket.h>
#elif defined(US_AUTH_GETPEERUCRED)
#  include <ucred.h>
#endif

#include <stdio.h>
#include <sys/types.h>
#include <errno.h>
#include <bzlib.h>

#include <crm/crm.h>   /* indirectly: pcmk_err_generic */
#include <crm/msg_xml.h>
#include <crm/common/ipc.h>
#include <crm/common/ipc_internal.h>
#include "crmcommon_private.h"

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

    (*api)->ipc_size_max = 0;

    // Set server methods and max_size (if not default)
    switch (server) {
        case pcmk_ipc_attrd:
            break;

        case pcmk_ipc_based:
            (*api)->ipc_size_max = 512 * 1024; // 512KB
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
            // @TODO max_size could vary by client, maybe take as argument?
            (*api)->ipc_size_max = 5 * 1024 * 1024; // 5MB
            break;
    }
    if ((*api)->cmds == NULL) {
        pcmk_free_ipc_api(*api);
        *api = NULL;
        return ENOMEM;
    }

    (*api)->ipc = crm_ipc_new(pcmk_ipc_name(*api, false),
                              (*api)->ipc_size_max);
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
    crm_trace("Created %s API IPC object", pcmk_ipc_name(*api, true));
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
 * \param[in] api         IPC API connection
 * \param[in] event_type  The type of event that occurred
 * \param[in] status      Event status
 * \param[in] event_data  Event-specific data
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
 * \param[in]  user_data  IPC API connection that disconnected
 *
 * \note This function can be used as a main loop IPC destroy callback.
 */
static void
ipc_post_disconnect(gpointer user_data)
{
    pcmk_ipc_api_t *api = user_data;

    crm_info("Disconnected from %s IPC API", pcmk_ipc_name(api, true));

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
        crm_trace("Freeing IPC API object after disconnect");
        free(api);
    }
}

/*!
 * \brief Free the contents of an IPC API object
 *
 * \param[in] api  IPC API object to free
 */
void
pcmk_free_ipc_api(pcmk_ipc_api_t *api)
{
    bool free_on_disconnect = false;

    if (api == NULL) {
        return;
    }
    crm_debug("Releasing %s IPC API", pcmk_ipc_name(api, true));

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
        crm_trace("Freeing IPC API object");
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
pcmk_ipc_name(pcmk_ipc_api_t *api, bool for_log)
{
    if (api == NULL) {
        return for_log? "Pacemaker" : NULL;
    }
    switch (api->server) {
        case pcmk_ipc_attrd:
            return for_log? "attribute manager" : NULL /* T_ATTRD */;

        case pcmk_ipc_based:
            return for_log? "CIB manager" : NULL /* PCMK__SERVER_BASED_RW */;

        case pcmk_ipc_controld:
            return for_log? "controller" : CRM_SYSTEM_CRMD;

        case pcmk_ipc_execd:
            return for_log? "executor" : NULL /* CRM_SYSTEM_LRMD */;

        case pcmk_ipc_fenced:
            return for_log? "fencer" : NULL /* "stonith-ng" */;

        case pcmk_ipc_pacemakerd:
            return for_log? "launcher" : CRM_SYSTEM_MCP;

        case pcmk_ipc_schedulerd:
            return for_log? "scheduler" : CRM_SYSTEM_PENGINE;

        default:
            return for_log? "Pacemaker" : NULL;
    }
}

/*!
 * \brief Check whether an IPC API connection is active
 *
 * \param[in] api  IPC API connection
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
 * \param[in] api  IPC API connection
 */
static bool
call_api_dispatch(pcmk_ipc_api_t *api, xmlNode *message)
{
    crm_log_xml_trace(message, "ipc-received");
    if ((api->cmds != NULL) && (api->cmds->dispatch != NULL)) {
        return api->cmds->dispatch(api, message);
    }

    return false;
}

#define MORE_MESSAGES -1

/* Do the hard work of dispatch_ipc_data.  This is split out into its own
 * function so it can be shared with pcmk__send_ipc_request.  The return
 * value is as follows:
 *
 * pcmk_rc_error: Some error occurred.  It's up to the caller to decide
 *                what to do with that fact.
 * pcmk_rc_ok: There are no more messages expected from the server.  Quit
 *             reading.
 * MORE_MESSAGES: There are more messages expected from the server.  Keep
 *                reading.
 */
static int
dispatch_ipc_data(const char *buffer, pcmk_ipc_api_t *api)
{
    bool more = false;
    xmlNode *msg;

    if (buffer == NULL) {
        crm_warn("Empty message received from %s IPC",
                 pcmk_ipc_name(api, true));
        return pcmk_rc_error;
    }

    msg = string2xml(buffer);
    if (msg == NULL) {
        crm_warn("Malformed message received from %s IPC",
                 pcmk_ipc_name(api, true));
        return pcmk_rc_error;
    }

    more = call_api_dispatch(api, msg);
    free_xml(msg);

    if (more) {
        return MORE_MESSAGES;
    } else {
        return pcmk_rc_ok;
    }
}

/*!
 * \internal
 * \brief Dispatch data read from IPC source
 *
 * \param[in] buffer     Data read from IPC
 * \param[in] length     Number of bytes of data in buffer (ignored)
 * \param[in] user_data  IPC object
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
 *       crm_ipc_get_fd(api->ipc), so the caller can call poll() themselves.
 */
int
pcmk_poll_ipc(pcmk_ipc_api_t *api, int timeout_ms)
{
    int rc;
    struct pollfd pollfd = { 0, };

    if ((api == NULL) || (api->dispatch_type != pcmk_ipc_dispatch_poll)) {
        return EINVAL;
    }
    pollfd.fd = crm_ipc_get_fd(api->ipc);
    pollfd.events = POLLIN;
    rc = poll(&pollfd, 1, timeout_ms);
    if (rc < 0) {
        return errno;
    } else if (rc == 0) {
        return EAGAIN;
    }
    return pcmk_rc_ok;
}

/*!
 * \brief Dispatch available messages on an IPC connection (without main loop)
 *
 * \param[in]  api  IPC API connection
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
    crm_debug("Connected to %s IPC (attached to main loop)",
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
    int rc;

    if (!crm_ipc_connect(api->ipc)) {
        rc = errno;
        crm_ipc_close(api->ipc);
        return rc;
    }
    crm_debug("Connected to %s IPC (without main loop)",
              pcmk_ipc_name(api, true));
    return pcmk_rc_ok;
}

/*!
 * \brief Connect to a Pacemaker daemon via IPC
 *
 * \param[in]  api            IPC API instance
 * \param[out] dispatch_type  How IPC replies should be dispatched
 *
 * \return Standard Pacemaker return code
 */
int
pcmk_connect_ipc(pcmk_ipc_api_t *api, enum pcmk_ipc_dispatch dispatch_type)
{
    int rc = pcmk_rc_ok;

    if (api == NULL) {
        crm_err("Cannot connect to uninitialized API object");
        return EINVAL;
    }

    if (api->ipc == NULL) {
        api->ipc = crm_ipc_new(pcmk_ipc_name(api, false),
                                  api->ipc_size_max);
        if (api->ipc == NULL) {
            crm_err("Failed to re-create IPC API");
            return ENOMEM;
        }
    }

    if (crm_ipc_connected(api->ipc)) {
        crm_trace("Already connected to %s IPC API", pcmk_ipc_name(api, true));
        return pcmk_rc_ok;
    }

    api->dispatch_type = dispatch_type;
    switch (dispatch_type) {
        case pcmk_ipc_dispatch_main:
            rc = connect_with_main_loop(api);
            break;

        case pcmk_ipc_dispatch_sync:
        case pcmk_ipc_dispatch_poll:
            rc = connect_without_main_loop(api);
            break;
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
 * \brief Disconnect an IPC API instance
 *
 * \param[in]  api  IPC API connection
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

                crm_ipc_destroy(ipc);
                ipc_post_disconnect(api);
            }
            break;
    }
}

/*!
 * \brief Register a callback for IPC API events
 *
 * \param[in] api          IPC API connection
 * \param[in] callback     Callback to register
 * \param[in] userdata     Caller data to pass to callback
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
 * \param[in] api          IPC API connection
 * \param[in] request      XML request to send
 *
 * \return Standard Pacemaker return code
 *
 * \note Daemon-specific IPC API functions should call this function to send
 *       requests, because it handles different dispatch types appropriately.
 */
int
pcmk__send_ipc_request(pcmk_ipc_api_t *api, xmlNode *request)
{
    int rc;
    xmlNode *reply = NULL;
    enum crm_ipc_flags flags = crm_ipc_flags_none;

    if ((api == NULL) || (api->ipc == NULL) || (request == NULL)) {
        return EINVAL;
    }
    crm_log_xml_trace(request, "ipc-sent");

    // Synchronous dispatch requires waiting for a reply
    if ((api->dispatch_type == pcmk_ipc_dispatch_sync)
        && (api->cmds != NULL)
        && (api->cmds->reply_expected != NULL)
        && (api->cmds->reply_expected(api, request))) {
        flags = crm_ipc_client_response;
    }

    // The 0 here means a default timeout of 5 seconds
    rc = crm_ipc_send(api->ipc, request, flags, 0, &reply);

    if (rc < 0) {
        return pcmk_legacy2rc(rc);
    } else if (rc == 0) {
        return ENODATA;
    }

    // With synchronous dispatch, we dispatch any reply now
    if (reply != NULL) {
        bool more = call_api_dispatch(api, reply);

        free_xml(reply);

        while (more) {
            rc = crm_ipc_read(api->ipc);

            if (rc == -EAGAIN || rc == -ENOMSG || rc == pcmk_ok) {
                return pcmk_rc_ok;
            } else if (rc < 0) {
                return -rc;
            }

            dispatch_ipc_data(crm_ipc_buffer(api->ipc), 0, api);
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
create_purge_node_request(pcmk_ipc_api_t *api, const char *node_name,
                          uint32_t nodeid)
{
    xmlNode *request = NULL;
    const char *client = crm_system_name? crm_system_name : "client";

    switch (api->server) {
        case pcmk_ipc_attrd:
            request = create_xml_node(NULL, __func__);
            crm_xml_add(request, F_TYPE, T_ATTRD);
            crm_xml_add(request, F_ORIG, crm_system_name);
            crm_xml_add(request, PCMK__XA_TASK, PCMK__ATTRD_CMD_PEER_REMOVE);
            crm_xml_add(request, PCMK__XA_ATTR_NODE_NAME, node_name);
            if (nodeid > 0) {
                crm_xml_add_int(request, PCMK__XA_ATTR_NODE_ID, (int) nodeid);
            }
            break;

        case pcmk_ipc_controld:
        case pcmk_ipc_fenced:
        case pcmk_ipc_pacemakerd:
            request = create_request(CRM_OP_RM_NODE_CACHE, NULL, NULL,
                                     pcmk_ipc_name(api, false), client, NULL);
            if (nodeid > 0) {
                crm_xml_set_id(request, "%lu", (unsigned long) nodeid);
            }
            crm_xml_add(request, XML_ATTR_UNAME, node_name);
            break;

        case pcmk_ipc_based:
        case pcmk_ipc_execd:
        case pcmk_ipc_schedulerd:
            break;
    }
    return request;
}

/*!
 * \brief Ask a Pacemaker daemon to purge a node from its peer cache
 *
 * \param[in]  api        IPC API connection
 * \param[in]  node_name  If not NULL, name of node to purge
 * \param[in]  nodeid     If not 0, node ID of node to purge
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
    free_xml(request);

    crm_debug("%s peer cache purge of node %s[%lu]: rc=%d",
              pcmk_ipc_name(api, true), node_name, (unsigned long) nodeid, rc);
    return rc;
}

/*
 * Generic IPC API (to eventually be deprecated as public API and made internal)
 */

struct crm_ipc_s {
    struct pollfd pfd;
    unsigned int max_buf_size; // maximum bytes we can send or receive over IPC
    unsigned int buf_size;     // size of allocated buffer
    int msg_size;
    int need_reply;
    char *buffer;
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
 */
crm_ipc_t *
crm_ipc_new(const char *name, size_t max_size)
{
    crm_ipc_t *client = NULL;

    client = calloc(1, sizeof(crm_ipc_t));
    if (client == NULL) {
        crm_err("Could not create IPC connection: %s", strerror(errno));
        return NULL;
    }

    client->server_name = strdup(name);
    if (client->server_name == NULL) {
        crm_err("Could not create %s IPC connection: %s",
                name, strerror(errno));
        free(client);
        return NULL;
    }
    client->buf_size = pcmk__ipc_buffer_size(max_size);
    client->buffer = malloc(client->buf_size);
    if (client->buffer == NULL) {
        crm_err("Could not create %s IPC connection: %s",
                name, strerror(errno));
        free(client->server_name);
        free(client);
        return NULL;
    }

    /* Clients initiating connection pick the max buf size */
    client->max_buf_size = client->buf_size;

    client->pfd.fd = -1;
    client->pfd.events = POLLIN;
    client->pfd.revents = 0;

    return client;
}

/*!
 * \brief Establish an IPC connection to a Pacemaker component
 *
 * \param[in] client  Connection instance obtained from crm_ipc_new()
 *
 * \return TRUE on success, FALSE otherwise (in which case errno will be set;
 *         specifically, in case of discovering the remote side is not
 *         authentic, its value is set to ECONNABORTED).
 */
bool
crm_ipc_connect(crm_ipc_t * client)
{
    uid_t cl_uid = 0;
    gid_t cl_gid = 0;
    pid_t found_pid = 0; uid_t found_uid = 0; gid_t found_gid = 0;
    int rv;

    client->need_reply = FALSE;
    client->ipc = qb_ipcc_connect(client->server_name, client->buf_size);

    if (client->ipc == NULL) {
        crm_debug("Could not establish %s IPC connection: %s (%d)",
                  client->server_name, pcmk_rc_str(errno), errno);
        return FALSE;
    }

    client->pfd.fd = crm_ipc_get_fd(client);
    if (client->pfd.fd < 0) {
        rv = errno;
        /* message already omitted */
        crm_ipc_close(client);
        errno = rv;
        return FALSE;
    }

    rv = pcmk_daemon_user(&cl_uid, &cl_gid);
    if (rv < 0) {
        /* message already omitted */
        crm_ipc_close(client);
        errno = -rv;
        return FALSE;
    }

    if ((rv = pcmk__crm_ipc_is_authentic_process(client->ipc, client->pfd.fd, cl_uid, cl_gid,
                                                  &found_pid, &found_uid,
                                                  &found_gid)) == pcmk_rc_ipc_unauthorized) {
        crm_err("%s IPC provider authentication failed: process %lld has "
                "uid %lld (expected %lld) and gid %lld (expected %lld)",
                client->server_name,
                (long long) PCMK__SPECIAL_PID_AS_0(found_pid),
                (long long) found_uid, (long long) cl_uid,
                (long long) found_gid, (long long) cl_gid);
        crm_ipc_close(client);
        errno = ECONNABORTED;
        return FALSE;

    } else if (rv != pcmk_rc_ok) {
        crm_perror(LOG_ERR, "Could not verify authenticity of %s IPC provider",
                   client->server_name);
        crm_ipc_close(client);
        if (rv > 0) {
            errno = rv;
        } else {
            errno = ENOTCONN;
        }
        return FALSE;
    }

    qb_ipcc_context_set(client->ipc, client);

    client->max_buf_size = qb_ipcc_get_buffer_size(client->ipc);
    if (client->max_buf_size > client->buf_size) {
        free(client->buffer);
        client->buffer = calloc(1, client->max_buf_size);
        client->buf_size = client->max_buf_size;
    }
    return TRUE;
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
            crm_notice("Destroying active %s IPC connection",
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
            crm_trace("Destroying inactive %s IPC connection",
                      client->server_name);
        }
        free(client->buffer);
        free(client->server_name);
        free(client);
    }
}

int
crm_ipc_get_fd(crm_ipc_t * client)
{
    int fd = 0;

    if (client && client->ipc && (qb_ipcc_fd_get(client->ipc, &fd) == 0)) {
        return fd;
    }
    errno = EINVAL;
    crm_perror(LOG_ERR, "Could not obtain file descriptor for %s IPC",
               (client? client->server_name : "unspecified"));
    return -errno;
}

bool
crm_ipc_connected(crm_ipc_t * client)
{
    bool rc = FALSE;

    if (client == NULL) {
        crm_trace("No client");
        return FALSE;

    } else if (client->ipc == NULL) {
        crm_trace("No connection");
        return FALSE;

    } else if (client->pfd.fd < 0) {
        crm_trace("Bad descriptor");
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
 * \param[in] client  Connection to check
 *
 * \return Positive value if ready to be read, 0 if not ready, -errno on error
 */
int
crm_ipc_ready(crm_ipc_t *client)
{
    int rc;

    CRM_ASSERT(client != NULL);

    if (crm_ipc_connected(client) == FALSE) {
        return -ENOTCONN;
    }

    client->pfd.revents = 0;
    rc = poll(&(client->pfd), 1, 0);
    return (rc < 0)? -errno : rc;
}

// \return Standard Pacemaker return code
static int
crm_ipc_decompress(crm_ipc_t * client)
{
    pcmk__ipc_header_t *header = (pcmk__ipc_header_t *)(void*)client->buffer;

    if (header->size_compressed) {
        int rc = 0;
        unsigned int size_u = 1 + header->size_uncompressed;
        /* never let buf size fall below our max size required for ipc reads. */
        unsigned int new_buf_size = QB_MAX((sizeof(pcmk__ipc_header_t) + size_u), client->max_buf_size);
        char *uncompressed = calloc(1, new_buf_size);

        crm_trace("Decompressing message data %u bytes into %u bytes",
                 header->size_compressed, size_u);

        rc = BZ2_bzBuffToBuffDecompress(uncompressed + sizeof(pcmk__ipc_header_t), &size_u,
                                        client->buffer + sizeof(pcmk__ipc_header_t), header->size_compressed, 1, 0);

        if (rc != BZ_OK) {
            crm_err("Decompression failed: %s " CRM_XS " bzerror=%d",
                    bz2_strerror(rc), rc);
            free(uncompressed);
            return EILSEQ;
        }

        /*
         * This assert no longer holds true.  For an identical msg, some clients may
         * require compression, and others may not. If that same msg (event) is sent
         * to multiple clients, it could result in some clients receiving a compressed
         * msg even though compression was not explicitly required for them.
         *
         * CRM_ASSERT((header->size_uncompressed + sizeof(pcmk__ipc_header_t)) >= ipc_buffer_max);
         */
        CRM_ASSERT(size_u == header->size_uncompressed);

        memcpy(uncompressed, client->buffer, sizeof(pcmk__ipc_header_t));       /* Preserve the header */
        header = (pcmk__ipc_header_t *)(void*)uncompressed;

        free(client->buffer);
        client->buf_size = new_buf_size;
        client->buffer = uncompressed;
    }

    CRM_ASSERT(client->buffer[sizeof(pcmk__ipc_header_t) + header->size_uncompressed - 1] == 0);
    return pcmk_rc_ok;
}

long
crm_ipc_read(crm_ipc_t * client)
{
    pcmk__ipc_header_t *header = NULL;

    CRM_ASSERT(client != NULL);
    CRM_ASSERT(client->ipc != NULL);
    CRM_ASSERT(client->buffer != NULL);

    client->buffer[0] = 0;
    client->msg_size = qb_ipcc_event_recv(client->ipc, client->buffer,
                                          client->buf_size, 0);
    if (client->msg_size >= 0) {
        int rc = crm_ipc_decompress(client);

        if (rc != pcmk_rc_ok) {
            return pcmk_rc2legacy(rc);
        }

        header = (pcmk__ipc_header_t *)(void*)client->buffer;
        if (!pcmk__valid_ipc_header(header)) {
            return -EBADMSG;
        }

        crm_trace("Received %s IPC event %d size=%u rc=%d text='%.100s'",
                  client->server_name, header->qb.id, header->qb.size,
                  client->msg_size,
                  client->buffer + sizeof(pcmk__ipc_header_t));

    } else {
        crm_trace("No message received from %s IPC: %s",
                  client->server_name, pcmk_strerror(client->msg_size));

        if (client->msg_size == -EAGAIN) {
            return -EAGAIN;
        }
    }

    if (crm_ipc_connected(client) == FALSE || client->msg_size == -ENOTCONN) {
        crm_err("Connection to %s IPC failed", client->server_name);
    }

    if (header) {
        /* Data excluding the header */
        return header->size_uncompressed;
    }
    return -ENOMSG;
}

const char *
crm_ipc_buffer(crm_ipc_t * client)
{
    CRM_ASSERT(client != NULL);
    return client->buffer + sizeof(pcmk__ipc_header_t);
}

uint32_t
crm_ipc_buffer_flags(crm_ipc_t * client)
{
    pcmk__ipc_header_t *header = NULL;

    CRM_ASSERT(client != NULL);
    if (client->buffer == NULL) {
        return 0;
    }

    header = (pcmk__ipc_header_t *)(void*)client->buffer;
    return header->flags;
}

const char *
crm_ipc_name(crm_ipc_t * client)
{
    CRM_ASSERT(client != NULL);
    return client->server_name;
}

// \return Standard Pacemaker return code
static int
internal_ipc_get_reply(crm_ipc_t *client, int request_id, int ms_timeout,
                       ssize_t *bytes)
{
    time_t timeout = time(NULL) + 1 + (ms_timeout / 1000);
    int rc = pcmk_rc_ok;

    /* get the reply */
    crm_trace("Waiting on reply to %s IPC message %d",
              client->server_name, request_id);
    do {

        *bytes = qb_ipcc_recv(client->ipc, client->buffer, client->buf_size, 1000);
        if (*bytes > 0) {
            pcmk__ipc_header_t *hdr = NULL;

            rc = crm_ipc_decompress(client);
            if (rc != pcmk_rc_ok) {
                return rc;
            }

            hdr = (pcmk__ipc_header_t *)(void*)client->buffer;
            if (hdr->qb.id == request_id) {
                /* Got it */
                break;
            } else if (hdr->qb.id < request_id) {
                xmlNode *bad = string2xml(crm_ipc_buffer(client));

                crm_err("Discarding old reply %d (need %d)", hdr->qb.id, request_id);
                crm_log_xml_notice(bad, "OldIpcReply");

            } else {
                xmlNode *bad = string2xml(crm_ipc_buffer(client));

                crm_err("Discarding newer reply %d (need %d)", hdr->qb.id, request_id);
                crm_log_xml_notice(bad, "ImpossibleReply");
                CRM_ASSERT(hdr->qb.id <= request_id);
            }
        } else if (crm_ipc_connected(client) == FALSE) {
            crm_err("%s IPC provider disconnected while waiting for message %d",
                    client->server_name, request_id);
            break;
        }

    } while (time(NULL) < timeout);

    if (*bytes < 0) {
        rc = (int) -*bytes; // System errno
    }
    return rc;
}

/*!
 * \brief Send an IPC XML message
 *
 * \param[in]  client      Connection to IPC server
 * \param[in]  message     XML message to send
 * \param[in]  flags       Bitmask of crm_ipc_flags
 * \param[in]  ms_timeout  Give up if not sent within this much time
 *                         (5 seconds if 0, or no timeout if negative)
 * \param[out] reply       Reply from server (or NULL if none)
 *
 * \return Negative errno on error, otherwise size of reply received in bytes
 *         if reply was needed, otherwise number of bytes sent
 */
int
crm_ipc_send(crm_ipc_t * client, xmlNode * message, enum crm_ipc_flags flags, int32_t ms_timeout,
             xmlNode ** reply)
{
    int rc = 0;
    ssize_t qb_rc = 0;
    ssize_t bytes = 0;
    struct iovec *iov;
    static uint32_t id = 0;
    static int factor = 8;
    pcmk__ipc_header_t *header;

    if (client == NULL) {
        crm_notice("Can't send IPC request without connection (bug?): %.100s",
                   message);
        return -ENOTCONN;

    } else if (crm_ipc_connected(client) == FALSE) {
        /* Don't even bother */
        crm_notice("Can't send %s IPC requests: Connection closed",
                   client->server_name);
        return -ENOTCONN;
    }

    if (ms_timeout == 0) {
        ms_timeout = 5000;
    }

    if (client->need_reply) {
        qb_rc = qb_ipcc_recv(client->ipc, client->buffer, client->buf_size, ms_timeout);
        if (qb_rc < 0) {
            crm_warn("Sending %s IPC disabled until pending reply received",
                     client->server_name);
            return -EALREADY;

        } else {
            crm_notice("Sending %s IPC re-enabled after pending reply received",
                       client->server_name);
            client->need_reply = FALSE;
        }
    }

    id++;
    CRM_LOG_ASSERT(id != 0); /* Crude wrap-around detection */
    rc = pcmk__ipc_prepare_iov(id, message, client->max_buf_size, &iov, &bytes);
    if (rc != pcmk_rc_ok) {
        crm_warn("Couldn't prepare %s IPC request: %s " CRM_XS " rc=%d",
                 client->server_name, pcmk_rc_str(rc), rc);
        return pcmk_rc2legacy(rc);
    }

    header = iov[0].iov_base;
    pcmk__set_ipc_flags(header->flags, client->server_name, flags);

    if (pcmk_is_set(flags, crm_ipc_proxied)) {
        /* Don't look for a synchronous response */
        pcmk__clear_ipc_flags(flags, "client", crm_ipc_client_response);
    }

    if(header->size_compressed) {
        if(factor < 10 && (client->max_buf_size / 10) < (bytes / factor)) {
            crm_notice("Compressed message exceeds %d0%% of configured IPC "
                       "limit (%u bytes); consider setting PCMK_ipc_buffer to "
                       "%u or higher",
                       factor, client->max_buf_size, 2 * client->max_buf_size);
            factor++;
        }
    }

    crm_trace("Sending %s IPC request %d of %u bytes using %dms timeout",
              client->server_name, header->qb.id, header->qb.size, ms_timeout);

    if ((ms_timeout > 0) || !pcmk_is_set(flags, crm_ipc_client_response)) {

        time_t timeout = time(NULL) + 1 + (ms_timeout / 1000);

        do {
            /* @TODO Is this check really needed? Won't qb_ipcc_sendv() return
             * an error if it's not connected?
             */
            if (!crm_ipc_connected(client)) {
                goto send_cleanup;
            }

            qb_rc = qb_ipcc_sendv(client->ipc, iov, 2);
        } while ((qb_rc == -EAGAIN) && (time(NULL) < timeout));

        rc = (int) qb_rc; // Negative of system errno, or bytes sent
        if (qb_rc <= 0) {
            goto send_cleanup;

        } else if (!pcmk_is_set(flags, crm_ipc_client_response)) {
            crm_trace("Not waiting for reply to %s IPC request %d",
                      client->server_name, header->qb.id);
            goto send_cleanup;
        }

        rc = internal_ipc_get_reply(client, header->qb.id, ms_timeout, &bytes);
        if (rc != pcmk_rc_ok) {
            /* We didn't get the reply in time, so disable future sends for now.
             * The only alternative would be to close the connection since we
             * don't know how to detect and discard out-of-sequence replies.
             *
             * @TODO Implement out-of-sequence detection
             */
            client->need_reply = TRUE;
        }
        rc = (int) bytes; // Negative system errno, or size of reply received

    } else {
        // No timeout, and client response needed
        do {
            qb_rc = qb_ipcc_sendv_recv(client->ipc, iov, 2, client->buffer,
                                       client->buf_size, -1);
        } while ((qb_rc == -EAGAIN) && crm_ipc_connected(client));
        rc = (int) qb_rc; // Negative system errno, or size of reply received
    }

    if (rc > 0) {
        pcmk__ipc_header_t *hdr = (pcmk__ipc_header_t *)(void*)client->buffer;

        crm_trace("Received %d-byte reply %d to %s IPC %d: %.100s",
                  rc, hdr->qb.id, client->server_name, header->qb.id,
                  crm_ipc_buffer(client));

        if (reply) {
            *reply = string2xml(crm_ipc_buffer(client));
        }

    } else {
        crm_trace("No reply to %s IPC %d: rc=%d",
                  client->server_name, header->qb.id, rc);
    }

  send_cleanup:
    if (crm_ipc_connected(client) == FALSE) {
        crm_notice("Couldn't send %s IPC request %d: Connection closed "
                   CRM_XS " rc=%d", client->server_name, header->qb.id, rc);

    } else if (rc == -ETIMEDOUT) {
        crm_warn("%s IPC request %d failed: %s after %dms " CRM_XS " rc=%d",
                 client->server_name, header->qb.id, pcmk_strerror(rc),
                 ms_timeout, rc);
        crm_write_blackbox(0, NULL);

    } else if (rc <= 0) {
        crm_warn("%s IPC request %d failed: %s " CRM_XS " rc=%d",
                 client->server_name, header->qb.id,
                 ((rc == 0)? "No bytes sent" : pcmk_strerror(rc)), rc);
    }

    pcmk_free_ipc_event(iov);
    return rc;
}

int
pcmk__crm_ipc_is_authentic_process(qb_ipcc_connection_t *qb_ipc, int sock, uid_t refuid, gid_t refgid,
                                   pid_t *gotpid, uid_t *gotuid, gid_t *gotgid)
{
    int ret = 0;
    pid_t found_pid = 0; uid_t found_uid = 0; gid_t found_gid = 0;
#if defined(US_AUTH_PEERCRED_UCRED)
    struct ucred ucred;
    socklen_t ucred_len = sizeof(ucred);
#endif

#ifdef HAVE_QB_IPCC_AUTH_GET
    if (qb_ipc && !qb_ipcc_auth_get(qb_ipc, &found_pid, &found_uid, &found_gid)) {
        goto do_checks;
    }
#endif

#if defined(US_AUTH_PEERCRED_UCRED)
    if (!getsockopt(sock, SOL_SOCKET, SO_PEERCRED,
                    &ucred, &ucred_len)
                && ucred_len == sizeof(ucred)) {
        found_pid = ucred.pid; found_uid = ucred.uid; found_gid = ucred.gid;

#elif defined(US_AUTH_PEERCRED_SOCKPEERCRED)
    struct sockpeercred sockpeercred;
    socklen_t sockpeercred_len = sizeof(sockpeercred);

    if (!getsockopt(sock, SOL_SOCKET, SO_PEERCRED,
                    &sockpeercred, &sockpeercred_len)
                && sockpeercred_len == sizeof(sockpeercred_len)) {
        found_pid = sockpeercred.pid;
        found_uid = sockpeercred.uid; found_gid = sockpeercred.gid;

#elif defined(US_AUTH_GETPEEREID)
    if (!getpeereid(sock, &found_uid, &found_gid)) {
        found_pid = PCMK__SPECIAL_PID;  /* cannot obtain PID (FreeBSD) */

#elif defined(US_AUTH_GETPEERUCRED)
    ucred_t *ucred;
    if (!getpeerucred(sock, &ucred)) {
        errno = 0;
        found_pid = ucred_getpid(ucred);
        found_uid = ucred_geteuid(ucred); found_gid = ucred_getegid(ucred);
        ret = -errno;
        ucred_free(ucred);
        if (ret) {
            return (ret < 0) ? ret : -pcmk_err_generic;
        }

#else
#  error "No way to authenticate a Unix socket peer"
    errno = 0;
    if (0) {
#endif
#ifdef HAVE_QB_IPCC_AUTH_GET
    do_checks:
#endif
        if (gotpid != NULL) {
            *gotpid = found_pid;
        }
        if (gotuid != NULL) {
            *gotuid = found_uid;
        }
        if (gotgid != NULL) {
            *gotgid = found_gid;
        }
        if (found_uid == 0 || found_uid == refuid || found_gid == refgid) {
		ret = 0;
        } else {
                ret = pcmk_rc_ipc_unauthorized;
        }
    } else {
        ret = (errno > 0) ? errno : pcmk_rc_error;
    }
    return ret;
}

int
crm_ipc_is_authentic_process(int sock, uid_t refuid, gid_t refgid,
                             pid_t *gotpid, uid_t *gotuid, gid_t *gotgid)
{
    int ret  = pcmk__crm_ipc_is_authentic_process(NULL, sock, refuid, refgid,
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
        crm_info("Could not connect to %s IPC: %s", name, strerror(errno));
        rc = pcmk_rc_ipc_unresponsive;
        goto bail;
    }
#ifdef HAVE_QB_IPCC_CONNECT_ASYNC
    pollfd.events = POLLIN;
    do {
        poll_rc = poll(&pollfd, 1, 2000);
    } while ((poll_rc == -1) && (errno == EINTR));
    if ((poll_rc <= 0) || (qb_ipcc_connect_continue(c) != 0)) {
        crm_info("Could not connect to %s IPC: %s", name,
                 (poll_rc == 0)?"timeout":strerror(errno));
        rc = pcmk_rc_ipc_unresponsive;
        if (poll_rc > 0) {
            c = NULL; // qb_ipcc_connect_continue cleaned up for us
        }
        goto bail;
    }
#endif

    qb_rc = qb_ipcc_fd_get(c, &fd);
    if (qb_rc != 0) {
        rc = (int) -qb_rc; // System errno
        crm_err("Could not get fd from %s IPC: %s " CRM_XS " rc=%d",
                name, pcmk_rc_str(rc), rc);
        goto bail;
    }

    auth_rc = pcmk__crm_ipc_is_authentic_process(c, fd, refuid, refgid, &found_pid,
                                                 &found_uid, &found_gid);
    if (auth_rc == pcmk_rc_ipc_unauthorized) {
        crm_err("Daemon (IPC %s) effectively blocked with unauthorized"
                " process %lld (uid: %lld, gid: %lld)",
                name, (long long) PCMK__SPECIAL_PID_AS_0(found_pid),
                (long long) found_uid, (long long) found_gid);
        rc = pcmk_rc_ipc_unauthorized;
        goto bail;
    }

    if (auth_rc != pcmk_rc_ok) {
        rc = auth_rc;
        crm_err("Could not get peer credentials from %s IPC: %s "
                CRM_XS " rc=%d", name, pcmk_rc_str(rc), rc);
        goto bail;
    }

    if (gotpid != NULL) {
        *gotpid = found_pid;
    }

    rc = pcmk_rc_ok;
    if ((found_uid != refuid || found_gid != refgid)
            && strncmp(last_asked_name, name, sizeof(last_asked_name))) {
        if ((found_uid == 0) && (refuid != 0)) {
            crm_warn("Daemon (IPC %s) runs as root, whereas the expected"
                     " credentials are %lld:%lld, hazard of violating"
                     " the least privilege principle",
                     name, (long long) refuid, (long long) refgid);
        } else {
            crm_notice("Daemon (IPC %s) runs as %lld:%lld, whereas the"
                       " expected credentials are %lld:%lld, which may"
                       " mean a different set of privileges than expected",
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
