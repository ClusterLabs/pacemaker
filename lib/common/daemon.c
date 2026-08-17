/*
 * Copyright 2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <signal.h>                 // SIG*
#include <stdbool.h>                // bool, false, true
#include <stddef.h>                 // NULL
#include <time.h>                   // time

#include <glib.h>                   // g_clear_pointer, g_main_loop_*
#include <qb/qbipcs.h>              // qb_ipcs_service_handlers

#include <crm/common/ipc.h>         // crm_ipc_*, pcmk_ipc_api_t, pcmk_*_ipc_api
#include <crm/common/logging.h>     // CRM_CHECK
#include <crm/common/mainloop.h>    // mainloop_add_ipc_server
#include <crm/common/results.h>     // CRM_EX_*, crm_exit, pcmk_rc_*

/*!
 * \internal
 * \brief Initialize a previously allocated daemon object
 *
 * \param[in,out] d The daemon object
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__daemon_init(pcmk__daemon_t *d)
{
    d->start_time = time(NULL);

    d->mainloop = g_main_loop_new(NULL, false);
    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Accept a new client IPC connection
 *
 * \param[in,out] d   The daemon object
 * \param[in,out] c   New connection
 * \param[in]     uid Client user id
 * \param[in]     gid Client group id
 *
 * \return pcmk_ok on success, -errno otherwise
 */
int32_t
pcmk__daemon_ipc_accept(pcmk__daemon_t *d, qb_ipcs_connection_t *c,
                        uid_t uid, gid_t gid)
{
    if (d->shutting_down) {
        pcmk__info("Ignoring new connection from pid %d during shutdown",
                   pcmk__client_pid(c));
        return -ECONNREFUSED;
    }

    pcmk__trace("New client connection %p", c);

    if (pcmk__new_client(c, uid, gid) == NULL) {
        return -ENOMEM;
    }

    return pcmk_ok;
}

/*!
 * \internal
 * \brief Clean up IPC communication
 *
 * \param[in,out] d The daemon object
 */
void
pcmk__daemon_ipc_cleanup(pcmk__daemon_t *d)
{
    pcmk__drop_all_clients(d->ipcs);
    g_clear_pointer(&d->ipcs, qb_ipcs_destroy);
    pcmk__client_cleanup();
}

/*!
 * \internal
 * \brief Destroy a client IPC connection
 *
 * \param[in,out] d The daemon object
 * \param[in]     c Connection to destroy
 *
 * \return 0 (do not re-run this callback)
 */
int32_t
pcmk__daemon_ipc_closed(pcmk__daemon_t *d, qb_ipcs_connection_t *c)
{
    pcmk__client_t *client = pcmk__find_client(c);

    if (client == NULL) {
        pcmk__trace("Ignoring request to clean up unknown connection %p", c);
        return 0;
    }

    pcmk__trace("Cleaning up closed client connection %p", c);

    if (d->ipc_fns->closed != NULL) {
        d->ipc_fns->closed(d, client);
    } else {
        pcmk__free_client(client);
    }

    return 0;
}

/*!
 * \internal
 * \brief Destroy a client IPC connection
 *
 * \param[in,out] d The daemon object
 * \param[in,out] c Connection to destroy
 *
 * \note We handle a destroyed connection the same as a closed one,
 *       but we need a separate handler because the return type is different.
 */
void
pcmk__daemon_ipc_destroy(pcmk__daemon_t *d, qb_ipcs_connection_t *c)
{
    pcmk__trace("Destroying client connection %p", c);
    pcmk__daemon_ipc_closed(d, c);
}

/*!
 * \internal
 * \brief Handle an incoming IPC message from a connection
 *
 * \param[in,out] d    The daemon object
 * \param[in,out] c    IPC connection
 * \param[in]     data Message read from the connection
 * \param[in]     size Size of the read message
 */
void
pcmk__daemon_ipc_dispatch(pcmk__daemon_t *d, qb_ipcs_connection_t *c,
                          void *data, size_t size)
{
    int rc = pcmk_rc_ok;
    pcmk__request_t request = {
        .ipc_client = pcmk__find_client(c),
        .ipc_id = 0,
        .ipc_flags = 0,
        .peer = NULL,
        .xml = NULL,
        .call_options = 0,
        .flags = 0,
        .result = PCMK__UNKNOWN_RESULT,
    };

    // Sanity-check, and parse XML from IPC data
    CRM_CHECK(request.ipc_client != NULL, return);
    if (data == NULL) {
        pcmk__debug("No IPC data from PID %d", pcmk__client_pid(c));
        return;
    }

    rc = pcmk__ipc_msg_append(&request.ipc_client->buffer, data);

    if (rc == pcmk_rc_ipc_more) {
        /* We haven't read the complete message yet, so just return. */
        return;
    }

    if (rc != pcmk_rc_ok) {
        /* Some sort of error occurred reassembling the message.  All we can
         * do is clean up, log an error and return.
         */
        pcmk__err("Error when reading IPC message: %s", pcmk_rc_str(rc));

        if (request.ipc_client->buffer != NULL) {
            g_byte_array_free(request.ipc_client->buffer, TRUE);
            request.ipc_client->buffer = NULL;
        }

        return;
    }

    /* We've read the complete message and there's already a header on the
     * front.  Pass it off for processing.
     */
    request.xml = pcmk__client_data2xml(request.ipc_client, &request.ipc_id,
                                        &request.ipc_flags);
    g_byte_array_free(request.ipc_client->buffer, TRUE);
    request.ipc_client->buffer = NULL;

    if (request.xml == NULL) {
        pcmk__debug("Unrecognizable IPC data from PID %d", pcmk__client_pid(c));
        pcmk__ipc_send_ack(request.ipc_client, request.ipc_id, request.ipc_flags,
                           NULL, CRM_EX_PROTOCOL);
        return;
    }

    d->ipc_fns->dispatch(d, &request);

    pcmk__xml_free(request.xml);
    return;
}

/*!
 * \internal
 * \brief Initialize the IPC side of the server
 *
 * This is a generic function that should be good enough for most purposes.
 * Certain servers may require specialized functionality.
 *
 * \param[in,out] d  The daemon object
 * \param[in,out] cb The IPC callback object
 */
bool
pcmk__daemon_ipc_init(pcmk__daemon_t *d, struct qb_ipcs_service_handlers *cb)
{
    pcmk__assert((d->ipcs == NULL) && (cb != NULL));

    d->ipcs = mainloop_add_ipc_server_with_prio(pcmk__server_ipc_name(d->type),
                                                QB_IPC_SHM, cb, d->priority);

    if (d->ipcs == NULL) {
        pcmk__crit("Failed to create %s IPC server; shutting down",
                   pcmk__server_log_name(d->type));
        pcmk__crit("Verify pacemaker and pacemaker_remote are not both "
                   "enabled");
        return false;
    }

    return true;
}

/*!
 * \internal
 * \brief Determine if an instance of an IPC server is already running
 *
 * \param[in,out] d The daemon object
 *
 * \return \c true if an instance of \p d is already running, and \c false if not
 *
 * \note This function can be used to determine if a daemon is up and running
 *       since all daemons use IPC.
 *
 * \note This function only works for those daemons that have been converted
 *       to use \c pcmk_ipc_api_t as the client interface.  Older daemons will
 *       have to use their own daemon specific method to figure this out.
 */
bool
pcmk__daemon_ipc_running(pcmk__daemon_t *d)
{
    pcmk_ipc_api_t *old_instance = NULL;
    int rc = pcmk_rc_ok;

    rc = pcmk_new_ipc_api(&old_instance, d->type);
    if (rc != pcmk_rc_ok) {
        return false;
    }

    rc = pcmk__connect_ipc(old_instance, pcmk_ipc_dispatch_sync, 2);
    if (rc != pcmk_rc_ok) {
        pcmk__debug("No existing %s instance found: %s",
                    pcmk_ipc_name(old_instance, true), pcmk_rc_str(rc));
        pcmk_free_ipc_api(old_instance);
        return false;
    }

    pcmk_disconnect_ipc(old_instance);
    pcmk_free_ipc_api(old_instance);
    return true;
}

/*!
 * \internal
 * \brief Quit the daemon's main loop
 *
 * \param[in,out] d  The daemon object
 * \param[in]     ec The exit code to assign to the daemon
 */
void
pcmk__daemon_quit(pcmk__daemon_t *d, crm_exit_t ec)
{
    if (d->shutting_down) {
        return;
    }

    if ((d->fns != NULL) && (d->fns->quit != NULL)) {
        if (!d->fns->quit(d)) {
            return;
        }
    }

    pcmk__info("Shutting down %s", pcmk__server_log_name(d->type));

    // Tell various functions not to do anything
    d->shutting_down = true;

    d->ec = ec;

    // Don't respond to signals while shutting down
    mainloop_destroy_signal(SIGTERM);
    mainloop_destroy_signal(SIGCHLD);
    mainloop_destroy_signal(SIGPIPE);
    mainloop_destroy_signal(SIGUSR1);
    mainloop_destroy_signal(SIGUSR2);
    mainloop_destroy_signal(SIGTRAP);

    CRM_CHECK((d->mainloop != NULL) && g_main_loop_is_running(d->mainloop),
              return);

    g_main_loop_quit(d->mainloop);
}

/*!
 * \internal
 * \brief Run a daemon
 *
 * \param[in,out] d The daemon object
 */
void
pcmk__daemon_run(pcmk__daemon_t *d)
{
    pcmk__notice("Pacemaker %s successfully started and accepting connections",
                 pcmk__server_log_name(d->type));
    g_main_loop_run(d->mainloop);
    g_clear_pointer(&d->mainloop, g_main_loop_unref);
}

/*!
 * \internal
 * \brief Determine if an instance of an IPC server is already running
 *
 * \param[in,out] d The daemon object
 *
 * \return \c true if an instance of \p d is already running, and \c false if not
 *
 * \note This function only works for older daemons that have not yet been
 *       converted to use the \c pcmk_ipc_api_t client interface.  Once all have
 *       been updated, this function can be removed.
 */
bool
pcmk__generic_ipc_running(pcmk__daemon_t *d)
{
    const char *ipc_name = pcmk__server_ipc_name(d->type);
    crm_ipc_t *old_instance = NULL;
    int rc = pcmk_rc_ok;

    old_instance = crm_ipc_new(ipc_name, 0);
    if (old_instance == NULL) {
        /* This is an error - memory allocation failed, etc. - but crm_ipc_new
         * will have already logged an error message.
         */
        return false;
    }

    rc = pcmk__connect_generic_ipc(old_instance);
    if (rc != pcmk_rc_ok) {
        pcmk__debug("No existing %s instance found: %s", ipc_name,
                    pcmk_rc_str(rc));
        crm_ipc_destroy(old_instance);
        return false;
    }

    crm_ipc_close(old_instance);
    crm_ipc_destroy(old_instance);
    return true;
}
