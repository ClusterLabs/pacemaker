/*
 * Copyright 2020 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */
#ifndef PCMK__CONTROLD_API_H
#define PCMK__CONTROLD_API_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>                // bool

/* This is a demonstration of an abstracted controller IPC API. It is expected
 * that this will be improved and moved to libcrmcommon.
 *
 * @TODO We could consider whether it's reasonable to have a single type for
 * all daemons' IPC APIs (e.g. pcmk_ipc_api_t instead of pcmk_*_api_t). They
 * could potentially have common connect/disconnect methods and then a void* to
 * a group of API-specific methods.
 *
 * In that case, the callback type would also need to be generic, taking
 * (pcmk_ipc_api_t *api, void *api_data, void *user_data), with individual APIs
 * having functions for getting useful info from api_data. If all APIs followed
 * the call_id model, we could use int call_id instead of api_data.
 *
 * A major annoyance is that the controller IPC protocol currently does not have
 * any way to tie a particular reply to a particular request. The current
 * clients (crmadmin, crm_node, and crm_resource) simply know what kind of reply
 * to expect for the kind of request they sent. In crm_resource's case, all it
 * does is count replies, ignoring their content altogether.
 *
 * That really forces us to have a single callback for all events rather than a
 * per-request callback. That in turn implies that callers can only provide a
 * single user data pointer.
 *
 * @TODO Define protocol version constants to use in hello message.
 * @TODO Allow callers to specify timeouts.
 * @TODO Define call IDs for controller ops, while somehow maintaining backward
 *       compatibility, since a client running on a Pacemaker Remote node could
 *       be older or newer than the controller on the connection's cluster
 *       node.
 * @TODO The controller currently does not respond to hello messages. We should
 *       establish a common connection handshake protocol for all daemons that
 *       involves a hello message and acknowledgement. We should support sync
 *       or async connection (i.e. block until the ack is received, or return
 *       after the hello is sent and call a connection callback when the hello
 *       ack is received).
 */

//! \internal
typedef struct pcmk_controld_api_s pcmk_controld_api_t;

//! \internal
typedef struct pcmk_controld_api_callback_s {
    void (*callback)(pcmk_controld_api_t *api, void *api_data, void *user_data);
    void *user_data;
} pcmk_controld_api_cb_t;

//! \internal
struct pcmk_controld_api_s {
    //! \internal
    void *private;

    /*!
     * \internal
     * \brief Connect to the local controller
     *
     * \param[in] api           Controller API instance
     * \param[in] use_mainloop  If true, attach IPC to main loop
     * \param[in] dispatch_cb   If not NULL, call this when replies are received
     * \param[in] destroy_cb    If not NULL, call this if connection drops
     *
     * \return Standard Pacemaker return code
     * \note Only the pointers inside the callback objects need to be
     *       persistent, not the callback objects themselves. The destroy_cb
     *       will be called only for unrequested disconnects.
     */
    int (*connect)(pcmk_controld_api_t *api, bool use_mainloop,
                   pcmk_controld_api_cb_t *dispatch_cb,
                   pcmk_controld_api_cb_t *destroy_cb);

    /*!
     * \internal
     * \brief Disconnect from the local controller
     *
     * \param[in] api       Controller API instance
     *
     * \return Standard Pacemaker return code
     */
    int (*disconnect)(pcmk_controld_api_t *api);

    /*!
     * \internal
     * \brief Check number of replies still expected from controller
     *
     * \param[in] api       Controller API instance
     *
     * \return Number of expected replies
     */
    unsigned int (*replies_expected)(pcmk_controld_api_t *api);

    /*!
     * \internal
     * \brief Send a reprobe controller operation
     *
     * \param[in] api          Controller API instance
     * \param[in] target_node  Name of node to reprobe
     * \param[in] router_node  Router node for host
     *
     * \return Standard Pacemaker return code
     */
    int (*reprobe)(pcmk_controld_api_t *api, const char *target_node,
                   const char *router_node);

    /* @TODO These methods have a lot of arguments. One possibility would be to
     * make a struct for agent info (standard/provider/type), which theortically
     * could be used throughout pacemaker code. However that would end up being
     * really awkward to use generically, since sometimes you need to allocate
     * those strings (char *) and other times you only have references into XML
     * (const char *). We could make some structs just for this API.
     */

    /*!
     * \internal
     * \brief Ask the controller to fail a resource
     *
     * \param[in] api          Controller API instance
     * \param[in] target_node  Name of node resource is on
     * \param[in] router_node  Router node for target
     * \param[in] rsc_id       ID of resource to fail
     * \param[in] rsc_long_id  Long ID of resource (if any)
     * \param[in] standard     Standard of resource
     * \param[in] provider     Provider of resource (if any)
     * \param[in] type         Type of resource to fail
     *
     * \return Standard Pacemaker return code
     */
    int (*fail_resource)(pcmk_controld_api_t *api, const char *target_node,
                         const char *router_node, const char *rsc_id,
                         const char *rsc_long_id, const char *standard,
                         const char *provider, const char *type);

    /*!
     * \internal
     * \brief Ask the controller to refresh a resource
     *
     * \param[in] api          Controller API instance
     * \param[in] target_node  Name of node resource is on
     * \param[in] router_node  Router node for target
     * \param[in] rsc_id       ID of resource to refresh
     * \param[in] rsc_long_id  Long ID of resource (if any)
     * \param[in] standard     Standard of resource
     * \param[in] provider     Provider of resource (if any)
     * \param[in] type         Type of resource
     * \param[in] cib_only     If true, clean resource from CIB only
     *
     * \return Standard Pacemaker return code
     */
    int (*refresh_resource)(pcmk_controld_api_t *api, const char *target_node,
                            const char *router_node, const char *rsc_id,
                            const char *rsc_long_id, const char *standard,
                            const char *provider, const char *type,
                            bool cib_only);
};

/*!
 * \internal
 * \brief Create new controller IPC API object for clients
 *
 * \param[in] client_name  Client name to use with IPC
 * \param[in] client_uuid  Client UUID to use with IPC
 *
 * \return Newly allocated object
 * \note This function asserts on errors, so it will never return NULL.
 *       The caller is responsible for freeing the result with
 *       pcmk_free_controld_api().
 */
pcmk_controld_api_t *pcmk_new_controld_api(const char *client_name,
                                           const char *client_uuid);

/*!
 * \internal
 * \brief Free a controller IPC API object
 *
 * \param[in] api  Controller IPC API object to free
 */
void pcmk_free_controld_api(pcmk_controld_api_t *api);

#ifdef __cplusplus
}
#endif

#endif
