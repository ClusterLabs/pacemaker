/*
 * Copyright 2012-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_LRMD__H
#  define PCMK__CRM_LRMD__H

#include <stdbool.h>      // bool
#include <glib.h>         // guint, GList
#include <crm_config.h>
#include <crm/services.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Resource agent executor
 * \ingroup lrmd
 */

typedef struct lrmd_s lrmd_t;
typedef struct lrmd_key_value_s {
    char *key;
    char *value;
    struct lrmd_key_value_s *next;
} lrmd_key_value_t;

/* This should be bumped every time there is an incompatible change that
 * prevents older clients from connecting to this version of the server.
 */
#define LRMD_PROTOCOL_VERSION "1.1"

/* This is the version that the client version will actually be compared
 * against. This should be identical to LRMD_PROTOCOL_VERSION. However, we
 * accidentally bumped LRMD_PROTOCOL_VERSION in 6424a647 (1.1.15) when we didn't
 * need to, so for now it's different. If we ever have a truly incompatible
 * bump, we can drop this and compare against LRMD_PROTOCOL_VERSION.
 */
#define LRMD_MIN_PROTOCOL_VERSION "1.0"

/* *INDENT-OFF* */
#define DEFAULT_REMOTE_KEY_LOCATION PACEMAKER_CONFIG_DIR "/authkey"
#define ALT_REMOTE_KEY_LOCATION "/etc/corosync/authkey"
#define DEFAULT_REMOTE_PORT 3121
#define DEFAULT_REMOTE_USERNAME "lrmd"

#define F_LRMD_OPERATION        "lrmd_op"
#define F_LRMD_CLIENTNAME       "lrmd_clientname"
#define F_LRMD_IS_IPC_PROVIDER  "lrmd_is_ipc_provider"
#define F_LRMD_CLIENTID         "lrmd_clientid"
#define F_LRMD_PROTOCOL_VERSION "lrmd_protocol_version"
#define F_LRMD_REMOTE_MSG_TYPE  "lrmd_remote_msg_type"
#define F_LRMD_REMOTE_MSG_ID    "lrmd_remote_msg_id"
#define F_LRMD_CALLBACK_TOKEN   "lrmd_async_id"
#define F_LRMD_CALLID           "lrmd_callid"
#define F_LRMD_CALLOPTS         "lrmd_callopt"
#define F_LRMD_CALLDATA         "lrmd_calldata"
#define F_LRMD_RC               "lrmd_rc"
#define F_LRMD_EXEC_RC          "lrmd_exec_rc"
#define F_LRMD_OP_STATUS        "lrmd_exec_op_status"
#define F_LRMD_TIMEOUT          "lrmd_timeout"
#define F_LRMD_WATCHDOG         "lrmd_watchdog"
#define F_LRMD_CLASS            "lrmd_class"
#define F_LRMD_PROVIDER         "lrmd_provider"
#define F_LRMD_TYPE             "lrmd_type"
#define F_LRMD_ORIGIN           "lrmd_origin"

#define F_LRMD_RSC_RUN_TIME      "lrmd_run_time"
#define F_LRMD_RSC_RCCHANGE_TIME "lrmd_rcchange_time"
#define F_LRMD_RSC_EXEC_TIME     "lrmd_exec_time"
#define F_LRMD_RSC_QUEUE_TIME    "lrmd_queue_time"

#define F_LRMD_RSC_ID           "lrmd_rsc_id"
#define F_LRMD_RSC_ACTION       "lrmd_rsc_action"
#define F_LRMD_RSC_USERDATA_STR "lrmd_rsc_userdata_str"
#define F_LRMD_RSC_OUTPUT       "lrmd_rsc_output"
#define F_LRMD_RSC_EXIT_REASON  "lrmd_rsc_exit_reason"
#define F_LRMD_RSC_START_DELAY  "lrmd_rsc_start_delay"
#define F_LRMD_RSC_INTERVAL     "lrmd_rsc_interval"
#define F_LRMD_RSC_DELETED      "lrmd_rsc_deleted"
#define F_LRMD_RSC              "lrmd_rsc"

#define F_LRMD_ALERT_ID           "lrmd_alert_id"
#define F_LRMD_ALERT_PATH         "lrmd_alert_path"
#define F_LRMD_ALERT              "lrmd_alert"

#define LRMD_OP_RSC_REG           "lrmd_rsc_register"
#define LRMD_OP_RSC_EXEC          "lrmd_rsc_exec"
#define LRMD_OP_RSC_CANCEL        "lrmd_rsc_cancel"
#define LRMD_OP_RSC_UNREG         "lrmd_rsc_unregister"
#define LRMD_OP_RSC_INFO          "lrmd_rsc_info"
#define LRMD_OP_RSC_METADATA      "lrmd_rsc_metadata"
#define LRMD_OP_POKE              "lrmd_rsc_poke"
#define LRMD_OP_NEW_CLIENT        "lrmd_rsc_new_client"
#define LRMD_OP_CHECK             "lrmd_check"
#define LRMD_OP_ALERT_EXEC        "lrmd_alert_exec"
#define LRMD_OP_GET_RECURRING     "lrmd_get_recurring"

#define LRMD_IPC_OP_NEW           "new"
#define LRMD_IPC_OP_DESTROY       "destroy"
#define LRMD_IPC_OP_EVENT         "event"
#define LRMD_IPC_OP_REQUEST       "request"
#define LRMD_IPC_OP_RESPONSE      "response"
#define LRMD_IPC_OP_SHUTDOWN_REQ  "shutdown_req"
#define LRMD_IPC_OP_SHUTDOWN_ACK  "shutdown_ack"
#define LRMD_IPC_OP_SHUTDOWN_NACK "shutdown_nack"

#define F_LRMD_IPC_OP           "lrmd_ipc_op"
#define F_LRMD_IPC_IPC_SERVER   "lrmd_ipc_server"
#define F_LRMD_IPC_SESSION      "lrmd_ipc_session"
#define F_LRMD_IPC_CLIENT       "lrmd_ipc_client"
#define F_LRMD_IPC_USER         "lrmd_ipc_user"
#define F_LRMD_IPC_MSG          "lrmd_ipc_msg"
#define F_LRMD_IPC_MSG_ID       "lrmd_ipc_msg_id"
#define F_LRMD_IPC_MSG_FLAGS    "lrmd_ipc_msg_flags"

#define T_LRMD           "lrmd"
#define T_LRMD_REPLY     "lrmd_reply"
#define T_LRMD_NOTIFY    "lrmd_notify"
#define T_LRMD_IPC_PROXY "lrmd_ipc_proxy"
#define T_LRMD_RSC_OP    "lrmd_rsc_op"
/* *INDENT-ON* */

/*!
 * \brief Create a new connection to the local executor
 */
lrmd_t *lrmd_api_new(void);

/*!
 * \brief Create a new TLS connection to a remote executor
 *
 * \param[in] nodename  Name of remote node identified with this connection
 * \param[in] server    Hostname to connect to
 * \param[in] port      Port number to connect to (or 0 to use default)
 *
 * \return Newly created executor connection object
 * \note If only one of \p nodename and \p server is non-NULL, it will be used
 *       for both purposes. If both are NULL, a local IPC connection will be
 *       created instead.
 */
lrmd_t *lrmd_remote_api_new(const char *nodename, const char *server, int port);

/*!
 * \brief Use after lrmd_poll returns 1 to read and dispatch a message
 *
 * \param[in,out] lrmd  Executor connection object
 *
 * \return TRUE if connection is still up, FALSE if disconnected
 */
bool lrmd_dispatch(lrmd_t *lrmd);

/*!
 * \brief Check whether a message is available on an executor connection
 *
 * \param[in,out] lrmd     Executor connection object to check
 * \param[in]     timeout  Currently ignored
 *
 * \retval 1               Message is ready
 * \retval 0               Timeout occurred
 * \retval negative errno  Error occurred
 *
 * \note This is intended for callers that do not use a main loop.
 */
int lrmd_poll(lrmd_t *lrmd, int timeout);

/*!
 * \brief Destroy executor connection object
 *
 * \param[in,out] lrmd     Executor connection object to destroy
 */
void lrmd_api_delete(lrmd_t *lrmd);

lrmd_key_value_t *lrmd_key_value_add(lrmd_key_value_t * kvp, const char *key, const char *value);

enum lrmd_call_options {
    lrmd_opt_none                   = 0,

    //! Notify only the client that made the request (rather than all clients)
    lrmd_opt_notify_orig_only       = (1 << 1),

    /*!
     * Drop recurring operations initiated by a client when the client
     * disconnects. This option is only valid when registering a resource. When
     * used with a connection to a remote executor, recurring operations will be
     * dropped once all remote connections disconnect.
     *
     * @COMPAT This is broken, because these values should be unique bits, and
     * this value overlaps lrmd_opt_notify_orig_only (0x02). The impact is low
     * since this value is used only with registration requests and the other
     * one is used only with execution requests. Regardless, when we can break
     * API compatibility, this should be changed to (1 << 0) or (1 << 3).
     */
    lrmd_opt_drop_recurring         = 0x00000003,

    //! Send notifications for recurring operations only when the result changes
    lrmd_opt_notify_changes_only    = (1 << 2),
};

enum lrmd_callback_event {
    lrmd_event_register,
    lrmd_event_unregister,
    lrmd_event_exec_complete,
    lrmd_event_disconnect,
    lrmd_event_connect,
    lrmd_event_poke,
    lrmd_event_new_client,
};

typedef struct lrmd_event_data_s {
    /*! Type of event, register, unregister, call_completed... */
    enum lrmd_callback_event type;

    /*! The resource this event occurred on. */
    const char *rsc_id;
    /*! The action performed, start, stop, monitor... */
    const char *op_type;
    /*! The user data passed by caller of exec() API function */
    const char *user_data;

    /*! The client api call id associated with this event */
    int call_id;
    /*! The operation's timeout period in ms. */
    int timeout;
    /*! The operation's recurring interval in ms. */
    guint interval_ms;
    /*! The operation's start delay value in ms. */
    int start_delay;
    /*! This operation that just completed is on a deleted rsc. */
    int rsc_deleted;

    /*! The executed ra return code mapped to OCF */
    enum ocf_exitcode rc;
    /*! The executor status returned for exec_complete events */
    int op_status;
    /*! stdout from resource agent operation */
    const char *output;
    /*! Timestamp of when op ran */
    unsigned int t_run;
    /*! Timestamp of last rc change */
    unsigned int t_rcchange;
    /*! Time in length op took to execute */
    unsigned int exec_time;
    /*! Time in length spent in queue */
    unsigned int queue_time;

    /*! int connection result. Used for connection and poke events */
    int connection_rc;

    /* This is a GHashTable containing the
     * parameters given to the operation */
    void *params;

    /*! client node name associated with this connection
     * (used to match actions to the proper client when there are multiple)
     */
    const char *remote_nodename;

    /*! exit failure reason string from resource agent operation */
    const char *exit_reason;
} lrmd_event_data_t;

lrmd_event_data_t *lrmd_new_event(const char *rsc_id, const char *task,
                                  guint interval_ms);
lrmd_event_data_t *lrmd_copy_event(lrmd_event_data_t * event);
void lrmd_free_event(lrmd_event_data_t * event);

typedef struct lrmd_rsc_info_s {
    char *id;
    char *type;
    char *standard;
    char *provider;
} lrmd_rsc_info_t;

typedef struct lrmd_op_info_s {
    char *rsc_id;
    char *action;
    char *interval_ms_s;
    char *timeout_ms_s;
} lrmd_op_info_t;

lrmd_rsc_info_t *lrmd_new_rsc_info(const char *rsc_id, const char *standard,
                                   const char *provider, const char *type);
lrmd_rsc_info_t *lrmd_copy_rsc_info(lrmd_rsc_info_t * rsc_info);
void lrmd_free_rsc_info(lrmd_rsc_info_t * rsc_info);
void lrmd_free_op_info(lrmd_op_info_t *op_info);

typedef void (*lrmd_event_callback) (lrmd_event_data_t * event);

typedef struct lrmd_list_s {
    const char *val;
    struct lrmd_list_s *next;
} lrmd_list_t;

void lrmd_list_freeall(lrmd_list_t * head);
void lrmd_key_value_freeall(lrmd_key_value_t * head);

typedef struct lrmd_api_operations_s {
    /*!
     * \brief Connect to an executor
     *
     * \param[in,out] lrmd         Executor connection object
     * \param[in]     client_name  Arbitrary identifier to pass to server
     * \param[out]    fd           If not NULL, where to store file descriptor
     *                             for connection's socket
     *
     * \return Legacy Pacemaker return code
     */
    int (*connect) (lrmd_t *lrmd, const char *client_name, int *fd);

    /*!
     * \brief Initiate an executor connection without blocking
     *
     * \param[in,out] lrmd         Executor connection object
     * \param[in]     client_name  Arbitrary identifier to pass to server
     * \param[in]     timeout      Error if not connected within this time
     *                             (milliseconds)
     *
     * \return Legacy Pacemaker return code (if pcmk_ok, the event callback will
     *         be called later with the result)
     * \note This function requires a mainloop.
     */
    int (*connect_async) (lrmd_t *lrmd, const char *client_name,
                          int timeout /*ms */ );

    /*!
     * \brief Check whether connection to executor daemon is (still) active
     *
     * \param[in,out] lrmd  Executor connection object to check
     *
     * \return 1 if the executor connection is active, 0 otherwise
     */
    int (*is_connected) (lrmd_t *lrmd);

    /*!
     * \brief Poke executor connection to verify it is still active
     *
     * \param[in,out] lrmd  Executor connection object to check
     *
     * \return Legacy Pacemaker return code (if pcmk_ok, the event callback will
     *         be called later with the result)
     * \note The response comes in the form of a poke event to the callback.
     *
     */
    int (*poke_connection) (lrmd_t *lrmd);

    /*!
     * \brief Disconnect from the executor.
     *
     * \param[in,out] lrmd  Executor connection object to disconnect
     *
     * \return Legacy Pacemaker return code
     */
    int (*disconnect) (lrmd_t *lrmd);

    /*!
     * \brief Register a resource with the executor
     *
     * \param[in,out] lrmd      Executor connection object
     * \param[in]     rsc_id    ID of resource to register
     * \param[in]     standard  Resource's resource agent standard
     * \param[in]     provider  Resource's resource agent provider (or NULL)
     * \param[in]     agent     Resource's resource agent name
     * \param[in]     options   Group of enum lrmd_call_options flags
     *
     * \note Synchronous, guaranteed to occur in daemon before function returns.
     *
     * \return Legacy Pacemaker return code
     */
    int (*register_rsc) (lrmd_t *lrmd, const char *rsc_id, const char *standard,
                         const char *provider, const char *agent,
                         enum lrmd_call_options options);

    /*!
     * \brief Retrieve a resource's registration information
     *
     * \param[in,out] lrmd      Executor connection object
     * \param[in]     rsc_id    ID of resource to check
     * \param[in]     options   Group of enum lrmd_call_options flags
     *
     * \return Resource information on success, otherwise NULL
     */
    lrmd_rsc_info_t *(*get_rsc_info) (lrmd_t *lrmd, const char *rsc_id,
                                      enum lrmd_call_options options);

    /*!
     * \brief Retrieve recurring operations registered for a resource
     *
     * \param[in,out] lrmd        Executor connection object
     * \param[in]     rsc_id      ID of resource to check
     * \param[in]     timeout_ms  Error if not completed within this time
     * \param[in]     options     Group of enum lrmd_call_options flags
     * \param[out]    output      Where to store list of lrmd_op_info_t
     *
     * \return Legacy Pacemaker return code
     */
    int (*get_recurring_ops) (lrmd_t *lrmd, const char *rsc_id, int timeout_ms,
                              enum lrmd_call_options options, GList **output);

    /*!
     * \brief Unregister a resource from the executor
     *
     * \param[in,out] lrmd     Executor connection object
     * \param[in]     rsc_id   ID of resource to unregister
     * \param[in]     options  Group of enum lrmd_call_options flags
     *
     * \return Legacy Pacemaker return code (of particular interest, EINPROGRESS
     *         means that operations are in progress for the resource, and the
     *         unregistration will be done when they complete)
     * \note Pending and recurring operations will be cancelled.
     * \note Synchronous, guaranteed to occur in daemon before function returns.
     *
     */
    int (*unregister_rsc) (lrmd_t *lrmd, const char *rsc_id,
                           enum lrmd_call_options options);

    /*!
     * \brief Set a callback for executor events
     *
     * \param[in,out] lrmd      Executor connection object
     * \param[in]     callback  Callback to set
     */
    void (*set_callback) (lrmd_t *lrmd, lrmd_event_callback callback);

    /*!
     * \brief Request execution of a resource action
     *
     * \param[in,out] lrmd         Executor connection object
     * \param[in]     rsc_id       ID of resource
     * \param[in]     action       Name of resource action to execute
     * \param[in]     userdata     Arbitrary string to pass to event callback
     * \param[in]     interval_ms  If 0, execute action once, otherwise
     *                             recurring at this interval (in milliseconds)
     * \param[in]     timeout      Error if not complete within this time (in
     *                             milliseconds)
     * \param[in]     start_delay  Wait this long before execution (in
     *                             milliseconds)
     * \param[in]     options      Group of enum lrmd_call_options flags
     * \param[in,out] params       Parameters to pass to agent (will be freed)
     *
     * \return A call ID for the action on success (in which case the action is
     *         queued in the executor, and the event callback will be called
     *         later with the result), otherwise a negative legacy Pacemaker
     *         return code
     * \note exec() and cancel() operations on an individual resource are
     *       guaranteed to occur in the order the client API is called. However,
     *       operations on different resources are not guaranteed to occur in
     *       any specific order.
     */
    int (*exec) (lrmd_t *lrmd, const char *rsc_id, const char *action,
                 const char *userdata, guint interval_ms, int timeout,
                 int start_delay, enum lrmd_call_options options,
                 lrmd_key_value_t *params);

    /*!
     * \brief Cancel a recurring resource action
     *
     * \param[in,out] lrmd         Executor connection object
     * \param[in]     rsc_id       ID of resource
     * \param[in]     action       Name of resource action to cancel
     * \param[in]     interval_ms  Action's interval (in milliseconds)
     *
     * \return Legacy Pacemaker return code (if pcmk_ok, cancellation is queued
     *         on function return, and the event callback will be called later
     *         with an exec_complete event with an lrmd_op_status signifying
     *         that the operation is cancelled)
     *
     * \note exec() and cancel() operations on an individual resource are
     *       guaranteed to occur in the order the client API is called. However,
     *       operations on different resources are not guaranteed to occur in
     *       any specific order.
     */
    int (*cancel) (lrmd_t *lrmd, const char *rsc_id, const char *action,
                   guint interval_ms);

    /*!
     * \brief Retrieve resource agent metadata synchronously
     *
     * \param[in]  lrmd      Executor connection (unused)
     * \param[in]  standard  Resource agent class
     * \param[in]  provider  Resource agent provider
     * \param[in]  agent     Resource agent type
     * \param[out] output    Where to store metadata (must not be NULL)
     * \param[in]  options   Group of enum lrmd_call_options flags (unused)
     *
     * \return Legacy Pacemaker return code
     *
     * \note Caller is responsible for freeing output. This call is always
     *       synchronous (blocking), and always done directly by the library
     *       (not via the executor connection). This means that it is based on
     *       the local host environment, even if the executor connection is to a
     *       remote node, so this may fail if the agent is not installed
     *       locally. This also means that, if an external agent must be
     *       executed, it will be executed by the caller's user, not the
     *       executor's.
     */
    int (*get_metadata) (lrmd_t *lrmd, const char *standard,
                         const char *provider, const char *agent,
                         char **output, enum lrmd_call_options options);

    /*!
     * \brief Retrieve a list of installed resource agents
     *
     * \param[in]  lrmd      Executor connection (unused)
     * \param[out] agents    Where to store agent list (must not be NULL)
     * \param[in]  standard  Resource agent standard to list
     * \param[in]  provider  Resource agent provider to list (or NULL)
     *
     * \return Number of items in list on success, negative legacy Pacemaker
     *         return code otherwise
     *
     * \note if standard is not provided, all known agents will be returned
     * \note list must be freed using lrmd_list_freeall()
     */
    int (*list_agents) (lrmd_t *lrmd, lrmd_list_t **agents,
                        const char *standard, const char *provider);

    /*!
     * \brief Retrieve a list of resource agent providers
     *
     * \param[in]  lrmd       Executor connection (unused)
     * \param[in]  agent      If not NULL, list providers for this agent only
     * \param[out] providers  Where to store provider list
     *
     * \return Number of items in list on success, negative legacy Pacemaker
     *         return code otherwise
     * \note The caller is responsible for freeing *providers with
     *       lrmd_list_freeall().
     */
    int (*list_ocf_providers) (lrmd_t *lrmd, const char *agent,
                               lrmd_list_t **providers);

    /*!
     * \brief Retrieve a list of supported standards
     *
     * \param[in]  lrmd       Executor connection (unused)
     * \param[out] standards  Where to store standards list
     *
     * \return Number of items in list on success, negative legacy Pacemaker
     *         return code otherwise
     * \note The caller is responsible for freeing *standards with
     *       lrmd_list_freeall().
     */
    int (*list_standards) (lrmd_t *lrmd, lrmd_list_t **standards);

    /*!
     * \brief Execute an alert agent
     *
     * \param[in,out] lrmd        Executor connection
     * \param[in]     alert_id    Name of alert to execute
     * \param[in]     alert_path  Full path to alert executable
     * \param[in]     timeout     Error if not complete within this many
     *                            milliseconds
     * \param[in,out] params      Parameters to pass to agent (will be freed)
     *
     * \return Legacy Pacemaker return code (if pcmk_ok, the alert is queued in
     *         the executor, and the event callback will be called later with
     *         the result)
     *
     * \note Operations on individual alerts (by ID) are guaranteed to occur in
     *       the order the client API is called. Operations on different alerts
     *       are not guaranteed to occur in any specific order.
     */
    int (*exec_alert) (lrmd_t *lrmd, const char *alert_id,
                       const char *alert_path, int timeout,
                       lrmd_key_value_t *params);

    /*!
     * \brief Retrieve resource agent metadata synchronously with parameters
     *
     * \param[in]     lrmd      Executor connection (unused)
     * \param[in]     standard  Resource agent class
     * \param[in]     provider  Resource agent provider
     * \param[in]     agent     Resource agent type
     * \param[out]    output    Where to store metadata (must not be NULL)
     * \param[in]     options   Group of enum lrmd_call_options flags (unused)
     * \param[in,out] params    Parameters to pass to agent (will be freed)
     *
     * \return Legacy Pacemaker return code
     *
     * \note This is identical to the get_metadata() API call, except parameters
     *       will be passed to the resource agent via environment variables.
     */
    int (*get_metadata_params) (lrmd_t *lrmd, const char *standard,
                                const char *provider, const char *agent,
                                char **output, enum lrmd_call_options options,
                                lrmd_key_value_t *params);

} lrmd_api_operations_t;

struct lrmd_s {
    lrmd_api_operations_t *cmds;
    void *lrmd_private;
};

static inline const char *
lrmd_event_type2str(enum lrmd_callback_event type)
{
    switch (type) {
        case lrmd_event_register:
            return "register";
        case lrmd_event_unregister:
            return "unregister";
        case lrmd_event_exec_complete:
            return "exec_complete";
        case lrmd_event_disconnect:
            return "disconnect";
        case lrmd_event_connect:
            return "connect";
        case lrmd_event_poke:
            return "poke";
        case lrmd_event_new_client:
            return "new_client";
    }
    return "unknown";
}

#ifdef __cplusplus
}
#endif

#endif
