/*
 * Copyright (c) 2012 David Vossel <dvossel@redhat.com>
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
 *
 */

/**
 * \file
 * \brief Local Resource Manager 
 * \ingroup lrm
 */

#ifndef LRMD__H
#  define LRMD__H

typedef struct lrmd_s lrmd_t;
typedef struct lrmd_key_value_s {
    char *key;
    char *value;
    struct lrmd_key_value_s *next;
} lrmd_key_value_t;


/* *INDENT-OFF* */
#define DEFAULT_REMOTE_KEY_LOCATION "/etc/pacemaker/authkey"
#define ALT_REMOTE_KEY_LOCATION "/etc/corosync/authkey"
#define DEFAULT_REMOTE_PORT 1984
#define DEFAULT_REMOTE_USERNAME "lrmd"

#define F_LRMD_OPERATION        "lrmd_op"
#define F_LRMD_CLIENTNAME       "lrmd_clientname"
#define F_LRMD_IS_IPC_PROVIDER  "lrmd_is_ipc_provider"
#define F_LRMD_CLIENTID         "lrmd_clientid"
#define F_LRMD_REMOTE_MSG_TYPE  "lrmd_remote_msg_type"
#define F_LRMD_REMOTE_MSG_ID    "lrmd_remote_msg_id"
#define F_LRMD_CALLBACK_TOKEN   "lrmd_async_id"
#define F_LRMD_CALLID           "lrmd_callid"
#define F_LRMD_CANCEL_CALLID    "lrmd_cancel_callid"
#define F_LRMD_CALLOPTS         "lrmd_callopt"
#define F_LRMD_CALLDATA         "lrmd_calldata"
#define F_LRMD_RC               "lrmd_rc"
#define F_LRMD_EXEC_RC          "lrmd_exec_rc"
#define F_LRMD_OP_STATUS        "lrmd_exec_op_status"
#define F_LRMD_TIMEOUT          "lrmd_timeout"
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
#define F_LRMD_RSC_START_DELAY  "lrmd_rsc_start_delay"
#define F_LRMD_RSC_INTERVAL     "lrmd_rsc_interval"
#define F_LRMD_RSC_METADATA     "lrmd_rsc_metadata_res"
#define F_LRMD_RSC_DELETED      "lrmd_rsc_deleted"
#define F_LRMD_RSC              "lrmd_rsc"

#define LRMD_OP_RSC_CHK_REG       "lrmd_rsc_check_register"
#define LRMD_OP_RSC_REG           "lrmd_rsc_register"
#define LRMD_OP_RSC_EXEC          "lrmd_rsc_exec"
#define LRMD_OP_RSC_CANCEL        "lrmd_rsc_cancel"
#define LRMD_OP_RSC_UNREG         "lrmd_rsc_unregister"
#define LRMD_OP_RSC_INFO          "lrmd_rsc_info"
#define LRMD_OP_RSC_METADATA      "lrmd_rsc_metadata"
#define LRMD_OP_POKE              "lrmd_rsc_poke"

#define F_LRMD_IPC_OP           "lrmd_ipc_op"
#define F_LRMD_IPC_IPC_SERVER   "lrmd_ipc_server"
#define F_LRMD_IPC_SESSION      "lrmd_ipc_session"
#define F_LRMD_IPC_MSG          "lrmd_ipc_msg"
#define F_LRMD_IPC_MSG_ID       "lrmd_ipc_msg_id"
#define F_LRMD_IPC_MSG_FLAGS    "lrmd_ipc_msg_flags"

#define T_LRMD           "lrmd"
#define T_LRMD_REPLY     "lrmd_reply"
#define T_LRMD_NOTIFY    "lrmd_notify"
#define T_LRMD_IPC_PROXY "lrmd_ipc_proxy"
/* *INDENT-ON* */

/*!
 * \brief Create a new local lrmd connection
 */
lrmd_t *lrmd_api_new(void);

/*!
 * \brief Create a new remote lrmd connection using tls backend
 *
 * \note nodename and server may be the same value.
 *
 * \param nodename, the remote node name identified with this connection.
 * \param server, the server to connect to.
 * \param port, the port to connect to.
 */
lrmd_t *lrmd_remote_api_new(const char *nodename, const char *server, int port);

/*!
 * \brief Use after lrmd_poll returns 1.
 *
 * \param fd to poll on
 * \param timeout in ms
 *
 * \retval true - connection is still up
 * \retval false - disconnected
 */
bool lrmd_dispatch(lrmd_t * lrmd);

/*!
 * \brief Poll for a specified timeout period to determine if a message
 *        is ready for dispatch.
 * \retval 1 msg is ready
 * \retval 0 timeout occured
 * \retval negative error code
 */
int lrmd_poll(lrmd_t * lrmd, int timeout);

/*!
 * \brief Destroy lrmd object
 */
void lrmd_api_delete(lrmd_t * lrmd);
lrmd_key_value_t *lrmd_key_value_add(lrmd_key_value_t * kvp, const char *key, const char *value);

/* *INDENT-OFF* */
/* Reserved for future use */
enum lrmd_call_options {
    lrmd_opt_none = 0x00000000,
    /* lrmd_opt_sync_call = 0x00000001, //Not implemented, patches welcome. */
    /*! Only notify the client originating a exec() the results */
    lrmd_opt_notify_orig_only = 0x00000002,
    /*! Drop recurring operations initiated by a client when client disconnects.
     * This call_option is only valid when registering a resource. */
    lrmd_opt_drop_recurring = 0x00000003,
    /*! Only send out notifications for recurring operations whenthe result changes */
    lrmd_opt_notify_changes_only = 0x00000004,
};

enum lrmd_callback_event {
    lrmd_event_register,
    lrmd_event_unregister,
    lrmd_event_exec_complete,
    lrmd_event_disconnect,
    lrmd_event_connect,
    lrmd_event_poke,
};

enum lrmd_exec_rc {
    PCMK_EXECRA_OK                  = 0,
    PCMK_EXECRA_UNKNOWN_ERROR       = 1,
    PCMK_EXECRA_INVALID_PARAM       = 2,
    PCMK_EXECRA_UNIMPLEMENT_FEATURE = 3,
    PCMK_EXECRA_INSUFFICIENT_PRIV   = 4,
    PCMK_EXECRA_NOT_INSTALLED       = 5,
    PCMK_EXECRA_NOT_CONFIGURED      = 6,
    PCMK_EXECRA_NOT_RUNNING         = 7,
    PCMK_EXECRA_RUNNING_MASTER      = 8,
    PCMK_EXECRA_FAILED_MASTER       = 9,

    /* For status command only */
    PCMK_EXECRA_STATUS_UNKNOWN      = 14,
};
/* *INDENT-ON* */

typedef struct lrmd_event_data_s {
    /*! Type of event, register, unregister, call_completed... */
    enum lrmd_callback_event type;

    /*! The resource this event occurred on. */
    const char *rsc_id;
    /*! The action performed, start, stop, monitor... */
    const char *op_type;
    /*! The userdata string given do exec() api function */
    const char *user_data;

    /*! The client api call id associated with this event */
    int call_id;
    /*! The operation's timeout period in ms. */
    int timeout;
    /*! The operation's recurring interval in ms. */
    int interval;
    /*! The operation's start delay value in ms. */
    int start_delay;
    /*! This operation that just completed is on a deleted rsc. */
    int rsc_deleted;

    /*! The executed ra return code */
    enum lrmd_exec_rc rc;
    /*! The lrmd status returned for exec_complete events */
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

    /* client node name associated with this conneciton.
     * This is useful if multiple clients are being utilized by
     * a single process. This name allows the actions to be matched
     * to the proper client. */
    const char *remote_nodename;

} lrmd_event_data_t;

lrmd_event_data_t *lrmd_copy_event(lrmd_event_data_t * event);
void lrmd_free_event(lrmd_event_data_t * event);

typedef struct lrmd_rsc_info_s {
    char *id;
    char *type;
    char *class;
    char *provider;
} lrmd_rsc_info_t;

lrmd_rsc_info_t *lrmd_copy_rsc_info(lrmd_rsc_info_t * rsc_info);
void lrmd_free_rsc_info(lrmd_rsc_info_t * rsc_info);

typedef void (*lrmd_event_callback) (lrmd_event_data_t * event);

typedef struct lrmd_list_s {
    const char *val;
    struct lrmd_list_s *next;
} lrmd_list_t;

void lrmd_list_freeall(lrmd_list_t * head);
void lrmd_key_value_freeall(lrmd_key_value_t * head);

typedef struct lrmd_api_operations_s {
    /*!
     * \brief Connect from the lrmd.
     *
     * \retval 0, success
     * \retval negative error code on failure
     */
    int (*connect) (lrmd_t * lrmd, const char *client_name, int *fd);

    /*!
     * \brief Establish an connection to lrmd, don't block while connecting.
     * \note this function requires the use of mainloop.
     *
     * \note The is returned using the event callback.
     * \note When this function returns 0, the callback will be invoked
     *       to report the final result of the connect.
     * \retval 0, connect in progress, wait for event callback
     * \retval -1, failure.
     */
    int (*connect_async) (lrmd_t * lrmd, const char *client_name, int timeout /*ms */ );

    /*!
     * \brief Is connected to lrmd daemon?
     *
     * \retval 0, false
     * \retval 1, true
     */
    int (*is_connected) (lrmd_t * lrmd);

    /*!
     * \brief Poke lrmd connection to verify it is still capable of serving requests
     * \note The response comes in the form of a poke event to the callback. 
     *
     * \retval 0, wait for response in callback
     * \retval -1, connection failure, callback may not be invoked
     */
    int (*poke_connection) (lrmd_t * lrmd);

    /*!
     * \brief Disconnect from the lrmd.
     *
     * \retval 0, success
     * \retval negative error code on failure
     */
    int (*disconnect) (lrmd_t * lrmd);

    /*!
     * \brief Register a resource with the lrmd.
     *
     * \note Synchronous, guaranteed to occur in daemon before function returns.
     *
     * \retval 0, success
     * \retval negative error code on failure
     */
    int (*register_rsc) (lrmd_t * lrmd,
                         const char *rsc_id,
                         const char *class,
                         const char *provider, const char *agent, enum lrmd_call_options options);

    /*!
     * \brief Retrieve registration info for a rsc
     *
     * \retval info on success
     * \retval NULL on failure
     */
    lrmd_rsc_info_t *(*get_rsc_info) (lrmd_t * lrmd,
                                      const char *rsc_id, enum lrmd_call_options options);

    /*!
     * \brief Unregister a resource from the lrmd.
     *
     * \note All pending and recurring operations will be cancelled
     *       automatically.
     *
     * \note Synchronous, guaranteed to occur in daemon before function returns.
     *
     * \retval 0, success
     * \retval -1, success, but operations are currently executing on the rsc which will
     *         return once they are completed.
     * \retval negative error code on failure
     *
     */
    int (*unregister_rsc) (lrmd_t * lrmd, const char *rsc_id, enum lrmd_call_options options);

    /*!
     * \brief Sets the callback to receive lrmd events on.
     */
    void (*set_callback) (lrmd_t * lrmd, lrmd_event_callback callback);

    /*!
     * \brief Issue a command on a resource
     *
     * \note Asynchronous, command is queued in daemon on function return, but
     *       execution of command is not synced.
     *
     * \note Operations on individual resources are guaranteed to occur
     *       in the order the client api calls them in.
     *
     * \note Operations between different resources are not guaranteed
     *       to occur in any specific order in relation to one another
     *       regardless of what order the client api is called in.
     * \retval call_id to track async event result on success
     * \retval negative error code on failure
     */
    int (*exec) (lrmd_t * lrmd, const char *rsc_id, const char *action, const char *userdata,   /* userdata string given back in event notification */
                 int interval,  /* ms */
                 int timeout,   /* ms */
                 int start_delay,       /* ms */
                 enum lrmd_call_options options, lrmd_key_value_t * params);    /* ownership of params is given up to api here */

    /*!
     * \brief Cancel a recurring command.
     *
     * \note Synchronous, guaranteed to occur in daemon before function returns.
     *
     * \note The cancel is completed async from this call.
     *       We can be guaranteed the cancel has completed once
     *       the callback receives an exec_complete event with
     *       the lrmd_op_status signifying that the operation is
     *       cancelled.
     * \note For each resource, cancel operations and exec operations
     *       are processed in the order they are received.
     *       It is safe to assume that for a single resource, a cancel
     *       will occur in the lrmd before an exec if the client's cancel
     *       api call occurs before the exec api call.
     *
     *       It is not however safe to assume any operation on one resource will
     *       occur before an operation on another resource regardless of
     *       the order the client api is called in.
     *
     * \retval 0, cancel command sent.
     * \retval negative error code on failure
     */
    int (*cancel) (lrmd_t * lrmd, const char *rsc_id, const char *action, int interval);

    /*!
     * \brief Get the metadata documentation for a resource.
     *
     * \note Value is returned in output.  Output must be freed when set
     *
     * \retval lrmd_ok success
     * \retval negative error code on failure
     */
    int (*get_metadata) (lrmd_t * lrmd,
                         const char *class,
                         const char *provider,
                         const char *agent, char **output, enum lrmd_call_options options);

    /*!
     * \brief Retrieve a list of installed resource agents.
     *
     * \note if class is not provided, all known agents will be returned
     * \note list must be freed using lrmd_list_freeall()
     *
     * \retval num items in list on success
     * \retval negative error code on failure
     */
    int (*list_agents) (lrmd_t * lrmd, lrmd_list_t ** agents, const char *class,
                        const char *provider);

    /*!
     * \brief Retrieve a list of resource agent providers
     *
     * \note When the agent is provided, only the agent's provider will be returned
     * \note When no agent is supplied, all providers will be returned.
     * \note List must be freed using lrmd_list_freeall()
     *
     * \retval num items in list on success
     * \retval negative error code on failure
     */
    int (*list_ocf_providers) (lrmd_t * lrmd, const char *agent, lrmd_list_t ** providers);

    /*!
     * \brief Retrieve a list of standards supported by this machine/installation
     *
     * \note List must be freed using lrmd_list_freeall()
     *
     * \retval num items in list on success
     * \retval negative error code on failure
     */
    int (*list_standards) (lrmd_t * lrmd, lrmd_list_t ** standards);

} lrmd_api_operations_t;

struct lrmd_s {
    lrmd_api_operations_t *cmds;
    void *private;
};

static inline const char *
lrmd_event_rc2str(enum lrmd_exec_rc rc)
{
    switch (rc) {
        case PCMK_EXECRA_OK:
            return "ok";
        case PCMK_EXECRA_UNKNOWN_ERROR:
            return "unknown error";
        case PCMK_EXECRA_INVALID_PARAM:
            return "invalid parameter";
        case PCMK_EXECRA_UNIMPLEMENT_FEATURE:
            return "unimplemented feature";
        case PCMK_EXECRA_INSUFFICIENT_PRIV:
            return "insufficient privileges";
        case PCMK_EXECRA_NOT_INSTALLED:
            return "not installed";
        case PCMK_EXECRA_NOT_CONFIGURED:
            return "not configured";
        case PCMK_EXECRA_NOT_RUNNING:
            return "not running";
        case PCMK_EXECRA_RUNNING_MASTER:
            return "master";
        case PCMK_EXECRA_FAILED_MASTER:
            return "master (failed)";
        case PCMK_EXECRA_STATUS_UNKNOWN:
            return "status: unknown";
        default:
            break;
    }
    return "<unknown>";
}

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
    }
    return "unknown";
}

#endif
