/*
 * Copyright 2010-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_SERVICES__H
#define PCMK__CRM_SERVICES__H

#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

#include <glib.h>

#include <crm/common/agents.h>
#include <crm/common/results.h>

#ifdef __cplusplus
extern "C" {
#endif

// NOTE: booth (as of at least 1.1) checks for the existence of this header

/*!
 * \file
 * \brief Services API
 * \ingroup core
 */

/* TODO: Autodetect these two ?*/
#ifndef SYSTEMCTL
#define SYSTEMCTL "/bin/systemctl"
#endif

/* This is the string passed in the OCF_EXIT_REASON_PREFIX environment variable.
 * The stderr output that occurs after this prefix is encountered is considered
 * the exit reason for a completed operation.
 */
#define PCMK_OCF_REASON_PREFIX "ocf-exit-reason:"

// Agent version to use if agent doesn't specify one
#define PCMK_DEFAULT_AGENT_VERSION "0.1"

enum lsb_exitcode {
    PCMK_LSB_OK                  = 0,

    // NOTE: booth (as of at least 1.1) uses this value
    PCMK_LSB_UNKNOWN_ERROR       = 1,

    PCMK_LSB_INVALID_PARAM       = 2,
    PCMK_LSB_UNIMPLEMENT_FEATURE = 3,
    PCMK_LSB_INSUFFICIENT_PRIV   = 4,
    PCMK_LSB_NOT_INSTALLED       = 5,
    PCMK_LSB_NOT_CONFIGURED      = 6,
    PCMK_LSB_NOT_RUNNING         = 7,
};

// LSB uses different return codes for status actions
enum lsb_status_exitcode {
    PCMK_LSB_STATUS_OK             = 0,
    PCMK_LSB_STATUS_VAR_PID        = 1,
    PCMK_LSB_STATUS_VAR_LOCK       = 2,
    PCMK_LSB_STATUS_NOT_RUNNING    = 3,
    PCMK_LSB_STATUS_UNKNOWN        = 4,

    /* custom codes should be in the 150-199 range reserved for application use */
    PCMK_LSB_STATUS_NOT_INSTALLED      = 150,
    PCMK_LSB_STATUS_INSUFFICIENT_PRIV  = 151,
};

enum svc_action_flags {
    /* On timeout, only kill pid, do not kill entire pid group */
    SVC_ACTION_LEAVE_GROUP = 0x01,
    SVC_ACTION_NON_BLOCKED = 0x02,
};

typedef struct svc_action_private_s svc_action_private_t;

/*!
 * \brief Object for executing external actions
 *
 * \note This object should never be instantiated directly, but instead created
 *       using one of the constructor functions (resources_action_create() for
 *       resource agents, services_alert_create() for alert agents, or
 *       services_action_create_generic() for generic executables). Similarly,
 *       do not use sizeof() on this struct.
 *
 * \deprecated Use \c svc_action_t instead of <tt>struct svc_action_s</tt>.
 */
/*
 * NOTE: Internally, services__create_resource_action() is preferable to
 * resources_action_create().
 */
typedef struct svc_action_s {
    /*! Operation key (<resource>_<action>_<interval>) for resource actions,
     *  XML ID for alert actions, or NULL for generic actions
     */
    char *id;

    //! XML ID of resource being executed for resource actions, otherwise NULL
    char *rsc;

    //! Name of action being executed for resource actions, otherwise NULL
    char *action;

    //! Action interval for recurring resource actions, otherwise 0
    guint interval_ms;

    //! Resource standard for resource actions, otherwise NULL
    char *standard;

    //! Resource provider for resource actions that require it, otherwise NULL
    char *provider;

    //! Resource agent name for resource actions, otherwise NULL
    char *agent;

    int timeout;    //!< Action timeout (in milliseconds)

    /*! A hash table of name/value pairs to use as parameters for resource and
     *  alert actions, otherwise NULL. These will be used to set environment
     *  variables for non-fencing resource agents and alert agents, and to send
     *  stdin to fence agents.
     */
    GHashTable *params;

    int rc;         //!< Exit status of action (set by library upon completion)

    //!@{
    //! This field should be treated as internal to Pacemaker
    int pid;        // Process ID of child
    int cancel;     // Whether this is a cancellation of a recurring action
    //!@}

    int status;     //!< Execution status (enum pcmk_exec_status set by library)

    /*! Action counter (set by library for resource actions, or by caller
     * otherwise)
     */
    int sequence;

    //!@{
    //! This field should be treated as internal to Pacemaker
    int expected_rc;    // Unused
    int synchronous;    // Whether execution should be synchronous (blocking)
    //!@}

    enum svc_action_flags flags;    //!< Flag group of enum svc_action_flags
    char *stderr_data;              //!< Action stderr (set by library)
    char *stdout_data;              //!< Action stdout (set by library)
    void *cb_data;                  //!< For caller's use (not used by library)

    //! This field should be treated as internal to Pacemaker
    svc_action_private_t *opaque;
} svc_action_t;

/*!
 * \brief Get a list of providers
 *
 * \param[in] standard  List providers of this resource agent standard
 *
 * \return List of providers as char * list items (or NULL if standard does not
 *         support providers)
 * \note The caller is responsible for freeing the result using
 *       g_list_free_full(list, free).
 */
GList *resources_list_providers(const char *standard);

/*!
 * \brief Get a list of resource agents
 *
 * \param[in] standard  List agents of this standard (or NULL for all)
 * \param[in] provider  List agents of this provider (or NULL for all)
 *
 * \return List of resource agents as char * items.
 * \note The caller is responsible for freeing the result using
 *       g_list_free_full(list, free).
 */
GList *resources_list_agents(const char *standard, const char *provider);

/*!
 * Get list of available standards
 *
 * \return List of resource standards as char * items.
 * \note The caller is responsible for freeing the result using
 *       g_list_free_full(list, free).
 */
GList *resources_list_standards(void);

/*!
 * \brief Check whether a resource agent exists on the local host
 *
 * \param[in] standard  Resource agent standard of agent to check
 * \param[in] provider  Provider of agent to check (or NULL)
 * \param[in] agent     Name of agent to check
 *
 * \return TRUE if agent exists locally, otherwise FALSE
 */
gboolean resources_agent_exists(const char *standard, const char *provider,
                                const char *agent);

/*!
 * \brief Create a new resource action
 *
 * \param[in]     name        Name of resource that action is for
 * \param[in]     standard    Resource agent standard
 * \param[in]     provider    Resource agent provider
 * \param[in]     agent       Resource agent name
 * \param[in]     action      Name of action to create
 * \param[in]     interval_ms How often to repeat action (if 0, execute once)
 * \param[in]     timeout     Error if not complete within this time (ms)
 * \param[in,out] params      Action parameters
 * \param[in]     flags       Group of enum svc_action_flags
 *
 * \return Newly allocated action
 * \note This function assumes ownership of (and may free) \p params.
 * \note The caller is responsible for freeing the return value using
 *       services_action_free().
 */
svc_action_t *resources_action_create(const char *name, const char *standard,
                                      const char *provider, const char *agent,
                                      const char *action, guint interval_ms,
                                      int timeout, GHashTable *params,
                                      enum svc_action_flags flags);

/*!
 * \brief Reschedule a recurring action for immediate execution
 *
 * \param[in] name         Name of resource that action is for
 * \param[in] action       Action's name
 * \param[in] interval_ms  Action's interval (in milliseconds)
 *
 * \return TRUE on success, otherwise FALSE
 */
gboolean services_action_kick(const char *name, const char *action,
                              guint interval_ms);

const char *resources_find_service_class(const char *agent);

/*!
 * \brief Request execution of an arbitrary command
 *
 * This API has useful infrastructure in place to be able to run a command
 * in the background and get notified via a callback when the command finishes.
 *
 * \param[in] exec  Full path to command executable
 * \param[in] args  NULL-terminated list of arguments to pass to command
 *
 * \return Newly allocated action object
 */
svc_action_t *services_action_create_generic(const char *exec,
                                             const char *args[]);

void services_action_cleanup(svc_action_t *op);
void services_action_free(svc_action_t *op);
int services_action_user(svc_action_t *op, const char *user);
gboolean services_action_sync(svc_action_t *op);

/*!
 * \brief Run an action asynchronously, with callback after process is forked
 *
 * \param[in,out] op                    Action to run
 * \param[in]     action_callback       Function to call when action completes
 *                                      (if NULL, any previously set callback will
 *                                      continue to be used)
 * \param[in]     action_fork_callback  Function to call after child process is
 *                                      forked for action (if NULL, any
 *                                      previously set callback will continue to
 *                                      be used)
 *
 * \retval TRUE if the caller should not free or otherwise use \p op again,
 *         because one of these conditions is true:
 *
 *         * \p op is NULL.
 *         * The action was successfully initiated, in which case
 *           \p action_fork_callback has been called, but \p action_callback has
 *           not (it will be called when the action completes).
 *         * The action's ID matched an existing recurring action. The existing
 *           action has taken over the callback and callback data from \p op
 *           and has been re-initiated asynchronously, and \p op has been freed.
 *         * Another action for the same resource is in flight, and \p op will
 *           be blocked until it completes.
 *         * The action could not be initiated, and is either non-recurring or
 *           being cancelled. \p action_fork_callback has not been called, but
 *           \p action_callback has, and \p op has been freed.
 *
 * \retval FALSE if \op is still valid, because the action cannot be initiated,
 *         and is a recurring action that is not being cancelled.
 *         \p action_fork_callback has not been called, but \p action_callback
 *         has, and a timer has been set for the next invocation of \p op.
 */
gboolean services_action_async_fork_notify(svc_action_t *op,
        void (*action_callback) (svc_action_t *),
        void (*action_fork_callback) (svc_action_t *));

/*!
 * \brief Request asynchronous execution of an action
 *
 * \param[in,out] op               Action to execute
 * \param[in]     action_callback  Function to call when the action completes
 *                                 (if NULL, any previously set callback will
 *                                 continue to be used)
 *
 * \retval TRUE if the caller should not free or otherwise use \p op again,
 *         because one of these conditions is true:
 *
 *         * \p op is NULL.
 *         * The action was successfully initiated, in which case
 *           \p action_callback has not been called (it will be called when the
 *           action completes).
 *         * The action's ID matched an existing recurring action. The existing
 *           action has taken over the callback and callback data from \p op
 *           and has been re-initiated asynchronously, and \p op has been freed.
 *         * Another action for the same resource is in flight, and \p op will
 *           be blocked until it completes.
 *         * The action could not be initiated, and is either non-recurring or
 *           being cancelled. \p action_callback has been called, and \p op has
 *           been freed.
 *
 * \retval FALSE if \op is still valid, because the action cannot be initiated,
 *         and is a recurring action that is not being cancelled.
 *         \p action_callback has been called, and a timer has been set for the
 *         next invocation of \p op.
 */
gboolean services_action_async(svc_action_t *op,
                               void (*action_callback) (svc_action_t *));

gboolean services_action_cancel(const char *name, const char *action,
                                guint interval_ms);

/* functions for alert agents */
svc_action_t *services_alert_create(const char *id, const char *exec,
                                   int timeout, GHashTable *params,
                                   int sequence, void *cb_data);
gboolean services_alert_async(svc_action_t *action,
                              void (*cb)(svc_action_t *op));

enum ocf_exitcode services_result2ocf(const char *standard, const char *action,
                                      int exit_status);

#  ifdef __cplusplus
}
#  endif

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
#include <crm/services_compat.h>
#endif

#endif                          /* __PCMK_SERVICES__ */
