/*
 * Copyright 2010-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef __PCMK_SERVICES__
#  define __PCMK_SERVICES__

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Services API
 * \ingroup core
 */

#  include <glib.h>
#  include <stdio.h>
#  include <stdint.h>
#  include <string.h>
#  include <stdbool.h>
#  include <sys/types.h>

#  include <crm_config.h>       // OCF_ROOT_DIR
#  include "common/results.h"

#  ifndef LSB_ROOT_DIR
#    define LSB_ROOT_DIR "/etc/init.d"
#  endif

/* TODO: Autodetect these two ?*/
#  ifndef SYSTEMCTL
#    define SYSTEMCTL "/bin/systemctl"
#  endif

/* Known resource classes */
#define PCMK_RESOURCE_CLASS_OCF     "ocf"
#define PCMK_RESOURCE_CLASS_SERVICE "service"
#define PCMK_RESOURCE_CLASS_LSB     "lsb"
#define PCMK_RESOURCE_CLASS_SYSTEMD "systemd"
#define PCMK_RESOURCE_CLASS_UPSTART "upstart"
#define PCMK_RESOURCE_CLASS_NAGIOS  "nagios"
#define PCMK_RESOURCE_CLASS_STONITH "stonith"

/* This is the string passed in the OCF_EXIT_REASON_PREFIX environment variable.
 * The stderr output that occurs after this prefix is encountered is considered
 * the exit reason for a completed operation.
 */
#define PCMK_OCF_REASON_PREFIX "ocf-exit-reason:"

// Agent version to use if agent doesn't specify one
#define PCMK_DEFAULT_AGENT_VERSION "0.1"

enum lsb_exitcode {
    PCMK_LSB_OK                  = 0,
    PCMK_LSB_UNKNOWN_ERROR       = 1,
    PCMK_LSB_INVALID_PARAM       = 2,
    PCMK_LSB_UNIMPLEMENT_FEATURE = 3,
    PCMK_LSB_INSUFFICIENT_PRIV   = 4,
    PCMK_LSB_NOT_INSTALLED       = 5,
    PCMK_LSB_NOT_CONFIGURED      = 6,
    PCMK_LSB_NOT_RUNNING         = 7,
};

/* The return codes for the status operation are not the same for other
 * operatios - go figure
 */
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

enum nagios_exitcode {
    NAGIOS_STATE_OK        = 0,
    NAGIOS_STATE_WARNING   = 1,
    NAGIOS_STATE_CRITICAL  = 2,
    NAGIOS_STATE_UNKNOWN   = 3,
    NAGIOS_STATE_DEPENDENT = 4,

    NAGIOS_INSUFFICIENT_PRIV = 100,
    NAGIOS_NOT_INSTALLED     = 101,
};

enum svc_action_flags {
    /* On timeout, only kill pid, do not kill entire pid group */
    SVC_ACTION_LEAVE_GROUP = 0x01,
    SVC_ACTION_NON_BLOCKED = 0x02,
};

typedef struct svc_action_private_s svc_action_private_t;
typedef struct svc_action_s {
    char *id;
    char *rsc;
    char *action;
    guint interval_ms;

    char *standard;
    char *provider;
    char *agent;

    int timeout;
    GHashTable *params; /* used for setting up environment for ocf-ra &
                           alert agents
                           and to be sent via stdin for fence-agents
                         */

    int rc;
    int pid;
    int cancel;
    int status;
    int sequence;
    int expected_rc;
    int synchronous;
    enum svc_action_flags flags;

    char *stderr_data;
    char *stdout_data;

    /*!
     * Data stored by the creator of the action.
     *
     * This may be used to hold data that is needed later on by a callback,
     * for example.
     */
    void *cb_data;

    svc_action_private_t *opaque;
} svc_action_t;

/**
 * \brief Get a list of files or directories in a given path
 *
 * \param[in] root       full path to a directory to read
 * \param[in] files      return list of files if TRUE or directories if FALSE
 * \param[in] executable if TRUE and files is TRUE, only return executable files
 *
 * \return a list of what was found.  The list items are char *.
 * \note It is the caller's responsibility to free the result with g_list_free_full(list, free).
 */
    GList *get_directory_list(const char *root, gboolean files, gboolean executable);

/**
 * Get a list of services
 *
 * \return a list of services.  The list items are gchar *.  This list _must_
 *         be destroyed using g_list_free_full(list, free).
 */
    GList *services_list(void);

/**
 * \brief Get a list of providers
 *
 * \param[in] standard  list providers of this standard (e.g. ocf, lsb, etc.)
 *
 * \return a list of providers as char * list items (or NULL if standard does not support providers)
 * \note The caller is responsible for freeing the result using g_list_free_full(list, free).
 */
    GList *resources_list_providers(const char *standard);

/**
 * \brief Get a list of resource agents
 *
 * \param[in] standard  list agents using this standard (e.g. ocf, lsb, etc.) (or NULL for all)
 * \param[in] provider  list agents from this provider (or NULL for all)
 *
 * \return a list of resource agents.  The list items are char *.
 * \note The caller is responsible for freeing the result using g_list_free_full(list, free).
 */
    GList *resources_list_agents(const char *standard, const char *provider);

/**
 * Get list of available standards
 *
 * \return a list of resource standards. The list items are char *. This list _must_
 *         be destroyed using g_list_free_full(list, free).
 */
    GList *resources_list_standards(void);

/**
 * Does the given standard, provider, and agent describe a resource that can exist?
 *
 * \param[in] standard  Which class of agent does the resource belong to?
 * \param[in] provider  What provides the agent (NULL for most standards)?
 * \param[in] agent     What is the name of the agent?
 *
 * \return A boolean
 */
    gboolean resources_agent_exists(const char *standard, const char *provider, const char *agent);

svc_action_t *services_action_create(const char *name, const char *action,
                                     guint interval_ms, int timeout /* ms */);

/**
 * \brief Create a new resource action
 *
 * \param[in] name        Name of resource
 * \param[in] standard    Resource agent standard (ocf, lsb, etc.)
 * \param[in] provider    Resource agent provider
 * \param[in] agent       Resource agent name
 * \param[in] action      action (start, stop, monitor, etc.)
 * \param[in] interval_ms How often to repeat this action (if 0, execute once)
 * \param[in] timeout     Consider action failed if it does not complete in this many milliseconds
 * \param[in] params      Action parameters
 *
 * \return newly allocated action instance
 *
 * \post After the call, 'params' is owned, and later free'd by the svc_action_t result
 * \note The caller is responsible for freeing the return value using
 *       services_action_free().
 */
svc_action_t *resources_action_create(const char *name, const char *standard,
                                      const char *provider, const char *agent,
                                      const char *action, guint interval_ms,
                                      int timeout /* ms */, GHashTable *params,
                                      enum svc_action_flags flags);

/**
 * Kick a recurring action so it is scheduled immediately for re-execution
 */
gboolean services_action_kick(const char *name, const char *action,
                              guint interval_ms);

    const char *resources_find_service_class(const char *agent);

/**
 * Utilize services API to execute an arbitrary command.
 *
 * This API has useful infrastructure in place to be able to run a command
 * in the background and get notified via a callback when the command finishes.
 *
 * \param[in] exec command to execute
 * \param[in] args arguments to the command, NULL terminated
 *
 * \return a svc_action_t object, used to pass to the execute function
 * (services_action_sync() or services_action_async()) and is
 * provided to the callback.
 */
    svc_action_t *services_action_create_generic(const char *exec, const char *args[]);

    void services_action_cleanup(svc_action_t * op);
    void services_action_free(svc_action_t * op);
    int services_action_user(svc_action_t *op, const char *user);

    gboolean services_action_sync(svc_action_t * op);

/**
 * Run an action asynchronously.
 *
 * \param[in] op services action data
 * \param[in] action_callback callback for when the action completes
 * \param[in] action_fork_callback callback for when action forked successfully
 *
 * \retval TRUE succesfully started execution
 * \retval FALSE failed to start execution, no callback will be received
 */
    gboolean services_action_async_fork_notify(svc_action_t * op,
        void (*action_callback) (svc_action_t *),
        void (*action_fork_callback) (svc_action_t *));

    gboolean services_action_async(svc_action_t * op,
                                   void (*action_callback) (svc_action_t *));

gboolean services_action_cancel(const char *name, const char *action,
                                guint interval_ms);

/* functions for alert agents */
svc_action_t *services_alert_create(const char *id, const char *exec,
                                   int timeout, GHashTable *params,
                                   int sequence, void *cb_data);
gboolean services_alert_async(svc_action_t *action,
                              void (*cb)(svc_action_t *op));

    static inline const char *services_ocf_exitcode_str(enum ocf_exitcode code) {
        switch (code) {
            case PCMK_OCF_OK:
                return "ok";
            case PCMK_OCF_UNKNOWN_ERROR:
                return "error";
            case PCMK_OCF_INVALID_PARAM:
                return "invalid parameter";
            case PCMK_OCF_UNIMPLEMENT_FEATURE:
                return "unimplemented feature";
            case PCMK_OCF_INSUFFICIENT_PRIV:
                return "insufficient privileges";
            case PCMK_OCF_NOT_INSTALLED:
                return "not installed";
            case PCMK_OCF_NOT_CONFIGURED:
                return "not configured";
            case PCMK_OCF_NOT_RUNNING:
                return "not running";
            case PCMK_OCF_RUNNING_PROMOTED:
                return "promoted";
            case PCMK_OCF_FAILED_PROMOTED:
                return "promoted (failed)";
            case PCMK_OCF_TIMEOUT:
                return "OCF_TIMEOUT";
            case PCMK_OCF_DEGRADED:
                return "OCF_DEGRADED";
            case PCMK_OCF_DEGRADED_PROMOTED:
                return "promoted (degraded)";

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
            case PCMK_OCF_NOT_SUPPORTED:
                return "not supported (DEPRECATED STATUS)";
            case PCMK_OCF_CANCELLED:
                return "cancelled (DEPRECATED STATUS)";
            case PCMK_OCF_OTHER_ERROR:
                return "other error (DEPRECATED STATUS)";
            case PCMK_OCF_SIGNAL:
                return "interrupted by signal (DEPRECATED STATUS)";
            case PCMK_OCF_PENDING:
                return "pending (DEPRECATED STATUS)";
#endif
            default:
                return "unknown";
        }
    }

    /**
     * \brief Get OCF equivalent of LSB exit code
     *
     * \param[in] action        LSB action that produced exit code
     * \param[in] lsb_exitcode  Exit code of LSB action
     *
     * \return PCMK_OCF_* constant that corresponds to LSB exit code
     */
    static inline enum ocf_exitcode
    services_get_ocf_exitcode(const char *action, int lsb_exitcode)
    {
        /* For non-status actions, LSB and OCF share error code meaning <= 7 */
        if (action && strcmp(action, "status") && strcmp(action, "monitor")) {
            if ((lsb_exitcode < 0) || (lsb_exitcode > PCMK_LSB_NOT_RUNNING)) {
                return PCMK_OCF_UNKNOWN_ERROR;
            }
            return (enum ocf_exitcode)lsb_exitcode;
        }

        /* status has different return codes */
        switch (lsb_exitcode) {
            case PCMK_LSB_STATUS_OK:
                return PCMK_OCF_OK;
            case PCMK_LSB_STATUS_NOT_INSTALLED:
                return PCMK_OCF_NOT_INSTALLED;
            case PCMK_LSB_STATUS_INSUFFICIENT_PRIV:
                return PCMK_OCF_INSUFFICIENT_PRIV;
            case PCMK_LSB_STATUS_VAR_PID:
            case PCMK_LSB_STATUS_VAR_LOCK:
            case PCMK_LSB_STATUS_NOT_RUNNING:
                return PCMK_OCF_NOT_RUNNING;
        }
        return PCMK_OCF_UNKNOWN_ERROR;
    }

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
#include <crm/services_compat.h>
#endif

#  ifdef __cplusplus
}
#  endif

#endif                          /* __PCMK_SERVICES__ */
