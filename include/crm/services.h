/*
 * Copyright (C) 2010 Andrew Beekhof <andrew@beekhof.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/**
 * \file
 * \brief Services API
 * \ingroup core
 */

#ifndef __PCMK_SERVICES__
#  define __PCMK_SERVICES__

#  ifdef __cplusplus
extern "C" {
#  endif

#  include <glib.h>
#  include <stdio.h>
#  include <string.h>
#  include <stdbool.h>

#  ifndef OCF_ROOT_DIR
#    define OCF_ROOT_DIR "/usr/lib/ocf"
#  endif

#  ifndef LSB_ROOT_DIR
#    define LSB_ROOT_DIR "/etc/init.d"
#  endif

/* TODO: Autodetect these two ?*/
#  ifndef SYSTEMCTL
#    define SYSTEMCTL "/bin/systemctl"
#  endif

#  ifndef SERVICE_SCRIPT
#    define SERVICE_SCRIPT "/sbin/service"
#  endif


/* This is the string passed in the OCF_EXIT_REASON_PREFIX
 * environment variable. The stderr output that occurs
 * after this prefix is encountered is considered the exit
 * reason for a completed operationt */
#define PCMK_OCF_REASON_PREFIX "ocf-exit-reason:"

/* *INDENT-OFF* */
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

/* Uniform exit codes
 * Everything is mapped to its OCF equivalent so that Pacemaker only deals with one set of codes
 */
enum ocf_exitcode {
    PCMK_OCF_OK                   = 0,
    PCMK_OCF_UNKNOWN_ERROR        = 1,
    PCMK_OCF_INVALID_PARAM        = 2,
    PCMK_OCF_UNIMPLEMENT_FEATURE  = 3,
    PCMK_OCF_INSUFFICIENT_PRIV    = 4,
    PCMK_OCF_NOT_INSTALLED        = 5,
    PCMK_OCF_NOT_CONFIGURED       = 6,
    PCMK_OCF_NOT_RUNNING          = 7,  /* End of overlap with LSB */
    PCMK_OCF_RUNNING_MASTER       = 8,
    PCMK_OCF_FAILED_MASTER        = 9,


    /* 150-199	reserved for application use */
    PCMK_OCF_CONNECTION_DIED = 189, /* Operation failure implied by disconnection of the LRM API to a local or remote node */

    PCMK_OCF_DEGRADED        = 190, /* Active resource that is no longer 100% functional */
    PCMK_OCF_DEGRADED_MASTER = 191, /* Promoted resource that is no longer 100% functional */

    PCMK_OCF_EXEC_ERROR    = 192, /* Generic problem invoking the agent */
    PCMK_OCF_UNKNOWN       = 193, /* State of the service is unknown - used for recording in-flight operations */
    PCMK_OCF_SIGNAL        = 194,
    PCMK_OCF_NOT_SUPPORTED = 195,
    PCMK_OCF_PENDING       = 196,
    PCMK_OCF_CANCELLED     = 197,
    PCMK_OCF_TIMEOUT       = 198,
    PCMK_OCF_OTHER_ERROR   = 199, /* Keep the same codes as PCMK_LSB */
};

enum op_status {
    PCMK_LRM_OP_PENDING = -1,
    PCMK_LRM_OP_DONE,
    PCMK_LRM_OP_CANCELLED,
    PCMK_LRM_OP_TIMEOUT,
    PCMK_LRM_OP_NOTSUPPORTED,
    PCMK_LRM_OP_ERROR,
    PCMK_LRM_OP_ERROR_HARD,
    PCMK_LRM_OP_ERROR_FATAL,
    PCMK_LRM_OP_NOT_INSTALLED,
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
};

/* *INDENT-ON* */

    typedef struct svc_action_private_s svc_action_private_t;
    typedef struct svc_action_s {
        char *id;
        char *rsc;
        char *action;
        int interval;

        char *standard;
        char *provider;
        char *agent;

        int timeout;
        GHashTable *params;

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

    /**
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

    svc_action_t *services_action_create(const char *name, const char *action,
                                         int interval /* ms */ , int timeout /* ms */ );

/**
 * \brief Create a new resource action
 *
 * \param[in] name     name of resource
 * \param[in] standard resource agent standard (ocf, lsb, etc.)
 * \param[in] provider resource agent provider
 * \param[in] agent    resource agent name
 * \param[in] action   action (start, stop, monitor, etc.)
 * \param[in] interval how often to repeat this action, in milliseconds (if 0, execute only once)
 * \param[in] timeout  consider action failed if it does not complete in this many milliseconds
 * \param[in] params   action parameters
 *
 * \return newly allocated action instance
 *
 * \post After the call, 'params' is owned, and later free'd by the svc_action_t result
 * \note The caller is responsible for freeing the return value using
 *       services_action_free().
 */
    svc_action_t *resources_action_create(const char *name, const char *standard,
                                          const char *provider, const char *agent,
                                          const char *action, int interval /* ms */ ,
                                          int timeout /* ms */ , GHashTable * params,
                                          enum svc_action_flags flags);

/**
 * Kick a recurring action so it is scheduled immediately for re-execution
 */
    gboolean services_action_kick(const char *name, const char *action, int interval /* ms */);

/**
 * Find the first class that can provide service::${agent}
 *
 * \param[in] agent which agent to search for
 * \return NULL, or the first class that provides the named agent
 */
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

    gboolean services_action_sync(svc_action_t * op);

/**
 * Run an action asynchronously.
 *
 * \param[in] op services action data
 * \param[in] action_callback callback for when the action completes
 *
 * \retval TRUE succesfully started execution
 * \retval FALSE failed to start execution, no callback will be received
 */
    gboolean services_action_async(svc_action_t * op, void (*action_callback) (svc_action_t *));

    gboolean services_action_cancel(const char *name, const char *action, int interval);

    static inline const char *services_lrm_status_str(enum op_status status) {
        switch (status) {
            case PCMK_LRM_OP_PENDING:
                return "pending";
                case PCMK_LRM_OP_DONE:return "complete";
                case PCMK_LRM_OP_CANCELLED:return "Cancelled";
                case PCMK_LRM_OP_TIMEOUT:return "Timed Out";
                case PCMK_LRM_OP_NOTSUPPORTED:return "NOT SUPPORTED";
                case PCMK_LRM_OP_ERROR:return "Error";
                case PCMK_LRM_OP_NOT_INSTALLED:return "Not installed";
                default:return "UNKNOWN!";
        }
    }

    static inline const char *services_ocf_exitcode_str(enum ocf_exitcode code) {
        switch (code) {
            case PCMK_OCF_OK:
                return "ok";
            case PCMK_OCF_UNKNOWN_ERROR:
                return "unknown error";
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
            case PCMK_OCF_RUNNING_MASTER:
                return "master";
            case PCMK_OCF_FAILED_MASTER:
                return "master (failed)";
            case PCMK_OCF_SIGNAL:
                return "OCF_SIGNAL";
            case PCMK_OCF_NOT_SUPPORTED:
                return "OCF_NOT_SUPPORTED";
            case PCMK_OCF_PENDING:
                return "OCF_PENDING";
            case PCMK_OCF_CANCELLED:
                return "OCF_CANCELLED";
            case PCMK_OCF_TIMEOUT:
                return "OCF_TIMEOUT";
            case PCMK_OCF_OTHER_ERROR:
                return "OCF_OTHER_ERROR";
            case PCMK_OCF_DEGRADED:
                return "OCF_DEGRADED";
            case PCMK_OCF_DEGRADED_MASTER:
                return "OCF_DEGRADED_MASTER";
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

#  ifdef __cplusplus
}
#  endif

#endif                          /* __PCMK_SERVICES__ */
