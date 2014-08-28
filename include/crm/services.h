/*
 * Copyright (C) 2010 Andrew Beekhof <andrew@beekhof.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
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
    PCMK_LSB_STATUS_NOT_INSTALLED  = 4,
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
 * Get a list of files or directories in a given path
 *
 * \param[in] root full path to a directory to read
 * \param[in] files true to get a list of files, false for a list of directories
 *
 * \return a list of what was found.  The list items are gchar *.  This list _must_
 *         be destroyed using g_list_free_full(list, free).
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
 * Get a list of providers
 *
 * \param[in] the standard for providers to check for (such as "ocf")
 *
 * \return a list of providers.  The list items are gchar *.  This list _must_
 *         be destroyed using g_list_free_full(list, free).
 */
    GList *resources_list_providers(const char *standard);

/**
 * Get a list of resource agents
 *
 * \param[in] the standard for research agents to check for
 *            (such as "ocf", "lsb", or "windows")
 *
 * \return a list of resource agents.  The list items are gchar *.  This list _must_
 *         be destroyed using g_list_free_full(list, free).
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
 * Create a resources action.
 *
 * \param[in] timeout the timeout in milliseconds
 * \param[in] interval how often to repeat this action, in milliseconds.
 *            If this value is 0, only execute this action one time.
 *
 * \post After the call, 'params' is owned, and later free'd by the svc_action_t result
 */
    svc_action_t *resources_action_create(const char *name, const char *standard,
                                          const char *provider, const char *agent,
                                          const char *action, int interval /* ms */ ,
                                          int timeout /* ms */ , GHashTable * params);

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

    void
     services_action_free(svc_action_t * op);

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
    }} static inline const char *services_ocf_exitcode_str(enum ocf_exitcode code) {
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
            default:
                return "unknown";
        }
    }

    static inline enum ocf_exitcode
     services_get_ocf_exitcode(char *action, int lsb_exitcode) {
        if (action != NULL && strcmp("status", action) == 0) {
            switch (lsb_exitcode) {
                case PCMK_LSB_STATUS_OK:
                    return PCMK_OCF_OK;
                case PCMK_LSB_STATUS_VAR_PID:
                    return PCMK_OCF_NOT_RUNNING;
                case PCMK_LSB_STATUS_VAR_LOCK:
                    return PCMK_OCF_NOT_RUNNING;
                case PCMK_LSB_STATUS_NOT_RUNNING:
                    return PCMK_OCF_NOT_RUNNING;
                case PCMK_LSB_STATUS_NOT_INSTALLED:
                    return PCMK_OCF_UNKNOWN_ERROR;
                default:
                    return PCMK_OCF_UNKNOWN_ERROR;
            }

        } else if (lsb_exitcode > PCMK_LSB_NOT_RUNNING) {
            return PCMK_OCF_UNKNOWN_ERROR;
        }

        /* For non-status operations, the PCMK_LSB and PCMK_OCF share error code meaning
         * for rc <= 7 */
        return (enum ocf_exitcode)lsb_exitcode;
    }

#  ifdef __cplusplus
}
#  endif

#endif                          /* __PCMK_SERVICES__ */
