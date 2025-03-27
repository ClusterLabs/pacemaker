/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <libgen.h>
#include <inttypes.h>
#include <sys/types.h>

#include <glib.h>
#include <libxml/tree.h>            // xmlNode

#include <crm/crm.h>
#include <crm/stonith-ng.h>
#include <crm/fencing/internal.h>
#include <crm/common/xml.h>
#include <crm/services_internal.h>

#include "fencing_private.h"

struct stonith_action_s {
    /*! user defined data */
    char *agent;
    char *action;
    GHashTable *args;
    int timeout;
    bool async;
    void *userdata;
    void (*done_cb) (int pid, const pcmk__action_result_t *result,
                     void *user_data);
    void (*fork_cb) (int pid, void *user_data);

    svc_action_t *svc_action;

    /*! internal timing information */
    time_t initial_start_time;
    int tries;
    int remaining_timeout;
    int max_retries;

    int pid;
    pcmk__action_result_t result;
};

static int internal_stonith_action_execute(stonith_action_t *action);
static void log_action(stonith_action_t *action, pid_t pid);

/*!
 * \internal
 * \brief Set an action's result based on services library result
 *
 * \param[in,out] action      Fence action to set result for
 * \param[in,out] svc_action  Service action to get result from
 */
static void
set_result_from_svc_action(stonith_action_t *action, svc_action_t *svc_action)
{
    services__copy_result(svc_action, &(action->result));
    pcmk__set_result_output(&(action->result),
                            services__grab_stdout(svc_action),
                            services__grab_stderr(svc_action));
}

static void
log_action(stonith_action_t *action, pid_t pid)
{
    /* The services library has already logged the output at info or debug
     * level, so just raise to warning for stderr.
     */
    if (action->result.action_stderr != NULL) {
        /* Logging the whole string confuses syslog when the string is xml */
        char *prefix = crm_strdup_printf("%s[%d] stderr:", action->agent, pid);

        crm_log_output(LOG_WARNING, prefix, action->result.action_stderr);
        free(prefix);
    }
}

static void
append_config_arg(gpointer key, gpointer value, gpointer user_data)
{
    /* Filter out parameters handled directly by Pacemaker.
     *
     * STONITH_ATTR_ACTION_OP is added elsewhere and should never be part of the
     * fencing resource's parameter list. We should ignore its value if it is
     * configured there.
     */
    if (!pcmk__str_eq(key, STONITH_ATTR_ACTION_OP, pcmk__str_casei)
        && !pcmk_stonith_param(key)
        && (strstr(key, CRM_META) == NULL)
        && !pcmk__str_eq(key, PCMK_XA_CRM_FEATURE_SET, pcmk__str_none)) {

        crm_trace("Passing %s=%s with fence action",
                  (const char *) key, (const char *) (value? value : ""));
        pcmk__insert_dup((GHashTable *) user_data, key, pcmk__s(value, ""));
    }
}

/*!
 * \internal
 * \brief Create a table of arguments for a fencing action
 *
 * \param[in] agent          Fencing agent name
 * \param[in] action         Name of fencing action
 * \param[in] target         Name of target node for fencing action
 * \param[in] target_nodeid  Node ID of target node for fencing action
 * \param[in] device_args    Fence device parameters
 * \param[in] port_map       Target node-to-port mapping for fence device
 * \param[in] host_arg       Argument name for passing target
 *
 * \return Newly created hash table of arguments for fencing action
 */
static GHashTable *
make_args(const char *agent, const char *action, const char *target,
          uint32_t target_nodeid, GHashTable *device_args,
          GHashTable *port_map, const char *host_arg)
{
    GHashTable *arg_list = NULL;
    const char *value = NULL;

    CRM_CHECK(action != NULL, return NULL);

    arg_list = pcmk__strkey_table(free, free);

    // Add action to arguments (using an alias if requested)
    if (device_args) {
        char buffer[512];

        snprintf(buffer, sizeof(buffer), "pcmk_%s_action", action);
        value = g_hash_table_lookup(device_args, buffer);
        if (value) {
            crm_debug("Substituting '%s' for fence action %s targeting %s",
                      value, action, pcmk__s(target, "no node"));
            action = value;
        }
    }

    // Tell the fence agent what action to perform
    pcmk__insert_dup(arg_list, STONITH_ATTR_ACTION_OP, action);

    /* If this is a fencing operation against another node, add more standard
     * arguments.
     */
    if ((target != NULL) && (device_args != NULL)) {
        const char *param = NULL;

        /* Always pass the target's name, per
         * https://github.com/ClusterLabs/fence-agents/blob/main/doc/FenceAgentAPI.md
         */
        pcmk__insert_dup(arg_list, "nodename", target);

        // If the target's node ID was specified, pass it, too
        if (target_nodeid != 0) {
            char *nodeid = crm_strdup_printf("%" PRIu32, target_nodeid);

            // cts-fencing looks for this log message
            crm_info("Passing '%s' as nodeid with fence action '%s' targeting %s",
                     nodeid, action, pcmk__s(target, "no node"));
            g_hash_table_insert(arg_list, strdup("nodeid"), nodeid);
        }

        // Check whether target should be specified as some other argument
        param = g_hash_table_lookup(device_args, PCMK_STONITH_HOST_ARGUMENT);
        if (param == NULL) {
            // Use caller's default (likely from agent metadata)
            param = host_arg;
        }
        if ((param != NULL)
            && !pcmk__str_eq(agent, "fence_legacy", pcmk__str_none)
            && !pcmk__str_eq(param, PCMK_VALUE_NONE, pcmk__str_casei)) {

            value = g_hash_table_lookup(device_args, param);
            if (pcmk__str_eq(value, "dynamic",
                             pcmk__str_casei|pcmk__str_null_matches)) {
                /* If the host argument is "dynamic" or not configured,
                 * reset it to the target
                 */
                const char *alias = NULL;

                if (port_map) {
                    alias = g_hash_table_lookup(port_map, target);
                }
                if (alias == NULL) {
                    alias = target;
                }
                crm_debug("Passing %s='%s' with fence action %s targeting %s",
                          param, alias, action, pcmk__s(target, "no node"));
                pcmk__insert_dup(arg_list, param, alias);
            }
        }
    }

    if (device_args) {
        g_hash_table_foreach(device_args, append_config_arg, arg_list);
    }

    return arg_list;
}

/*!
 * \internal
 * \brief Free all memory used by a stonith action
 *
 * \param[in,out] action  Action to free
 */
void
stonith__destroy_action(stonith_action_t *action)
{
    if (action) {
        free(action->agent);
        if (action->args) {
            g_hash_table_destroy(action->args);
        }
        free(action->action);
        if (action->svc_action) {
            services_action_free(action->svc_action);
        }
        pcmk__reset_result(&(action->result));
        free(action);
    }
}

/*!
 * \internal
 * \brief Get the result of an executed stonith action
 *
 * \param[in] action  Executed action
 *
 * \return Pointer to action's result (or NULL if \p action is NULL)
 */
pcmk__action_result_t *
stonith__action_result(stonith_action_t *action)
{
    return (action == NULL)? NULL : &(action->result);
}

#define FAILURE_MAX_RETRIES 2

/*!
 * \internal
 * \brief Create a new fencing action to be executed
 *
 * \param[in] agent          Fence agent to use
 * \param[in] action_name    Fencing action to be executed
 * \param[in] target         Name of target of fencing action (if known)
 * \param[in] target_nodeid  Node ID of target of fencing action (if known)
 * \param[in] timeout_sec    Timeout to be used when executing action
 * \param[in] device_args    Parameters to pass to fence agent
 * \param[in] port_map       Mapping of target names to device ports
 * \param[in] host_arg       Agent parameter used to pass target name
 *
 * \return Newly created fencing action (asserts on error, never NULL)
 */
stonith_action_t *
stonith__action_create(const char *agent, const char *action_name,
                       const char *target, uint32_t target_nodeid,
                       int timeout_sec, GHashTable *device_args,
                       GHashTable *port_map, const char *host_arg)
{
    stonith_action_t *action = pcmk__assert_alloc(1, sizeof(stonith_action_t));

    action->args = make_args(agent, action_name, target, target_nodeid,
                             device_args, port_map, host_arg);
    crm_debug("Preparing '%s' action targeting %s using agent %s",
              action_name, pcmk__s(target, "no node"), agent);
    action->agent = strdup(agent);
    action->action = strdup(action_name);
    action->timeout = action->remaining_timeout = timeout_sec;
    action->max_retries = FAILURE_MAX_RETRIES;

    pcmk__set_result(&(action->result), PCMK_OCF_UNKNOWN, PCMK_EXEC_UNKNOWN,
                     "Initialization bug in fencing library");

    if (device_args) {
        char buffer[512];
        const char *value = NULL;

        snprintf(buffer, sizeof(buffer), "pcmk_%s_retries", action_name);
        value = g_hash_table_lookup(device_args, buffer);

        if (value) {
            action->max_retries = atoi(value);
        }
    }

    return action;
}

static gboolean
update_remaining_timeout(stonith_action_t * action)
{
    int diff = time(NULL) - action->initial_start_time;

    if (action->tries >= action->max_retries) {
        crm_info("Attempted to execute agent %s (%s) the maximum number of times (%d) allowed",
                 action->agent, action->action, action->max_retries);
        action->remaining_timeout = 0;
    } else if ((action->result.execution_status != PCMK_EXEC_TIMEOUT)
               && (diff < (action->timeout * 0.7))) {
        /* only set remaining timeout period if there is 30%
         * or greater of the original timeout period left */
        action->remaining_timeout = action->timeout - diff;
    } else {
        action->remaining_timeout = 0;
    }
    return action->remaining_timeout ? TRUE : FALSE;
}

/*!
 * \internal
 * \brief Map a fencing action result to a standard return code
 *
 * \param[in] result  Fencing action result to map
 *
 * \return Standard Pacemaker return code that best corresponds to \p result
 */
int
stonith__result2rc(const pcmk__action_result_t *result)
{
    if (pcmk__result_ok(result)) {
        return pcmk_rc_ok;
    }

    switch (result->execution_status) {
        case PCMK_EXEC_PENDING:         return EINPROGRESS;
        case PCMK_EXEC_CANCELLED:       return ECANCELED;
        case PCMK_EXEC_TIMEOUT:         return ETIME;
        case PCMK_EXEC_NOT_INSTALLED:   return ENOENT;
        case PCMK_EXEC_NOT_SUPPORTED:   return EOPNOTSUPP;
        case PCMK_EXEC_NOT_CONNECTED:   return ENOTCONN;
        case PCMK_EXEC_NO_FENCE_DEVICE: return ENODEV;
        case PCMK_EXEC_NO_SECRETS:      return EACCES;

        /* For the fencing API, PCMK_EXEC_INVALID is used with fencer API
         * operations that don't involve executing an agent (for example,
         * registering devices). This allows us to use the CRM_EX_* codes in the
         * exit status for finer-grained responses.
         */
        case PCMK_EXEC_INVALID:
            switch (result->exit_status) {
                case CRM_EX_INVALID_PARAM:      return EINVAL;
                case CRM_EX_INSUFFICIENT_PRIV:  return EACCES;
                case CRM_EX_PROTOCOL:           return EPROTO;

               /* CRM_EX_EXPIRED is used for orphaned fencing operations left
                * over from a previous instance of the fencer. For API backward
                * compatibility, this is mapped to the previously used code for
                * this case, EHOSTUNREACH.
                */
                case CRM_EX_EXPIRED:            return EHOSTUNREACH;
                default:                        break;
            }
            break;

        default:
            break;
    }

    // Try to provide useful error code based on result's error output

    if (result->action_stderr == NULL) {
        return ENODATA;

    } else if (strcasestr(result->action_stderr, "timed out")
               || strcasestr(result->action_stderr, "timeout")) {
        return ETIME;

    } else if (strcasestr(result->action_stderr, "unrecognised action")
               || strcasestr(result->action_stderr, "unrecognized action")
               || strcasestr(result->action_stderr, "unsupported action")) {
        return EOPNOTSUPP;
    }

    // Oh well, we tried
    return pcmk_rc_error;
}

/*!
 * \internal
 * \brief Determine execution status equivalent of legacy fencer return code
 *
 * Fence action notifications, and fence action callbacks from older fencers
 * (<=2.1.2) in a rolling upgrade, will have only a legacy return code. Map this
 * to an execution status as best as possible (essentially, the inverse of
 * stonith__result2rc()).
 *
 * \param[in] rc           Legacy return code from fencer
 *
 * \return Execution status best corresponding to \p rc
 */
int
stonith__legacy2status(int rc)
{
    if (rc >= 0) {
        return PCMK_EXEC_DONE;
    }
    switch (-rc) {
        case EACCES:            return PCMK_EXEC_NO_SECRETS;
        case ECANCELED:         return PCMK_EXEC_CANCELLED;
        case EHOSTUNREACH:      return PCMK_EXEC_INVALID;
        case EINPROGRESS:       return PCMK_EXEC_PENDING;
        case ENODEV:            return PCMK_EXEC_NO_FENCE_DEVICE;
        case ENOENT:            return PCMK_EXEC_NOT_INSTALLED;
        case ENOTCONN:          return PCMK_EXEC_NOT_CONNECTED;
        case EOPNOTSUPP:        return PCMK_EXEC_NOT_SUPPORTED;
        case EPROTO:            return PCMK_EXEC_INVALID;
        case EPROTONOSUPPORT:   return PCMK_EXEC_NOT_SUPPORTED;
        case ETIME:             return PCMK_EXEC_TIMEOUT;
        case ETIMEDOUT:         return PCMK_EXEC_TIMEOUT;
        default:                return PCMK_EXEC_ERROR;
    }
}

/*!
 * \internal
 * \brief Add a fencing result to an XML element as attributes
 *
 * \param[in,out] xml     XML element to add result to
 * \param[in]     result  Fencing result to add (assume success if NULL)
 */
void
stonith__xe_set_result(xmlNode *xml, const pcmk__action_result_t *result)
{
    int exit_status = CRM_EX_OK;
    enum pcmk_exec_status execution_status = PCMK_EXEC_DONE;
    const char *exit_reason = NULL;
    const char *action_stdout = NULL;
    int rc = pcmk_ok;

    CRM_CHECK(xml != NULL, return);

    if (result != NULL) {
        exit_status = result->exit_status;
        execution_status = result->execution_status;
        exit_reason = result->exit_reason;
        action_stdout = result->action_stdout;
        rc = pcmk_rc2legacy(stonith__result2rc(result));
    }

    pcmk__xe_set_int(xml, PCMK__XA_OP_STATUS, (int) execution_status);
    pcmk__xe_set_int(xml, PCMK__XA_RC_CODE, exit_status);
    pcmk__xe_set(xml, PCMK_XA_EXIT_REASON, exit_reason);
    pcmk__xe_set(xml, PCMK__XA_ST_OUTPUT, action_stdout);

    /* @COMPAT Peers in rolling upgrades, Pacemaker Remote nodes, and external
     * code that use libstonithd <=2.1.2 don't check for the full result, and
     * need a legacy return code instead.
     */
    pcmk__xe_set_int(xml, PCMK__XA_ST_RC, rc);
}

/*!
 * \internal
 * \brief Find a fencing result beneath an XML element
 *
 * \param[in]  xml     XML element to search
 *
 * \return \p xml or descendant of it that contains a fencing result, else NULL
 */
xmlNode *
stonith__find_xe_with_result(xmlNode *xml)
{
    xmlNode *match = pcmk__xpath_find_one(xml->doc,
                                          "//*[@" PCMK__XA_RC_CODE "]",
                                          LOG_NEVER);

    if (match == NULL) {
        /* @COMPAT Peers <=2.1.2 in a rolling upgrade provide only a legacy
         * return code, not a full result, so check for that.
         */
        match = pcmk__xpath_find_one(xml->doc, "//*[@" PCMK__XA_ST_RC "]",
                                     LOG_ERR);
    }
    return match;
}

/*!
 * \internal
 * \brief Get a fencing result from an XML element's attributes
 *
 * \param[in]  xml     XML element with fencing result
 * \param[out] result  Where to store fencing result
 */
void
stonith__xe_get_result(const xmlNode *xml, pcmk__action_result_t *result)
{
    int exit_status = CRM_EX_OK;
    int execution_status = PCMK_EXEC_DONE;
    const char *exit_reason = NULL;
    char *action_stdout = NULL;

    CRM_CHECK((xml != NULL) && (result != NULL), return);

    exit_reason = pcmk__xe_get(xml, PCMK_XA_EXIT_REASON);
    action_stdout = pcmk__xe_get_copy(xml, PCMK__XA_ST_OUTPUT);

    // A result must include an exit status and execution status
    if ((pcmk__xe_get_int(xml, PCMK__XA_RC_CODE, &exit_status) != pcmk_rc_ok)
        || (pcmk__xe_get_int(xml, PCMK__XA_OP_STATUS,
                             &execution_status) != pcmk_rc_ok)) {
        int rc = pcmk_ok;
        exit_status = CRM_EX_ERROR;

        /* @COMPAT Peers <=2.1.2 in rolling upgrades provide only a legacy
         * return code, not a full result, so check for that.
         */
        if (pcmk__xe_get_int(xml, PCMK__XA_ST_RC, &rc) == pcmk_rc_ok) {
            if ((rc == pcmk_ok) || (rc == -EINPROGRESS)) {
                exit_status = CRM_EX_OK;
            }
            execution_status = stonith__legacy2status(rc);
            exit_reason = pcmk_strerror(rc);

        } else {
            execution_status = PCMK_EXEC_ERROR;
            exit_reason = "Fencer reply contained neither a full result "
                          "nor a legacy return code (bug?)";
        }
    }
    pcmk__set_result(result, exit_status, execution_status, exit_reason);
    pcmk__set_result_output(result, action_stdout, NULL);
}

static void
stonith_action_async_done(svc_action_t *svc_action)
{
    stonith_action_t *action = (stonith_action_t *) svc_action->cb_data;

    set_result_from_svc_action(action, svc_action);
    svc_action->params = NULL;
    log_action(action, action->pid);

    if (!pcmk__result_ok(&(action->result))
        && update_remaining_timeout(action)) {

        int rc = internal_stonith_action_execute(action);
        if (rc == pcmk_ok) {
            return;
        }
    }

    if (action->done_cb) {
        action->done_cb(action->pid, &(action->result), action->userdata);
    }

    action->svc_action = NULL; // don't remove our caller
    stonith__destroy_action(action);
}

static void
stonith_action_async_forked(svc_action_t *svc_action)
{
    stonith_action_t *action = (stonith_action_t *) svc_action->cb_data;

    action->pid = svc_action->pid;
    action->svc_action = svc_action;

    if (action->fork_cb) {
        (action->fork_cb) (svc_action->pid, action->userdata);
    }

    pcmk__set_result(&(action->result), PCMK_OCF_UNKNOWN, PCMK_EXEC_PENDING,
                     NULL);

    crm_trace("Child process %d performing action '%s' successfully forked",
              action->pid, action->action);
}

/*!
 * \internal
 * \brief Convert a fencing library action to a services library action
 *
 * \param[in,out] action  Fencing library action to convert
 *
 * \return Services library action equivalent to \p action on success; on error,
 *         NULL will be returned and \p action's result will be set
 */
static svc_action_t *
stonith_action_to_svc(stonith_action_t *action)
{
    static int stonith_sequence = 0;

    char *path = crm_strdup_printf(PCMK__FENCE_BINDIR "/%s", action->agent);
    svc_action_t *svc_action = services_action_create_generic(path, NULL);

    free(path);
    if (svc_action->rc != PCMK_OCF_UNKNOWN) {
        set_result_from_svc_action(action, svc_action);
        services_action_free(svc_action);
        return NULL;
    }

    svc_action->timeout = action->remaining_timeout * 1000;
    svc_action->standard = pcmk__str_copy(PCMK_RESOURCE_CLASS_STONITH);
    svc_action->id = crm_strdup_printf("%s_%s_%dof%d", action->agent,
                                       action->action, action->tries,
                                       action->max_retries);
    svc_action->agent = pcmk__str_copy(action->agent);
    svc_action->sequence = stonith_sequence++;
    svc_action->params = action->args;
    svc_action->cb_data = (void *) action;
    svc_action->flags = pcmk__set_flags_as(__func__, __LINE__,
                                           LOG_TRACE, "Action",
                                           svc_action->id, svc_action->flags,
                                           SVC_ACTION_NON_BLOCKED,
                                           "SVC_ACTION_NON_BLOCKED");

    return svc_action;
}

static int
internal_stonith_action_execute(stonith_action_t * action)
{
    int rc = pcmk_ok;
    int is_retry = 0;
    svc_action_t *svc_action = NULL;

    CRM_CHECK(action != NULL, return -EINVAL);

    if ((action->action == NULL) || (action->args == NULL)
        || (action->agent == NULL)) {
        pcmk__set_result(&(action->result), PCMK_OCF_UNKNOWN_ERROR,
                         PCMK_EXEC_ERROR_FATAL, "Bug in fencing library");
        return -EINVAL;
    }

    if (action->tries++ == 0) {
        // First attempt of the desired action
        action->initial_start_time = time(NULL);
    } else {
        // Later attempt after earlier failure
        crm_info("Attempt %d to execute '%s' action of agent %s "
                 "(%ds timeout remaining)",
                 action->tries, action->action, action->agent,
                 action->remaining_timeout);
        is_retry = 1;
    }

    svc_action = stonith_action_to_svc(action);
    if (svc_action == NULL) {
        // The only possible errors are out-of-memory and too many arguments
        return -E2BIG;
    }

    /* keep retries from executing out of control and free previous results */
    if (is_retry) {
        pcmk__reset_result(&(action->result));
        // @TODO This should be nonblocking via timer if mainloop is used
        sleep(1);
    }

    if (action->async) {
        // We never create a recurring action, so this should always return TRUE
        CRM_LOG_ASSERT(services_action_async_fork_notify(svc_action,
                                              &stonith_action_async_done,
                                              &stonith_action_async_forked));
        return pcmk_ok;

    } else if (!services_action_sync(svc_action)) {
        rc = -ECONNABORTED; // @TODO Update API to return more useful error
    }

    set_result_from_svc_action(action, svc_action);
    svc_action->params = NULL;
    services_action_free(svc_action);
    return rc;
}

/*!
 * \internal
 * \brief Kick off execution of an async stonith action
 *
 * \param[in,out] action        Action to be executed
 * \param[in,out] userdata      Datapointer to be passed to callbacks
 * \param[in]     done          Callback to notify action has failed/succeeded
 * \param[in]     fork_callback Callback to notify successful fork of child
 *
 * \return pcmk_ok if ownership of action has been taken, -errno otherwise
 */
int
stonith__execute_async(stonith_action_t * action, void *userdata,
                       void (*done) (int pid,
                                     const pcmk__action_result_t *result,
                                     void *user_data),
                       void (*fork_cb) (int pid, void *user_data))
{
    if (!action) {
        return -EINVAL;
    }

    action->userdata = userdata;
    action->done_cb = done;
    action->fork_cb = fork_cb;
    action->async = true;

    return internal_stonith_action_execute(action);
}

/*!
 * \internal
 * \brief Execute a stonith action
 *
 * \param[in,out] action  Action to execute
 *
 * \return pcmk_ok on success, -errno otherwise
 */
int
stonith__execute(stonith_action_t *action)
{
    int rc = pcmk_ok;

    CRM_CHECK(action != NULL, return -EINVAL);

    // Keep trying until success, max retries, or timeout
    do {
        rc = internal_stonith_action_execute(action);
    } while ((rc != pcmk_ok) && update_remaining_timeout(action));

    return rc;
}
