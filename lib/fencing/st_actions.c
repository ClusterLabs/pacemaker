/*
 * Copyright 2004-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <libgen.h>
#include <inttypes.h>
#include <sys/types.h>
#include <glib.h>

#include <crm/crm.h>
#include <crm/stonith-ng.h>
#include <crm/fencing/internal.h>
#include <crm/msg_xml.h>
#include <crm/services_internal.h>

#include "fencing_private.h"

struct stonith_action_s {
    /*! user defined data */
    char *agent;
    char *action;
    char *victim;
    GHashTable *args;
    int timeout;
    int async;
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
 * \param[in] action      Fence action to set result for
 * \param[in] svc_action  Service action to get result from
 */
static void
set_result_from_svc_action(stonith_action_t *action, svc_action_t *svc_action)
{
    pcmk__set_result(&(action->result), svc_action->rc, svc_action->status,
                     services__exit_reason(svc_action));
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
    /* The fencer will filter "action" out when it registers the device,
     * but ignore it here in case any external API users don't.
     *
     * Also filter out parameters handled directly by Pacemaker.
     */
    if (!pcmk__str_eq(key, STONITH_ATTR_ACTION_OP, pcmk__str_casei)
        && !pcmk_stonith_param(key)
        && (strstr(key, CRM_META) == NULL)
        && !pcmk__str_eq(key, "crm_feature_set", pcmk__str_casei)) {

        crm_trace("Passing %s=%s with fence action",
                  (const char *) key, (const char *) (value? value : ""));
        g_hash_table_insert((GHashTable *) user_data,
                            strdup(key), strdup(value? value : ""));
    }
}

static GHashTable *
make_args(const char *agent, const char *action, const char *victim,
          uint32_t victim_nodeid, GHashTable * device_args,
          GHashTable * port_map, const char *host_arg)
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
                      value, action, victim);
            action = value;
        }
    }
    g_hash_table_insert(arg_list, strdup(STONITH_ATTR_ACTION_OP),
                        strdup(action));

    /* If this is a fencing operation against another node, add more standard
     * arguments.
     */
    if (victim && device_args) {
        const char *param = NULL;

        /* Always pass the target's name, per
         * https://github.com/ClusterLabs/fence-agents/blob/master/doc/FenceAgentAPI.md
         */
        g_hash_table_insert(arg_list, strdup("nodename"), strdup(victim));

        // If the target's node ID was specified, pass it, too
        if (victim_nodeid) {
            char *nodeid = crm_strdup_printf("%" PRIu32, victim_nodeid);

            // cts-fencing looks for this log message
            crm_info("Passing '%s' as nodeid with fence action '%s' targeting %s",
                     nodeid, action, victim);
            g_hash_table_insert(arg_list, strdup("nodeid"), nodeid);
        }

        // Check whether target must be specified in some other way
        param = g_hash_table_lookup(device_args, PCMK_STONITH_HOST_ARGUMENT);
        if (!pcmk__str_eq(agent, "fence_legacy", pcmk__str_none)
            && !pcmk__str_eq(param, "none", pcmk__str_casei)) {

            if (param == NULL) {
                /* Use the caller's default for pcmk_host_argument, or "port" if
                 * none was given
                 */
                param = (host_arg == NULL)? "port" : host_arg;
            }
            value = g_hash_table_lookup(device_args, param);

            if (pcmk__str_eq(value, "dynamic",
                             pcmk__str_casei|pcmk__str_null_matches)) {
                /* If the host argument was "dynamic" or not explicitly specified,
                 * add it with the target
                 */
                const char *alias = NULL;

                if (port_map) {
                    alias = g_hash_table_lookup(port_map, victim);
                }
                if (alias == NULL) {
                    alias = victim;
                }
                crm_debug("Passing %s='%s' with fence action %s targeting %s",
                          param, alias, action, victim);
                g_hash_table_insert(arg_list, strdup(param), strdup(alias));
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
        free(action->victim);
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
stonith_action_t *
stonith_action_create(const char *agent,
                      const char *_action,
                      const char *victim,
                      uint32_t victim_nodeid,
                      int timeout, GHashTable * device_args,
                      GHashTable * port_map, const char *host_arg)
{
    stonith_action_t *action;

    action = calloc(1, sizeof(stonith_action_t));
    CRM_ASSERT(action != NULL);

    action->args = make_args(agent, _action, victim, victim_nodeid,
                             device_args, port_map, host_arg);
    crm_debug("Preparing '%s' action for %s using agent %s",
              _action, (victim? victim : "no target"), agent);
    action->agent = strdup(agent);
    action->action = strdup(_action);
    pcmk__str_update(&action->victim, victim);
    action->timeout = action->remaining_timeout = timeout;
    action->max_retries = FAILURE_MAX_RETRIES;

    pcmk__set_result(&(action->result), PCMK_OCF_UNKNOWN, PCMK_EXEC_UNKNOWN,
                     "Initialization bug in fencing library");

    if (device_args) {
        char buffer[512];
        const char *value = NULL;

        snprintf(buffer, sizeof(buffer), "pcmk_%s_retries", _action);
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
 * \param[in] xml     XML element to add result to
 * \param[in] result  Fencing result to add (assume success if NULL)
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

    crm_xml_add_int(xml, XML_LRM_ATTR_OPSTATUS, (int) execution_status);
    crm_xml_add_int(xml, XML_LRM_ATTR_RC, exit_status);
    crm_xml_add(xml, XML_LRM_ATTR_EXIT_REASON, exit_reason);
    crm_xml_add(xml, F_STONITH_OUTPUT, action_stdout);

    /* @COMPAT Peers in rolling upgrades, Pacemaker Remote nodes, and external
     * code that use libstonithd <=2.1.2 don't check for the full result, and
     * need a legacy return code instead.
     */
    crm_xml_add_int(xml, F_STONITH_RC, rc);
}

/*!
 * \internal
 * \brief Find a fencing result beneath an XML element
 *
 * \param[in]  xml     XML element to search
 *
 * \return \p xml or descendent of it that contains a fencing result, else NULL
 */
xmlNode *
stonith__find_xe_with_result(xmlNode *xml)
{
    xmlNode *match = get_xpath_object("//@" XML_LRM_ATTR_RC, xml, LOG_NEVER);

    if (match == NULL) {
        /* @COMPAT Peers <=2.1.2 in a rolling upgrade provide only a legacy
         * return code, not a full result, so check for that.
         */
        match = get_xpath_object("//@" F_STONITH_RC, xml, LOG_ERR);
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
stonith__xe_get_result(xmlNode *xml, pcmk__action_result_t *result)
{
    int exit_status = CRM_EX_OK;
    int execution_status = PCMK_EXEC_DONE;
    const char *exit_reason = NULL;
    char *action_stdout = NULL;

    CRM_CHECK((xml != NULL) && (result != NULL), return);

    exit_reason = crm_element_value(xml, XML_LRM_ATTR_EXIT_REASON);
    action_stdout = crm_element_value_copy(xml, F_STONITH_OUTPUT);

    // A result must include an exit status and execution status
    if ((crm_element_value_int(xml, XML_LRM_ATTR_RC, &exit_status) < 0)
        || (crm_element_value_int(xml, XML_LRM_ATTR_OPSTATUS,
                                  &execution_status) < 0)) {
        int rc = pcmk_ok;
        exit_status = CRM_EX_ERROR;

        /* @COMPAT Peers <=2.1.2 in rolling upgrades provide only a legacy
         * return code, not a full result, so check for that.
         */
        if (crm_element_value_int(xml, F_STONITH_RC, &rc) == 0) {
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

    crm_debug("Child process %d performing action '%s' exited with rc %d",
                action->pid, action->action, svc_action->rc);

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

static int
internal_stonith_action_execute(stonith_action_t * action)
{
    int rc = -EPROTO;
    int is_retry = 0;
    svc_action_t *svc_action = NULL;
    static int stonith_sequence = 0;
    char *buffer = NULL;

    CRM_CHECK(action != NULL, return -EINVAL);

    if ((action->action == NULL) || (action->args == NULL)
        || (action->agent == NULL)) {
        pcmk__set_result(&(action->result), PCMK_OCF_UNKNOWN_ERROR,
                         PCMK_EXEC_ERROR_FATAL, "Bug in fencing library");
        return -EINVAL;
    }

    if (!action->tries) {
        action->initial_start_time = time(NULL);
    }
    action->tries++;

    if (action->tries > 1) {
        crm_info("Attempt %d to execute %s (%s). remaining timeout is %d",
                 action->tries, action->agent, action->action, action->remaining_timeout);
        is_retry = 1;
    }

    buffer = crm_strdup_printf(PCMK__FENCE_BINDIR "/%s",
                               basename(action->agent));
    svc_action = services_action_create_generic(buffer, NULL);
    free(buffer);

    if (svc_action->rc != PCMK_OCF_UNKNOWN) {
        set_result_from_svc_action(action, svc_action);
        services_action_free(svc_action);
        return -E2BIG;
    }

    svc_action->timeout = 1000 * action->remaining_timeout;
    svc_action->standard = strdup(PCMK_RESOURCE_CLASS_STONITH);
    svc_action->id = crm_strdup_printf("%s_%s_%d", basename(action->agent),
                                       action->action, action->tries);
    svc_action->agent = strdup(action->agent);
    svc_action->sequence = stonith_sequence++;
    svc_action->params = action->args;
    svc_action->cb_data = (void *) action;
    svc_action->flags = pcmk__set_flags_as(__func__, __LINE__,
                                           LOG_TRACE, "Action",
                                           svc_action->id, svc_action->flags,
                                           SVC_ACTION_NON_BLOCKED,
                                           "SVC_ACTION_NON_BLOCKED");

    /* keep retries from executing out of control and free previous results */
    if (is_retry) {
        pcmk__reset_result(&(action->result));
        sleep(1);
    }

    if (action->async) {
        // We never create a recurring action, so this should always return TRUE
        CRM_LOG_ASSERT(services_action_async_fork_notify(svc_action,
                                              &stonith_action_async_done,
                                              &stonith_action_async_forked));
        return pcmk_ok;

    } else if (services_action_sync(svc_action)) { // sync success
        rc = pcmk_ok;

    } else { // sync failure
        rc = -ECONNABORTED;
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
stonith_action_execute_async(stonith_action_t * action,
                             void *userdata,
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
    action->async = 1;

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
