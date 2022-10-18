/*
 * Copyright 2009-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <sys/param.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/utsname.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/ipc.h>
#include <crm/common/ipc_internal.h>
#include <crm/cluster/internal.h>
#include <crm/common/mainloop.h>

#include <crm/stonith-ng.h>
#include <crm/fencing/internal.h>
#include <crm/common/xml.h>

#include <pacemaker-fenced.h>

GHashTable *device_list = NULL;
GHashTable *topology = NULL;
static GList *cmd_list = NULL;

static GHashTable *fenced_handlers = NULL;

struct device_search_s {
    /* target of fence action */
    char *host;
    /* requested fence action */
    char *action;
    /* timeout to use if a device is queried dynamically for possible targets */
    int per_device_timeout;
    /* number of registered fencing devices at time of request */
    int replies_needed;
    /* number of device replies received so far */
    int replies_received;
    /* whether the target is eligible to perform requested action (or off) */
    bool allow_suicide;

    /* private data to pass to search callback function */
    void *user_data;
    /* function to call when all replies have been received */
    void (*callback) (GList * devices, void *user_data);
    /* devices capable of performing requested action (or off if remapping) */
    GList *capable;
    /* Whether to perform searches that support the action */
    uint32_t support_action_only;
};

static gboolean stonith_device_dispatch(gpointer user_data);
static void st_child_done(int pid, const pcmk__action_result_t *result,
                          void *user_data);
static void stonith_send_reply(xmlNode * reply, int call_options, const char *remote_peer,
                               pcmk__client_t *client);

static void search_devices_record_result(struct device_search_s *search, const char *device,
                                         gboolean can_fence);

static int get_agent_metadata(const char *agent, xmlNode **metadata);
static void read_action_metadata(stonith_device_t *device);
static enum fenced_target_by unpack_level_kind(const xmlNode *level);

typedef struct async_command_s {

    int id;
    int pid;
    int fd_stdout;
    int options;
    int default_timeout; /* seconds */
    int timeout; /* seconds */

    int start_delay; // seconds (-1 means disable static/random fencing delays)
    int delay_id;

    char *op;
    char *origin;
    char *client;
    char *client_name;
    char *remote_op_id;

    char *target;
    uint32_t target_nodeid;
    char *action;
    char *device;

    GList *device_list;
    GList *next_device_iter; // device_list entry for next device to execute

    void *internal_user_data;
    void (*done_cb) (int pid, const pcmk__action_result_t *result,
                     void *user_data);
    guint timer_sigterm;
    guint timer_sigkill;
    /*! If the operation timed out, this is the last signal
     *  we sent to the process to get it to terminate */
    int last_timeout_signo;

    stonith_device_t *active_on;
    stonith_device_t *activating_on;
} async_command_t;

static xmlNode *construct_async_reply(const async_command_t *cmd,
                                      const pcmk__action_result_t *result);

static gboolean
is_action_required(const char *action, const stonith_device_t *device)
{
    return device && device->automatic_unfencing && pcmk__str_eq(action, "on",
                                                                 pcmk__str_casei);
}

static int
get_action_delay_max(const stonith_device_t *device, const char *action)
{
    const char *value = NULL;
    int delay_max = 0;

    if (!pcmk__is_fencing_action(action)) {
        return 0;
    }

    value = g_hash_table_lookup(device->params, PCMK_STONITH_DELAY_MAX);
    if (value) {
       delay_max = crm_parse_interval_spec(value) / 1000;
    }

    return delay_max;
}

static int
get_action_delay_base(const stonith_device_t *device, const char *action,
                      const char *target)
{
    char *hash_value = NULL;
    int delay_base = 0;

    if (!pcmk__is_fencing_action(action)) {
        return 0;
    }

    hash_value = g_hash_table_lookup(device->params, PCMK_STONITH_DELAY_BASE);

    if (hash_value) {
        char *value = strdup(hash_value);
        char *valptr = value;

        CRM_ASSERT(value != NULL);

        if (target != NULL) {
            for (char *val = strtok(value, "; \t"); val != NULL; val = strtok(NULL, "; \t")) {
                char *mapval = strchr(val, ':');

                if (mapval == NULL || mapval[1] == 0) {
                    crm_err("pcmk_delay_base: empty value in mapping", val);
                    continue;
                }

                if (mapval != val && strncasecmp(target, val, (size_t)(mapval - val)) == 0) {
                    value = mapval + 1;
                    crm_debug("pcmk_delay_base mapped to %s for %s",
                              value, target);
                    break;
                }
            }
        }

        if (strchr(value, ':') == 0) {
           delay_base = crm_parse_interval_spec(value) / 1000;
        }

        free(valptr);
    }

    return delay_base;
}

/*!
 * \internal
 * \brief Override STONITH timeout with pcmk_*_timeout if available
 *
 * \param[in] device           STONITH device to use
 * \param[in] action           STONITH action name
 * \param[in] default_timeout  Timeout to use if device does not have
 *                             a pcmk_*_timeout parameter for action
 *
 * \return Value of pcmk_(action)_timeout if available, otherwise default_timeout
 * \note For consistency, it would be nice if reboot/off/on timeouts could be
 *       set the same way as start/stop/monitor timeouts, i.e. with an
 *       <operation> entry in the fencing resource configuration. However that
 *       is insufficient because fencing devices may be registered directly via
 *       the fencer's register_device() API instead of going through the CIB
 *       (e.g. stonith_admin uses it for its -R option, and the executor uses it
 *       to ensure a device is registered when a command is issued). As device
 *       properties, pcmk_*_timeout parameters can be grabbed by the fencer when
 *       the device is registered, whether by CIB change or API call.
 */
static int
get_action_timeout(const stonith_device_t *device, const char *action,
                   int default_timeout)
{
    if (action && device && device->params) {
        char buffer[64] = { 0, };
        const char *value = NULL;

        /* If "reboot" was requested but the device does not support it,
         * we will remap to "off", so check timeout for "off" instead
         */
        if (pcmk__str_eq(action, "reboot", pcmk__str_casei)
            && !pcmk_is_set(device->flags, st_device_supports_reboot)) {
            crm_trace("%s doesn't support reboot, using timeout for off instead",
                      device->id);
            action = "off";
        }

        /* If the device config specified an action-specific timeout, use it */
        snprintf(buffer, sizeof(buffer), "pcmk_%s_timeout", action);
        value = g_hash_table_lookup(device->params, buffer);
        if (value) {
            return atoi(value);
        }
    }
    return default_timeout;
}

/*!
 * \internal
 * \brief Get the currently executing device for a fencing operation
 *
 * \param[in] cmd  Fencing operation to check
 *
 * \return Currently executing device for \p cmd if any, otherwise NULL
 */
static stonith_device_t *
cmd_device(const async_command_t *cmd)
{
    if ((cmd == NULL) || (cmd->device == NULL) || (device_list == NULL)) {
        return NULL;
    }
    return g_hash_table_lookup(device_list, cmd->device);
}

/*!
 * \internal
 * \brief Return the configured reboot action for a given device
 *
 * \param[in] device_id  Device ID
 *
 * \return Configured reboot action for \p device_id
 */
const char *
fenced_device_reboot_action(const char *device_id)
{
    const char *action = NULL;

    if ((device_list != NULL) && (device_id != NULL)) {
        stonith_device_t *device = g_hash_table_lookup(device_list, device_id);

        if ((device != NULL) && (device->params != NULL)) {
            action = g_hash_table_lookup(device->params, "pcmk_reboot_action");
        }
    }
    return pcmk__s(action, "reboot");
}

/*!
 * \internal
 * \brief Check whether a given device supports the "on" action
 *
 * \param[in] device_id  Device ID
 *
 * \return true if \p device_id supports "on", otherwise false
 */
bool
fenced_device_supports_on(const char *device_id)
{
    if ((device_list != NULL) && (device_id != NULL)) {
        stonith_device_t *device = g_hash_table_lookup(device_list, device_id);

        if (device != NULL) {
            return pcmk_is_set(device->flags, st_device_supports_on);
        }
    }
    return false;
}

static void
free_async_command(async_command_t * cmd)
{
    if (!cmd) {
        return;
    }

    if (cmd->delay_id) {
        g_source_remove(cmd->delay_id);
    }

    cmd_list = g_list_remove(cmd_list, cmd);

    g_list_free_full(cmd->device_list, free);
    free(cmd->device);
    free(cmd->action);
    free(cmd->target);
    free(cmd->remote_op_id);
    free(cmd->client);
    free(cmd->client_name);
    free(cmd->origin);
    free(cmd->op);
    free(cmd);
}

/*!
 * \internal
 * \brief Create a new asynchronous fencing operation from request XML
 *
 * \param[in] msg  Fencing request XML (from IPC or CPG)
 *
 * \return Newly allocated fencing operation on success, otherwise NULL
 *
 * \note This asserts on memory errors, so a NULL return indicates an
 *       unparseable message.
 */
static async_command_t *
create_async_command(xmlNode *msg)
{
    xmlNode *op = NULL;
    async_command_t *cmd = NULL;

    if (msg == NULL) {
        return NULL;
    }

    op = get_xpath_object("//@" F_STONITH_ACTION, msg, LOG_ERR);
    if (op == NULL) {
        return NULL;
    }

    cmd = calloc(1, sizeof(async_command_t));
    CRM_ASSERT(cmd != NULL);

    // All messages must include these
    cmd->action = crm_element_value_copy(op, F_STONITH_ACTION);
    cmd->op = crm_element_value_copy(msg, F_STONITH_OPERATION);
    cmd->client = crm_element_value_copy(msg, F_STONITH_CLIENTID);
    if ((cmd->action == NULL) || (cmd->op == NULL) || (cmd->client == NULL)) {
        free_async_command(cmd);
        return NULL;
    }

    crm_element_value_int(msg, F_STONITH_CALLID, &(cmd->id));
    crm_element_value_int(msg, F_STONITH_CALLOPTS, &(cmd->options));
    crm_element_value_int(msg, F_STONITH_DELAY, &(cmd->start_delay));
    crm_element_value_int(msg, F_STONITH_TIMEOUT, &(cmd->default_timeout));
    cmd->timeout = cmd->default_timeout;

    cmd->origin = crm_element_value_copy(msg, F_ORIG);
    cmd->remote_op_id = crm_element_value_copy(msg, F_STONITH_REMOTE_OP_ID);
    cmd->client_name = crm_element_value_copy(msg, F_STONITH_CLIENTNAME);
    cmd->target = crm_element_value_copy(op, F_STONITH_TARGET);
    cmd->device = crm_element_value_copy(op, F_STONITH_DEVICE);

    cmd->done_cb = st_child_done;

    // Track in global command list
    cmd_list = g_list_append(cmd_list, cmd);

    return cmd;
}

static int
get_action_limit(stonith_device_t * device)
{
    const char *value = NULL;
    int action_limit = 1;

    value = g_hash_table_lookup(device->params, PCMK_STONITH_ACTION_LIMIT);
    if ((value == NULL)
        || (pcmk__scan_min_int(value, &action_limit, INT_MIN) != pcmk_rc_ok)
        || (action_limit == 0)) {
        action_limit = 1;
    }
    return action_limit;
}

static int
get_active_cmds(stonith_device_t * device)
{
    int counter = 0;
    GList *gIter = NULL;
    GList *gIterNext = NULL;

    CRM_CHECK(device != NULL, return 0);

    for (gIter = cmd_list; gIter != NULL; gIter = gIterNext) {
        async_command_t *cmd = gIter->data;

        gIterNext = gIter->next;

        if (cmd->active_on == device) {
            counter++;
        }
    }

    return counter;
}

static void
fork_cb(int pid, void *user_data)
{
    async_command_t *cmd = (async_command_t *) user_data;
    stonith_device_t * device =
        /* in case of a retry we've done the move from
           activating_on to active_on already
         */
        cmd->activating_on?cmd->activating_on:cmd->active_on;

    CRM_ASSERT(device);
    crm_debug("Operation '%s' [%d]%s%s using %s now running with %ds timeout",
              cmd->action, pid,
              ((cmd->target == NULL)? "" : " targeting "),
              pcmk__s(cmd->target, ""), device->id, cmd->timeout);
    cmd->active_on = device;
    cmd->activating_on = NULL;
}

static int
get_agent_metadata_cb(gpointer data) {
    stonith_device_t *device = data;
    guint period_ms;

    switch (get_agent_metadata(device->agent, &device->agent_metadata)) {
        case pcmk_rc_ok:
            if (device->agent_metadata) {
                read_action_metadata(device);
                stonith__device_parameter_flags(&(device->flags), device->id,
                                        device->agent_metadata);
            }
            return G_SOURCE_REMOVE;

        case EAGAIN:
            period_ms = pcmk__mainloop_timer_get_period(device->timer);
            if (period_ms < 160 * 1000) {
                mainloop_timer_set_period(device->timer, 2 * period_ms);
            }
            return G_SOURCE_CONTINUE;

        default:
            return G_SOURCE_REMOVE;
    }
}

/*!
 * \internal
 * \brief Call a command's action callback for an internal (not library) result
 *
 * \param[in,out] cmd               Command to report result for
 * \param[in]     execution_status  Execution status to use for result
 * \param[in]     exit_status       Exit status to use for result
 * \param[in]     exit_reason       Exit reason to use for result
 */
static void
report_internal_result(async_command_t *cmd, int exit_status,
                       int execution_status, const char *exit_reason)
{
    pcmk__action_result_t result = PCMK__UNKNOWN_RESULT;

    pcmk__set_result(&result, exit_status, execution_status, exit_reason);
    cmd->done_cb(0, &result, cmd);
    pcmk__reset_result(&result);
}

static gboolean
stonith_device_execute(stonith_device_t * device)
{
    int exec_rc = 0;
    const char *action_str = NULL;
    const char *host_arg = NULL;
    async_command_t *cmd = NULL;
    stonith_action_t *action = NULL;
    int active_cmds = 0;
    int action_limit = 0;
    GList *gIter = NULL;
    GList *gIterNext = NULL;

    CRM_CHECK(device != NULL, return FALSE);

    active_cmds = get_active_cmds(device);
    action_limit = get_action_limit(device);
    if (action_limit > -1 && active_cmds >= action_limit) {
        crm_trace("%s is over its action limit of %d (%u active action%s)",
                  device->id, action_limit, active_cmds,
                  pcmk__plural_s(active_cmds));
        return TRUE;
    }

    for (gIter = device->pending_ops; gIter != NULL; gIter = gIterNext) {
        async_command_t *pending_op = gIter->data;

        gIterNext = gIter->next;

        if (pending_op && pending_op->delay_id) {
            crm_trace("Operation '%s'%s%s using %s was asked to run too early, "
                      "waiting for start delay of %ds",
                      pending_op->action,
                      ((pending_op->target == NULL)? "" : " targeting "),
                      pcmk__s(pending_op->target, ""),
                      device->id, pending_op->start_delay);
            continue;
        }

        device->pending_ops = g_list_remove_link(device->pending_ops, gIter);
        g_list_free_1(gIter);

        cmd = pending_op;
        break;
    }

    if (cmd == NULL) {
        crm_trace("No actions using %s are needed", device->id);
        return TRUE;
    }

    if (pcmk__str_any_of(device->agent, STONITH_WATCHDOG_AGENT,
                         STONITH_WATCHDOG_AGENT_INTERNAL, NULL)) {
        if (pcmk__is_fencing_action(cmd->action)) {
            if (node_does_watchdog_fencing(stonith_our_uname)) {
                pcmk__panic(__func__);
                goto done;
            }
        } else {
            crm_info("Faking success for %s watchdog operation", cmd->action);
            report_internal_result(cmd, CRM_EX_OK, PCMK_EXEC_DONE, NULL);
            goto done;
        }
    }

#if SUPPORT_CIBSECRETS
    exec_rc = pcmk__substitute_secrets(device->id, device->params);
    if (exec_rc != pcmk_rc_ok) {
        if (pcmk__str_eq(cmd->action, "stop", pcmk__str_casei)) {
            crm_info("Proceeding with stop operation for %s "
                     "despite being unable to load CIB secrets (%s)",
                     device->id, pcmk_rc_str(exec_rc));
        } else {
            crm_err("Considering %s unconfigured "
                    "because unable to load CIB secrets: %s",
                     device->id, pcmk_rc_str(exec_rc));
            report_internal_result(cmd, CRM_EX_ERROR, PCMK_EXEC_NO_SECRETS,
                                   "Failed to get CIB secrets");
            goto done;
        }
    }
#endif

    action_str = cmd->action;
    if (pcmk__str_eq(cmd->action, "reboot", pcmk__str_casei)
        && !pcmk_is_set(device->flags, st_device_supports_reboot)) {

        crm_notice("Remapping 'reboot' action%s%s using %s to 'off' "
                   "because agent '%s' does not support reboot",
                   ((cmd->target == NULL)? "" : " targeting "),
                   pcmk__s(cmd->target, ""), device->id, device->agent);
        action_str = "off";
    }

    if (pcmk_is_set(device->flags, st_device_supports_parameter_port)) {
        host_arg = "port";

    } else if (pcmk_is_set(device->flags, st_device_supports_parameter_plug)) {
        host_arg = "plug";
    }

    action = stonith__action_create(device->agent, action_str, cmd->target,
                                    cmd->target_nodeid, cmd->timeout,
                                    device->params, device->aliases, host_arg);

    /* for async exec, exec_rc is negative for early error exit
       otherwise handling of success/errors is done via callbacks */
    cmd->activating_on = device;
    exec_rc = stonith__execute_async(action, (void *)cmd, cmd->done_cb,
                                     fork_cb);
    if (exec_rc < 0) {
        cmd->activating_on = NULL;
        cmd->done_cb(0, stonith__action_result(action), cmd);
        stonith__destroy_action(action);
    }

done:
    /* Device might get triggered to work by multiple fencing commands
     * simultaneously. Trigger the device again to make sure any
     * remaining concurrent commands get executed. */
    if (device->pending_ops) {
        mainloop_set_trigger(device->work);
    }
    return TRUE;
}

static gboolean
stonith_device_dispatch(gpointer user_data)
{
    return stonith_device_execute(user_data);
}

static gboolean
start_delay_helper(gpointer data)
{
    async_command_t *cmd = data;
    stonith_device_t *device = cmd_device(cmd);

    cmd->delay_id = 0;
    if (device) {
        mainloop_set_trigger(device->work);
    }

    return FALSE;
}

static void
schedule_stonith_command(async_command_t * cmd, stonith_device_t * device)
{
    int delay_max = 0;
    int delay_base = 0;
    int requested_delay = cmd->start_delay;

    CRM_CHECK(cmd != NULL, return);
    CRM_CHECK(device != NULL, return);

    if (cmd->device) {
        free(cmd->device);
    }

    if (device->include_nodeid && (cmd->target != NULL)) {
        crm_node_t *node = crm_get_peer(0, cmd->target);

        cmd->target_nodeid = node->id;
    }

    cmd->device = strdup(device->id);
    cmd->timeout = get_action_timeout(device, cmd->action, cmd->default_timeout);

    if (cmd->remote_op_id) {
        crm_debug("Scheduling '%s' action%s%s using %s for remote peer %s "
                  "with op id %.8s and timeout %ds",
                  cmd->action,
                  (cmd->target == NULL)? "" : " targeting ",
                  pcmk__s(cmd->target, ""),
                  device->id, cmd->origin, cmd->remote_op_id, cmd->timeout);
    } else {
        crm_debug("Scheduling '%s' action%s%s using %s for %s with timeout %ds",
                  cmd->action,
                  (cmd->target == NULL)? "" : " targeting ",
                  pcmk__s(cmd->target, ""),
                  device->id, cmd->client, cmd->timeout);
    }

    device->pending_ops = g_list_append(device->pending_ops, cmd);
    mainloop_set_trigger(device->work);

    // Value -1 means disable any static/random fencing delays
    if (requested_delay < 0) {
        return;
    }

    delay_max = get_action_delay_max(device, cmd->action);
    delay_base = get_action_delay_base(device, cmd->action, cmd->target);
    if (delay_max == 0) {
        delay_max = delay_base;
    }
    if (delay_max < delay_base) {
        crm_warn(PCMK_STONITH_DELAY_BASE " (%ds) is larger than "
                 PCMK_STONITH_DELAY_MAX " (%ds) for %s using %s "
                 "(limiting to maximum delay)",
                 delay_base, delay_max, cmd->action, device->id);
        delay_base = delay_max;
    }
    if (delay_max > 0) {
        // coverity[dont_call] We're not using rand() for security
        cmd->start_delay +=
            ((delay_max != delay_base)?(rand() % (delay_max - delay_base)):0)
            + delay_base;
    }

    if (cmd->start_delay > 0) {
        crm_notice("Delaying '%s' action%s%s using %s for %ds " CRM_XS
                   " timeout=%ds requested_delay=%ds base=%ds max=%ds",
                   cmd->action,
                   (cmd->target == NULL)? "" : " targeting ",
                   pcmk__s(cmd->target, ""),
                   device->id, cmd->start_delay, cmd->timeout,
                   requested_delay, delay_base, delay_max);
        cmd->delay_id =
            g_timeout_add_seconds(cmd->start_delay, start_delay_helper, cmd);
    }
}

static void
free_device(gpointer data)
{
    GList *gIter = NULL;
    stonith_device_t *device = data;

    g_hash_table_destroy(device->params);
    g_hash_table_destroy(device->aliases);

    for (gIter = device->pending_ops; gIter != NULL; gIter = gIter->next) {
        async_command_t *cmd = gIter->data;

        crm_warn("Removal of device '%s' purged operation '%s'", device->id, cmd->action);
        report_internal_result(cmd, CRM_EX_ERROR, PCMK_EXEC_NO_FENCE_DEVICE,
                               "Device was removed before action could be executed");
    }
    g_list_free(device->pending_ops);

    g_list_free_full(device->targets, free);

    if (device->timer) {
        mainloop_timer_stop(device->timer);
        mainloop_timer_del(device->timer);
    }

    mainloop_destroy_trigger(device->work);

    free_xml(device->agent_metadata);
    free(device->namespace);
    if (device->on_target_actions != NULL) {
        g_string_free(device->on_target_actions, TRUE);
    }
    free(device->agent);
    free(device->id);
    free(device);
}

void free_device_list(void)
{
    if (device_list != NULL) {
        g_hash_table_destroy(device_list);
        device_list = NULL;
    }
}

void
init_device_list(void)
{
    if (device_list == NULL) {
        device_list = pcmk__strkey_table(NULL, free_device);
    }
}

static GHashTable *
build_port_aliases(const char *hostmap, GList ** targets)
{
    char *name = NULL;
    int last = 0, lpc = 0, max = 0, added = 0;
    GHashTable *aliases = pcmk__strikey_table(free, free);

    if (hostmap == NULL) {
        return aliases;
    }

    max = strlen(hostmap);
    for (; lpc <= max; lpc++) {
        switch (hostmap[lpc]) {
                /* Skip escaped chars */
            case '\\':
                lpc++;
                break;

                /* Assignment chars */
            case '=':
            case ':':
                if (lpc > last) {
                    free(name);
                    name = calloc(1, 1 + lpc - last);
                    memcpy(name, hostmap + last, lpc - last);
                }
                last = lpc + 1;
                break;

                /* Delimeter chars */
                /* case ',': Potentially used to specify multiple ports */
            case 0:
            case ';':
            case ' ':
            case '\t':
                if (name) {
                    char *value = NULL;
                    int k = 0;

                    value = calloc(1, 1 + lpc - last);
                    memcpy(value, hostmap + last, lpc - last);

                    for (int i = 0; value[i] != '\0'; i++) {
                        if (value[i] != '\\') {
                            value[k++] = value[i];
                        }
                    }
                    value[k] = '\0';

                    crm_debug("Adding alias '%s'='%s'", name, value);
                    g_hash_table_replace(aliases, name, value);
                    if (targets) {
                        *targets = g_list_append(*targets, strdup(value));
                    }
                    value = NULL;
                    name = NULL;
                    added++;

                } else if (lpc > last) {
                    crm_debug("Parse error at offset %d near '%s'", lpc - last, hostmap + last);
                }

                last = lpc + 1;
                break;
        }

        if (hostmap[lpc] == 0) {
            break;
        }
    }

    if (added == 0) {
        crm_info("No host mappings detected in '%s'", hostmap);
    }

    free(name);
    return aliases;
}

GHashTable *metadata_cache = NULL;

void
free_metadata_cache(void) {
    if (metadata_cache != NULL) {
        g_hash_table_destroy(metadata_cache);
        metadata_cache = NULL;
    }
}

static void
init_metadata_cache(void) {
    if (metadata_cache == NULL) {
        metadata_cache = pcmk__strkey_table(free, free);
    }
}

int
get_agent_metadata(const char *agent, xmlNode ** metadata)
{
    char *buffer = NULL;

    if (metadata == NULL) {
        return EINVAL;
    }
    *metadata = NULL;
    if (pcmk__str_eq(agent, STONITH_WATCHDOG_AGENT_INTERNAL, pcmk__str_none)) {
        return pcmk_rc_ok;
    }
    init_metadata_cache();
    buffer = g_hash_table_lookup(metadata_cache, agent);
    if (buffer == NULL) {
        stonith_t *st = stonith_api_new();
        int rc;

        if (st == NULL) {
            crm_warn("Could not get agent meta-data: "
                     "API memory allocation failed");
            return EAGAIN;
        }
        rc = st->cmds->metadata(st, st_opt_sync_call, agent,
                                NULL, &buffer, 10);
        stonith_api_delete(st);
        if (rc || !buffer) {
            crm_err("Could not retrieve metadata for fencing agent %s", agent);
            return EAGAIN;
        }
        g_hash_table_replace(metadata_cache, strdup(agent), buffer);
    }

    *metadata = string2xml(buffer);
    return pcmk_rc_ok;
}

static gboolean
is_nodeid_required(xmlNode * xml)
{
    xmlXPathObjectPtr xpath = NULL;

    if (stand_alone) {
        return FALSE;
    }

    if (!xml) {
        return FALSE;
    }

    xpath = xpath_search(xml, "//parameter[@name='nodeid']");
    if (numXpathResults(xpath)  <= 0) {
        freeXpathObject(xpath);
        return FALSE;
    }

    freeXpathObject(xpath);
    return TRUE;
}

static void
read_action_metadata(stonith_device_t *device)
{
    xmlXPathObjectPtr xpath = NULL;
    int max = 0;
    int lpc = 0;

    if (device->agent_metadata == NULL) {
        return;
    }

    xpath = xpath_search(device->agent_metadata, "//action");
    max = numXpathResults(xpath);

    if (max <= 0) {
        freeXpathObject(xpath);
        return;
    }

    for (lpc = 0; lpc < max; lpc++) {
        const char *action = NULL;
        xmlNode *match = getXpathResult(xpath, lpc);

        CRM_LOG_ASSERT(match != NULL);
        if(match == NULL) { continue; };

        action = crm_element_value(match, "name");

        if(pcmk__str_eq(action, "list", pcmk__str_casei)) {
            stonith__set_device_flags(device->flags, device->id,
                                      st_device_supports_list);
        } else if(pcmk__str_eq(action, "status", pcmk__str_casei)) {
            stonith__set_device_flags(device->flags, device->id,
                                      st_device_supports_status);
        } else if(pcmk__str_eq(action, "reboot", pcmk__str_casei)) {
            stonith__set_device_flags(device->flags, device->id,
                                      st_device_supports_reboot);
        } else if (pcmk__str_eq(action, "on", pcmk__str_casei)) {
            /* "automatic" means the cluster will unfence node when it joins */
            /* "required" is a deprecated synonym for "automatic" */
            if (pcmk__xe_attr_is_true(match, "automatic") || pcmk__xe_attr_is_true(match, "required")) {
                device->automatic_unfencing = TRUE;
            }
            stonith__set_device_flags(device->flags, device->id,
                                      st_device_supports_on);
        }

        if ((action != NULL) && pcmk__xe_attr_is_true(match, "on_target")) {
            pcmk__add_word(&(device->on_target_actions), 64, action);
        }
    }

    freeXpathObject(xpath);
}

/*!
 * \internal
 * \brief Set a pcmk_*_action parameter if not already set
 *
 * \param[in,out] params  Device parameters
 * \param[in]     action  Name of action
 * \param[in]     value   Value to use if action is not already set
 */
static void
map_action(GHashTable *params, const char *action, const char *value)
{
    char *key = crm_strdup_printf("pcmk_%s_action", action);

    if (g_hash_table_lookup(params, key)) {
        crm_warn("Ignoring %s='%s', see %s instead",
                 STONITH_ATTR_ACTION_OP, value, key);
        free(key);
    } else {
        crm_warn("Mapping %s='%s' to %s='%s'",
                 STONITH_ATTR_ACTION_OP, value, key, value);
        g_hash_table_insert(params, key, strdup(value));
    }
}

/*!
 * \internal
 * \brief Create device parameter table from XML
 *
 * \param[in]  name    Device name (used for logging only)
 * \param[in]  dev     XML containing device parameters
 */
static GHashTable *
xml2device_params(const char *name, const xmlNode *dev)
{
    GHashTable *params = xml2list(dev);
    const char *value;

    /* Action should never be specified in the device configuration,
     * but we support it for users who are familiar with other software
     * that worked that way.
     */
    value = g_hash_table_lookup(params, STONITH_ATTR_ACTION_OP);
    if (value != NULL) {
        crm_warn("%s has '%s' parameter, which should never be specified in configuration",
                 name, STONITH_ATTR_ACTION_OP);

        if (*value == '\0') {
            crm_warn("Ignoring empty '%s' parameter", STONITH_ATTR_ACTION_OP);

        } else if (strcmp(value, "reboot") == 0) {
            crm_warn("Ignoring %s='reboot' (see stonith-action cluster property instead)",
                     STONITH_ATTR_ACTION_OP);

        } else if (strcmp(value, "off") == 0) {
            map_action(params, "reboot", value);

        } else {
            map_action(params, "off", value);
            map_action(params, "reboot", value);
        }

        g_hash_table_remove(params, STONITH_ATTR_ACTION_OP);
    }

    return params;
}

static const char *
target_list_type(stonith_device_t * dev)
{
    const char *check_type = NULL;

    check_type = g_hash_table_lookup(dev->params, PCMK_STONITH_HOST_CHECK);

    if (check_type == NULL) {

        if (g_hash_table_lookup(dev->params, PCMK_STONITH_HOST_LIST)) {
            check_type = "static-list";
        } else if (g_hash_table_lookup(dev->params, PCMK_STONITH_HOST_MAP)) {
            check_type = "static-list";
        } else if (pcmk_is_set(dev->flags, st_device_supports_list)) {
            check_type = "dynamic-list";
        } else if (pcmk_is_set(dev->flags, st_device_supports_status)) {
            check_type = "status";
        } else {
            check_type = PCMK__VALUE_NONE;
        }
    }

    return check_type;
}

static stonith_device_t *
build_device_from_xml(xmlNode *dev)
{
    const char *value;
    stonith_device_t *device = NULL;
    char *agent = crm_element_value_copy(dev, "agent");

    CRM_CHECK(agent != NULL, return device);

    device = calloc(1, sizeof(stonith_device_t));

    CRM_CHECK(device != NULL, {free(agent); return device;});

    device->id = crm_element_value_copy(dev, XML_ATTR_ID);
    device->agent = agent;
    device->namespace = crm_element_value_copy(dev, "namespace");
    device->params = xml2device_params(device->id, dev);

    value = g_hash_table_lookup(device->params, PCMK_STONITH_HOST_LIST);
    if (value) {
        device->targets = stonith__parse_targets(value);
    }

    value = g_hash_table_lookup(device->params, PCMK_STONITH_HOST_MAP);
    device->aliases = build_port_aliases(value, &(device->targets));

    value = target_list_type(device);
    if (!pcmk__str_eq(value, "static-list", pcmk__str_casei) && device->targets) {
        /* Other than "static-list", dev-> targets is unnecessary. */
        g_list_free_full(device->targets, free);
        device->targets = NULL;
    }
    switch (get_agent_metadata(device->agent, &device->agent_metadata)) {
        case pcmk_rc_ok:
            if (device->agent_metadata) {
                read_action_metadata(device);
                stonith__device_parameter_flags(&(device->flags), device->id,
                                                device->agent_metadata);
            }
            break;

        case EAGAIN:
            if (device->timer == NULL) {
                device->timer = mainloop_timer_add("get_agent_metadata", 10 * 1000,
                                           TRUE, get_agent_metadata_cb, device);
            }
            if (!mainloop_timer_running(device->timer)) {
                mainloop_timer_start(device->timer);
            }
            break;

        default:
            break;
    }

    value = g_hash_table_lookup(device->params, "nodeid");
    if (!value) {
        device->include_nodeid = is_nodeid_required(device->agent_metadata);
    }

    value = crm_element_value(dev, "rsc_provides");
    if (pcmk__str_eq(value, PCMK__VALUE_UNFENCING, pcmk__str_casei)) {
        device->automatic_unfencing = TRUE;
    }

    if (is_action_required("on", device)) {
        crm_info("Fencing device '%s' requires unfencing", device->id);
    }

    if (device->on_target_actions != NULL) {
        crm_info("Fencing device '%s' requires actions (%s) to be executed "
                 "on target", device->id,
                 (const char *) device->on_target_actions->str);
    }

    device->work = mainloop_add_trigger(G_PRIORITY_HIGH, stonith_device_dispatch, device);
    /* TODO: Hook up priority */

    return device;
}

static void
schedule_internal_command(const char *origin,
                          stonith_device_t * device,
                          const char *action,
                          const char *target,
                          int timeout,
                          void *internal_user_data,
                          void (*done_cb) (int pid,
                                           const pcmk__action_result_t *result,
                                           void *user_data))
{
    async_command_t *cmd = NULL;

    cmd = calloc(1, sizeof(async_command_t));

    cmd->id = -1;
    cmd->default_timeout = timeout ? timeout : 60;
    cmd->timeout = cmd->default_timeout;
    cmd->action = strdup(action);
    pcmk__str_update(&cmd->target, target);
    cmd->device = strdup(device->id);
    cmd->origin = strdup(origin);
    cmd->client = strdup(crm_system_name);
    cmd->client_name = strdup(crm_system_name);

    cmd->internal_user_data = internal_user_data;
    cmd->done_cb = done_cb; /* cmd, not internal_user_data, is passed to 'done_cb' as the userdata */

    schedule_stonith_command(cmd, device);
}

// Fence agent status commands use custom exit status codes
enum fence_status_code {
    fence_status_invalid    = -1,
    fence_status_active     = 0,
    fence_status_unknown    = 1,
    fence_status_inactive   = 2,
};

static void
status_search_cb(int pid, const pcmk__action_result_t *result, void *user_data)
{
    async_command_t *cmd = user_data;
    struct device_search_s *search = cmd->internal_user_data;
    stonith_device_t *dev = cmd_device(cmd);
    gboolean can = FALSE;

    free_async_command(cmd);

    if (!dev) {
        search_devices_record_result(search, NULL, FALSE);
        return;
    }

    mainloop_set_trigger(dev->work);

    if (result->execution_status != PCMK_EXEC_DONE) {
        crm_warn("Assuming %s cannot fence %s "
                 "because status could not be executed: %s%s%s%s",
                 dev->id, search->host,
                 pcmk_exec_status_str(result->execution_status),
                 ((result->exit_reason == NULL)? "" : " ("),
                 ((result->exit_reason == NULL)? "" : result->exit_reason),
                 ((result->exit_reason == NULL)? "" : ")"));
        search_devices_record_result(search, dev->id, FALSE);
        return;
    }

    switch (result->exit_status) {
        case fence_status_unknown:
            crm_trace("%s reported it cannot fence %s", dev->id, search->host);
            break;

        case fence_status_active:
        case fence_status_inactive:
            crm_trace("%s reported it can fence %s", dev->id, search->host);
            can = TRUE;
            break;

        default:
            crm_warn("Assuming %s cannot fence %s "
                     "(status returned unknown code %d)",
                     dev->id, search->host, result->exit_status);
            break;
    }
    search_devices_record_result(search, dev->id, can);
}

static void
dynamic_list_search_cb(int pid, const pcmk__action_result_t *result,
                       void *user_data)
{
    async_command_t *cmd = user_data;
    struct device_search_s *search = cmd->internal_user_data;
    stonith_device_t *dev = cmd_device(cmd);
    gboolean can_fence = FALSE;

    free_async_command(cmd);

    /* Host/alias must be in the list output to be eligible to be fenced
     *
     * Will cause problems if down'd nodes aren't listed or (for virtual nodes)
     *  if the guest is still listed despite being moved to another machine
     */
    if (!dev) {
        search_devices_record_result(search, NULL, FALSE);
        return;
    }

    mainloop_set_trigger(dev->work);

    if (pcmk__result_ok(result)) {
        crm_info("Refreshing target list for %s", dev->id);
        g_list_free_full(dev->targets, free);
        dev->targets = stonith__parse_targets(result->action_stdout);
        dev->targets_age = time(NULL);

    } else if (dev->targets != NULL) {
        if (result->execution_status == PCMK_EXEC_DONE) {
            crm_info("Reusing most recent target list for %s "
                     "because list returned error code %d",
                     dev->id, result->exit_status);
        } else {
            crm_info("Reusing most recent target list for %s "
                     "because list could not be executed: %s%s%s%s",
                     dev->id, pcmk_exec_status_str(result->execution_status),
                     ((result->exit_reason == NULL)? "" : " ("),
                     ((result->exit_reason == NULL)? "" : result->exit_reason),
                     ((result->exit_reason == NULL)? "" : ")"));
        }

    } else { // We have never successfully executed list
        if (result->execution_status == PCMK_EXEC_DONE) {
            crm_warn("Assuming %s cannot fence %s "
                     "because list returned error code %d",
                     dev->id, search->host, result->exit_status);
        } else {
            crm_warn("Assuming %s cannot fence %s "
                     "because list could not be executed: %s%s%s%s",
                     dev->id, search->host,
                     pcmk_exec_status_str(result->execution_status),
                     ((result->exit_reason == NULL)? "" : " ("),
                     ((result->exit_reason == NULL)? "" : result->exit_reason),
                     ((result->exit_reason == NULL)? "" : ")"));
        }

        /* Fall back to pcmk_host_check="status" if the user didn't explicitly
         * specify "dynamic-list".
         */
        if (g_hash_table_lookup(dev->params, PCMK_STONITH_HOST_CHECK) == NULL) {
            crm_notice("Switching to pcmk_host_check='status' for %s", dev->id);
            g_hash_table_replace(dev->params, strdup(PCMK_STONITH_HOST_CHECK),
                                 strdup("status"));
        }
    }

    if (dev->targets) {
        const char *alias = g_hash_table_lookup(dev->aliases, search->host);

        if (!alias) {
            alias = search->host;
        }
        if (pcmk__str_in_list(alias, dev->targets, pcmk__str_casei)) {
            can_fence = TRUE;
        }
    }
    search_devices_record_result(search, dev->id, can_fence);
}

/*!
 * \internal
 * \brief Returns true if any key in first is not in second or second has a different value for key
 */
static int
device_params_diff(GHashTable *first, GHashTable *second) {
    char *key = NULL;
    char *value = NULL;
    GHashTableIter gIter;

    g_hash_table_iter_init(&gIter, first);
    while (g_hash_table_iter_next(&gIter, (void **)&key, (void **)&value)) {

        if(strstr(key, "CRM_meta") == key) {
            continue;
        } else if(strcmp(key, "crm_feature_set") == 0) {
            continue;
        } else {
            char *other_value = g_hash_table_lookup(second, key);

            if (!other_value || !pcmk__str_eq(other_value, value, pcmk__str_casei)) {
                crm_trace("Different value for %s: %s != %s", key, other_value, value);
                return 1;
            }
        }
    }

    return 0;
}

/*!
 * \internal
 * \brief Checks to see if an identical device already exists in the device_list
 */
static stonith_device_t *
device_has_duplicate(const stonith_device_t *device)
{
    stonith_device_t *dup = g_hash_table_lookup(device_list, device->id);

    if (!dup) {
        crm_trace("No match for %s", device->id);
        return NULL;

    } else if (!pcmk__str_eq(dup->agent, device->agent, pcmk__str_casei)) {
        crm_trace("Different agent: %s != %s", dup->agent, device->agent);
        return NULL;
    }

    /* Use calculate_operation_digest() here? */
    if (device_params_diff(device->params, dup->params) ||
        device_params_diff(dup->params, device->params)) {
        return NULL;
    }

    crm_trace("Match");
    return dup;
}

int
stonith_device_register(xmlNode *dev, gboolean from_cib)
{
    stonith_device_t *dup = NULL;
    stonith_device_t *device = build_device_from_xml(dev);
    guint ndevices = 0;
    int rv = pcmk_ok;

    CRM_CHECK(device != NULL, return -ENOMEM);

    /* do we have a watchdog-device? */
    if (pcmk__str_eq(device->id, STONITH_WATCHDOG_ID, pcmk__str_none) ||
        pcmk__str_any_of(device->agent, STONITH_WATCHDOG_AGENT,
                     STONITH_WATCHDOG_AGENT_INTERNAL, NULL)) do {
        if (stonith_watchdog_timeout_ms <= 0) {
            crm_err("Ignoring watchdog fence device without "
                    "stonith-watchdog-timeout set.");
            rv = -ENODEV;
            /* fall through to cleanup & return */
        } else if (!pcmk__str_any_of(device->agent, STONITH_WATCHDOG_AGENT,
                                 STONITH_WATCHDOG_AGENT_INTERNAL, NULL)) {
            crm_err("Ignoring watchdog fence device with unknown "
                    "agent '%s' unequal '" STONITH_WATCHDOG_AGENT "'.",
                    device->agent?device->agent:"");
            rv = -ENODEV;
            /* fall through to cleanup & return */
        } else if (!pcmk__str_eq(device->id, STONITH_WATCHDOG_ID,
                                 pcmk__str_none)) {
            crm_err("Ignoring watchdog fence device "
                    "named %s !='"STONITH_WATCHDOG_ID"'.",
                    device->id?device->id:"");
            rv = -ENODEV;
            /* fall through to cleanup & return */
        } else {
            if (pcmk__str_eq(device->agent, STONITH_WATCHDOG_AGENT,
                             pcmk__str_none)) {
                /* this either has an empty list or the targets
                   configured for watchdog-fencing
                 */
                g_list_free_full(stonith_watchdog_targets, free);
                stonith_watchdog_targets = device->targets;
                device->targets = NULL;
            }
            if (node_does_watchdog_fencing(stonith_our_uname)) {
                g_list_free_full(device->targets, free);
                device->targets = stonith__parse_targets(stonith_our_uname);
                g_hash_table_replace(device->params,
                                     strdup(PCMK_STONITH_HOST_LIST),
                                     strdup(stonith_our_uname));
                /* proceed as with any other stonith-device */
                break;
            }

            crm_debug("Skip registration of watchdog fence device on node not in host-list.");
            /* cleanup and fall through to more cleanup and return */
            device->targets = NULL;
            stonith_device_remove(device->id, from_cib);
        }
        free_device(device);
        return rv;
    } while (0);

    dup = device_has_duplicate(device);
    if (dup) {
        ndevices = g_hash_table_size(device_list);
        crm_debug("Device '%s' already in device list (%d active device%s)",
                  device->id, ndevices, pcmk__plural_s(ndevices));
        free_device(device);
        device = dup;
        dup = g_hash_table_lookup(device_list, device->id);
        dup->dirty = FALSE;

    } else {
        stonith_device_t *old = g_hash_table_lookup(device_list, device->id);

        if (from_cib && old && old->api_registered) {
            /* If the cib is writing over an entry that is shared with a stonith client,
             * copy any pending ops that currently exist on the old entry to the new one.
             * Otherwise the pending ops will be reported as failures
             */
            crm_info("Overwriting existing entry for %s from CIB", device->id);
            device->pending_ops = old->pending_ops;
            device->api_registered = TRUE;
            old->pending_ops = NULL;
            if (device->pending_ops) {
                mainloop_set_trigger(device->work);
            }
        }
        g_hash_table_replace(device_list, device->id, device);

        ndevices = g_hash_table_size(device_list);
        crm_notice("Added '%s' to device list (%d active device%s)",
                   device->id, ndevices, pcmk__plural_s(ndevices));
    }

    if (from_cib) {
        device->cib_registered = TRUE;
    } else {
        device->api_registered = TRUE;
    }

    return pcmk_ok;
}

void
stonith_device_remove(const char *id, bool from_cib)
{
    stonith_device_t *device = g_hash_table_lookup(device_list, id);
    guint ndevices = 0;

    if (!device) {
        ndevices = g_hash_table_size(device_list);
        crm_info("Device '%s' not found (%d active device%s)",
                 id, ndevices, pcmk__plural_s(ndevices));
        return;
    }

    if (from_cib) {
        device->cib_registered = FALSE;
    } else {
        device->verified = FALSE;
        device->api_registered = FALSE;
    }

    if (!device->cib_registered && !device->api_registered) {
        g_hash_table_remove(device_list, id);
        ndevices = g_hash_table_size(device_list);
        crm_info("Removed '%s' from device list (%d active device%s)",
                 id, ndevices, pcmk__plural_s(ndevices));
    } else {
        crm_trace("Not removing '%s' from device list (%d active) because "
                  "still registered via:%s%s",
                  id, g_hash_table_size(device_list),
                  (device->cib_registered? " cib" : ""),
                  (device->api_registered? " api" : ""));
    }
}

/*!
 * \internal
 * \brief Return the number of stonith levels registered for a node
 *
 * \param[in] tp  Node's topology table entry
 *
 * \return Number of non-NULL levels in topology entry
 * \note This function is used only for log messages.
 */
static int
count_active_levels(const stonith_topology_t *tp)
{
    int lpc = 0;
    int count = 0;

    for (lpc = 0; lpc < ST_LEVEL_MAX; lpc++) {
        if (tp->levels[lpc] != NULL) {
            count++;
        }
    }
    return count;
}

static void
free_topology_entry(gpointer data)
{
    stonith_topology_t *tp = data;

    int lpc = 0;

    for (lpc = 0; lpc < ST_LEVEL_MAX; lpc++) {
        if (tp->levels[lpc] != NULL) {
            g_list_free_full(tp->levels[lpc], free);
        }
    }
    free(tp->target);
    free(tp->target_value);
    free(tp->target_pattern);
    free(tp->target_attribute);
    free(tp);
}

void
free_topology_list(void)
{
    if (topology != NULL) {
        g_hash_table_destroy(topology);
        topology = NULL;
    }
}

void
init_topology_list(void)
{
    if (topology == NULL) {
        topology = pcmk__strkey_table(NULL, free_topology_entry);
    }
}

char *
stonith_level_key(const xmlNode *level, enum fenced_target_by mode)
{
    if (mode == fenced_target_by_unknown) {
        mode = unpack_level_kind(level);
    }
    switch (mode) {
        case fenced_target_by_name:
            return crm_element_value_copy(level, XML_ATTR_STONITH_TARGET);

        case fenced_target_by_pattern:
            return crm_element_value_copy(level, XML_ATTR_STONITH_TARGET_PATTERN);

        case fenced_target_by_attribute:
            return crm_strdup_printf("%s=%s",
                crm_element_value(level, XML_ATTR_STONITH_TARGET_ATTRIBUTE),
                crm_element_value(level, XML_ATTR_STONITH_TARGET_VALUE));

        default:
            return crm_strdup_printf("unknown-%s", ID(level));
    }
}

/*!
 * \internal
 * \brief Parse target identification from topology level XML
 *
 * \param[in] level  Topology level XML to parse
 *
 * \return How to identify target of \p level
 */
static int
unpack_level_kind(const xmlNode *level)
{
    if (crm_element_value(level, XML_ATTR_STONITH_TARGET) != NULL) {
        return fenced_target_by_name;
    }
    if (crm_element_value(level, XML_ATTR_STONITH_TARGET_PATTERN) != NULL) {
        return fenced_target_by_pattern;
    }
    if (!stand_alone /* if standalone, there's no attribute manager */
        && (crm_element_value(level, XML_ATTR_STONITH_TARGET_ATTRIBUTE) != NULL)
        && (crm_element_value(level, XML_ATTR_STONITH_TARGET_VALUE) != NULL)) {
        return fenced_target_by_attribute;
    }
    return fenced_target_by_unknown;
}

static stonith_key_value_t *
parse_device_list(const char *devices)
{
    int lpc = 0;
    int max = 0;
    int last = 0;
    stonith_key_value_t *output = NULL;

    if (devices == NULL) {
        return output;
    }

    max = strlen(devices);
    for (lpc = 0; lpc <= max; lpc++) {
        if (devices[lpc] == ',' || devices[lpc] == 0) {
            char *line = strndup(devices + last, lpc - last);

            output = stonith_key_value_add(output, NULL, line);
            free(line);

            last = lpc + 1;
        }
    }

    return output;
}

/*!
 * \internal
 * \brief Unpack essential information from topology request XML
 *
 * \param[in]  xml     Request XML to search
 * \param[out] mode    If not NULL, where to store level kind
 * \param[out] target  If not NULL, where to store representation of target
 * \param[out] id      If not NULL, where to store level number
 * \param[out] desc    If not NULL, where to store log-friendly level description
 *
 * \return Topology level XML from within \p xml, or NULL if not found
 * \note The caller is responsible for freeing \p *target and \p *desc if set.
 */
static xmlNode *
unpack_level_request(xmlNode *xml, enum fenced_target_by *mode, char **target,
                     int *id, char **desc)
{
    enum fenced_target_by local_mode = fenced_target_by_unknown;
    char *local_target = NULL;
    int local_id = 0;

    /* The level element can be the top element or lower. If top level, don't
     * search by xpath, because it might give multiple hits if the XML is the
     * CIB.
     */
    if ((xml != NULL)
        && !pcmk__str_eq(TYPE(xml), XML_TAG_FENCING_LEVEL, pcmk__str_none)) {
        xml = get_xpath_object("//" XML_TAG_FENCING_LEVEL, xml, LOG_WARNING);
    }

    if (xml == NULL) {
        if (desc != NULL) {
            *desc = crm_strdup_printf("missing");
        }
    } else {
        local_mode = unpack_level_kind(xml);
        local_target = stonith_level_key(xml, local_mode);
        crm_element_value_int(xml, XML_ATTR_STONITH_INDEX, &local_id);
        if (desc != NULL) {
            *desc = crm_strdup_printf("%s[%d]", local_target, local_id);
        }
    }

    if (mode != NULL) {
        *mode = local_mode;
    }
    if (id != NULL) {
        *id = local_id;
    }

    if (target != NULL) {
        *target = local_target;
    } else {
        free(local_target);
    }

    return xml;
}

/*!
 * \internal
 * \brief Register a fencing topology level for a target
 *
 * Given an XML request specifying the target name, level index, and device IDs
 * for the level, this will create an entry for the target in the global topology
 * table if one does not already exist, then append the specified device IDs to
 * the entry's device list for the specified level.
 *
 * \param[in]  msg     XML request for STONITH level registration
 * \param[out] desc    If not NULL, set to string representation "TARGET[LEVEL]"
 * \param[out] result  Where to set result of registration
 */
void
fenced_register_level(xmlNode *msg, char **desc, pcmk__action_result_t *result)
{
    int id = 0;
    xmlNode *level;
    enum fenced_target_by mode;
    char *target;

    stonith_topology_t *tp;
    stonith_key_value_t *dIter = NULL;
    stonith_key_value_t *devices = NULL;

    CRM_CHECK((msg != NULL) && (result != NULL), return);

    level = unpack_level_request(msg, &mode, &target, &id, desc);
    if (level == NULL) {
        fenced_set_protocol_error(result);
        return;
    }

    // Ensure an ID was given (even the client API adds an ID)
    if (pcmk__str_empty(ID(level))) {
        crm_warn("Ignoring registration for topology level without ID");
        free(target);
        crm_log_xml_trace(level, "Bad level");
        pcmk__format_result(result, CRM_EX_INVALID_PARAM, PCMK_EXEC_INVALID,
                            "Topology level is invalid without ID");
        return;
    }

    // Ensure a valid target was specified
    if (mode == fenced_target_by_unknown) {
        crm_warn("Ignoring registration for topology level '%s' "
                 "without valid target", ID(level));
        free(target);
        crm_log_xml_trace(level, "Bad level");
        pcmk__format_result(result, CRM_EX_INVALID_PARAM, PCMK_EXEC_INVALID,
                            "Invalid target for topology level '%s'",
                            ID(level));
        return;
    }

    // Ensure level ID is in allowed range
    if ((id <= 0) || (id >= ST_LEVEL_MAX)) {
        crm_warn("Ignoring topology registration for %s with invalid level %d",
                  target, id);
        free(target);
        crm_log_xml_trace(level, "Bad level");
        pcmk__format_result(result, CRM_EX_INVALID_PARAM, PCMK_EXEC_INVALID,
                            "Invalid level number '%s' for topology level '%s'",
                            pcmk__s(crm_element_value(level,
                                                      XML_ATTR_STONITH_INDEX),
                                    ""),
                            ID(level));
        return;
    }

    /* Find or create topology table entry */
    tp = g_hash_table_lookup(topology, target);
    if (tp == NULL) {
        tp = calloc(1, sizeof(stonith_topology_t));
        if (tp == NULL) {
            pcmk__set_result(result, CRM_EX_ERROR, PCMK_EXEC_ERROR,
                             strerror(ENOMEM));
            free(target);
            return;
        }
        tp->kind = mode;
        tp->target = target;
        tp->target_value = crm_element_value_copy(level, XML_ATTR_STONITH_TARGET_VALUE);
        tp->target_pattern = crm_element_value_copy(level, XML_ATTR_STONITH_TARGET_PATTERN);
        tp->target_attribute = crm_element_value_copy(level, XML_ATTR_STONITH_TARGET_ATTRIBUTE);

        g_hash_table_replace(topology, tp->target, tp);
        crm_trace("Added %s (%d) to the topology (%d active entries)",
                  target, (int) mode, g_hash_table_size(topology));
    } else {
        free(target);
    }

    if (tp->levels[id] != NULL) {
        crm_info("Adding to the existing %s[%d] topology entry",
                 tp->target, id);
    }

    devices = parse_device_list(crm_element_value(level, XML_ATTR_STONITH_DEVICES));
    for (dIter = devices; dIter; dIter = dIter->next) {
        const char *device = dIter->value;

        crm_trace("Adding device '%s' for %s[%d]", device, tp->target, id);
        tp->levels[id] = g_list_append(tp->levels[id], strdup(device));
    }
    stonith_key_value_freeall(devices, 1, 1);

    {
        int nlevels = count_active_levels(tp);

        crm_info("Target %s has %d active fencing level%s",
                 tp->target, nlevels, pcmk__plural_s(nlevels));
    }

    pcmk__set_result(result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);
}

/*!
 * \internal
 * \brief Unregister a fencing topology level for a target
 *
 * Given an XML request specifying the target name and level index (or 0 for all
 * levels), this will remove any corresponding entry for the target from the
 * global topology table.
 *
 * \param[in]  msg     XML request for STONITH level registration
 * \param[out] desc    If not NULL, set to string representation "TARGET[LEVEL]"
 * \param[out] result  Where to set result of unregistration
 */
void
fenced_unregister_level(xmlNode *msg, char **desc,
                        pcmk__action_result_t *result)
{
    int id = -1;
    stonith_topology_t *tp;
    char *target;
    xmlNode *level = NULL;

    CRM_CHECK(result != NULL, return);

    level = unpack_level_request(msg, NULL, &target, &id, desc);
    if (level == NULL) {
        fenced_set_protocol_error(result);
        return;
    }

    // Ensure level ID is in allowed range
    if ((id < 0) || (id >= ST_LEVEL_MAX)) {
        crm_warn("Ignoring topology unregistration for %s with invalid level %d",
                  target, id);
        free(target);
        crm_log_xml_trace(level, "Bad level");
        pcmk__format_result(result, CRM_EX_INVALID_PARAM, PCMK_EXEC_INVALID,
                            "Invalid level number '%s' for topology level %s",
                            pcmk__s(crm_element_value(level,
                                                      XML_ATTR_STONITH_INDEX),
                                    "<null>"),

                            // Client API doesn't add ID to unregistration XML
                            pcmk__s(ID(level), ""));
        return;
    }

    tp = g_hash_table_lookup(topology, target);
    if (tp == NULL) {
        guint nentries = g_hash_table_size(topology);

        crm_info("No fencing topology found for %s (%d active %s)",
                 target, nentries,
                 pcmk__plural_alt(nentries, "entry", "entries"));

    } else if (id == 0 && g_hash_table_remove(topology, target)) {
        guint nentries = g_hash_table_size(topology);

        crm_info("Removed all fencing topology entries related to %s "
                 "(%d active %s remaining)", target, nentries,
                 pcmk__plural_alt(nentries, "entry", "entries"));

    } else if (tp->levels[id] != NULL) {
        guint nlevels;

        g_list_free_full(tp->levels[id], free);
        tp->levels[id] = NULL;

        nlevels = count_active_levels(tp);
        crm_info("Removed level %d from fencing topology for %s "
                 "(%d active level%s remaining)",
                 id, target, nlevels, pcmk__plural_s(nlevels));
    }

    free(target);
    pcmk__set_result(result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);
}

static char *
list_to_string(GList *list, const char *delim, gboolean terminate_with_delim)
{
    int max = g_list_length(list);
    size_t delim_len = delim?strlen(delim):0;
    size_t alloc_size = 1 + (max?((max-1+(terminate_with_delim?1:0))*delim_len):0);
    char *rv;
    GList *gIter;

    for (gIter = list; gIter != NULL; gIter = gIter->next) {
        const char *value = (const char *) gIter->data;

        alloc_size += strlen(value);
    }
    rv = calloc(alloc_size, sizeof(char));
    if (rv) {
        char *pos = rv;
        const char *lead_delim = "";

        for (gIter = list; gIter != NULL; gIter = gIter->next) {
            const char *value = (const char *) gIter->data;

            pos = &pos[sprintf(pos, "%s%s", lead_delim, value)];
            lead_delim = delim;
        }
        if (max && terminate_with_delim) {
            sprintf(pos, "%s", delim);
        }
    }
    return rv;
}

/*!
 * \internal
 * \brief Execute a fence agent action directly (and asynchronously)
 *
 * Handle a STONITH_OP_EXEC API message by scheduling a requested agent action
 * directly on a specified device. Only list, monitor, and status actions are
 * expected to use this call, though it should work with any agent command.
 *
 * \param[in]  msg     Request XML specifying action
 * \param[out] result  Where to store result of action
 *
 * \note If the action is monitor, the device must be registered via the API
 *       (CIB registration is not sufficient), because monitor should not be
 *       possible unless the device is "started" (API registered).
 */
static void
execute_agent_action(xmlNode *msg, pcmk__action_result_t *result)
{
    xmlNode *dev = get_xpath_object("//" F_STONITH_DEVICE, msg, LOG_ERR);
    xmlNode *op = get_xpath_object("//@" F_STONITH_ACTION, msg, LOG_ERR);
    const char *id = crm_element_value(dev, F_STONITH_DEVICE);
    const char *action = crm_element_value(op, F_STONITH_ACTION);
    async_command_t *cmd = NULL;
    stonith_device_t *device = NULL;

    if ((id == NULL) || (action == NULL)) {
        crm_info("Malformed API action request: device %s, action %s",
                 (id? id : "not specified"),
                 (action? action : "not specified"));
        fenced_set_protocol_error(result);
        return;
    }

    if (pcmk__str_eq(id, STONITH_WATCHDOG_ID, pcmk__str_none)) {
        // Watchdog agent actions are implemented internally
        if (stonith_watchdog_timeout_ms <= 0) {
            pcmk__set_result(result, CRM_EX_ERROR, PCMK_EXEC_NO_FENCE_DEVICE,
                             "Watchdog fence device not configured");
            return;

        } else if (pcmk__str_eq(action, "list", pcmk__str_casei)) {
            pcmk__set_result(result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);
            pcmk__set_result_output(result,
                                    list_to_string(stonith_watchdog_targets,
                                                   "\n", TRUE),
                                    NULL);
            return;

        } else if (pcmk__str_eq(action, "monitor", pcmk__str_casei)) {
            pcmk__set_result(result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);
            return;
        }
    }

    device = g_hash_table_lookup(device_list, id);
    if (device == NULL) {
        crm_info("Ignoring API '%s' action request because device %s not found",
                 action, id);
        pcmk__format_result(result, CRM_EX_ERROR, PCMK_EXEC_NO_FENCE_DEVICE,
                            "'%s' not found", id);
        return;

    } else if (!device->api_registered && !strcmp(action, "monitor")) {
        // Monitors may run only on "started" (API-registered) devices
        crm_info("Ignoring API '%s' action request because device %s not active",
                 action, id);
        pcmk__format_result(result, CRM_EX_ERROR, PCMK_EXEC_NO_FENCE_DEVICE,
                            "'%s' not active", id);
        return;
    }

    cmd = create_async_command(msg);
    if (cmd == NULL) {
        crm_log_xml_warn(msg, "invalid");
        fenced_set_protocol_error(result);
        return;
    }

    schedule_stonith_command(cmd, device);
    pcmk__set_result(result, CRM_EX_OK, PCMK_EXEC_PENDING, NULL);
}

static void
search_devices_record_result(struct device_search_s *search, const char *device, gboolean can_fence)
{
    search->replies_received++;
    if (can_fence && device) {
        if (search->support_action_only != st_device_supports_none) {
            stonith_device_t *dev = g_hash_table_lookup(device_list, device);
            if (dev && !pcmk_is_set(dev->flags, search->support_action_only)) {
                return;
            }
        }
        search->capable = g_list_append(search->capable, strdup(device));
    }

    if (search->replies_needed == search->replies_received) {

        guint ndevices = g_list_length(search->capable);

        crm_debug("Search found %d device%s that can perform '%s' targeting %s",
                  ndevices, pcmk__plural_s(ndevices),
                  (search->action? search->action : "unknown action"),
                  (search->host? search->host : "any node"));

        search->callback(search->capable, search->user_data);
        free(search->host);
        free(search->action);
        free(search);
    }
}

/*!
 * \internal
 * \brief Check whether the local host is allowed to execute a fencing action
 *
 * \param[in] device         Fence device to check
 * \param[in] action         Fence action to check
 * \param[in] target         Hostname of fence target
 * \param[in] allow_suicide  Whether self-fencing is allowed for this operation
 *
 * \return TRUE if local host is allowed to execute action, FALSE otherwise
 */
static gboolean
localhost_is_eligible(const stonith_device_t *device, const char *action,
                      const char *target, gboolean allow_suicide)
{
    gboolean localhost_is_target = pcmk__str_eq(target, stonith_our_uname,
                                                pcmk__str_casei);

    if ((device != NULL) && (action != NULL)
        && (device->on_target_actions != NULL)
        && (strstr((const char*) device->on_target_actions->str,
                   action) != NULL)) {

        if (!localhost_is_target) {
            crm_trace("Operation '%s' using %s can only be executed for local "
                      "host, not %s", action, device->id, target);
            return FALSE;
        }

    } else if (localhost_is_target && !allow_suicide) {
        crm_trace("'%s' operation does not support self-fencing", action);
        return FALSE;
    }
    return TRUE;
}

static void
can_fence_host_with_device(stonith_device_t *dev,
                           struct device_search_s *search)
{
    gboolean can = FALSE;
    const char *check_type = NULL;
    const char *target = NULL;
    const char *alias = NULL;
    const char *action = (search == NULL)? NULL : search->action;

    CRM_CHECK((dev != NULL) && (action != NULL), goto search_report_results);

    target = search->host;
    if (target == NULL) {
        can = TRUE;
        goto search_report_results;
    }

    /* Short-circuit query if this host is not allowed to perform the action */
    if (pcmk__str_eq(action, "reboot", pcmk__str_casei)) {
        /* A "reboot" *might* get remapped to "off" then "on", so short-circuit
         * only if all three are disallowed. If only one or two are disallowed,
         * we'll report that with the results. We never allow suicide for
         * remapped "on" operations because the host is off at that point.
         */
        if (!localhost_is_eligible(dev, "reboot", target, search->allow_suicide)
            && !localhost_is_eligible(dev, "off", target, search->allow_suicide)
            && !localhost_is_eligible(dev, "on", target, FALSE)) {
            goto search_report_results;
        }
    } else if (!localhost_is_eligible(dev, action, target,
                                      search->allow_suicide)) {
        goto search_report_results;
    }

    alias = g_hash_table_lookup(dev->aliases, target);
    if (alias == NULL) {
        alias = target;
    }

    check_type = target_list_type(dev);

    if (pcmk__str_eq(check_type, PCMK__VALUE_NONE, pcmk__str_casei)) {
        can = TRUE;

    } else if (pcmk__str_eq(check_type, "static-list", pcmk__str_casei)) {

        /* Presence in the hostmap is sufficient
         * Only use if all hosts on which the device can be active can always fence all listed hosts
         */

        if (pcmk__str_in_list(target, dev->targets, pcmk__str_casei)) {
            can = TRUE;
        } else if (g_hash_table_lookup(dev->params, PCMK_STONITH_HOST_MAP)
                   && g_hash_table_lookup(dev->aliases, target)) {
            can = TRUE;
        }

    } else if (pcmk__str_eq(check_type, "dynamic-list", pcmk__str_casei)) {
        time_t now = time(NULL);

        if (dev->targets == NULL || dev->targets_age + 60 < now) {
            int device_timeout = get_action_timeout(dev, "list", search->per_device_timeout);

            if (device_timeout > search->per_device_timeout) {
                crm_notice("Since the pcmk_list_timeout(%ds) parameter of %s is larger than stonith-timeout(%ds), timeout may occur",
                    device_timeout, dev->id, search->per_device_timeout);
            }

            crm_trace("Running '%s' to check whether %s is eligible to fence %s (%s)",
                      check_type, dev->id, target, action);

            schedule_internal_command(__func__, dev, "list", NULL,
                                      search->per_device_timeout, search, dynamic_list_search_cb);

            /* we'll respond to this search request async in the cb */
            return;
        }

        if (pcmk__str_in_list(alias, dev->targets, pcmk__str_casei)) {
            can = TRUE;
        }

    } else if (pcmk__str_eq(check_type, "status", pcmk__str_casei)) {
        int device_timeout = get_action_timeout(dev, check_type, search->per_device_timeout);

        if (device_timeout > search->per_device_timeout) {
            crm_notice("Since the pcmk_status_timeout(%ds) parameter of %s is larger than stonith-timeout(%ds), timeout may occur",
                device_timeout, dev->id, search->per_device_timeout);
        }

        crm_trace("Running '%s' to check whether %s is eligible to fence %s (%s)",
                  check_type, dev->id, target, action);
        schedule_internal_command(__func__, dev, "status", target,
                                  search->per_device_timeout, search, status_search_cb);
        /* we'll respond to this search request async in the cb */
        return;
    } else {
        crm_err("Invalid value for " PCMK_STONITH_HOST_CHECK ": %s", check_type);
        check_type = "Invalid " PCMK_STONITH_HOST_CHECK;
    }

    if (pcmk__str_eq(target, alias, pcmk__str_casei)) {
        crm_info("%s is%s eligible to fence (%s) %s: %s",
                 dev->id, (can? "" : " not"), action, target, check_type);
    } else {
        crm_info("%s is%s eligible to fence (%s) %s (aka. '%s'): %s",
                 dev->id, (can? "" : " not"), action, target, alias,
                 check_type);
    }

  search_report_results:
    search_devices_record_result(search, dev ? dev->id : NULL, can);
}

static void
search_devices(gpointer key, gpointer value, gpointer user_data)
{
    stonith_device_t *dev = value;
    struct device_search_s *search = user_data;

    can_fence_host_with_device(dev, search);
}

#define DEFAULT_QUERY_TIMEOUT 20
static void
get_capable_devices(const char *host, const char *action, int timeout, bool suicide, void *user_data,
                    void (*callback) (GList * devices, void *user_data), uint32_t support_action_only)
{
    struct device_search_s *search;
    guint ndevices = g_hash_table_size(device_list);

    if (ndevices == 0) {
        callback(NULL, user_data);
        return;
    }

    search = calloc(1, sizeof(struct device_search_s));
    if (!search) {
        crm_crit("Cannot search for capable fence devices: %s",
                 strerror(ENOMEM));
        callback(NULL, user_data);
        return;
    }

    pcmk__str_update(&search->host, host);
    pcmk__str_update(&search->action, action);
    search->per_device_timeout = timeout;
    search->allow_suicide = suicide;
    search->callback = callback;
    search->user_data = user_data;
    search->support_action_only = support_action_only;

    /* We are guaranteed this many replies, even if a device is
     * unregistered while the search is in progress.
     */
    search->replies_needed = ndevices;

    crm_debug("Searching %d device%s to see which can execute '%s' targeting %s",
              ndevices, pcmk__plural_s(ndevices),
              (search->action? search->action : "unknown action"),
              (search->host? search->host : "any node"));
    g_hash_table_foreach(device_list, search_devices, search);
}

struct st_query_data {
    xmlNode *reply;
    char *remote_peer;
    char *client_id;
    char *target;
    char *action;
    int call_options;
};

/*!
 * \internal
 * \brief Add action-specific attributes to query reply XML
 *
 * \param[in,out] xml     XML to add attributes to
 * \param[in]     action  Fence action
 * \param[in]     device  Fence device
 * \param[in]     target  Fence target
 */
static void
add_action_specific_attributes(xmlNode *xml, const char *action,
                               const stonith_device_t *device,
                               const char *target)
{
    int action_specific_timeout;
    int delay_max;
    int delay_base;

    CRM_CHECK(xml && action && device, return);

    if (is_action_required(action, device)) {
        crm_trace("Action '%s' is required using %s", action, device->id);
        crm_xml_add_int(xml, F_STONITH_DEVICE_REQUIRED, 1);
    }

    action_specific_timeout = get_action_timeout(device, action, 0);
    if (action_specific_timeout) {
        crm_trace("Action '%s' has timeout %dms using %s",
                  action, action_specific_timeout, device->id);
        crm_xml_add_int(xml, F_STONITH_ACTION_TIMEOUT, action_specific_timeout);
    }

    delay_max = get_action_delay_max(device, action);
    if (delay_max > 0) {
        crm_trace("Action '%s' has maximum random delay %dms using %s",
                  action, delay_max, device->id);
        crm_xml_add_int(xml, F_STONITH_DELAY_MAX, delay_max / 1000);
    }

    delay_base = get_action_delay_base(device, action, target);
    if (delay_base > 0) {
        crm_xml_add_int(xml, F_STONITH_DELAY_BASE, delay_base / 1000);
    }

    if ((delay_max > 0) && (delay_base == 0)) {
        crm_trace("Action '%s' has maximum random delay %dms using %s",
                  action, delay_max, device->id);
    } else if ((delay_max == 0) && (delay_base > 0)) {
        crm_trace("Action '%s' has a static delay of %dms using %s",
                  action, delay_base, device->id);
    } else if ((delay_max > 0) && (delay_base > 0)) {
        crm_trace("Action '%s' has a minimum delay of %dms and a randomly chosen "
                  "maximum delay of %dms using %s",
                  action, delay_base, delay_max, device->id);
    }
}

/*!
 * \internal
 * \brief Add "disallowed" attribute to query reply XML if appropriate
 *
 * \param[in,out] xml            XML to add attribute to
 * \param[in]     action         Fence action
 * \param[in]     device         Fence device
 * \param[in]     target         Fence target
 * \param[in]     allow_suicide  Whether self-fencing is allowed
 */
static void
add_disallowed(xmlNode *xml, const char *action, const stonith_device_t *device,
               const char *target, gboolean allow_suicide)
{
    if (!localhost_is_eligible(device, action, target, allow_suicide)) {
        crm_trace("Action '%s' using %s is disallowed for local host",
                  action, device->id);
        pcmk__xe_set_bool_attr(xml, F_STONITH_ACTION_DISALLOWED, true);
    }
}

/*!
 * \internal
 * \brief Add child element with action-specific values to query reply XML
 *
 * \param[in,out] xml            XML to add attribute to
 * \param[in]     action         Fence action
 * \param[in]     device         Fence device
 * \param[in]     target         Fence target
 * \param[in]     allow_suicide  Whether self-fencing is allowed
 */
static void
add_action_reply(xmlNode *xml, const char *action,
                 const stonith_device_t *device, const char *target,
                 gboolean allow_suicide)
{
    xmlNode *child = create_xml_node(xml, F_STONITH_ACTION);

    crm_xml_add(child, XML_ATTR_ID, action);
    add_action_specific_attributes(child, action, device, target);
    add_disallowed(child, action, device, target, allow_suicide);
}

static void
stonith_query_capable_device_cb(GList * devices, void *user_data)
{
    struct st_query_data *query = user_data;
    int available_devices = 0;
    xmlNode *dev = NULL;
    xmlNode *list = NULL;
    GList *lpc = NULL;
    pcmk__client_t *client = NULL;

    if (query->client_id != NULL) {
        client = pcmk__find_client_by_id(query->client_id);
        if ((client == NULL) && (query->remote_peer == NULL)) {
            crm_trace("Skipping reply to %s: no longer a client",
                      query->client_id);
            goto done;
        }
    }

    /* Pack the results into XML */
    list = create_xml_node(NULL, __func__);
    crm_xml_add(list, F_STONITH_TARGET, query->target);
    for (lpc = devices; lpc != NULL; lpc = lpc->next) {
        stonith_device_t *device = g_hash_table_lookup(device_list, lpc->data);
        const char *action = query->action;

        if (!device) {
            /* It is possible the device got unregistered while
             * determining who can fence the target */
            continue;
        }

        available_devices++;

        dev = create_xml_node(list, F_STONITH_DEVICE);
        crm_xml_add(dev, XML_ATTR_ID, device->id);
        crm_xml_add(dev, "namespace", device->namespace);
        crm_xml_add(dev, "agent", device->agent);
        crm_xml_add_int(dev, F_STONITH_DEVICE_VERIFIED, device->verified);
        crm_xml_add_int(dev, F_STONITH_DEVICE_SUPPORT_FLAGS, device->flags);

        /* If the originating fencer wants to reboot the node, and we have a
         * capable device that doesn't support "reboot", remap to "off" instead.
         */
        if (!pcmk_is_set(device->flags, st_device_supports_reboot)
            && pcmk__str_eq(query->action, "reboot", pcmk__str_casei)) {
            crm_trace("%s doesn't support reboot, using values for off instead",
                      device->id);
            action = "off";
        }

        /* Add action-specific values if available */
        add_action_specific_attributes(dev, action, device, query->target);
        if (pcmk__str_eq(query->action, "reboot", pcmk__str_casei)) {
            /* A "reboot" *might* get remapped to "off" then "on", so after
             * sending the "reboot"-specific values in the main element, we add
             * sub-elements for "off" and "on" values.
             *
             * We short-circuited earlier if "reboot", "off" and "on" are all
             * disallowed for the local host. However if only one or two are
             * disallowed, we send back the results and mark which ones are
             * disallowed. If "reboot" is disallowed, this might cause problems
             * with older fencer versions, which won't check for it. Older
             * versions will ignore "off" and "on", so they are not a problem.
             */
            add_disallowed(dev, action, device, query->target,
                           pcmk_is_set(query->call_options, st_opt_allow_suicide));
            add_action_reply(dev, "off", device, query->target,
                             pcmk_is_set(query->call_options, st_opt_allow_suicide));
            add_action_reply(dev, "on", device, query->target, FALSE);
        }

        /* A query without a target wants device parameters */
        if (query->target == NULL) {
            xmlNode *attrs = create_xml_node(dev, XML_TAG_ATTRS);

            g_hash_table_foreach(device->params, hash2field, attrs);
        }
    }

    crm_xml_add_int(list, F_STONITH_AVAILABLE_DEVICES, available_devices);
    if (query->target) {
        crm_debug("Found %d matching device%s for target '%s'",
                  available_devices, pcmk__plural_s(available_devices),
                  query->target);
    } else {
        crm_debug("%d device%s installed",
                  available_devices, pcmk__plural_s(available_devices));
    }

    if (list != NULL) {
        crm_log_xml_trace(list, "Add query results");
        add_message_xml(query->reply, F_STONITH_CALLDATA, list);
    }

    stonith_send_reply(query->reply, query->call_options, query->remote_peer,
                       client);

done:
    free_xml(query->reply);
    free(query->remote_peer);
    free(query->client_id);
    free(query->target);
    free(query->action);
    free(query);
    free_xml(list);
    g_list_free_full(devices, free);
}

/*!
 * \internal
 * \brief Log the result of an asynchronous command
 *
 * \param[in] cmd        Command the result is for
 * \param[in] result     Result of command
 * \param[in] pid        Process ID of command, if available
 * \param[in] next       Alternate device that will be tried if command failed
 * \param[in] op_merged  Whether this command was merged with an earlier one
 */
static void
log_async_result(const async_command_t *cmd,
                 const pcmk__action_result_t *result,
                 int pid, const char *next, bool op_merged)
{
    int log_level = LOG_ERR;
    int output_log_level = LOG_NEVER;
    guint devices_remaining = g_list_length(cmd->next_device_iter);

    GString *msg = g_string_sized_new(80); // Reasonable starting size

    // Choose log levels appropriately if we have a result
    if (pcmk__result_ok(result)) {
        log_level = (cmd->target == NULL)? LOG_DEBUG : LOG_NOTICE;
        if ((result->action_stdout != NULL)
            && !pcmk__str_eq(cmd->action, "metadata", pcmk__str_casei)) {
            output_log_level = LOG_DEBUG;
        }
        next = NULL;
    } else {
        log_level = (cmd->target == NULL)? LOG_NOTICE : LOG_ERR;
        if ((result->action_stdout != NULL)
            && !pcmk__str_eq(cmd->action, "metadata", pcmk__str_casei)) {
            output_log_level = LOG_WARNING;
        }
    }

    // Build the log message piece by piece
    pcmk__g_strcat(msg, "Operation '", cmd->action, "' ", NULL);
    if (pid != 0) {
        g_string_append_printf(msg, "[%d] ", pid);
    }
    if (cmd->target != NULL) {
        pcmk__g_strcat(msg, "targeting ", cmd->target, " ", NULL);
    }
    if (cmd->device != NULL) {
        pcmk__g_strcat(msg, "using ", cmd->device, " ", NULL);
    }

    // Add exit status or execution status as appropriate
    if (result->execution_status == PCMK_EXEC_DONE) {
        g_string_append_printf(msg, "returned %d", result->exit_status);
    } else {
        pcmk__g_strcat(msg, "could not be executed: ",
                       pcmk_exec_status_str(result->execution_status), NULL);
    }

    // Add exit reason and next device if appropriate
    if (result->exit_reason != NULL) {
        pcmk__g_strcat(msg, " (", result->exit_reason, ")", NULL);
    }
    if (next != NULL) {
        pcmk__g_strcat(msg, ", retrying with ", next, NULL);
    }
    if (devices_remaining > 0) {
        g_string_append_printf(msg, " (%u device%s remaining)",
                               (unsigned int) devices_remaining,
                               pcmk__plural_s(devices_remaining));
    }
    g_string_append_printf(msg, " " CRM_XS " %scall %d from %s",
                           (op_merged? "merged " : ""), cmd->id,
                           cmd->client_name);

    // Log the result
    do_crm_log(log_level, "%s", msg->str);
    g_string_free(msg, TRUE);

    // Log the output (which may have multiple lines), if appropriate
    if (output_log_level != LOG_NEVER) {
        char *prefix = crm_strdup_printf("%s[%d]", cmd->device, pid);

        crm_log_output(output_log_level, prefix, result->action_stdout);
        free(prefix);
    }
}

/*!
 * \internal
 * \brief Reply to requester after asynchronous command completion
 *
 * \param[in] cmd      Command that completed
 * \param[in] result   Result of command
 * \param[in] pid      Process ID of command, if available
 * \param[in] merged   If true, command was merged with another, not executed
 */
static void
send_async_reply(const async_command_t *cmd, const pcmk__action_result_t *result,
                 int pid, bool merged)
{
    xmlNode *reply = NULL;
    pcmk__client_t *client = NULL;

    CRM_CHECK((cmd != NULL) && (result != NULL), return);

    log_async_result(cmd, result, pid, NULL, merged);

    if (cmd->client != NULL) {
        client = pcmk__find_client_by_id(cmd->client);
        if ((client == NULL) && (cmd->origin == NULL)) {
            crm_trace("Skipping reply to %s: no longer a client", cmd->client);
            return;
        }
    }

    reply = construct_async_reply(cmd, result);
    if (merged) {
        pcmk__xe_set_bool_attr(reply, F_STONITH_MERGED, true);
    }

    if (!stand_alone && pcmk__is_fencing_action(cmd->action)
        && pcmk__str_eq(cmd->origin, cmd->target, pcmk__str_casei)) {
        /* The target was also the originator, so broadcast the result on its
         * behalf (since it will be unable to).
         */
        crm_trace("Broadcast '%s' result for %s (target was also originator)",
                  cmd->action, cmd->target);
        crm_xml_add(reply, F_SUBTYPE, "broadcast");
        crm_xml_add(reply, F_STONITH_OPERATION, T_STONITH_NOTIFY);
        send_cluster_message(NULL, crm_msg_stonith_ng, reply, FALSE);
    } else {
        // Reply only to the originator
        stonith_send_reply(reply, cmd->options, cmd->origin, client);
    }

    crm_log_xml_trace(reply, "Reply");
    free_xml(reply);

    if (stand_alone) {
        /* Do notification with a clean data object */
        xmlNode *notify_data = create_xml_node(NULL, T_STONITH_NOTIFY_FENCE);

        stonith__xe_set_result(notify_data, result);
        crm_xml_add(notify_data, F_STONITH_TARGET, cmd->target);
        crm_xml_add(notify_data, F_STONITH_OPERATION, cmd->op);
        crm_xml_add(notify_data, F_STONITH_DELEGATE, "localhost");
        crm_xml_add(notify_data, F_STONITH_DEVICE, cmd->device);
        crm_xml_add(notify_data, F_STONITH_REMOTE_OP_ID, cmd->remote_op_id);
        crm_xml_add(notify_data, F_STONITH_ORIGIN, cmd->client);

        fenced_send_notification(T_STONITH_NOTIFY_FENCE, result, notify_data);
        fenced_send_notification(T_STONITH_NOTIFY_HISTORY, NULL, NULL);
    }
}

static void
cancel_stonith_command(async_command_t * cmd)
{
    stonith_device_t *device = cmd_device(cmd);

    if (device) {
        crm_trace("Cancel scheduled '%s' action using %s",
                  cmd->action, device->id);
        device->pending_ops = g_list_remove(device->pending_ops, cmd);
    }
}

/*!
 * \internal
 * \brief Cancel and reply to any duplicates of a just-completed operation
 *
 * Check whether any fencing operations are scheduled to do the same thing as
 * one that just succeeded. If so, rather than performing the same operation
 * twice, return the result of this operation for all matching pending commands.
 *
 * \param[in,out] cmd     Fencing operation that just succeeded
 * \param[in]     result  Result of \p cmd
 * \param[in]     pid     If nonzero, process ID of agent invocation (for logs)
 *
 * \note Duplicate merging will do the right thing for either type of remapped
 *       reboot. If the executing fencer remapped an unsupported reboot to off,
 *       then cmd->action will be "reboot" and will be merged with any other
 *       reboot requests. If the originating fencer remapped a topology reboot
 *       to off then on, we will get here once with cmd->action "off" and once
 *       with "on", and they will be merged separately with similar requests.
 */
static void
reply_to_duplicates(async_command_t *cmd, const pcmk__action_result_t *result,
                    int pid)
{
    GList *next = NULL;

    for (GList *iter = cmd_list; iter != NULL; iter = next) {
        async_command_t *cmd_other = iter->data;

        next = iter->next; // We might delete this entry, so grab next now

        if (cmd == cmd_other) {
            continue;
        }

        /* A pending operation matches if:
         * 1. The client connections are different.
         * 2. The target is the same.
         * 3. The fencing action is the same.
         * 4. The device scheduled to execute the action is the same.
         */
        if (pcmk__str_eq(cmd->client, cmd_other->client, pcmk__str_casei) ||
            !pcmk__str_eq(cmd->target, cmd_other->target, pcmk__str_casei) ||
            !pcmk__str_eq(cmd->action, cmd_other->action, pcmk__str_casei) ||
            !pcmk__str_eq(cmd->device, cmd_other->device, pcmk__str_casei)) {

            continue;
        }

        crm_notice("Merging fencing action '%s'%s%s originating from "
                   "client %s with identical fencing request from client %s",
                   cmd_other->action,
                   (cmd_other->target == NULL)? "" : " targeting ",
                   pcmk__s(cmd_other->target, ""), cmd_other->client_name,
                   cmd->client_name);

        // Stop tracking the duplicate, send its result, and cancel it
        cmd_list = g_list_remove_link(cmd_list, iter);
        send_async_reply(cmd_other, result, pid, true);
        cancel_stonith_command(cmd_other);

        free_async_command(cmd_other);
        g_list_free_1(iter);
    }
}

/*!
 * \internal
 * \brief Return the next required device (if any) for an operation
 *
 * \param[in,out] cmd  Fencing operation that just succeeded
 *
 * \return Next device required for action if any, otherwise NULL
 */
static stonith_device_t *
next_required_device(async_command_t *cmd)
{
    for (GList *iter = cmd->next_device_iter; iter != NULL; iter = iter->next) {
        stonith_device_t *next_device = g_hash_table_lookup(device_list,
                                                            iter->data);

        if (is_action_required(cmd->action, next_device)) {
            /* This is only called for successful actions, so it's OK to skip
             * non-required devices.
             */
            cmd->next_device_iter = iter->next;
            return next_device;
        }
    }
    return NULL;
}

static void
st_child_done(int pid, const pcmk__action_result_t *result, void *user_data)
{
    async_command_t *cmd = user_data;

    stonith_device_t *device = NULL;
    stonith_device_t *next_device = NULL;

    CRM_CHECK(cmd != NULL, return);

    device = cmd_device(cmd);
    cmd->active_on = NULL;

    /* The device is ready to do something else now */
    if (device) {
        if (!device->verified && pcmk__result_ok(result) &&
            (pcmk__strcase_any_of(cmd->action, "list", "monitor", "status", NULL))) {

            device->verified = TRUE;
        }

        mainloop_set_trigger(device->work);
    }

    if (pcmk__result_ok(result)) {
        next_device = next_required_device(cmd);

    } else if ((cmd->next_device_iter != NULL)
               && !is_action_required(cmd->action, device)) {
        /* if this device didn't work out, see if there are any others we can try.
         * if the failed device was 'required', we can't pick another device. */
        next_device = g_hash_table_lookup(device_list,
                                          cmd->next_device_iter->data);
        cmd->next_device_iter = cmd->next_device_iter->next;
    }

    if (next_device == NULL) {
        send_async_reply(cmd, result, pid, false);
        if (pcmk__result_ok(result)) {
            reply_to_duplicates(cmd, result, pid);
        }
        free_async_command(cmd);

    } else { // This operation requires more fencing
        log_async_result(cmd, result, pid, next_device->id, false);
        schedule_stonith_command(cmd, next_device);
    }
}

static gint
sort_device_priority(gconstpointer a, gconstpointer b)
{
    const stonith_device_t *dev_a = a;
    const stonith_device_t *dev_b = b;

    if (dev_a->priority > dev_b->priority) {
        return -1;
    } else if (dev_a->priority < dev_b->priority) {
        return 1;
    }
    return 0;
}

static void
stonith_fence_get_devices_cb(GList * devices, void *user_data)
{
    async_command_t *cmd = user_data;
    stonith_device_t *device = NULL;
    guint ndevices = g_list_length(devices);

    crm_info("Found %d matching device%s for target '%s'",
             ndevices, pcmk__plural_s(ndevices), cmd->target);

    if (devices != NULL) {
        /* Order based on priority */
        devices = g_list_sort(devices, sort_device_priority);
        device = g_hash_table_lookup(device_list, devices->data);
    }

    if (device == NULL) { // No device found
        pcmk__action_result_t result = PCMK__UNKNOWN_RESULT;

        pcmk__format_result(&result, CRM_EX_ERROR, PCMK_EXEC_NO_FENCE_DEVICE,
                            "No device configured for target '%s'",
                            cmd->target);
        send_async_reply(cmd, &result, 0, false);
        pcmk__reset_result(&result);
        free_async_command(cmd);
        g_list_free_full(devices, free);

    } else { // Device found, schedule it for fencing
        cmd->device_list = devices;
        cmd->next_device_iter = devices->next;
        schedule_stonith_command(cmd, device);
    }
}

/*!
 * \internal
 * \brief Execute a fence action via the local node
 *
 * \param[in]  msg     Fencing request
 * \param[out] result  Where to store result of fence action
 */
static void
fence_locally(xmlNode *msg, pcmk__action_result_t *result)
{
    const char *device_id = NULL;
    stonith_device_t *device = NULL;
    async_command_t *cmd = NULL;
    xmlNode *dev = NULL;

    CRM_CHECK((msg != NULL) && (result != NULL), return);

    dev = get_xpath_object("//@" F_STONITH_TARGET, msg, LOG_ERR);

    cmd = create_async_command(msg);
    if (cmd == NULL) {
        crm_log_xml_warn(msg, "invalid");
        fenced_set_protocol_error(result);
        return;
    }

    device_id = crm_element_value(dev, F_STONITH_DEVICE);
    if (device_id != NULL) {
        device = g_hash_table_lookup(device_list, device_id);
        if (device == NULL) {
            crm_err("Requested device '%s' is not available", device_id);
            pcmk__format_result(result, CRM_EX_ERROR, PCMK_EXEC_NO_FENCE_DEVICE,
                                "Requested device '%s' not found", device_id);
            return;
        }
        schedule_stonith_command(cmd, device);

    } else {
        const char *host = crm_element_value(dev, F_STONITH_TARGET);

        if (pcmk_is_set(cmd->options, st_opt_cs_nodeid)) {
            int nodeid = 0;
            crm_node_t *node = NULL;

            pcmk__scan_min_int(host, &nodeid, 0);
            node = pcmk__search_known_node_cache(nodeid, NULL, CRM_GET_PEER_ANY);
            if (node != NULL) {
                host = node->uname;
            }
        }

        /* If we get to here, then self-fencing is implicitly allowed */
        get_capable_devices(host, cmd->action, cmd->default_timeout,
                            TRUE, cmd, stonith_fence_get_devices_cb, 
                            pcmk__str_eq(cmd->action, "on", pcmk__str_casei)? st_device_supports_on: st_device_supports_none);
    }

    pcmk__set_result(result, CRM_EX_OK, PCMK_EXEC_PENDING, NULL);
}

/*!
 * \internal
 * \brief Build an XML reply for a fencing operation
 *
 * \param[in] request  Request that reply is for
 * \param[in] data     If not NULL, add to reply as call data
 * \param[in] result   Full result of fencing operation
 *
 * \return Newly created XML reply
 * \note The caller is responsible for freeing the result.
 * \note This has some overlap with construct_async_reply(), but that copies
 *       values from an async_command_t, whereas this one copies them from the
 *       request.
 */
xmlNode *
fenced_construct_reply(const xmlNode *request, xmlNode *data,
                       const pcmk__action_result_t *result)
{
    xmlNode *reply = NULL;

    reply = create_xml_node(NULL, T_STONITH_REPLY);

    crm_xml_add(reply, "st_origin", __func__);
    crm_xml_add(reply, F_TYPE, T_STONITH_NG);
    stonith__xe_set_result(reply, result);

    if (request == NULL) {
        /* Most likely, this is the result of a stonith operation that was
         * initiated before we came up. Unfortunately that means we lack enough
         * information to provide clients with a full result.
         *
         * @TODO Maybe synchronize this information at start-up?
         */
        crm_warn("Missing request information for client notifications for "
                 "operation with result '%s' (initiated before we came up?)",
                 pcmk_exec_status_str(result->execution_status));

    } else {
        const char *name = NULL;
        const char *value = NULL;

        // Attributes to copy from request to reply
        const char *names[] = {
            F_STONITH_OPERATION,
            F_STONITH_CALLID,
            F_STONITH_CLIENTID,
            F_STONITH_CLIENTNAME,
            F_STONITH_REMOTE_OP_ID,
            F_STONITH_CALLOPTS
        };

        for (int lpc = 0; lpc < PCMK__NELEM(names); lpc++) {
            name = names[lpc];
            value = crm_element_value(request, name);
            crm_xml_add(reply, name, value);
        }
        if (data != NULL) {
            add_message_xml(reply, F_STONITH_CALLDATA, data);
        }
    }
    return reply;
}

/*!
 * \internal
 * \brief Build an XML reply to an asynchronous fencing command
 *
 * \param[in] cmd     Fencing command that reply is for
 * \param[in] result  Command result
 */
static xmlNode *
construct_async_reply(const async_command_t *cmd,
                      const pcmk__action_result_t *result)
{
    xmlNode *reply = create_xml_node(NULL, T_STONITH_REPLY);

    crm_xml_add(reply, "st_origin", __func__);
    crm_xml_add(reply, F_TYPE, T_STONITH_NG);
    crm_xml_add(reply, F_STONITH_OPERATION, cmd->op);
    crm_xml_add(reply, F_STONITH_DEVICE, cmd->device);
    crm_xml_add(reply, F_STONITH_REMOTE_OP_ID, cmd->remote_op_id);
    crm_xml_add(reply, F_STONITH_CLIENTID, cmd->client);
    crm_xml_add(reply, F_STONITH_CLIENTNAME, cmd->client_name);
    crm_xml_add(reply, F_STONITH_TARGET, cmd->target);
    crm_xml_add(reply, F_STONITH_ACTION, cmd->op);
    crm_xml_add(reply, F_STONITH_ORIGIN, cmd->origin);
    crm_xml_add_int(reply, F_STONITH_CALLID, cmd->id);
    crm_xml_add_int(reply, F_STONITH_CALLOPTS, cmd->options);

    stonith__xe_set_result(reply, result);
    return reply;
}

bool fencing_peer_active(crm_node_t *peer)
{
    if (peer == NULL) {
        return FALSE;
    } else if (peer->uname == NULL) {
        return FALSE;
    } else if (pcmk_is_set(peer->processes, crm_get_cluster_proc())) {
        return TRUE;
    }
    return FALSE;
}

void
set_fencing_completed(remote_fencing_op_t *op)
{
    struct timespec tv;

    qb_util_timespec_from_epoch_get(&tv);
    op->completed = tv.tv_sec;
    op->completed_nsec = tv.tv_nsec;
}

/*!
 * \internal
 * \brief Look for alternate node needed if local node shouldn't fence target
 *
 * \param[in] target  Node that must be fenced
 *
 * \return Name of an alternate node that should fence \p target if any,
 *         or NULL otherwise
 */
static const char *
check_alternate_host(const char *target)
{
    if (pcmk__str_eq(target, stonith_our_uname, pcmk__str_casei)) {
        GHashTableIter gIter;
        crm_node_t *entry = NULL;

        g_hash_table_iter_init(&gIter, crm_peer_cache);
        while (g_hash_table_iter_next(&gIter, NULL, (void **)&entry)) {
            if (fencing_peer_active(entry)
                && !pcmk__str_eq(entry->uname, target, pcmk__str_casei)) {
                crm_notice("Forwarding self-fencing request to %s",
                           entry->uname);
                return entry->uname;
            }
        }
        crm_warn("Will handle own fencing because no peer can");
    }
    return NULL;
}

/*!
 * \internal
 * \brief Send a reply to a CPG peer or IPC client
 *
 * \param[in]     reply         XML reply to send
 * \param[in]     call_options  Send synchronously if st_opt_sync_call is set
 * \param[in]     remote_peer   If not NULL, name of peer node to send CPG reply
 * \param[in,out] client        If not NULL, client to send IPC reply
 */
static void
stonith_send_reply(xmlNode *reply, int call_options, const char *remote_peer,
                   pcmk__client_t *client)
{
    CRM_CHECK((reply != NULL) && ((remote_peer != NULL) || (client != NULL)),
              return);

    if (remote_peer == NULL) {
        do_local_reply(reply, client, call_options);
    } else {
        send_cluster_message(crm_get_peer(0, remote_peer), crm_msg_stonith_ng,
                             reply, FALSE);
    }
}

static void 
remove_relay_op(xmlNode * request)
{
    xmlNode *dev = get_xpath_object("//@" F_STONITH_ACTION, request, LOG_TRACE);
    const char *relay_op_id = NULL; 
    const char *op_id = NULL;
    const char *client_name = NULL;
    const char *target = NULL; 
    remote_fencing_op_t *relay_op = NULL; 

    if (dev) { 
        target = crm_element_value(dev, F_STONITH_TARGET); 
    }

    relay_op_id = crm_element_value(request, F_STONITH_REMOTE_OP_ID_RELAY);
    op_id = crm_element_value(request, F_STONITH_REMOTE_OP_ID);
    client_name = crm_element_value(request, F_STONITH_CLIENTNAME);

    /* Delete RELAY operation. */
    if (relay_op_id && target && pcmk__str_eq(target, stonith_our_uname, pcmk__str_casei)) {
        relay_op = g_hash_table_lookup(stonith_remote_op_list, relay_op_id);

        if (relay_op) {
            GHashTableIter iter;
            remote_fencing_op_t *list_op = NULL; 
            g_hash_table_iter_init(&iter, stonith_remote_op_list);

            /* If the operation to be deleted is registered as a duplicate, delete the registration. */
            while (g_hash_table_iter_next(&iter, NULL, (void **)&list_op)) {
                GList *dup_iter = NULL;
                if (list_op != relay_op) {
                    for (dup_iter = list_op->duplicates; dup_iter != NULL; dup_iter = dup_iter->next) {
                        remote_fencing_op_t *other = dup_iter->data;
                        if (other == relay_op) {
                            other->duplicates = g_list_remove(other->duplicates, relay_op);
                            break;
                        }
                    }
                }
            }
            crm_debug("Deleting relay op %s ('%s'%s%s for %s), "
                      "replaced by op %s ('%s'%s%s for %s)",
                      relay_op->id, relay_op->action,
                      (relay_op->target == NULL)? "" : " targeting ",
                      pcmk__s(relay_op->target, ""),
                      relay_op->client_name, op_id, relay_op->action,
                      (target == NULL)? "" : " targeting ", pcmk__s(target, ""),
                      client_name);

            g_hash_table_remove(stonith_remote_op_list, relay_op_id);
        }
    }
}

/*!
 * \internal
 * \brief Check whether an API request was sent by a privileged user
 *
 * API commands related to fencing configuration may be done only by privileged
 * IPC users (i.e. root or hacluster), because all other users should go through
 * the CIB to have ACLs applied. If no client was given, this is a peer request,
 * which is always allowed.
 *
 * \param[in] c   IPC client that sent request (or NULL if sent by CPG peer)
 * \param[in] op  Requested API operation (for logging only)
 *
 * \return true if sender is peer or privileged client, otherwise false
 */
static inline bool
is_privileged(const pcmk__client_t *c, const char *op)
{
    if ((c == NULL) || pcmk_is_set(c->flags, pcmk__client_privileged)) {
        return true;
    } else {
        crm_warn("Rejecting IPC request '%s' from unprivileged client %s",
                 pcmk__s(op, ""), pcmk__client_name(c));
        return false;
    }
}

// CRM_OP_REGISTER
static xmlNode *
handle_register_request(pcmk__request_t *request)
{
    xmlNode *reply = create_xml_node(NULL, "reply");

    CRM_ASSERT(request->ipc_client != NULL);
    crm_xml_add(reply, F_STONITH_OPERATION, CRM_OP_REGISTER);
    crm_xml_add(reply, F_STONITH_CLIENTID, request->ipc_client->id);
    pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);
    pcmk__set_request_flags(request, pcmk__request_reuse_options);
    return reply;
}

// STONITH_OP_EXEC
static xmlNode *
handle_agent_request(pcmk__request_t *request)
{
    execute_agent_action(request->xml, &request->result);
    if (request->result.execution_status == PCMK_EXEC_PENDING) {
        return NULL;
    }
    return fenced_construct_reply(request->xml, NULL, &request->result);
}

// STONITH_OP_TIMEOUT_UPDATE
static xmlNode *
handle_update_timeout_request(pcmk__request_t *request)
{
    const char *call_id = crm_element_value(request->xml, F_STONITH_CALLID);
    const char *client_id = crm_element_value(request->xml, F_STONITH_CLIENTID);
    int op_timeout = 0;

    crm_element_value_int(request->xml, F_STONITH_TIMEOUT, &op_timeout);
    do_stonith_async_timeout_update(client_id, call_id, op_timeout);
    pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);
    return NULL;
}

// STONITH_OP_QUERY
static xmlNode *
handle_query_request(pcmk__request_t *request)
{
    int timeout = 0;
    xmlNode *dev = NULL;
    const char *action = NULL;
    const char *target = NULL;
    const char *client_id = crm_element_value(request->xml, F_STONITH_CLIENTID);
    struct st_query_data *query = NULL;

    if (request->peer != NULL) {
        // Record it for the future notification
        create_remote_stonith_op(client_id, request->xml, TRUE);
    }

    /* Delete the DC node RELAY operation. */
    remove_relay_op(request->xml);

    pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);

    dev = get_xpath_object("//@" F_STONITH_ACTION, request->xml, LOG_NEVER);
    if (dev != NULL) {
        const char *device = crm_element_value(dev, F_STONITH_DEVICE);

        if (pcmk__str_eq(device, "manual_ack", pcmk__str_casei)) {
            return NULL; // No query or reply necessary
        }
        target = crm_element_value(dev, F_STONITH_TARGET);
        action = crm_element_value(dev, F_STONITH_ACTION);
    }

    crm_log_xml_trace(request->xml, "Query");

    query = calloc(1, sizeof(struct st_query_data));
    CRM_ASSERT(query != NULL);

    query->reply = fenced_construct_reply(request->xml, NULL, &request->result);
    pcmk__str_update(&query->remote_peer, request->peer);
    pcmk__str_update(&query->client_id, client_id);
    pcmk__str_update(&query->target, target);
    pcmk__str_update(&query->action, action);
    query->call_options = request->call_options;

    crm_element_value_int(request->xml, F_STONITH_TIMEOUT, &timeout);
    get_capable_devices(target, action, timeout,
                        pcmk_is_set(query->call_options, st_opt_allow_suicide),
                        query, stonith_query_capable_device_cb, st_device_supports_none);
    return NULL;
}

// T_STONITH_NOTIFY
static xmlNode *
handle_notify_request(pcmk__request_t *request)
{
    const char *flag_name = NULL;

    CRM_ASSERT(request->ipc_client != NULL);
    flag_name = crm_element_value(request->xml, F_STONITH_NOTIFY_ACTIVATE);
    if (flag_name != NULL) {
        crm_debug("Enabling %s callbacks for client %s",
                  flag_name, pcmk__request_origin(request));
        pcmk__set_client_flags(request->ipc_client, get_stonith_flag(flag_name));
    }

    flag_name = crm_element_value(request->xml, F_STONITH_NOTIFY_DEACTIVATE);
    if (flag_name != NULL) {
        crm_debug("Disabling %s callbacks for client %s",
                  flag_name, pcmk__request_origin(request));
        pcmk__clear_client_flags(request->ipc_client,
                                 get_stonith_flag(flag_name));
    }

    pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);
    pcmk__set_request_flags(request, pcmk__request_reuse_options);

    return pcmk__ipc_create_ack(request->ipc_flags, "ack", NULL, CRM_EX_OK);
}

// STONITH_OP_RELAY
static xmlNode *
handle_relay_request(pcmk__request_t *request)
{
    xmlNode *dev = get_xpath_object("//@" F_STONITH_TARGET, request->xml,
                                    LOG_TRACE);

    crm_notice("Received forwarded fencing request from "
               "%s %s to fence (%s) peer %s",
               pcmk__request_origin_type(request),
               pcmk__request_origin(request),
               crm_element_value(dev, F_STONITH_ACTION),
               crm_element_value(dev, F_STONITH_TARGET));

    if (initiate_remote_stonith_op(NULL, request->xml, FALSE) == NULL) {
        fenced_set_protocol_error(&request->result);
        return fenced_construct_reply(request->xml, NULL, &request->result);
    }

    pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_PENDING, NULL);
    return NULL;
}

// STONITH_OP_FENCE
static xmlNode *
handle_fence_request(pcmk__request_t *request)
{
    if ((request->peer != NULL) || stand_alone) {
        fence_locally(request->xml, &request->result);

    } else if (pcmk_is_set(request->call_options, st_opt_manual_ack)) {
        switch (fenced_handle_manual_confirmation(request->ipc_client,
                                                  request->xml)) {
            case pcmk_rc_ok:
                pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_DONE,
                                 NULL);
                break;
            case EINPROGRESS:
                pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_PENDING,
                                 NULL);
                break;
            default:
                fenced_set_protocol_error(&request->result);
                break;
        }

    } else {
        const char *alternate_host = NULL;
        xmlNode *dev = get_xpath_object("//@" F_STONITH_TARGET, request->xml,
                                        LOG_TRACE);
        const char *target = crm_element_value(dev, F_STONITH_TARGET);
        const char *action = crm_element_value(dev, F_STONITH_ACTION);
        const char *device = crm_element_value(dev, F_STONITH_DEVICE);

        if (request->ipc_client != NULL) {
            int tolerance = 0;

            crm_notice("Client %s wants to fence (%s) %s using %s",
                       pcmk__request_origin(request), action,
                       target, (device? device : "any device"));
            crm_element_value_int(dev, F_STONITH_TOLERANCE, &tolerance);
            if (stonith_check_fence_tolerance(tolerance, target, action)) {
                pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_DONE,
                                 NULL);
                return fenced_construct_reply(request->xml, NULL,
                                              &request->result);
            }
            alternate_host = check_alternate_host(target);

        } else {
            crm_notice("Peer %s wants to fence (%s) '%s' with device '%s'",
                       request->peer, action, target,
                       (device == NULL)? "(any)" : device);
        }

        if (alternate_host != NULL) {
            const char *client_id = NULL;
            remote_fencing_op_t *op = NULL;

            if (request->ipc_client->id == 0) {
                client_id = crm_element_value(request->xml, F_STONITH_CLIENTID);
            } else {
                client_id = request->ipc_client->id;
            }

            /* Create a duplicate fencing operation to relay with the client ID.
             * When a query response is received, this operation should be
             * deleted to avoid keeping the duplicate around.
             */
            op = create_remote_stonith_op(client_id, request->xml, FALSE);

            crm_xml_add(request->xml, F_STONITH_OPERATION, STONITH_OP_RELAY);
            crm_xml_add(request->xml, F_STONITH_CLIENTID,
                        request->ipc_client->id);
            crm_xml_add(request->xml, F_STONITH_REMOTE_OP_ID, op->id);
            send_cluster_message(crm_get_peer(0, alternate_host),
                                 crm_msg_stonith_ng, request->xml, FALSE);
            pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_PENDING,
                             NULL);

        } else if (initiate_remote_stonith_op(request->ipc_client, request->xml,
                                              FALSE) == NULL) {
            fenced_set_protocol_error(&request->result);

        } else {
            pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_PENDING,
                             NULL);
        }
    }

    if (request->result.execution_status == PCMK_EXEC_PENDING) {
        return NULL;
    }
    return fenced_construct_reply(request->xml, NULL, &request->result);
}

// STONITH_OP_FENCE_HISTORY
static xmlNode *
handle_history_request(pcmk__request_t *request)
{
    xmlNode *reply = NULL;
    xmlNode *data = NULL;

    stonith_fence_history(request->xml, &data, request->peer,
                          request->call_options);
    pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);
    if (!pcmk_is_set(request->call_options, st_opt_discard_reply)) {
        /* When the local node broadcasts its history, it sets
         * st_opt_discard_reply and doesn't need a reply.
         */
        reply = fenced_construct_reply(request->xml, data, &request->result);
    }
    free_xml(data);
    return reply;
}

// STONITH_OP_DEVICE_ADD
static xmlNode *
handle_device_add_request(pcmk__request_t *request)
{
    const char *op = crm_element_value(request->xml, F_STONITH_OPERATION);
    xmlNode *dev = get_xpath_object("//" F_STONITH_DEVICE, request->xml,
                                    LOG_ERR);

    if (is_privileged(request->ipc_client, op)) {
        int rc = stonith_device_register(dev, FALSE);

        pcmk__set_result(&request->result,
                         ((rc == pcmk_ok)? CRM_EX_OK : CRM_EX_ERROR),
                         stonith__legacy2status(rc),
                         ((rc == pcmk_ok)? NULL : pcmk_strerror(rc)));
    } else {
        pcmk__set_result(&request->result, CRM_EX_INSUFFICIENT_PRIV,
                         PCMK_EXEC_INVALID,
                         "Unprivileged users must register device via CIB");
    }
    fenced_send_device_notification(op, &request->result,
                                    (dev == NULL)? NULL : ID(dev));
    return fenced_construct_reply(request->xml, NULL, &request->result);
}

// STONITH_OP_DEVICE_DEL
static xmlNode *
handle_device_delete_request(pcmk__request_t *request)
{
    xmlNode *dev = get_xpath_object("//" F_STONITH_DEVICE, request->xml,
                                    LOG_ERR);
    const char *device_id = crm_element_value(dev, XML_ATTR_ID);
    const char *op = crm_element_value(request->xml, F_STONITH_OPERATION);

    if (is_privileged(request->ipc_client, op)) {
        stonith_device_remove(device_id, false);
        pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);
    } else {
        pcmk__set_result(&request->result, CRM_EX_INSUFFICIENT_PRIV,
                         PCMK_EXEC_INVALID,
                         "Unprivileged users must delete device via CIB");
    }
    fenced_send_device_notification(op, &request->result, device_id);
    return fenced_construct_reply(request->xml, NULL, &request->result);
}

// STONITH_OP_LEVEL_ADD
static xmlNode *
handle_level_add_request(pcmk__request_t *request)
{
    char *desc = NULL;
    const char *op = crm_element_value(request->xml, F_STONITH_OPERATION);

    if (is_privileged(request->ipc_client, op)) {
        fenced_register_level(request->xml, &desc, &request->result);
    } else {
        unpack_level_request(request->xml, NULL, NULL, NULL, &desc);
        pcmk__set_result(&request->result, CRM_EX_INSUFFICIENT_PRIV,
                         PCMK_EXEC_INVALID,
                         "Unprivileged users must add level via CIB");
    }
    fenced_send_level_notification(op, &request->result, desc);
    free(desc);
    return fenced_construct_reply(request->xml, NULL, &request->result);
}

// STONITH_OP_LEVEL_DEL
static xmlNode *
handle_level_delete_request(pcmk__request_t *request)
{
    char *desc = NULL;
    const char *op = crm_element_value(request->xml, F_STONITH_OPERATION);

    if (is_privileged(request->ipc_client, op)) {
        fenced_unregister_level(request->xml, &desc, &request->result);
    } else {
        unpack_level_request(request->xml, NULL, NULL, NULL, &desc);
        pcmk__set_result(&request->result, CRM_EX_INSUFFICIENT_PRIV,
                         PCMK_EXEC_INVALID,
                         "Unprivileged users must delete level via CIB");
    }
    fenced_send_level_notification(op, &request->result, desc);
    free(desc);
    return fenced_construct_reply(request->xml, NULL, &request->result);
}

// CRM_OP_RM_NODE_CACHE
static xmlNode *
handle_cache_request(pcmk__request_t *request)
{
    int node_id = 0;
    const char *name = NULL;

    crm_element_value_int(request->xml, XML_ATTR_ID, &node_id);
    name = crm_element_value(request->xml, XML_ATTR_UNAME);
    reap_crm_member(node_id, name);
    pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);
    return NULL;
}

static xmlNode *
handle_unknown_request(pcmk__request_t *request)
{
    crm_err("Unknown IPC request %s from %s %s",
            request->op, pcmk__request_origin_type(request),
            pcmk__request_origin(request));
    pcmk__format_result(&request->result, CRM_EX_PROTOCOL, PCMK_EXEC_INVALID,
                        "Unknown IPC request type '%s' (bug?)", request->op);
    return fenced_construct_reply(request->xml, NULL, &request->result);
}

static void
fenced_register_handlers(void)
{
    pcmk__server_command_t handlers[] = {
        { CRM_OP_REGISTER, handle_register_request },
        { STONITH_OP_EXEC, handle_agent_request },
        { STONITH_OP_TIMEOUT_UPDATE, handle_update_timeout_request },
        { STONITH_OP_QUERY, handle_query_request },
        { T_STONITH_NOTIFY, handle_notify_request },
        { STONITH_OP_RELAY, handle_relay_request },
        { STONITH_OP_FENCE, handle_fence_request },
        { STONITH_OP_FENCE_HISTORY, handle_history_request },
        { STONITH_OP_DEVICE_ADD, handle_device_add_request },
        { STONITH_OP_DEVICE_DEL, handle_device_delete_request },
        { STONITH_OP_LEVEL_ADD, handle_level_add_request },
        { STONITH_OP_LEVEL_DEL, handle_level_delete_request },
        { CRM_OP_RM_NODE_CACHE, handle_cache_request },
        { NULL, handle_unknown_request },
    };

    fenced_handlers = pcmk__register_handlers(handlers);
}

void
fenced_unregister_handlers(void)
{
    if (fenced_handlers != NULL) {
        g_hash_table_destroy(fenced_handlers);
        fenced_handlers = NULL;
    }
}

static void
handle_request(pcmk__request_t *request)
{
    xmlNode *reply = NULL;
    const char *reason = NULL;

    if (fenced_handlers == NULL) {
        fenced_register_handlers();
    }
    reply = pcmk__process_request(request, fenced_handlers);
    if (reply != NULL) {
        if (pcmk_is_set(request->flags, pcmk__request_reuse_options)
            && (request->ipc_client != NULL)) {
            /* Certain IPC-only commands must reuse the call options from the
             * original request rather than the ones set by stonith_send_reply()
             * -> do_local_reply().
             */
            pcmk__ipc_send_xml(request->ipc_client, request->ipc_id, reply,
                               request->ipc_flags);
            request->ipc_client->request_id = 0;
        } else {
            stonith_send_reply(reply, request->call_options,
                               request->peer, request->ipc_client);
        }
        free_xml(reply);
    }

    reason = request->result.exit_reason;
    crm_debug("Processed %s request from %s %s: %s%s%s%s",
              request->op, pcmk__request_origin_type(request),
              pcmk__request_origin(request),
              pcmk_exec_status_str(request->result.execution_status),
              (reason == NULL)? "" : " (",
              (reason == NULL)? "" : reason,
              (reason == NULL)? "" : ")");
}

static void
handle_reply(pcmk__client_t *client, xmlNode *request, const char *remote_peer)
{
    // Copy, because request might be freed before we want to log this
    char *op = crm_element_value_copy(request, F_STONITH_OPERATION);

    if (pcmk__str_eq(op, STONITH_OP_QUERY, pcmk__str_none)) {
        process_remote_stonith_query(request);
    } else if (pcmk__str_any_of(op, T_STONITH_NOTIFY, STONITH_OP_FENCE, NULL)) {
        fenced_process_fencing_reply(request);
    } else {
        crm_err("Ignoring unknown %s reply from %s %s",
                pcmk__s(op, "untyped"), ((client == NULL)? "peer" : "client"),
                ((client == NULL)? remote_peer : pcmk__client_name(client)));
        crm_log_xml_warn(request, "UnknownOp");
        free(op);
        return;
    }
    crm_debug("Processed %s reply from %s %s",
              op, ((client == NULL)? "peer" : "client"),
              ((client == NULL)? remote_peer : pcmk__client_name(client)));
    free(op);
}

/*!
 * \internal
 * \brief Handle a message from an IPC client or CPG peer
 *
 * \param[in,out] client      If not NULL, IPC client that sent message
 * \param[in]     id          If from IPC client, IPC message ID
 * \param[in]     flags       Message flags
 * \param[in,out] message     Message XML
 * \param[in]     remote_peer If not NULL, CPG peer that sent message
 */
void
stonith_command(pcmk__client_t *client, uint32_t id, uint32_t flags,
                xmlNode *message, const char *remote_peer)
{
    int call_options = st_opt_none;
    bool is_reply = false;

    CRM_CHECK(message != NULL, return);

    if (get_xpath_object("//" T_STONITH_REPLY, message, LOG_NEVER) != NULL) {
        is_reply = true;
    }
    crm_element_value_int(message, F_STONITH_CALLOPTS, &call_options);
    crm_debug("Processing %ssynchronous %s %s %u from %s %s",
              pcmk_is_set(call_options, st_opt_sync_call)? "" : "a",
              crm_element_value(message, F_STONITH_OPERATION),
              (is_reply? "reply" : "request"), id,
              ((client == NULL)? "peer" : "client"),
              ((client == NULL)? remote_peer : pcmk__client_name(client)));

    if (pcmk_is_set(call_options, st_opt_sync_call)) {
        CRM_ASSERT(client == NULL || client->request_id == id);
    }

    if (is_reply) {
        handle_reply(client, message, remote_peer);
    } else {
        pcmk__request_t request = {
            .ipc_client     = client,
            .ipc_id         = id,
            .ipc_flags      = flags,
            .peer           = remote_peer,
            .xml            = message,
            .call_options   = call_options,
            .result         = PCMK__UNKNOWN_RESULT,
        };

        request.op = crm_element_value_copy(request.xml, F_STONITH_OPERATION);
        CRM_CHECK(request.op != NULL, return);

        if (pcmk_is_set(request.call_options, st_opt_sync_call)) {
            pcmk__set_request_flags(&request, pcmk__request_sync);
        }

        handle_request(&request);
        pcmk__reset_request(&request);
    }
}
