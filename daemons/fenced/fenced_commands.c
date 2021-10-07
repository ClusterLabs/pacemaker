/*
 * Copyright 2009-2021 the Pacemaker project contributors
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
GList *cmd_list = NULL;

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
};

static gboolean stonith_device_dispatch(gpointer user_data);
static void st_child_done(int pid, const pcmk__action_result_t *result,
                          void *user_data);
static void stonith_send_reply(xmlNode * reply, int call_options, const char *remote_peer,
                               const char *client_id);

static void search_devices_record_result(struct device_search_s *search, const char *device,
                                         gboolean can_fence);

static int get_agent_metadata(const char *agent, xmlNode **metadata);
static void read_action_metadata(stonith_device_t *device);

typedef struct async_command_s {

    int id;
    int pid;
    int fd_stdout;
    int options;
    int default_timeout; /* seconds */
    int timeout; /* seconds */

    int start_delay; /* seconds */
    int delay_id;

    char *op;
    char *origin;
    char *client;
    char *client_name;
    char *remote_op_id;

    char *victim;
    uint32_t victim_nodeid;
    char *action;
    char *device;

    GList *device_list;
    GList *device_next;

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

static xmlNode *stonith_construct_async_reply(async_command_t * cmd, const char *output,
                                              xmlNode * data, int rc);

static gboolean
is_action_required(const char *action, stonith_device_t *device)
{
    return device && device->automatic_unfencing && pcmk__str_eq(action, "on",
                                                                 pcmk__str_casei);
}

static int
get_action_delay_max(stonith_device_t * device, const char * action)
{
    const char *value = NULL;
    int delay_max = 0;

    if (!pcmk__strcase_any_of(action, "off", "reboot", NULL)) {
        return 0;
    }

    value = g_hash_table_lookup(device->params, PCMK_STONITH_DELAY_MAX);
    if (value) {
       delay_max = crm_parse_interval_spec(value) / 1000;
    }

    return delay_max;
}

static int
get_action_delay_base(stonith_device_t *device, const char *action, const char *victim)
{
    char *hash_value = NULL;
    int delay_base = 0;

    if (!pcmk__strcase_any_of(action, "off", "reboot", NULL)) {
        return 0;
    }

    hash_value = g_hash_table_lookup(device->params, PCMK_STONITH_DELAY_BASE);

    if (hash_value) {
        char *value = strdup(hash_value);
        char *valptr = value;

        CRM_ASSERT(value != NULL);

        if (victim) {
            for (char *val = strtok(value, "; \t"); val != NULL; val = strtok(NULL, "; \t")) {
                char *mapval = strchr(val, ':');

                if (mapval == NULL || mapval[1] == 0) {
                    crm_err("pcmk_delay_base: empty value in mapping", val);
                    continue;
                }

                if (mapval != val && strncasecmp(victim, val, (size_t)(mapval - val)) == 0) {
                    value = mapval + 1;
                    crm_debug("pcmk_delay_base mapped to %s for %s", value, victim);
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
get_action_timeout(stonith_device_t * device, const char *action, int default_timeout)
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
    free(cmd->victim);
    free(cmd->remote_op_id);
    free(cmd->client);
    free(cmd->client_name);
    free(cmd->origin);
    free(cmd->op);
    free(cmd);
}

static async_command_t *
create_async_command(xmlNode * msg)
{
    async_command_t *cmd = NULL;
    xmlNode *op = get_xpath_object("//@" F_STONITH_ACTION, msg, LOG_ERR);
    const char *action = crm_element_value(op, F_STONITH_ACTION);

    CRM_CHECK(action != NULL, crm_log_xml_warn(msg, "NoAction"); return NULL);

    crm_log_xml_trace(msg, "Command");
    cmd = calloc(1, sizeof(async_command_t));
    crm_element_value_int(msg, F_STONITH_CALLID, &(cmd->id));
    crm_element_value_int(msg, F_STONITH_CALLOPTS, &(cmd->options));
    crm_element_value_int(msg, F_STONITH_TIMEOUT, &(cmd->default_timeout));
    cmd->timeout = cmd->default_timeout;
    // Value -1 means disable any static/random fencing delays
    crm_element_value_int(msg, F_STONITH_DELAY, &(cmd->start_delay));

    cmd->origin = crm_element_value_copy(msg, F_ORIG);
    cmd->remote_op_id = crm_element_value_copy(msg, F_STONITH_REMOTE_OP_ID);
    cmd->client = crm_element_value_copy(msg, F_STONITH_CLIENTID);
    cmd->client_name = crm_element_value_copy(msg, F_STONITH_CLIENTNAME);
    cmd->op = crm_element_value_copy(msg, F_STONITH_OPERATION);
    cmd->action = strdup(action);
    cmd->victim = crm_element_value_copy(op, F_STONITH_TARGET);
    cmd->device = crm_element_value_copy(op, F_STONITH_DEVICE);

    CRM_CHECK(cmd->op != NULL, crm_log_xml_warn(msg, "NoOp"); free_async_command(cmd); return NULL);
    CRM_CHECK(cmd->client != NULL, crm_log_xml_warn(msg, "NoClient"));

    cmd->done_cb = st_child_done;
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
              ((cmd->victim == NULL)? "" : " targeting "),
              ((cmd->victim == NULL)? "" : cmd->victim),
              device->id, cmd->timeout);
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
 * \param[in] cmd               Command to report result for
 * \param[in] execution_status  Execution status to use for result
 * \param[in] exit_status       Exit status to use for result
 * \param[in] exit_reason       Exit reason to use for result
 */
static void
report_internal_result(async_command_t *cmd, int exit_status,
                       int execution_status, const char *exit_reason)
{
    pcmk__action_result_t result = {
        // Ensure we don't pass garbage to free()
        .exit_reason = NULL,
        .action_stdout = NULL,
        .action_stderr = NULL
    };

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
                      ((pending_op->victim == NULL)? "" : " targeting "),
                      ((pending_op->victim == NULL)? "" : pending_op->victim),
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
        if (pcmk__strcase_any_of(cmd->action, "reboot", "off", NULL)) {
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
                   ((cmd->victim == NULL)? "" : " targeting "),
                   ((cmd->victim == NULL)? "" : cmd->victim),
                   device->id, device->agent);
        action_str = "off";
    }

    if (pcmk_is_set(device->flags, st_device_supports_parameter_port)) {
        host_arg = "port";

    } else if (pcmk_is_set(device->flags, st_device_supports_parameter_plug)) {
        host_arg = "plug";
    }

    action = stonith_action_create(device->agent,
                                   action_str,
                                   cmd->victim,
                                   cmd->victim_nodeid,
                                   cmd->timeout, device->params,
                                   device->aliases, host_arg);

    /* for async exec, exec_rc is negative for early error exit
       otherwise handling of success/errors is done via callbacks */
    cmd->activating_on = device;
    exec_rc = stonith_action_execute_async(action, (void *)cmd,
                                           cmd->done_cb, fork_cb);
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
    stonith_device_t *device = NULL;

    cmd->delay_id = 0;
    device = cmd->device ? g_hash_table_lookup(device_list, cmd->device) : NULL;

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

    if (device->include_nodeid && cmd->victim) {
        crm_node_t *node = crm_get_peer(0, cmd->victim);

        cmd->victim_nodeid = node->id;
    }

    cmd->device = strdup(device->id);
    cmd->timeout = get_action_timeout(device, cmd->action, cmd->default_timeout);

    if (cmd->remote_op_id) {
        crm_debug("Scheduling '%s' action%s%s using %s for remote peer %s "
                  "with op id %.8s and timeout %ds",
                  cmd->action,
                  cmd->victim ? " targeting " : "", cmd->victim ? cmd->victim : "",
                  device->id, cmd->origin, cmd->remote_op_id, cmd->timeout);
    } else {
        crm_debug("Scheduling '%s' action%s%s using %s for %s with timeout %ds",
                  cmd->action,
                  cmd->victim ? " targeting " : "", cmd->victim ? cmd->victim : "",
                  device->id, cmd->client, cmd->timeout);
    }

    device->pending_ops = g_list_append(device->pending_ops, cmd);
    mainloop_set_trigger(device->work);

    // Value -1 means disable any static/random fencing delays
    if (requested_delay < 0) {
        return;
    }

    delay_max = get_action_delay_max(device, cmd->action);
    delay_base = get_action_delay_base(device, cmd->action, cmd->victim);
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
                   cmd->victim ? " targeting " : "", cmd->victim ? cmd->victim : "",
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
    free(device->on_target_actions);
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

#define MAX_ACTION_LEN 256

static char *
add_action(char *actions, const char *action)
{
    int offset = 0;

    if (actions == NULL) {
        actions = calloc(1, MAX_ACTION_LEN);
    } else {
        offset = strlen(actions);
    }

    if (offset > 0) {
        offset += snprintf(actions+offset, MAX_ACTION_LEN - offset, " ");
    }
    offset += snprintf(actions+offset, MAX_ACTION_LEN - offset, "%s", action);

    return actions;
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
        const char *on_target = NULL;
        const char *action = NULL;
        xmlNode *match = getXpathResult(xpath, lpc);

        CRM_LOG_ASSERT(match != NULL);
        if(match == NULL) { continue; };

        on_target = crm_element_value(match, "on_target");
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
            const char *automatic = crm_element_value(match, "automatic");

            /* "required" is a deprecated synonym for "automatic" */
            const char *required = crm_element_value(match, "required");

            if (crm_is_true(automatic) || crm_is_true(required)) {
                device->automatic_unfencing = TRUE;
            }
        }

        if (action && crm_is_true(on_target)) {
            device->on_target_actions = add_action(device->on_target_actions, action);
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
 * \param[in]     name    Device name (used for logging only)
 * \param[in,out] params  Device parameters
 */
static GHashTable *
xml2device_params(const char *name, xmlNode *dev)
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
            check_type = "none";
        }
    }

    return check_type;
}

static stonith_device_t *
build_device_from_xml(xmlNode * msg)
{
    const char *value;
    xmlNode *dev = get_xpath_object("//" F_STONITH_DEVICE, msg, LOG_ERR);
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
    if (pcmk__str_eq(value, "unfencing", pcmk__str_casei)) {
        device->automatic_unfencing = TRUE;
    }

    if (is_action_required("on", device)) {
        crm_info("Fencing device '%s' requires unfencing", device->id);
    }

    if (device->on_target_actions) {
        crm_info("Fencing device '%s' requires actions (%s) to be executed "
                 "on target", device->id, device->on_target_actions);
    }

    device->work = mainloop_add_trigger(G_PRIORITY_HIGH, stonith_device_dispatch, device);
    /* TODO: Hook up priority */

    return device;
}

static void
schedule_internal_command(const char *origin,
                          stonith_device_t * device,
                          const char *action,
                          const char *victim,
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
    cmd->victim = victim ? strdup(victim) : NULL;
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
    stonith_device_t *dev = cmd->device ? g_hash_table_lookup(device_list, cmd->device) : NULL;
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
    stonith_device_t *dev = cmd->device ? g_hash_table_lookup(device_list, cmd->device) : NULL;
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

    if ((result->execution_status == PCMK_EXEC_DONE)
        && (result->exit_status == CRM_EX_OK)) {
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
device_has_duplicate(stonith_device_t * device)
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
stonith_device_register(xmlNode * msg, const char **desc, gboolean from_cib)
{
    stonith_device_t *dup = NULL;
    stonith_device_t *device = build_device_from_xml(msg);
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
    if (desc) {
        *desc = device->id;
    }

    if (from_cib) {
        device->cib_registered = TRUE;
    } else {
        device->api_registered = TRUE;
    }

    return pcmk_ok;
}

int
stonith_device_remove(const char *id, gboolean from_cib)
{
    stonith_device_t *device = g_hash_table_lookup(device_list, id);
    guint ndevices = 0;

    if (!device) {
        ndevices = g_hash_table_size(device_list);
        crm_info("Device '%s' not found (%d active device%s)",
                 id, ndevices, pcmk__plural_s(ndevices));
        return pcmk_ok;
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
    return pcmk_ok;
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
count_active_levels(stonith_topology_t * tp)
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

char *stonith_level_key(xmlNode *level, int mode)
{
    if(mode == -1) {
        mode = stonith_level_kind(level);
    }

    switch(mode) {
        case 0:
            return crm_element_value_copy(level, XML_ATTR_STONITH_TARGET);
        case 1:
            return crm_element_value_copy(level, XML_ATTR_STONITH_TARGET_PATTERN);
        case 2:
            {
                const char *name = crm_element_value(level, XML_ATTR_STONITH_TARGET_ATTRIBUTE);
                const char *value = crm_element_value(level, XML_ATTR_STONITH_TARGET_VALUE);

                if(name && value) {
                    return crm_strdup_printf("%s=%s", name, value);
                }
            }
        default:
            return crm_strdup_printf("Unknown-%d-%s", mode, ID(level));
    }
}

int stonith_level_kind(xmlNode * level)
{
    int mode = 0;
    const char *target = crm_element_value(level, XML_ATTR_STONITH_TARGET);

    if(target == NULL) {
        mode++;
        target = crm_element_value(level, XML_ATTR_STONITH_TARGET_PATTERN);
    }

    if(stand_alone == FALSE && target == NULL) {

        mode++;

        if(crm_element_value(level, XML_ATTR_STONITH_TARGET_ATTRIBUTE) == NULL) {
            mode++;

        } else if(crm_element_value(level, XML_ATTR_STONITH_TARGET_VALUE) == NULL) {
            mode++;
        }
    }

    return mode;
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
 * \brief Register a STONITH level for a target
 *
 * Given an XML request specifying the target name, level index, and device IDs
 * for the level, this will create an entry for the target in the global topology
 * table if one does not already exist, then append the specified device IDs to
 * the entry's device list for the specified level.
 *
 * \param[in]  msg   XML request for STONITH level registration
 * \param[out] desc  If not NULL, will be set to string representation ("TARGET[LEVEL]")
 *
 * \return pcmk_ok on success, -EINVAL if XML does not specify valid level index
 */
int
stonith_level_register(xmlNode *msg, char **desc)
{
    int id = 0;
    xmlNode *level;
    int mode;
    char *target;

    stonith_topology_t *tp;
    stonith_key_value_t *dIter = NULL;
    stonith_key_value_t *devices = NULL;

    /* Allow the XML here to point to the level tag directly, or wrapped in
     * another tag. If directly, don't search by xpath, because it might give
     * multiple hits (e.g. if the XML is the CIB).
     */
    if (pcmk__str_eq(TYPE(msg), XML_TAG_FENCING_LEVEL, pcmk__str_casei)) {
        level = msg;
    } else {
        level = get_xpath_object("//" XML_TAG_FENCING_LEVEL, msg, LOG_ERR);
    }
    CRM_CHECK(level != NULL, return -EINVAL);

    mode = stonith_level_kind(level);
    target = stonith_level_key(level, mode);
    crm_element_value_int(level, XML_ATTR_STONITH_INDEX, &id);

    if (desc) {
        *desc = crm_strdup_printf("%s[%d]", target, id);
    }

    /* Sanity-check arguments */
    if (mode >= 3 || (id <= 0) || (id >= ST_LEVEL_MAX)) {
        crm_trace("Could not add %s[%d] (%d) to the topology (%d active entries)", target, id, mode, g_hash_table_size(topology));
        free(target);
        crm_log_xml_err(level, "Bad topology");
        return -EINVAL;
    }

    /* Find or create topology table entry */
    tp = g_hash_table_lookup(topology, target);
    if (tp == NULL) {
        tp = calloc(1, sizeof(stonith_topology_t));
        tp->kind = mode;
        tp->target = target;
        tp->target_value = crm_element_value_copy(level, XML_ATTR_STONITH_TARGET_VALUE);
        tp->target_pattern = crm_element_value_copy(level, XML_ATTR_STONITH_TARGET_PATTERN);
        tp->target_attribute = crm_element_value_copy(level, XML_ATTR_STONITH_TARGET_ATTRIBUTE);

        g_hash_table_replace(topology, tp->target, tp);
        crm_trace("Added %s (%d) to the topology (%d active entries)",
                  target, mode, g_hash_table_size(topology));
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
    return pcmk_ok;
}

int
stonith_level_remove(xmlNode *msg, char **desc)
{
    int id = 0;
    stonith_topology_t *tp;
    char *target;

    /* Unlike additions, removal requests should always have one level tag */
    xmlNode *level = get_xpath_object("//" XML_TAG_FENCING_LEVEL, msg, LOG_ERR);

    CRM_CHECK(level != NULL, return -EINVAL);

    target = stonith_level_key(level, -1);
    crm_element_value_int(level, XML_ATTR_STONITH_INDEX, &id);
    if (desc) {
        *desc = crm_strdup_printf("%s[%d]", target, id);
    }

    /* Sanity-check arguments */
    if (id >= ST_LEVEL_MAX) {
        free(target);
        return -EINVAL;
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

    } else if (id > 0 && tp->levels[id] != NULL) {
        guint nlevels;

        g_list_free_full(tp->levels[id], free);
        tp->levels[id] = NULL;

        nlevels = count_active_levels(tp);
        crm_info("Removed level %d from fencing topology for %s "
                 "(%d active level%s remaining)",
                 id, target, nlevels, pcmk__plural_s(nlevels));
    }

    free(target);
    return pcmk_ok;
}

/*!
 * \internal
 * \brief Schedule an (asynchronous) action directly on a stonith device
 *
 * Handle a STONITH_OP_EXEC API message by scheduling a requested agent action
 * directly on a specified device. Only list, monitor, and status actions are
 * expected to use this call, though it should work with any agent command.
 *
 * \param[in]  msg     API message XML with desired action
 * \param[out] output  Unused
 *
 * \return -EINPROGRESS on success, -errno otherwise
 * \note If the action is monitor, the device must be registered via the API
 *       (CIB registration is not sufficient), because monitor should not be
 *       possible unless the device is "started" (API registered).
 */

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

static int
stonith_device_action(xmlNode * msg, char **output)
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
        return -EPROTO;
    }

    if (pcmk__str_eq(id, STONITH_WATCHDOG_ID, pcmk__str_none)) {
        if (stonith_watchdog_timeout_ms <= 0) {
            return -ENODEV;
        } else {
            if (pcmk__str_eq(action, "list", pcmk__str_casei)) {
                *output = list_to_string(stonith_watchdog_targets, "\n", TRUE);
                return pcmk_ok;
            } else if (pcmk__str_eq(action, "monitor", pcmk__str_casei)) {
                return pcmk_ok;
            }
        }
    }

    device = g_hash_table_lookup(device_list, id);
    if ((device == NULL)
        || (!device->api_registered && !strcmp(action, "monitor"))) {

        // Monitors may run only on "started" (API-registered) devices
        crm_info("Ignoring API '%s' action request because device %s not found",
                 action, id);
        return -ENODEV;
    }

    cmd = create_async_command(msg);
    if (cmd == NULL) {
        return -EPROTO;
    }

    schedule_stonith_command(cmd, device);
    return -EINPROGRESS;
}

static void
search_devices_record_result(struct device_search_s *search, const char *device, gboolean can_fence)
{
    search->replies_received++;

    if (can_fence && device) {
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

    if (device && action && device->on_target_actions
        && strstr(device->on_target_actions, action)) {
        if (!localhost_is_target) {
            crm_trace("Operation '%s' using %s can only be executed for "
                      "local host, not %s", action, device->id, target);
            return FALSE;
        }

    } else if (localhost_is_target && !allow_suicide) {
        crm_trace("'%s' operation does not support self-fencing", action);
        return FALSE;
    }
    return TRUE;
}

static void
can_fence_host_with_device(stonith_device_t * dev, struct device_search_s *search)
{
    gboolean can = FALSE;
    const char *check_type = NULL;
    const char *host = search->host;
    const char *alias = NULL;

    CRM_LOG_ASSERT(dev != NULL);

    if (dev == NULL) {
        goto search_report_results;
    } else if (host == NULL) {
        can = TRUE;
        goto search_report_results;
    }

    /* Short-circuit query if this host is not allowed to perform the action */
    if (pcmk__str_eq(search->action, "reboot", pcmk__str_casei)) {
        /* A "reboot" *might* get remapped to "off" then "on", so short-circuit
         * only if all three are disallowed. If only one or two are disallowed,
         * we'll report that with the results. We never allow suicide for
         * remapped "on" operations because the host is off at that point.
         */
        if (!localhost_is_eligible(dev, "reboot", host, search->allow_suicide)
            && !localhost_is_eligible(dev, "off", host, search->allow_suicide)
            && !localhost_is_eligible(dev, "on", host, FALSE)) {
            goto search_report_results;
        }
    } else if (!localhost_is_eligible(dev, search->action, host,
                                      search->allow_suicide)) {
        goto search_report_results;
    }

    alias = g_hash_table_lookup(dev->aliases, host);
    if (alias == NULL) {
        alias = host;
    }

    check_type = target_list_type(dev);

    if (pcmk__str_eq(check_type, "none", pcmk__str_casei)) {
        can = TRUE;

    } else if (pcmk__str_eq(check_type, "static-list", pcmk__str_casei)) {

        /* Presence in the hostmap is sufficient
         * Only use if all hosts on which the device can be active can always fence all listed hosts
         */

        if (pcmk__str_in_list(host, dev->targets, pcmk__str_casei)) {
            can = TRUE;
        } else if (g_hash_table_lookup(dev->params, PCMK_STONITH_HOST_MAP)
                   && g_hash_table_lookup(dev->aliases, host)) {
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
                      check_type, dev->id, search->host, search->action);

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
                  check_type, dev->id, search->host, search->action);
        schedule_internal_command(__func__, dev, "status", search->host,
                                  search->per_device_timeout, search, status_search_cb);
        /* we'll respond to this search request async in the cb */
        return;
    } else {
        crm_err("Invalid value for " PCMK_STONITH_HOST_CHECK ": %s", check_type);
        check_type = "Invalid " PCMK_STONITH_HOST_CHECK;
    }

    if (pcmk__str_eq(host, alias, pcmk__str_casei)) {
        crm_notice("%s is%s eligible to fence (%s) %s: %s",
                   dev->id, (can? "" : " not"), search->action, host,
                   check_type);
    } else {
        crm_notice("%s is%s eligible to fence (%s) %s (aka. '%s'): %s",
                   dev->id, (can? "" : " not"), search->action, host, alias,
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
                    void (*callback) (GList * devices, void *user_data))
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

    search->host = host ? strdup(host) : NULL;
    search->action = action ? strdup(action) : NULL;
    search->per_device_timeout = timeout;
    search->allow_suicide = suicide;
    search->callback = callback;
    search->user_data = user_data;

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
                               stonith_device_t *device, const char *target)
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
add_disallowed(xmlNode *xml, const char *action, stonith_device_t *device,
               const char *target, gboolean allow_suicide)
{
    if (!localhost_is_eligible(device, action, target, allow_suicide)) {
        crm_trace("Action '%s' using %s is disallowed for local host",
                  action, device->id);
        crm_xml_add(xml, F_STONITH_ACTION_DISALLOWED, XML_BOOLEAN_TRUE);
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
add_action_reply(xmlNode *xml, const char *action, stonith_device_t *device,
               const char *target, gboolean allow_suicide)
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
    stonith_send_reply(query->reply, query->call_options, query->remote_peer, query->client_id);

    free_xml(query->reply);
    free(query->remote_peer);
    free(query->client_id);
    free(query->target);
    free(query->action);
    free(query);
    free_xml(list);
    g_list_free_full(devices, free);
}

static void
stonith_query(xmlNode * msg, const char *remote_peer, const char *client_id, int call_options)
{
    struct st_query_data *query = NULL;
    const char *action = NULL;
    const char *target = NULL;
    int timeout = 0;
    xmlNode *dev = get_xpath_object("//@" F_STONITH_ACTION, msg, LOG_NEVER);

    crm_element_value_int(msg, F_STONITH_TIMEOUT, &timeout);
    if (dev) {
        const char *device = crm_element_value(dev, F_STONITH_DEVICE);

        target = crm_element_value(dev, F_STONITH_TARGET);
        action = crm_element_value(dev, F_STONITH_ACTION);
        if (device && pcmk__str_eq(device, "manual_ack", pcmk__str_casei)) {
            /* No query or reply necessary */
            return;
        }
    }

    crm_log_xml_debug(msg, "Query");
    query = calloc(1, sizeof(struct st_query_data));

    query->reply = stonith_construct_reply(msg, NULL, NULL, pcmk_ok);
    query->remote_peer = remote_peer ? strdup(remote_peer) : NULL;
    query->client_id = client_id ? strdup(client_id) : NULL;
    query->target = target ? strdup(target) : NULL;
    query->action = action ? strdup(action) : NULL;
    query->call_options = call_options;

    get_capable_devices(target, action, timeout,
                        pcmk_is_set(call_options, st_opt_allow_suicide),
                        query, stonith_query_capable_device_cb);
}

/*!
 * \internal
 * \brief Log the result of an asynchronous command
 *
 * \param[in] cmd        Command the result is for
 * \param[in] rc         Legacy return code corresponding to result
 * \param[in] pid        Process ID of command, if available
 * \param[in] next       Alternate device that will be tried if command failed
 * \param[in] output     Command output, if any
 * \param[in] op_merged  Whether this command was merged with an earlier one
 */
static void
log_async_result(async_command_t *cmd, int rc, int pid, const char *next,
                 const char *output, gboolean op_merged)
{
    int log_level = LOG_ERR;
    int output_log_level = LOG_NEVER;
    guint devices_remaining = g_list_length(cmd->device_next);

    GString *msg = g_string_sized_new(80); // Reasonable starting size

    // Choose log levels appropriately
    if (rc == 0) { // Success
        log_level = (cmd->victim == NULL)? LOG_DEBUG : LOG_NOTICE;
        if ((output != NULL)
            && !pcmk__str_eq(cmd->action, "metadata", pcmk__str_casei)) {
            output_log_level = LOG_DEBUG;
        }
        next = NULL;
    } else { // Failure
        log_level = (cmd->victim == NULL)? LOG_NOTICE : LOG_ERR;
        if ((output != NULL)
            && !pcmk__str_eq(cmd->action, "metadata", pcmk__str_casei)) {
            output_log_level = LOG_WARNING;
        }
    }

    // Build the log message piece by piece
    g_string_printf(msg, "Operation '%s' ", cmd->action);
    if (pid != 0) {
        g_string_append_printf(msg, "[%d] ", pid);
    }
    if (cmd->victim != NULL) {
        g_string_append_printf(msg, "targeting %s ", cmd->victim);
    }
    g_string_append_printf(msg, "using %s ", cmd->device);

    // Add result
    g_string_append_printf(msg, "returned %d (%s)", rc, pcmk_strerror(rc));

    // Add next device if appropriate
    if (next != NULL) {
        g_string_append_printf(msg, ", retrying with %s", next);
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

        crm_log_output(output_log_level, prefix, output);
        free(prefix);
    }
}

static void
stonith_send_async_reply(async_command_t *cmd, const char *output, int rc,
                         int pid, bool merged)
{
    xmlNode *reply = NULL;
    gboolean bcast = FALSE;

    reply = stonith_construct_async_reply(cmd, output, NULL, rc);

    // Only replies for certain actions are broadcast
    if (pcmk__str_any_of(cmd->action, "metadata", "monitor", "list", "status",
                         NULL)) {
        crm_trace("Never broadcast '%s' replies", cmd->action);

    } else if (!stand_alone && pcmk__str_eq(cmd->origin, cmd->victim, pcmk__str_casei) && !pcmk__str_eq(cmd->action, "on", pcmk__str_casei)) {
        crm_trace("Broadcast '%s' reply for %s", cmd->action, cmd->victim);
        crm_xml_add(reply, F_SUBTYPE, "broadcast");
        bcast = TRUE;
    }

    log_async_result(cmd, rc, pid, NULL, output, merged);
    crm_log_xml_trace(reply, "Reply");

    if (merged) {
        crm_xml_add(reply, F_STONITH_MERGED, "true");
    }

    if (bcast) {
        crm_xml_add(reply, F_STONITH_OPERATION, T_STONITH_NOTIFY);
        send_cluster_message(NULL, crm_msg_stonith_ng, reply, FALSE);

    } else if (cmd->origin) {
        crm_trace("Directed reply to %s", cmd->origin);
        send_cluster_message(crm_get_peer(0, cmd->origin), crm_msg_stonith_ng, reply, FALSE);

    } else {
        crm_trace("Directed local %ssync reply to %s",
                  (cmd->options & st_opt_sync_call) ? "" : "a-", cmd->client_name);
        do_local_reply(reply, cmd->client, cmd->options & st_opt_sync_call, FALSE);
    }

    if (stand_alone) {
        /* Do notification with a clean data object */
        xmlNode *notify_data = create_xml_node(NULL, T_STONITH_NOTIFY_FENCE);

        crm_xml_add_int(notify_data, F_STONITH_RC, rc);
        crm_xml_add(notify_data, F_STONITH_TARGET, cmd->victim);
        crm_xml_add(notify_data, F_STONITH_OPERATION, cmd->op);
        crm_xml_add(notify_data, F_STONITH_DELEGATE, "localhost");
        crm_xml_add(notify_data, F_STONITH_DEVICE, cmd->device);
        crm_xml_add(notify_data, F_STONITH_REMOTE_OP_ID, cmd->remote_op_id);
        crm_xml_add(notify_data, F_STONITH_ORIGIN, cmd->client);

        do_stonith_notify(0, T_STONITH_NOTIFY_FENCE, rc, notify_data);
        do_stonith_notify(0, T_STONITH_NOTIFY_HISTORY, 0, NULL);
    }

    free_xml(reply);
}

static void
cancel_stonith_command(async_command_t * cmd)
{
    stonith_device_t *device;

    CRM_CHECK(cmd != NULL, return);

    if (!cmd->device) {
        return;
    }

    device = g_hash_table_lookup(device_list, cmd->device);

    if (device) {
        crm_trace("Cancel scheduled '%s' action using %s",
                  cmd->action, device->id);
        device->pending_ops = g_list_remove(device->pending_ops, cmd);
    }
}

static void
st_child_done(int pid, const pcmk__action_result_t *result, void *user_data)
{
    stonith_device_t *device = NULL;
    stonith_device_t *next_device = NULL;
    async_command_t *cmd = user_data;

    GList *gIter = NULL;
    GList *gIterNext = NULL;

    CRM_CHECK(cmd != NULL, return);

    cmd->active_on = NULL;

    /* The device is ready to do something else now */
    device = g_hash_table_lookup(device_list, cmd->device);
    if (device) {
        if (!device->verified && (result->exit_status == CRM_EX_OK) &&
            (pcmk__strcase_any_of(cmd->action, "list", "monitor", "status", NULL))) {

            device->verified = TRUE;
        }

        mainloop_set_trigger(device->work);
    }

    if (result->exit_status == CRM_EX_OK) {
        GList *iter;
        /* see if there are any required devices left to execute for this op */
        for (iter = cmd->device_next; iter != NULL; iter = iter->next) {
            next_device = g_hash_table_lookup(device_list, iter->data);

            if (next_device != NULL && is_action_required(cmd->action, next_device)) {
                cmd->device_next = iter->next;
                break;
            }
            next_device = NULL;
        }

    } else if ((cmd->device_next != NULL)
               && !is_action_required(cmd->action, device)) {
        /* if this device didn't work out, see if there are any others we can try.
         * if the failed device was 'required', we can't pick another device. */
        next_device = g_hash_table_lookup(device_list, cmd->device_next->data);
        cmd->device_next = cmd->device_next->next;
    }

    /* this operation requires more fencing, hooray! */
    if (next_device) {
        log_async_result(cmd, pcmk_rc2legacy(stonith__result2rc(result)), pid,
                         next_device->id, result->action_stdout, FALSE);
        schedule_stonith_command(cmd, next_device);
        /* Prevent cmd from being freed */
        cmd = NULL;
        goto done;
    }

    stonith_send_async_reply(cmd, result->action_stdout,
                             pcmk_rc2legacy(stonith__result2rc(result)), pid,
                             false);

    if (result->exit_status != CRM_EX_OK) {
        goto done;
    }

    /* Check to see if any operations are scheduled to do the exact
     * same thing that just completed.  If so, rather than
     * performing the same fencing operation twice, return the result
     * of this operation for all pending commands it matches. */
    for (gIter = cmd_list; gIter != NULL; gIter = gIterNext) {
        async_command_t *cmd_other = gIter->data;

        gIterNext = gIter->next;

        if (cmd == cmd_other) {
            continue;
        }

        /* A pending scheduled command matches the command that just finished if.
         * 1. The client connections are different.
         * 2. The node victim is the same.
         * 3. The fencing action is the same.
         * 4. The device scheduled to execute the action is the same.
         */
        if (pcmk__str_eq(cmd->client, cmd_other->client, pcmk__str_casei) ||
            !pcmk__str_eq(cmd->victim, cmd_other->victim, pcmk__str_casei) ||
            !pcmk__str_eq(cmd->action, cmd_other->action, pcmk__str_casei) ||
            !pcmk__str_eq(cmd->device, cmd_other->device, pcmk__str_casei)) {

            continue;
        }

        /* Duplicate merging will do the right thing for either type of remapped
         * reboot. If the executing fencer remapped an unsupported reboot to
         * off, then cmd->action will be reboot and will be merged with any
         * other reboot requests. If the originating fencer remapped a
         * topology reboot to off then on, we will get here once with
         * cmd->action "off" and once with "on", and they will be merged
         * separately with similar requests.
         */
        crm_notice("Merging fencing action '%s' targeting %s originating from "
                   "client %s with identical fencing request from client %s",
                   cmd_other->action, cmd_other->victim, cmd_other->client_name,
                   cmd->client_name);

        cmd_list = g_list_remove_link(cmd_list, gIter);

        stonith_send_async_reply(cmd_other, result->action_stdout,
                                 pcmk_rc2legacy(stonith__result2rc(result)),
                                 pid, true);
        cancel_stonith_command(cmd_other);

        free_async_command(cmd_other);
        g_list_free_1(gIter);
    }

  done:
    free_async_command(cmd);
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
             ndevices, pcmk__plural_s(ndevices), cmd->victim);

    if (devices != NULL) {
        /* Order based on priority */
        devices = g_list_sort(devices, sort_device_priority);
        device = g_hash_table_lookup(device_list, devices->data);

        if (device) {
            cmd->device_list = devices;
            cmd->device_next = devices->next;
            devices = NULL;     /* list owned by cmd now */
        }
    }

    /* we have a device, schedule it for fencing. */
    if (device) {
        schedule_stonith_command(cmd, device);
        /* in progress */
        return;
    }

    /* no device found! */
    stonith_send_async_reply(cmd, NULL, -ENODEV, 0, false);

    free_async_command(cmd);
    g_list_free_full(devices, free);
}

static int
stonith_fence(xmlNode * msg)
{
    const char *device_id = NULL;
    stonith_device_t *device = NULL;
    async_command_t *cmd = create_async_command(msg);
    xmlNode *dev = get_xpath_object("//@" F_STONITH_TARGET, msg, LOG_ERR);

    if (cmd == NULL) {
        return -EPROTO;
    }

    device_id = crm_element_value(dev, F_STONITH_DEVICE);
    if (device_id) {
        device = g_hash_table_lookup(device_list, device_id);
        if (device == NULL) {
            crm_err("Requested device '%s' is not available", device_id);
            return -ENODEV;
        }
        schedule_stonith_command(cmd, device);

    } else {
        const char *host = crm_element_value(dev, F_STONITH_TARGET);

        if (cmd->options & st_opt_cs_nodeid) {
            int nodeid;
            crm_node_t *node;

            pcmk__scan_min_int(host, &nodeid, 0);
            node = pcmk__search_known_node_cache(nodeid, NULL, CRM_GET_PEER_ANY);
            if (node) {
                host = node->uname;
            }
        }

        /* If we get to here, then self-fencing is implicitly allowed */
        get_capable_devices(host, cmd->action, cmd->default_timeout,
                            TRUE, cmd, stonith_fence_get_devices_cb);
    }

    return -EINPROGRESS;
}

xmlNode *
stonith_construct_reply(xmlNode * request, const char *output, xmlNode * data, int rc)
{
    xmlNode *reply = NULL;

    reply = create_xml_node(NULL, T_STONITH_REPLY);

    crm_xml_add(reply, "st_origin", __func__);
    crm_xml_add(reply, F_TYPE, T_STONITH_NG);
    crm_xml_add(reply, "st_output", output);
    crm_xml_add_int(reply, F_STONITH_RC, rc);

    if (request == NULL) {
        /* Most likely, this is the result of a stonith operation that was
         * initiated before we came up. Unfortunately that means we lack enough
         * information to provide clients with a full result.
         *
         * @TODO Maybe synchronize this information at start-up?
         */
        crm_warn("Missing request information for client notifications for "
                 "operation with result %d (initiated before we came up?)", rc);

    } else {
        const char *name = NULL;
        const char *value = NULL;

        const char *names[] = {
            F_STONITH_OPERATION,
            F_STONITH_CALLID,
            F_STONITH_CLIENTID,
            F_STONITH_CLIENTNAME,
            F_STONITH_REMOTE_OP_ID,
            F_STONITH_CALLOPTS
        };

        crm_trace("Creating a result reply with%s reply output (rc=%d)",
                  (data? "" : "out"), rc);
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

static xmlNode *
stonith_construct_async_reply(async_command_t * cmd, const char *output, xmlNode * data, int rc)
{
    xmlNode *reply = NULL;

    crm_trace("Creating a basic reply");
    reply = create_xml_node(NULL, T_STONITH_REPLY);

    crm_xml_add(reply, "st_origin", __func__);
    crm_xml_add(reply, F_TYPE, T_STONITH_NG);

    crm_xml_add(reply, F_STONITH_OPERATION, cmd->op);
    crm_xml_add(reply, F_STONITH_DEVICE, cmd->device);
    crm_xml_add(reply, F_STONITH_REMOTE_OP_ID, cmd->remote_op_id);
    crm_xml_add(reply, F_STONITH_CLIENTID, cmd->client);
    crm_xml_add(reply, F_STONITH_CLIENTNAME, cmd->client_name);
    crm_xml_add(reply, F_STONITH_TARGET, cmd->victim);
    crm_xml_add(reply, F_STONITH_ACTION, cmd->op);
    crm_xml_add(reply, F_STONITH_ORIGIN, cmd->origin);
    crm_xml_add_int(reply, F_STONITH_CALLID, cmd->id);
    crm_xml_add_int(reply, F_STONITH_CALLOPTS, cmd->options);

    crm_xml_add_int(reply, F_STONITH_RC, rc);

    crm_xml_add(reply, "st_output", output);

    if (data != NULL) {
        crm_info("Attaching reply output");
        add_message_xml(reply, F_STONITH_CALLDATA, data);
    }
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

void set_fencing_completed(remote_fencing_op_t * op)
{
#ifdef CLOCK_MONOTONIC
    struct timespec tv;

    clock_gettime(CLOCK_MONOTONIC, &tv);

    op->completed = tv.tv_sec;
    op->completed_nsec = tv.tv_nsec;
#else
    op->completed = time(NULL);
    op->completed_nsec = 0L;
#endif
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
    const char *alternate_host = NULL;

    crm_trace("Checking if we (%s) can fence %s", stonith_our_uname, target);
    if (find_topology_for_host(target) && pcmk__str_eq(target, stonith_our_uname, pcmk__str_casei)) {
        GHashTableIter gIter;
        crm_node_t *entry = NULL;

        g_hash_table_iter_init(&gIter, crm_peer_cache);
        while (g_hash_table_iter_next(&gIter, NULL, (void **)&entry)) {
            crm_trace("Checking for %s.%d != %s", entry->uname, entry->id, target);
            if (fencing_peer_active(entry)
                && !pcmk__str_eq(entry->uname, target, pcmk__str_casei)) {
                alternate_host = entry->uname;
                break;
            }
        }
        if (alternate_host == NULL) {
            crm_err("No alternate host available to handle request "
                    "for self-fencing with topology");
            g_hash_table_iter_init(&gIter, crm_peer_cache);
            while (g_hash_table_iter_next(&gIter, NULL, (void **)&entry)) {
                crm_notice("Peer[%d] %s", entry->id, entry->uname);
            }
        }
    }

    return alternate_host;
}

static void
stonith_send_reply(xmlNode * reply, int call_options, const char *remote_peer,
                   const char *client_id)
{
    if (remote_peer) {
        send_cluster_message(crm_get_peer(0, remote_peer), crm_msg_stonith_ng, reply, FALSE);
    } else {
        do_local_reply(reply, client_id,
                       pcmk_is_set(call_options, st_opt_sync_call),
                       (remote_peer != NULL));
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
            crm_debug("Deleting relay op %s ('%s' targeting %s for %s), "
                      "replaced by op %s ('%s' targeting %s for %s)",
                      relay_op->id, relay_op->action, relay_op->target,
                      relay_op->client_name, op_id, relay_op->action, target,
                      client_name);

            g_hash_table_remove(stonith_remote_op_list, relay_op_id);
        }
    }
}

static int
handle_request(pcmk__client_t *client, uint32_t id, uint32_t flags,
               xmlNode *request, const char *remote_peer)
{
    int call_options = 0;
    int rc = -EOPNOTSUPP;

    xmlNode *data = NULL;
    xmlNode *reply = NULL;

    char *output = NULL;
    const char *op = crm_element_value(request, F_STONITH_OPERATION);
    const char *client_id = crm_element_value(request, F_STONITH_CLIENTID);

    /* IPC commands related to fencing configuration may be done only by
     * privileged users (i.e. root or hacluster), because all other users should
     * go through the CIB to have ACLs applied.
     *
     * If no client was given, this is a peer request, which is always allowed.
     */
    bool allowed = (client == NULL)
                   || pcmk_is_set(client->flags, pcmk__client_privileged);

    crm_element_value_int(request, F_STONITH_CALLOPTS, &call_options);

    if (pcmk_is_set(call_options, st_opt_sync_call)) {
        CRM_ASSERT(client == NULL || client->request_id == id);
    }

    if (pcmk__str_eq(op, CRM_OP_REGISTER, pcmk__str_none)) {
        xmlNode *reply = create_xml_node(NULL, "reply");

        CRM_ASSERT(client);
        crm_xml_add(reply, F_STONITH_OPERATION, CRM_OP_REGISTER);
        crm_xml_add(reply, F_STONITH_CLIENTID, client->id);
        pcmk__ipc_send_xml(client, id, reply, flags);
        client->request_id = 0;
        free_xml(reply);
        return 0;

    } else if (pcmk__str_eq(op, STONITH_OP_EXEC, pcmk__str_none)) {
        rc = stonith_device_action(request, &output);

    } else if (pcmk__str_eq(op, STONITH_OP_TIMEOUT_UPDATE, pcmk__str_none)) {
        const char *call_id = crm_element_value(request, F_STONITH_CALLID);
        const char *client_id = crm_element_value(request, F_STONITH_CLIENTID);
        int op_timeout = 0;

        crm_element_value_int(request, F_STONITH_TIMEOUT, &op_timeout);
        do_stonith_async_timeout_update(client_id, call_id, op_timeout);
        return 0;

    } else if (pcmk__str_eq(op, STONITH_OP_QUERY, pcmk__str_none)) {
        if (remote_peer) {
            create_remote_stonith_op(client_id, request, TRUE); /* Record it for the future notification */
        }

        /* Delete the DC node RELAY operation. */
        remove_relay_op(request);

        stonith_query(request, remote_peer, client_id, call_options);
        return 0;

    } else if (pcmk__str_eq(op, T_STONITH_NOTIFY, pcmk__str_none)) {
        const char *flag_name = NULL;

        CRM_ASSERT(client);
        flag_name = crm_element_value(request, F_STONITH_NOTIFY_ACTIVATE);
        if (flag_name) {
            crm_debug("Enabling %s callbacks for client %s",
                      flag_name, pcmk__client_name(client));
            pcmk__set_client_flags(client, get_stonith_flag(flag_name));
        }

        flag_name = crm_element_value(request, F_STONITH_NOTIFY_DEACTIVATE);
        if (flag_name) {
            crm_debug("Disabling %s callbacks for client %s",
                      flag_name, pcmk__client_name(client));
            pcmk__clear_client_flags(client, get_stonith_flag(flag_name));
        }

        pcmk__ipc_send_ack(client, id, flags, "ack", CRM_EX_OK);
        return 0;

    } else if (pcmk__str_eq(op, STONITH_OP_RELAY, pcmk__str_none)) {
        xmlNode *dev = get_xpath_object("//@" F_STONITH_TARGET, request, LOG_TRACE);

        crm_notice("Received forwarded fencing request from "
                   "%s %s to fence (%s) peer %s",
                   ((client == NULL)? "peer" : "client"),
                   ((client == NULL)? remote_peer : pcmk__client_name(client)),
                   crm_element_value(dev, F_STONITH_ACTION),
                   crm_element_value(dev, F_STONITH_TARGET));

        if (initiate_remote_stonith_op(NULL, request, FALSE) != NULL) {
            rc = -EINPROGRESS;
        }

    } else if (pcmk__str_eq(op, STONITH_OP_FENCE, pcmk__str_none)) {

        if (remote_peer || stand_alone) {
            rc = stonith_fence(request);

        } else if (call_options & st_opt_manual_ack) {
            remote_fencing_op_t *rop = NULL;
            xmlNode *dev = get_xpath_object("//@" F_STONITH_TARGET, request, LOG_TRACE);
            const char *target = crm_element_value(dev, F_STONITH_TARGET);

            crm_notice("Received manual confirmation that %s is fenced", target);
            rop = initiate_remote_stonith_op(client, request, TRUE);
            rc = stonith_manual_ack(request, rop);

        } else {
            const char *alternate_host = NULL;
            xmlNode *dev = get_xpath_object("//@" F_STONITH_TARGET, request, LOG_TRACE);
            const char *target = crm_element_value(dev, F_STONITH_TARGET);
            const char *action = crm_element_value(dev, F_STONITH_ACTION);
            const char *device = crm_element_value(dev, F_STONITH_DEVICE);

            if (client) {
                int tolerance = 0;

                crm_notice("Client %s wants to fence (%s) %s using %s",
                           pcmk__client_name(client), action,
                           target, (device? device : "any device"));

                crm_element_value_int(dev, F_STONITH_TOLERANCE, &tolerance);

                if (stonith_check_fence_tolerance(tolerance, target, action)) {
                    rc = 0;
                    goto done;
                }

            } else {
                crm_notice("Peer %s wants to fence (%s) '%s' with device '%s'",
                           remote_peer, action, target, device ? device : "(any)");
            }

            alternate_host = check_alternate_host(target);

            if (alternate_host && client) {
                const char *client_id = NULL;
                remote_fencing_op_t *op = NULL;

                crm_notice("Forwarding self-fencing request to peer %s"
                           "due to topology", alternate_host);

                if (client->id) {
                    client_id = client->id;
                } else {
                    client_id = crm_element_value(request, F_STONITH_CLIENTID);
                }

                /* Create an operation for RELAY and send the ID in the RELAY message. */
                /* When a QUERY response is received, delete the RELAY operation to avoid the existence of duplicate operations. */
                op = create_remote_stonith_op(client_id, request, FALSE);

                crm_xml_add(request, F_STONITH_OPERATION, STONITH_OP_RELAY);
                crm_xml_add(request, F_STONITH_CLIENTID, client->id);
                crm_xml_add(request, F_STONITH_REMOTE_OP_ID, op->id);
                send_cluster_message(crm_get_peer(0, alternate_host), crm_msg_stonith_ng, request,
                                     FALSE);
                rc = -EINPROGRESS;

            } else if (initiate_remote_stonith_op(client, request, FALSE) != NULL) {
                rc = -EINPROGRESS;
            }
        }

    } else if (pcmk__str_eq(op, STONITH_OP_FENCE_HISTORY, pcmk__str_none)) {
        rc = stonith_fence_history(request, &data, remote_peer, call_options);
        if (call_options & st_opt_discard_reply) {
            /* we don't expect answers to the broadcast
             * we might have sent out
             */
            free_xml(data);
            return pcmk_ok;
        }

    } else if (pcmk__str_eq(op, STONITH_OP_DEVICE_ADD, pcmk__str_none)) {
        const char *device_id = NULL;

        if (allowed) {
            rc = stonith_device_register(request, &device_id, FALSE);
        } else {
            rc = -EACCES;
        }
        do_stonith_notify_device(call_options, op, rc, device_id);

    } else if (pcmk__str_eq(op, STONITH_OP_DEVICE_DEL, pcmk__str_none)) {
        xmlNode *dev = get_xpath_object("//" F_STONITH_DEVICE, request, LOG_ERR);
        const char *device_id = crm_element_value(dev, XML_ATTR_ID);

        if (allowed) {
            rc = stonith_device_remove(device_id, FALSE);
        } else {
            rc = -EACCES;
        }
        do_stonith_notify_device(call_options, op, rc, device_id);

    } else if (pcmk__str_eq(op, STONITH_OP_LEVEL_ADD, pcmk__str_none)) {
        char *device_id = NULL;

        if (allowed) {
            rc = stonith_level_register(request, &device_id);
        } else {
            rc = -EACCES;
        }
        do_stonith_notify_level(call_options, op, rc, device_id);
        free(device_id);

    } else if (pcmk__str_eq(op, STONITH_OP_LEVEL_DEL, pcmk__str_none)) {
        char *device_id = NULL;

        if (allowed) {
            rc = stonith_level_remove(request, &device_id);
        } else {
            rc = -EACCES;
        }
        do_stonith_notify_level(call_options, op, rc, device_id);

    } else if(pcmk__str_eq(op, CRM_OP_RM_NODE_CACHE, pcmk__str_casei)) {
        int node_id = 0;
        const char *name = NULL;

        crm_element_value_int(request, XML_ATTR_ID, &node_id);
        name = crm_element_value(request, XML_ATTR_UNAME);
        reap_crm_member(node_id, name);

        return pcmk_ok;

    } else {
        crm_err("Unknown IPC request %s from %s %s", op,
                ((client == NULL)? "peer" : "client"),
                ((client == NULL)? remote_peer : pcmk__client_name(client)));
    }

  done:

    if (rc == -EACCES) {
        crm_warn("Rejecting IPC request '%s' from unprivileged client %s",
                 crm_str(op), pcmk__client_name(client));
    }

    /* Always reply unless the request is in process still.
     * If in progress, a reply will happen async after the request
     * processing is finished */
    if (rc != -EINPROGRESS) {
        crm_trace("Reply handling: %p %u %u %d %d %s", client, client?client->request_id:0,
                  id, pcmk_is_set(call_options, st_opt_sync_call), call_options,
                  crm_element_value(request, F_STONITH_CALLOPTS));

        if (pcmk_is_set(call_options, st_opt_sync_call)) {
            CRM_ASSERT(client == NULL || client->request_id == id);
        }
        reply = stonith_construct_reply(request, output, data, rc);
        stonith_send_reply(reply, call_options, remote_peer, client_id);
    }

    free(output);
    free_xml(data);
    free_xml(reply);

    return rc;
}

static void
handle_reply(pcmk__client_t *client, xmlNode *request, const char *remote_peer)
{
    const char *op = crm_element_value(request, F_STONITH_OPERATION);

    if (pcmk__str_eq(op, STONITH_OP_QUERY, pcmk__str_none)) {
        process_remote_stonith_query(request);
    } else if (pcmk__str_eq(op, T_STONITH_NOTIFY, pcmk__str_none)) {
        process_remote_stonith_exec(request);
    } else if (pcmk__str_eq(op, STONITH_OP_FENCE, pcmk__str_none)) {
        /* Reply to a complex fencing op */
        process_remote_stonith_exec(request);
    } else {
        crm_err("Unknown %s reply from %s %s", op,
                ((client == NULL)? "peer" : "client"),
                ((client == NULL)? remote_peer : pcmk__client_name(client)));
        crm_log_xml_warn(request, "UnknownOp");
    }
}

void
stonith_command(pcmk__client_t *client, uint32_t id, uint32_t flags,
                xmlNode *request, const char *remote_peer)
{
    int call_options = 0;
    int rc = 0;
    gboolean is_reply = FALSE;

    /* Copy op for reporting. The original might get freed by handle_reply()
     * before we use it in crm_debug():
     *     handle_reply()
     *     |- process_remote_stonith_exec()
     *     |-- remote_op_done()
     *     |--- handle_local_reply_and_notify()
     *     |---- crm_xml_add(...F_STONITH_OPERATION...)
     *     |--- free_xml(op->request)
     */
    char *op = crm_element_value_copy(request, F_STONITH_OPERATION);

    if (get_xpath_object("//" T_STONITH_REPLY, request, LOG_NEVER)) {
        is_reply = TRUE;
    }

    crm_element_value_int(request, F_STONITH_CALLOPTS, &call_options);
    crm_debug("Processing %s%s %u from %s %s with call options 0x%08x",
              op, (is_reply? " reply" : ""), id,
              ((client == NULL)? "peer" : "client"),
              ((client == NULL)? remote_peer : pcmk__client_name(client)),
              call_options);

    if (pcmk_is_set(call_options, st_opt_sync_call)) {
        CRM_ASSERT(client == NULL || client->request_id == id);
    }

    if (is_reply) {
        handle_reply(client, request, remote_peer);
    } else {
        rc = handle_request(client, id, flags, request, remote_peer);
    }

    crm_debug("Processed %s%s from %s %s: %s (rc=%d)",
              op, (is_reply? " reply" : ""),
              ((client == NULL)? "peer" : "client"),
              ((client == NULL)? remote_peer : pcmk__client_name(client)),
              ((rc > 0)? "" : pcmk_strerror(rc)), rc);
    free(op);
}
