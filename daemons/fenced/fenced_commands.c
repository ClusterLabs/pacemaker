/*
 * Copyright 2009-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <sys/param.h>
#include <stdbool.h>                    // bool
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

#include <libxml/tree.h>                // xmlNode
#include <libxml/xpath.h>               // xmlXPathObject, etc.

#include <crm/crm.h>
#include <crm/common/ipc.h>
#include <crm/cluster/internal.h>
#include <crm/common/mainloop.h>

#include <crm/stonith-ng.h>
#include <crm/fencing/internal.h>
#include <crm/common/xml.h>

#include <pacemaker-fenced.h>

static GHashTable *device_table = NULL;

GHashTable *topology = NULL;
static GList *cmd_list = NULL;

static GHashTable *fenced_handlers = NULL;

struct device_search_s {
    /* target of fence action */
    char *host;
    /* requested fence action */
    char *action;
    /* timeout to use if a device is queried dynamically for possible targets */
    // @TODO This name is misleading now, it's the value of fencing-timeout
    int per_device_timeout;
    /* number of registered fencing devices at time of request */
    int replies_needed;
    /* number of device replies received so far */
    int replies_received;
    /* whether the target is eligible to perform requested action (or off) */
    bool allow_self;

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

static void search_devices_record_result(struct device_search_s *search, const char *device,
                                         gboolean can_fence);

static int get_agent_metadata(const char *agent, xmlNode **metadata);
static void read_action_metadata(fenced_device_t *device);
static enum fenced_target_by unpack_level_kind(const xmlNode *level);

typedef struct {
    int id;
    uint32_t options;
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
    char *action;
    char *device;

    //! Head of device list (used only for freeing list with command object)
    GList *device_list;

    //! Next item to process in \c device_list
    GList *next_device_iter;

    void *internal_user_data;
    void (*done_cb) (int pid, const pcmk__action_result_t *result,
                     void *user_data);

    fenced_device_t *active_on;
    fenced_device_t *activating_on;
} async_command_t;

static xmlNode *construct_async_reply(const async_command_t *cmd,
                                      const pcmk__action_result_t *result);

/*!
 * \internal
 * \brief Set a bad fencer API request error in a result object
 *
 * \param[out] result  Result to set
 */
static inline void
set_bad_request_result(pcmk__action_result_t *result)
{
    pcmk__set_result(result, CRM_EX_PROTOCOL, PCMK_EXEC_INVALID,
                     "Fencer API request missing required information (bug?)");
}

/*!
 * \internal
 * \brief Check whether the fencer's device table contains a watchdog device
 *
 * \retval \c true   If the device table contains a watchdog device
 * \retval \c false  Otherwise
 */
bool
fenced_has_watchdog_device(void)
{
    return (device_table != NULL)
           && (g_hash_table_lookup(device_table, STONITH_WATCHDOG_ID) != NULL);
}

/*!
 * \internal
 * \brief Call a function for each known fence device
 *
 * \param[in]     fn         Function to call for each device
 * \param[in,out] user_data  User data
 */
void
fenced_foreach_device(GHFunc fn, gpointer user_data)
{
    if (device_table == NULL) {
        return;
    }

    g_hash_table_foreach(device_table, fn, user_data);
}

/*!
 * \internal
 * \brief Remove each known fence device matching a given predicate
 *
 * \param[in] fn  Function that returns \c TRUE to remove a fence device or
 *                \c FALSE to keep it
 */
void
fenced_foreach_device_remove(GHRFunc fn)
{
    if (device_table == NULL) {
        return;
    }

    g_hash_table_foreach_remove(device_table, fn, NULL);
}

static gboolean
is_action_required(const char *action, const fenced_device_t *device)
{
    return (device != NULL)
           && pcmk__is_set(device->flags, fenced_df_auto_unfence)
           && pcmk__str_eq(action, PCMK_ACTION_ON, pcmk__str_none);
}

static int
get_action_delay_max(const fenced_device_t *device, const char *action)
{
    const char *value = NULL;
    guint delay_max = 0U;

    if (!pcmk__is_fencing_action(action)) {
        return 0;
    }

    value = g_hash_table_lookup(device->params, PCMK_FENCING_DELAY_MAX);
    if (value != NULL) {
        pcmk_parse_interval_spec(value, &delay_max);
        delay_max /= 1000;
    }

    return (int) delay_max;
}

/*!
 * \internal
 * \brief If a mapping matches the given target, return its port value
 *
 * \param[in] target   Fencing target node
 * \param[in] mapping  Target-to-port mapping (delimited by a colon)
 *
 * \return The port from \p mapping if it matches \p target, or \c NULL
 *         if \p mapping is malformed or is not a match.
 */
static gchar *
get_value_if_matching(const char *target, const char *mapping)
{
    gchar **nvpair = NULL;
    gchar *value = NULL;

    if (pcmk__str_empty(mapping)) {
        goto done;
    }

    nvpair = g_strsplit(mapping, ":", 2);

    if ((g_strv_length(nvpair) != 2)
        || pcmk__str_empty(nvpair[0]) || pcmk__str_empty(nvpair[1])) {

        pcmk__err(PCMK_FENCING_DELAY_BASE ": Malformed mapping '%s'", mapping);
        goto done;
    }

    if (!pcmk__str_eq(target, nvpair[0], pcmk__str_casei)) {
        goto done;
    }

    // Take ownership so that we don't free nvpair[1] with nvpair
    value = nvpair[1];
    nvpair[1] = NULL;

    pcmk__debug(PCMK_FENCING_DELAY_BASE " mapped to %s for %s", value, target);

done:
    g_strfreev(nvpair);
    return value;
}

/*!
 * \internal
 * \brief If a mapping exists from the target node to a port, return the port
 *
 * \param[in] target  Fencing target node
 * \param[in] values  List of target-to-port mappings (delimited by semicolon,
 *                    space, or tab characters), or a single interval spec
 *
 * \return Port to which \p target is mapped, or \c NULL if no such mapping
 *         exists
 *
 * \note The caller is responsible for freeing the return value using
 *       \c g_free().
 */
static gchar *
get_value_for_target(const char *target, const char *values)
{
    gchar *value = NULL;
    gchar **mappings = NULL;

    /* If there are no colons, don't try to parse as a list of mappings.
     * The caller will try to parse the values string as an interval spec.
     */
    if (strchr(values, ':') == NULL) {
        return NULL;
    }

    mappings = g_strsplit_set(values, "; \t", 0);

    for (gchar **mapping = mappings; (*mapping != NULL) && (value == NULL);
         mapping++) {

        value = get_value_if_matching(target, *mapping);
    }

    g_strfreev(mappings);
    return value;
}

/* @TODO Consolidate some of this with build_port_aliases(). But keep in
 * mind that build_port_aliases()/pcmk__host_map supports either '=' or ':'
 * as a mapping separator, while pcmk_delay_base supports only ':'.
 */
static int
get_action_delay_base(const fenced_device_t *device, const char *action,
                      const char *target)
{
    const char *param = NULL;
    gchar *stripped = NULL;
    gchar *delay_base_s = NULL;
    guint delay_base = 0U;

    if (!pcmk__is_fencing_action(action)) {
        return 0;
    }

    param = g_hash_table_lookup(device->params, PCMK_FENCING_DELAY_BASE);
    if (param == NULL) {
        return 0;
    }

    stripped = g_strstrip(g_strdup(param));

    if (target != NULL) {
        delay_base_s = get_value_for_target(target, stripped);
    }

    if (delay_base_s == NULL) {
        /* Either target is NULL or we didn't find a mapping for it. Try to
         * parse the entire stripped value as an interval spec. Take ownership
         * so that we don't free stripped twice.
         *
         * We can't tell based on which characters are present whether stripped
         * was a list of mappings or an interval spec. An ISO 8601 interval may
         * contain a colon, and a Pacemaker time-and-units string may contain
         * whitespace.
         */
        delay_base_s = stripped;
        stripped = NULL;
    }

    /* @COMPAT Should we accept only a simple time-and-units string, rather than
     * an interval spec?
     */
    pcmk_parse_interval_spec(delay_base_s, &delay_base);
    delay_base /= 1000;

    g_free(stripped);
    g_free(delay_base_s);
    return (int) delay_base;
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
get_action_timeout(const fenced_device_t *device, const char *action,
                   int default_timeout)
{
    char *timeout_param = NULL;
    const char *value = NULL;
    long long timeout_ms = 0;
    int timeout_sec = 0;

    if ((action == NULL) || (device == NULL) || (device->params == NULL)) {
        return default_timeout;
    }

    /* If "reboot" was requested but the device does not support it,
     * we will remap to "off", so check timeout for "off" instead
     */
    if (pcmk__str_eq(action, PCMK_ACTION_REBOOT, pcmk__str_none)
        && !pcmk__is_set(device->flags, fenced_df_supports_reboot)) {
        pcmk__trace("%s doesn't support reboot, using timeout for off instead",
                    device->id);
        action = PCMK_ACTION_OFF;
    }

    /* If the device config specified an action-specific timeout, use it */
    timeout_param = pcmk__assert_asprintf("pcmk_%s_timeout", action);
    value = g_hash_table_lookup(device->params, timeout_param);
    free(timeout_param);

    if (value == NULL) {
        return default_timeout;
    }

    if ((pcmk__parse_ms(value, &timeout_ms) != pcmk_rc_ok)
        || (timeout_ms < 0)) {
        return default_timeout;
    }

    timeout_ms = QB_MIN(timeout_ms, UINT_MAX);
    timeout_sec = pcmk__timeout_ms2s((guint) timeout_ms);

    return QB_MIN(timeout_sec, INT_MAX);
}

/*!
 * \internal
 * \brief Get the currently executing device for a fencing operation
 *
 * \param[in] cmd  Fencing operation to check
 *
 * \return Currently executing device for \p cmd if any, otherwise NULL
 */
static fenced_device_t *
cmd_device(const async_command_t *cmd)
{
    if ((cmd == NULL) || (cmd->device == NULL) || (device_table == NULL)) {
        return NULL;
    }
    return g_hash_table_lookup(device_table, cmd->device);
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
    fenced_device_t *device = NULL;
    const char *action = NULL;

    if ((device_table == NULL) || (device_id == NULL)) {
        return PCMK_ACTION_REBOOT;
    }

    device = g_hash_table_lookup(device_table, device_id);

    if ((device != NULL) && (device->params != NULL)) {
        action = g_hash_table_lookup(device->params, "pcmk_reboot_action");
    }

    return pcmk__s(action, PCMK_ACTION_REBOOT);
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
    fenced_device_t *device = NULL;

    if ((device_table == NULL) || (device_id == NULL)) {
        return false;
    }

    device = g_hash_table_lookup(device_table, device_id);

    if (device != NULL) {
        return pcmk__is_set(device->flags, fenced_df_supports_on);
    }

    return false;
}

static void
free_async_command(async_command_t * cmd)
{
    if (cmd == NULL) {
        return;
    }

    if (cmd->delay_id != 0) {
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
    int rc = pcmk_rc_ok;

    if (msg == NULL) {
        return NULL;
    }

    op = pcmk__xpath_find_one(msg->doc, "//*[@" PCMK__XA_ST_DEVICE_ACTION "]",
                              LOG_ERR);
    if (op == NULL) {
        return NULL;
    }

    cmd = pcmk__assert_alloc(1, sizeof(async_command_t));

    // All messages must include these
    cmd->action = pcmk__xe_get_copy(op, PCMK__XA_ST_DEVICE_ACTION);
    cmd->op = pcmk__xe_get_copy(msg, PCMK__XA_ST_OP);
    cmd->client = pcmk__xe_get_copy(msg, PCMK__XA_ST_CLIENTID);
    if ((cmd->action == NULL) || (cmd->op == NULL) || (cmd->client == NULL)) {
        free_async_command(cmd);
        return NULL;
    }

    pcmk__xe_get_int(msg, PCMK__XA_ST_CALLID, &(cmd->id));
    pcmk__xe_get_int(msg, PCMK__XA_ST_DELAY, &(cmd->start_delay));
    pcmk__xe_get_int(msg, PCMK__XA_ST_TIMEOUT, &(cmd->default_timeout));
    cmd->timeout = cmd->default_timeout;

    rc = pcmk__xe_get_flags(msg, PCMK__XA_ST_CALLOPT, &(cmd->options),
                            st_opt_none);
    if (rc != pcmk_rc_ok) {
        pcmk__warn("Couldn't parse options from request: %s", pcmk_rc_str(rc));
    }

    cmd->origin = pcmk__xe_get_copy(msg, PCMK__XA_SRC);
    cmd->remote_op_id = pcmk__xe_get_copy(msg, PCMK__XA_ST_REMOTE_OP);
    cmd->client_name = pcmk__xe_get_copy(msg, PCMK__XA_ST_CLIENTNAME);
    cmd->target = pcmk__xe_get_copy(op, PCMK__XA_ST_TARGET);
    cmd->device = pcmk__xe_get_copy(op, PCMK__XA_ST_DEVICE_ID);

    cmd->done_cb = st_child_done;

    // Track in global command list
    cmd_list = g_list_append(cmd_list, cmd);

    return cmd;
}

static int
get_action_limit(fenced_device_t *device)
{
    const char *value = NULL;
    int action_limit = 1;

    value = g_hash_table_lookup(device->params, PCMK_FENCING_ACTION_LIMIT);
    if ((value == NULL)
        || (pcmk__scan_min_int(value, &action_limit, INT_MIN) != pcmk_rc_ok)
        || (action_limit == 0)) {
        action_limit = 1;
    }
    return action_limit;
}

static int
get_active_cmds(fenced_device_t *device)
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
    fenced_device_t *device = cmd->activating_on;

    if (device == NULL) {
        /* In case of a retry, we've done the move from activating_on to
         * active_on already
         */
        device = cmd->active_on;
    }

    pcmk__assert(device != NULL);
    pcmk__debug("Operation '%s' [%d]%s%s using %s now running with %ds timeout",
                cmd->action, pid,
                ((cmd->target != NULL)? " targeting " : ""),
                pcmk__s(cmd->target, ""), device->id, cmd->timeout);
    cmd->active_on = device;
    cmd->activating_on = NULL;
}

static int
get_agent_metadata_cb(gpointer data) {
    fenced_device_t *device = data;
    guint period_ms;
    int rc = get_agent_metadata(device->agent, &device->agent_metadata);

    if (rc == pcmk_rc_ok) {
        if (device->agent_metadata != NULL) {
            read_action_metadata(device);
            device->default_host_arg =
                stonith__default_host_arg(device->agent_metadata);
        }

        return G_SOURCE_REMOVE;
    }

    if (rc == EAGAIN) {
        period_ms = pcmk__mainloop_timer_get_period(device->timer);
        if (period_ms < 160 * 1000) {
            mainloop_timer_set_period(device->timer, 2 * period_ms);
        }

        return G_SOURCE_CONTINUE;
    }

    return G_SOURCE_REMOVE;
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
stonith_device_execute(fenced_device_t *device)
{
    int exec_rc = 0;
    const char *action_str = NULL;
    async_command_t *cmd = NULL;
    stonith_action_t *action = NULL;
    int active_cmds = 0;
    int action_limit = 0;
    GList *iter = NULL;

    CRM_CHECK(device != NULL, return FALSE);

    active_cmds = get_active_cmds(device);
    action_limit = get_action_limit(device);
    if (action_limit > -1 && active_cmds >= action_limit) {
        pcmk__trace("%s is over its action limit of %d (%u active action%s)",
                    device->id, action_limit, active_cmds,
                    pcmk__plural_s(active_cmds));
        return TRUE;
    }

    iter = device->pending_ops;

    while (iter != NULL) {
        GList *next = iter->next;
        async_command_t *pending_op = iter->data;

        if ((pending_op != NULL) && (pending_op->delay_id != 0)) {
            pcmk__trace("Operation '%s'%s%s using %s was asked to run too "
                        "early, waiting for start delay of %ds",
                        pending_op->action,
                        ((pending_op->target == NULL)? "" : " targeting "),
                        pcmk__s(pending_op->target, ""),
                        device->id, pending_op->start_delay);
            iter = next;
            continue;
        }

        device->pending_ops = g_list_remove_link(device->pending_ops, iter);
        g_list_free_1(iter);

        cmd = pending_op;
        break;
    }

    if (cmd == NULL) {
        pcmk__trace("No actions using %s are needed", device->id);
        return TRUE;
    }

    if (pcmk__str_any_of(device->agent, STONITH_WATCHDOG_AGENT,
                         STONITH_WATCHDOG_AGENT_INTERNAL, NULL)) {
        if (pcmk__is_fencing_action(cmd->action)) {
            if (node_does_watchdog_fencing(fenced_get_local_node())) {
                pcmk__panic("Watchdog self-fencing required");
                goto done;
            }
        } else {
            pcmk__info("Faking success for %s watchdog operation", cmd->action);
            report_internal_result(cmd, CRM_EX_OK, PCMK_EXEC_DONE, NULL);
            goto done;
        }
    }

#if PCMK__ENABLE_CIBSECRETS
    exec_rc = pcmk__substitute_secrets(device->id, device->params);
    if (exec_rc != pcmk_rc_ok) {
        if (pcmk__str_eq(cmd->action, PCMK_ACTION_STOP, pcmk__str_none)) {
            pcmk__info("Proceeding with stop operation for %s despite being "
                       "unable to load CIB secrets (%s)",
                       device->id, pcmk_rc_str(exec_rc));
        } else {
            pcmk__err("Considering %s unconfigured because unable to load CIB "
                      "secrets: %s",
                      device->id, pcmk_rc_str(exec_rc));
            report_internal_result(cmd, CRM_EX_ERROR, PCMK_EXEC_NO_SECRETS,
                                   "Failed to get CIB secrets");
            goto done;
        }
    }
#endif

    action_str = cmd->action;
    if (pcmk__str_eq(cmd->action, PCMK_ACTION_REBOOT, pcmk__str_none)
        && !pcmk__is_set(device->flags, fenced_df_supports_reboot)) {

        pcmk__notice("Remapping 'reboot' action%s%s using %s to 'off' because "
                     "agent '%s' does not support reboot",
                     ((cmd->target == NULL)? "" : " targeting "),
                     pcmk__s(cmd->target, ""), device->id, device->agent);
        action_str = PCMK_ACTION_OFF;
    }

    action = stonith__action_create(device->agent, action_str, cmd->target,
                                    cmd->timeout, device->params,
                                    device->aliases, device->default_host_arg);

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
    if (device->pending_ops != NULL) {
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
    fenced_device_t *device = cmd_device(cmd);

    cmd->delay_id = 0;
    if (device != NULL) {
        mainloop_set_trigger(device->work);
    }

    return FALSE;
}

static void
schedule_stonith_command(async_command_t *cmd, fenced_device_t *device)
{
    int delay_max = 0;
    int delay_base = 0;
    int requested_delay = cmd->start_delay;

    CRM_CHECK(cmd != NULL, return);
    CRM_CHECK(device != NULL, return);

    if (cmd->device != NULL) {
        free(cmd->device);
    }

    cmd->device = pcmk__str_copy(device->id);
    cmd->timeout = get_action_timeout(device, cmd->action, cmd->default_timeout);

    if (cmd->remote_op_id != NULL) {
        pcmk__debug("Scheduling '%s' action%s%s using %s for remote peer %s "
                    "with op id %.8s and timeout %ds",
                    cmd->action,
                    (cmd->target == NULL)? "" : " targeting ",
                    pcmk__s(cmd->target, ""),
                    device->id, cmd->origin, cmd->remote_op_id, cmd->timeout);

    } else {
        pcmk__debug("Scheduling '%s' action%s%s using %s for %s with timeout "
                    "%ds",
                    cmd->action,
                    ((cmd->target != NULL)? " targeting " : ""),
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
        pcmk__warn(PCMK_FENCING_DELAY_BASE " (%ds) is larger than "
                   PCMK_FENCING_DELAY_MAX " (%ds) for %s using %s "
                   "(limiting to maximum delay)",
                   delay_base, delay_max, cmd->action, device->id);
        delay_base = delay_max;
    }
    if (delay_max > 0) {
        cmd->start_delay += delay_base;

        // Add random offset so that delay_base <= cmd->start_delay <= delay_max
        if (delay_max > delay_base) {
            // coverity[dont_call] Doesn't matter that rand() is predictable
            cmd->start_delay += rand() % (delay_max - delay_base + 1);
        }
    }

    if (cmd->start_delay > 0) {
        pcmk__notice("Delaying '%s' action%s%s using %s for %ds "
                     QB_XS " timeout=%ds requested_delay=%ds base=%ds max=%ds",
                     cmd->action, (cmd->target == NULL)? "" : " targeting ",
                     pcmk__s(cmd->target, ""), device->id, cmd->start_delay,
                     cmd->timeout, requested_delay, delay_base, delay_max);
        cmd->delay_id =
            pcmk__create_timer(cmd->start_delay * 1000, start_delay_helper, cmd);
    }
}

static void
free_device(gpointer data)
{
    fenced_device_t *device = data;

    g_hash_table_destroy(device->params);
    g_hash_table_destroy(device->aliases);

    for (GList *iter = device->pending_ops; iter != NULL; iter = iter->next) {
        async_command_t *cmd = iter->data;

        pcmk__warn("Removal of device '%s' purged operation '%s'", device->id,
                   cmd->action);
        report_internal_result(cmd, CRM_EX_ERROR, PCMK_EXEC_NO_FENCE_DEVICE,
                               "Device was removed before action could be executed");
    }
    g_list_free(device->pending_ops);

    g_list_free_full(device->targets, free);

    if (device->timer != NULL) {
        mainloop_timer_stop(device->timer);
        mainloop_timer_del(device->timer);
    }

    mainloop_destroy_trigger(device->work);

    pcmk__xml_free(device->agent_metadata);
    free(device->namespace);
    g_strfreev(device->on_target_actions);
    free(device->agent);
    free(device->id);
    free(device);
}

/*!
 * \internal
 * \brief Initialize the table of known fence devices
 */
void
fenced_init_device_table(void)
{
    if (device_table != NULL) {
        return;
    }

    device_table = pcmk__strkey_table(NULL, free_device);
}

/*!
 * \internal
 * \brief Free the table of known fence devices
 */
void
fenced_free_device_table(void)
{
    if (device_table == NULL) {
        return;
    }

    g_hash_table_destroy(device_table);
    device_table = NULL;
}

static GHashTable *
build_port_aliases(const char *hostmap, GList **targets)
{
    GHashTable *aliases = pcmk__strikey_table(free, free);
    gchar *stripped = NULL;
    gchar **mappings = NULL;

    if (pcmk__str_empty(hostmap)) {
        goto done;
    }

    stripped = g_strstrip(g_strdup(hostmap));
    mappings = g_strsplit_set(stripped, "; \t", 0);

    for (gchar **mapping = mappings; *mapping != NULL; mapping++) {
        gchar **nvpair = NULL;

        if (pcmk__str_empty(*mapping)) {
            continue;
        }

        // @COMPAT Drop support for '=' as delimiter
        nvpair = g_strsplit_set(*mapping, ":=", 2);

        if (pcmk__str_empty(nvpair[0]) || pcmk__str_empty(nvpair[1])) {
            pcmk__err(PCMK_FENCING_HOST_MAP ": Malformed mapping '%s'",
                      *mapping);

        } else {
            pcmk__debug("Adding alias '%s'='%s'", nvpair[0], nvpair[1]);
            pcmk__insert_dup(aliases, nvpair[0], nvpair[1]);
            *targets = g_list_append(*targets, pcmk__str_copy(nvpair[1]));
        }
        g_strfreev(nvpair);
    }

done:
    g_free(stripped);
    g_strfreev(mappings);
    return aliases;
}

GHashTable *metadata_cache = NULL;

void
free_metadata_cache(void)
{
    if (metadata_cache == NULL) {
        return;
    }

    g_hash_table_destroy(metadata_cache);
    metadata_cache = NULL;
}

static void
init_metadata_cache(void)
{
    if (metadata_cache != NULL) {
        return;
    }

    metadata_cache = pcmk__strkey_table(free, free);
}

int
get_agent_metadata(const char *agent, xmlNode ** metadata)
{
    char *buffer = NULL;
    stonith_t *st = NULL;
    int rc = pcmk_ok;

    if (metadata == NULL) {
        return EINVAL;
    }

    *metadata = NULL;

    if (pcmk__str_eq(agent, STONITH_WATCHDOG_AGENT_INTERNAL, pcmk__str_none)) {
        return pcmk_rc_ok;
    }

    init_metadata_cache();
    buffer = g_hash_table_lookup(metadata_cache, agent);

    if (buffer != NULL) {
        goto done;
    }

    st = stonith__api_new();

    if (st == NULL) {
        pcmk__warn("Could not get agent meta-data: API memory allocation "
                   "failed");
        return EAGAIN;
    }

    rc = st->cmds->metadata(st, st_opt_sync_call, agent, NULL, &buffer, 10);
    stonith__api_free(st);

    if ((rc != pcmk_ok) || (buffer == NULL)) {
        pcmk__err("Could not retrieve metadata for fencing agent %s", agent);
        return EAGAIN;
    }

    g_hash_table_replace(metadata_cache, pcmk__str_copy(agent), buffer);

done:
    *metadata = pcmk__xml_parse(buffer);
    return pcmk_rc_ok;
}

static void
read_action_metadata(fenced_device_t *device)
{
    xmlXPathObject *xpath = NULL;
    int max = 0;

    // @TODO Use GStrvBuilder when we require glib 2.68
    GPtrArray *on_target_actions = NULL;

    if (device->agent_metadata == NULL) {
        return;
    }

    xpath = pcmk__xpath_search(device->agent_metadata->doc,
                               "//" PCMK_XE_ACTION);
    max = pcmk__xpath_num_results(xpath);

    if (max == 0) {
        xmlXPathFreeObject(xpath);
        return;
    }

    for (int i = 0; i < max; i++) {
        const char *action = NULL;
        xmlNode *match = pcmk__xpath_result(xpath, i);

        CRM_LOG_ASSERT(match != NULL);
        if(match == NULL) { continue; };

        action = pcmk__xe_get(match, PCMK_XA_NAME);

        if (pcmk__str_eq(action, PCMK_ACTION_LIST, pcmk__str_none)) {
            fenced_device_set_flags(device, fenced_df_supports_list);

        } else if (pcmk__str_eq(action, PCMK_ACTION_STATUS, pcmk__str_none)) {
            fenced_device_set_flags(device, fenced_df_supports_status);

        } else if (pcmk__str_eq(action, PCMK_ACTION_REBOOT, pcmk__str_none)) {
            fenced_device_set_flags(device, fenced_df_supports_reboot);

        } else if (pcmk__str_eq(action, PCMK_ACTION_ON, pcmk__str_none)) {
            /* PCMK_XA_AUTOMATIC means the cluster will unfence a node when it
             * joins.
             *
             * @COMPAT PCMK__XA_REQUIRED is a deprecated synonym for
             * PCMK_XA_AUTOMATIC.
             */
            if (pcmk__xe_attr_is_true(match, PCMK_XA_AUTOMATIC)
                || pcmk__xe_attr_is_true(match, PCMK__XA_REQUIRED)) {

                fenced_device_set_flags(device, fenced_df_auto_unfence);
            }
            fenced_device_set_flags(device, fenced_df_supports_on);
        }

        if ((action != NULL)
            && pcmk__xe_attr_is_true(match, PCMK_XA_ON_TARGET)) {

            if (on_target_actions == NULL) {
                on_target_actions = g_ptr_array_new();
            }
            g_ptr_array_add(on_target_actions, g_strdup(action));
        }
    }

    if (on_target_actions != NULL) {
        g_ptr_array_add(on_target_actions, NULL);
        device->on_target_actions =
            (gchar **) g_ptr_array_free(on_target_actions, FALSE);
    }
    xmlXPathFreeObject(xpath);
}

static const char *
target_list_type(fenced_device_t *dev)
{
    const char *check_type = g_hash_table_lookup(dev->params,
                                                 PCMK_FENCING_HOST_CHECK);

    if (check_type != NULL) {
        return check_type;
    }

    if (g_hash_table_lookup(dev->params, PCMK_FENCING_HOST_LIST) != NULL) {
        return PCMK_VALUE_STATIC_LIST;
    }

    if (g_hash_table_lookup(dev->params, PCMK_FENCING_HOST_MAP) != NULL) {
        return PCMK_VALUE_STATIC_LIST;
    }

    if (pcmk__is_set(dev->flags, fenced_df_supports_list)) {
        return PCMK_VALUE_DYNAMIC_LIST;
    }

    if (pcmk__is_set(dev->flags, fenced_df_supports_status)) {
        return PCMK_VALUE_STATUS;
    }

    return PCMK_VALUE_NONE;
}

static fenced_device_t *
build_device_from_xml(const xmlNode *dev)
{
    const char *value;
    fenced_device_t *device = NULL;
    char *agent = pcmk__xe_get_copy(dev, PCMK_XA_AGENT);
    int rc = pcmk_rc_ok;

    CRM_CHECK(agent != NULL, return device);

    device = pcmk__assert_alloc(1, sizeof(fenced_device_t));

    device->id = pcmk__xe_get_copy(dev, PCMK_XA_ID);
    device->agent = agent;
    device->namespace = pcmk__xe_get_copy(dev, PCMK__XA_NAMESPACE);
    device->params = xml2list(dev);

    value = g_hash_table_lookup(device->params, PCMK_FENCING_HOST_LIST);
    if (value != NULL) {
        device->targets = stonith__parse_targets(value);
    }

    value = g_hash_table_lookup(device->params, PCMK_FENCING_HOST_MAP);
    device->aliases = build_port_aliases(value, &(device->targets));

    value = target_list_type(device);
    if (!pcmk__str_eq(value, PCMK_VALUE_STATIC_LIST, pcmk__str_casei)
        && (device->targets != NULL)) {

        // device->targets is necessary only with PCMK_VALUE_STATIC_LIST
        g_list_free_full(device->targets, free);
        device->targets = NULL;
    }

    rc = get_agent_metadata(device->agent, &device->agent_metadata);

    if ((rc == pcmk_rc_ok) && (device->agent_metadata != NULL)) {
        read_action_metadata(device);
        device->default_host_arg =
            stonith__default_host_arg(device->agent_metadata);

    } else if (rc == EAGAIN) {
        if (device->timer == NULL) {
            device->timer = mainloop_timer_add("get_agent_metadata", 10 * 1000,
                                               TRUE, get_agent_metadata_cb,
                                               device);
        }

        if (!mainloop_timer_running(device->timer)) {
            mainloop_timer_start(device->timer);
        }
    }

    value = pcmk__xe_get(dev, PCMK__XA_RSC_PROVIDES);
    if (pcmk__str_eq(value, PCMK_VALUE_UNFENCING, pcmk__str_casei)) {
        fenced_device_set_flags(device, fenced_df_auto_unfence);
    }

    if (is_action_required(PCMK_ACTION_ON, device)) {
        pcmk__info("Fencing device '%s' requires unfencing", device->id);
    }

    if (device->on_target_actions != NULL) {
        gchar *on_target_actions = g_strjoinv(" ", device->on_target_actions);

        pcmk__info("Fencing device '%s' requires actions (%s) to be executed "
                   "on target", device->id, on_target_actions);
        g_free(on_target_actions);
    }

    device->work = mainloop_add_trigger(G_PRIORITY_HIGH, stonith_device_dispatch, device);

    return device;
}

static void
schedule_internal_command(const char *origin, fenced_device_t *device,
                          const char *action, const char *target, int timeout,
                          void *internal_user_data,
                          void (*done_cb) (int pid,
                                           const pcmk__action_result_t *result,
                                           void *user_data))
{
    async_command_t *cmd = NULL;

    cmd = pcmk__assert_alloc(1, sizeof(async_command_t));

    cmd->id = -1;
    cmd->default_timeout = timeout ? timeout : 60;
    cmd->timeout = cmd->default_timeout;
    cmd->action = pcmk__str_copy(action);
    cmd->target = pcmk__str_copy(target);
    cmd->device = pcmk__str_copy(device->id);
    cmd->origin = pcmk__str_copy(origin);
    cmd->client = pcmk__str_copy(crm_system_name);
    cmd->client_name = pcmk__str_copy(crm_system_name);

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
    fenced_device_t *dev = cmd_device(cmd);
    gboolean can = FALSE;

    free_async_command(cmd);

    if (dev == NULL) {
        search_devices_record_result(search, NULL, FALSE);
        return;
    }

    mainloop_set_trigger(dev->work);

    if (result->execution_status != PCMK_EXEC_DONE) {
        const char *reason = result->exit_reason;

        pcmk__warn("Assuming %s cannot fence %s because status could not be "
                   "executed: %s%s%s%s",
                   dev->id, search->host,
                   pcmk_exec_status_str(result->execution_status),
                   ((reason != NULL)? " (" : ""), pcmk__s(reason, ""),
                   ((reason != NULL)? ")" : ""));
        search_devices_record_result(search, dev->id, FALSE);
        return;
    }

    switch (result->exit_status) {
        case fence_status_unknown:
            pcmk__trace("%s reported it cannot fence %s", dev->id,
                        search->host);
            break;

        case fence_status_active:
        case fence_status_inactive:
            pcmk__trace("%s reported it can fence %s", dev->id, search->host);
            can = TRUE;
            break;

        default:
            pcmk__warn("Assuming %s cannot fence %s (status returned unknown "
                       "code %d)",
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
    fenced_device_t *dev = cmd_device(cmd);
    gboolean can_fence = FALSE;

    free_async_command(cmd);

    /* Host/alias must be in the list output to be eligible to be fenced
     *
     * Will cause problems if down'd nodes aren't listed or (for virtual nodes)
     *  if the guest is still listed despite being moved to another machine
     */
    if (dev == NULL) {
        search_devices_record_result(search, NULL, FALSE);
        return;
    }

    mainloop_set_trigger(dev->work);

    if (pcmk__result_ok(result)) {
        pcmk__info("Refreshing target list for %s", dev->id);
        g_list_free_full(dev->targets, free);
        dev->targets = stonith__parse_targets(result->action_stdout);
        dev->targets_age = time(NULL);

    } else if (dev->targets != NULL) {
        if (result->execution_status == PCMK_EXEC_DONE) {
            pcmk__info("Reusing most recent target list for %s because list "
                       "returned error code %d",
                       dev->id, result->exit_status);
        } else {
            const char *reason = result->exit_reason;

            pcmk__info("Reusing most recent target list for %s because list "
                       "could not be executed: %s%s%s%s",
                       dev->id, pcmk_exec_status_str(result->execution_status),
                       ((reason != NULL)? " (" : ""), pcmk__s(reason, ""),
                       ((reason != NULL)? ")" : ""));
        }

    } else { // We have never successfully executed list
        if (result->execution_status == PCMK_EXEC_DONE) {
            pcmk__warn("Assuming %s cannot fence %s because list returned "
                       "error code %d",
                       dev->id, search->host, result->exit_status);
        } else {
            const char *reason = result->exit_reason;

            pcmk__warn("Assuming %s cannot fence %s because list could not be "
                       "executed: %s%s%s%s",
                       dev->id, search->host,
                       pcmk_exec_status_str(result->execution_status),
                       ((reason != NULL)? " (" : ""), pcmk__s(reason, ""),
                       ((reason != NULL)? ")" : ""));
        }

        /* Fall back to pcmk_host_check=PCMK_VALUE_STATUS if the user didn't
         * explicitly specify PCMK_VALUE_DYNAMIC_LIST
         */
        if (g_hash_table_lookup(dev->params, PCMK_FENCING_HOST_CHECK) == NULL) {
            pcmk__notice("Switching to pcmk_host_check='status' for %s",
                         dev->id);
            pcmk__insert_dup(dev->params, PCMK_FENCING_HOST_CHECK,
                             PCMK_VALUE_STATUS);
        }
    }

    if (dev->targets != NULL) {
        const char *alias = g_hash_table_lookup(dev->aliases, search->host);

        if (alias == NULL) {
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
static bool
device_params_diff(GHashTable *first, GHashTable *second) {
    char *key = NULL;
    char *value = NULL;
    GHashTableIter gIter;

    g_hash_table_iter_init(&gIter, first);
    while (g_hash_table_iter_next(&gIter, (void **)&key, (void **)&value)) {
        const char *other_value = NULL;

        if (g_str_has_prefix(key, CRM_META "_")
            || pcmk__str_eq(key, PCMK_XA_CRM_FEATURE_SET, pcmk__str_none)) {
            continue;
        }

        other_value = g_hash_table_lookup(second, key);

        if ((other_value == NULL)
            || !pcmk__str_eq(other_value, value, pcmk__str_casei)) {
            pcmk__trace("Different value for %s: %s != %s", key,
                        pcmk__s(other_value, "<null>"), value);
            return true;
        }
    }

    return false;
}

/*!
 * \internal
 * \brief Checks to see if an identical device already exists in the table
 */
static fenced_device_t *
device_has_duplicate(const fenced_device_t *device)
{
    fenced_device_t *dup = g_hash_table_lookup(device_table, device->id);

    if (dup == NULL) {
        pcmk__trace("No match for %s", device->id);
        return NULL;

    } else if (!pcmk__str_eq(dup->agent, device->agent, pcmk__str_casei)) {
        pcmk__trace("Different agent: %s != %s", dup->agent, device->agent);
        return NULL;
    }

    // Find a way to share logic with pcmk__digest_op_params() here?
    if (device_params_diff(device->params, dup->params) ||
        device_params_diff(dup->params, device->params)) {
        return NULL;
    }

    pcmk__trace("Match");
    return dup;
}

int
fenced_device_register(const xmlNode *dev, bool from_cib)
{
    const char *local_node_name = fenced_get_local_node();
    fenced_device_t *dup = NULL;
    fenced_device_t *device = build_device_from_xml(dev);
    int rc = pcmk_rc_ok;

    CRM_CHECK(device != NULL, return ENOMEM);

    /* do we have a watchdog-device? */
    if (pcmk__str_eq(device->id, STONITH_WATCHDOG_ID, pcmk__str_none)
        || pcmk__str_any_of(device->agent, STONITH_WATCHDOG_AGENT,
                            STONITH_WATCHDOG_AGENT_INTERNAL, NULL)) {

        if (fencing_watchdog_timeout_ms <= 0) {
            pcmk__err("Ignoring watchdog fence device without "
                      PCMK_OPT_FENCING_WATCHDOG_TIMEOUT " set");
            rc = ENODEV;
            goto done;
        }
        if (!pcmk__str_any_of(device->agent, STONITH_WATCHDOG_AGENT,
                              STONITH_WATCHDOG_AGENT_INTERNAL, NULL)) {
            pcmk__err("Ignoring watchdog fence device with unknown agent '%s' "
                      "rather than '" STONITH_WATCHDOG_AGENT "'",
                      pcmk__s(device->agent, ""));
            rc = ENODEV;
            goto done;
        }
        if (!pcmk__str_eq(device->id, STONITH_WATCHDOG_ID, pcmk__str_none)) {
            pcmk__err("Ignoring watchdog fence device named '%s' rather than "
                      "'" STONITH_WATCHDOG_ID "'",
                      pcmk__s(device->id, ""));
            rc = ENODEV;
            goto done;
        }

        if (pcmk__str_eq(device->agent, STONITH_WATCHDOG_AGENT,
                         pcmk__str_none)) {
            /* This has either an empty list or the targets configured for
             * watchdog fencing
             */
            g_list_free_full(stonith_watchdog_targets, free);
            stonith_watchdog_targets = device->targets;
            device->targets = NULL;
        }

        if (!node_does_watchdog_fencing(local_node_name)) {
            pcmk__debug("Skip registration of watchdog fence device on node "
                        "not in host list");
            device->targets = NULL;
            stonith_device_remove(device->id, from_cib);
            goto done;
        }

        // Proceed as with any other fencing device
        g_list_free_full(device->targets, free);
        device->targets = stonith__parse_targets(local_node_name);
        pcmk__insert_dup(device->params, PCMK_FENCING_HOST_LIST,
                         local_node_name);
    }

    dup = device_has_duplicate(device);
    if (dup != NULL) {
        guint ndevices = g_hash_table_size(device_table);

        pcmk__debug("Device '%s' already in device list (%d active device%s)",
                    device->id, ndevices, pcmk__plural_s(ndevices));
        free_device(device);
        device = dup;
        fenced_device_clear_flags(device, fenced_df_dirty);

    } else {
        guint ndevices = 0;
        fenced_device_t *old = g_hash_table_lookup(device_table, device->id);

        if (from_cib && (old != NULL)
            && pcmk__is_set(old->flags, fenced_df_api_registered)) {
            /* If the CIB is writing over an entry that is shared with a stonith
             * client, copy any pending ops that currently exist on the old
             * entry to the new one. Otherwise the pending ops will be reported
             * as failures.
             */
            pcmk__info("Overwriting existing entry for %s from CIB",
                       device->id);
            device->pending_ops = old->pending_ops;
            fenced_device_set_flags(device, fenced_df_api_registered);
            old->pending_ops = NULL;
            if (device->pending_ops != NULL) {
                mainloop_set_trigger(device->work);
            }
        }
        g_hash_table_replace(device_table, device->id, device);

        ndevices = g_hash_table_size(device_table);
        pcmk__notice("Added '%s' to device list (%d active device%s)",
                     device->id, ndevices, pcmk__plural_s(ndevices));
    }

    if (from_cib) {
        fenced_device_set_flags(device, fenced_df_cib_registered);
    } else {
        fenced_device_set_flags(device, fenced_df_api_registered);
    }

done:
    if (rc != pcmk_rc_ok) {
        free_device(device);
    }
    return rc;
}

void
stonith_device_remove(const char *id, bool from_cib)
{
    fenced_device_t *device = g_hash_table_lookup(device_table, id);
    guint ndevices = 0;

    if (device == NULL) {
        ndevices = g_hash_table_size(device_table);
        pcmk__info("Device '%s' not found (%u active device%s)", id, ndevices,
                   pcmk__plural_s(ndevices));
        return;
    }

    if (from_cib) {
        fenced_device_clear_flags(device, fenced_df_cib_registered);
    } else {
        fenced_device_clear_flags(device,
                                  fenced_df_api_registered|fenced_df_verified);
    }

    if (!pcmk__any_flags_set(device->flags,
                             fenced_df_api_registered
                             |fenced_df_cib_registered)) {

        g_hash_table_remove(device_table, id);
        ndevices = g_hash_table_size(device_table);
        pcmk__info("Removed '%s' from device list (%u active device%s)", id,
                   ndevices, pcmk__plural_s(ndevices));

    } else {
        // Exactly one is true at this point
        const bool cib_registered = pcmk__is_set(device->flags,
                                                 fenced_df_cib_registered);

        pcmk__trace("Not removing '%s' from device list (%u active) because "
                    "still registered via %s",
                    id, g_hash_table_size(device_table),
                    (cib_registered? "CIB" : "API"));
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
    int count = 0;

    for (int i = 0; i < ST__LEVEL_COUNT; i++) {
        if (tp->levels[i] != NULL) {
            count++;
        }
    }

    return count;
}

static void
free_topology_entry(gpointer data)
{
    stonith_topology_t *tp = data;

    for (int i = 0; i < ST__LEVEL_COUNT; i++) {
        if (tp->levels[i] != NULL) {
            g_list_free_full(tp->levels[i], free);
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
    if (topology == NULL) {
        return;
    }

    g_hash_table_destroy(topology);
    topology = NULL;
}

void
init_topology_list(void)
{
    if (topology != NULL) {
        return;
    }

    topology = pcmk__strkey_table(NULL, free_topology_entry);
}

char *
stonith_level_key(const xmlNode *level, enum fenced_target_by mode)
{
    if (mode == fenced_target_by_unknown) {
        mode = unpack_level_kind(level);
    }
    switch (mode) {
        case fenced_target_by_name:
            return pcmk__xe_get_copy(level, PCMK_XA_TARGET);

        case fenced_target_by_pattern:
            return pcmk__xe_get_copy(level, PCMK_XA_TARGET_PATTERN);

        case fenced_target_by_attribute:
            return pcmk__assert_asprintf("%s=%s",
                                         pcmk__xe_get(level,
                                                      PCMK_XA_TARGET_ATTRIBUTE),
                                         pcmk__xe_get(level,
                                                      PCMK_XA_TARGET_VALUE));

        default:
            return pcmk__assert_asprintf("unknown-%s", pcmk__xe_id(level));
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
static enum fenced_target_by
unpack_level_kind(const xmlNode *level)
{
    if (pcmk__xe_get(level, PCMK_XA_TARGET) != NULL) {
        return fenced_target_by_name;
    }
    if (pcmk__xe_get(level, PCMK_XA_TARGET_PATTERN) != NULL) {
        return fenced_target_by_pattern;
    }
    if ((pcmk__xe_get(level, PCMK_XA_TARGET_ATTRIBUTE) != NULL)
        && (pcmk__xe_get(level, PCMK_XA_TARGET_VALUE) != NULL)) {
        return fenced_target_by_attribute;
    }
    return fenced_target_by_unknown;
}

/*!
 * \internal
 * \brief Unpack essential information from topology request XML
 *
 * \param[in]  xml     Request XML to search
 * \param[out] mode    If not NULL, where to store level kind
 * \param[out] target  If not NULL, where to store representation of target
 * \param[out] id      If not NULL, where to store level number
 *
 * \return Topology level XML from within \p xml, or NULL if not found
 * \note The caller is responsible for freeing \p *target if set.
 */
static xmlNode *
unpack_level_request(xmlNode *xml, enum fenced_target_by *mode, char **target,
                     int *id)
{
    enum fenced_target_by local_mode = fenced_target_by_unknown;
    char *local_target = NULL;
    int local_id = 0;

    /* The level element can be the top element or lower. If top level, don't
     * search by xpath, because it might give multiple hits if the XML is the
     * CIB.
     */
    if ((xml != NULL) && !pcmk__xe_is(xml, PCMK_XE_FENCING_LEVEL)) {
        xml = pcmk__xpath_find_one(xml->doc, "//" PCMK_XE_FENCING_LEVEL,
                                   LOG_WARNING);
    }

    if (xml != NULL) {
        local_mode = unpack_level_kind(xml);
        local_target = stonith_level_key(xml, local_mode);
        pcmk__xe_get_int(xml, PCMK_XA_INDEX, &local_id);
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
 * \param[out] result  Where to set result of registration (can be \c NULL)
 */
void
fenced_register_level(xmlNode *msg, pcmk__action_result_t *result)
{
    int nlevels = 0;
    int id = 0;
    xmlNode *level;
    enum fenced_target_by mode;
    char *target;

    stonith_topology_t *tp;
    const char *value = NULL;

    CRM_CHECK(msg != NULL, return);

    level = unpack_level_request(msg, &mode, &target, &id);
    if (level == NULL) {
        set_bad_request_result(result);
        return;
    }

    // Ensure an ID was given (even the client API adds an ID)
    if (pcmk__str_empty(pcmk__xe_id(level))) {
        pcmk__warn("Ignoring registration for topology level without ID");
        free(target);
        pcmk__log_xml_trace(level, "Bad level");
        pcmk__format_result(result, CRM_EX_INVALID_PARAM, PCMK_EXEC_INVALID,
                            "Topology level is invalid without ID");
        return;
    }

    // Ensure a valid target was specified
    if (mode == fenced_target_by_unknown) {
        pcmk__warn("Ignoring registration for topology level '%s' without "
                   "valid target",
                   pcmk__xe_id(level));
        free(target);
        pcmk__log_xml_trace(level, "Bad level");
        pcmk__format_result(result, CRM_EX_INVALID_PARAM, PCMK_EXEC_INVALID,
                            "Invalid target for topology level '%s'",
                            pcmk__xe_id(level));
        return;
    }

    // Ensure level ID is in allowed range
    if ((id < ST__LEVEL_MIN) || (id > ST__LEVEL_MAX)) {
        pcmk__warn("Ignoring topology registration for %s with invalid level "
                   "%d",
                   target, id);
        free(target);
        pcmk__log_xml_trace(level, "Bad level");
        pcmk__format_result(result, CRM_EX_INVALID_PARAM, PCMK_EXEC_INVALID,
                            "Invalid level number '%s' for topology level '%s'",
                            pcmk__s(pcmk__xe_get(level, PCMK_XA_INDEX), ""),
                            pcmk__xe_id(level));
        return;
    }

    /* Find or create topology table entry */
    tp = g_hash_table_lookup(topology, target);
    if (tp == NULL) {
        tp = pcmk__assert_alloc(1, sizeof(stonith_topology_t));

        tp->kind = mode;
        tp->target = target;
        tp->target_value = pcmk__xe_get_copy(level, PCMK_XA_TARGET_VALUE);
        tp->target_pattern = pcmk__xe_get_copy(level, PCMK_XA_TARGET_PATTERN);
        tp->target_attribute = pcmk__xe_get_copy(level, PCMK_XA_TARGET_ATTRIBUTE);

        g_hash_table_replace(topology, tp->target, tp);
        pcmk__trace("Added %s (%d) to the topology (%u active entries)", target,
                    (int) mode, g_hash_table_size(topology));
    } else {
        free(target);
    }

    if (tp->levels[id] != NULL) {
        pcmk__info("Adding to the existing %s[%d] topology entry", tp->target,
                   id);
    }

    value = pcmk__xe_get(level, PCMK_XA_DEVICES);
    if (value != NULL) {
        /* Empty string and whitespace are not possible with schema validation
         * enabled. Don't bother handling them specially here.
         */
        gchar **devices = g_strsplit(value, ",", 0);

        for (char **dev = devices; (dev != NULL) && (*dev != NULL); dev++) {
            pcmk__trace("Adding device '%s' for %s[%d]", *dev, tp->target, id);
            tp->levels[id] = g_list_append(tp->levels[id],
                                           pcmk__str_copy(*dev));
        }
        g_strfreev(devices);
    }

    nlevels = count_active_levels(tp);

    pcmk__info("Target %s has %d active fencing level%s", tp->target, nlevels,
               pcmk__plural_s(nlevels));

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
 * \param[out] result  Where to set result of unregistration (can be \c NULL)
 */
void
fenced_unregister_level(xmlNode *msg, pcmk__action_result_t *result)
{
    int id = -1;
    stonith_topology_t *tp;
    char *target;
    xmlNode *level = NULL;

    level = unpack_level_request(msg, NULL, &target, &id);
    if (level == NULL) {
        set_bad_request_result(result);
        return;
    }

    // Ensure level ID is in allowed range
    if ((id < 0) || (id >= ST__LEVEL_COUNT)) {
        pcmk__warn("Ignoring topology unregistration for %s with invalid level "
                   "%d",
                   target, id);
        free(target);
        pcmk__log_xml_trace(level, "Bad level");
        pcmk__format_result(result, CRM_EX_INVALID_PARAM, PCMK_EXEC_INVALID,
                            "Invalid level number '%s' for topology level %s",
                            pcmk__s(pcmk__xe_get(level, PCMK_XA_INDEX),
                                    "<null>"),

                            // Client API doesn't add ID to unregistration XML
                            pcmk__s(pcmk__xe_id(level), ""));
        return;
    }

    tp = g_hash_table_lookup(topology, target);
    if (tp == NULL) {
        guint nentries = g_hash_table_size(topology);

        pcmk__info("No fencing topology found for %s (%d active %s)", target,
                   nentries, pcmk__plural_alt(nentries, "entry", "entries"));

    } else if (id == 0 && g_hash_table_remove(topology, target)) {
        guint nentries = g_hash_table_size(topology);

        pcmk__info("Removed all fencing topology entries related to %s (%d "
                   "active %s remaining)",
                   target, nentries,
                   pcmk__plural_alt(nentries, "entry", "entries"));

    } else if (tp->levels[id] != NULL) {
        guint nlevels;

        g_list_free_full(tp->levels[id], free);
        tp->levels[id] = NULL;

        nlevels = count_active_levels(tp);
        pcmk__info("Removed level %d from fencing topology for %s (%d "
                   "active level%s remaining)",
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

    char *pos = NULL;
    const char *lead_delim = "";

    for (const GList *iter = list; iter != NULL; iter = iter->next) {
        const char *value = (const char *) iter->data;

        alloc_size += strlen(value);
    }

    rv = pcmk__assert_alloc(alloc_size, sizeof(char));
    pos = rv;

    for (const GList *iter = list; iter != NULL; iter = iter->next) {
        const char *value = (const char *) iter->data;

        pos = &pos[sprintf(pos, "%s%s", lead_delim, value)];
        lead_delim = delim;
    }

    if ((max != 0) && terminate_with_delim) {
        sprintf(pos, "%s", delim);
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
    xmlNode *dev = pcmk__xpath_find_one(msg->doc, "//" PCMK__XE_ST_DEVICE_ID,
                                        LOG_ERR);
    xmlNode *op = pcmk__xpath_find_one(msg->doc,
                                       "//*[@" PCMK__XA_ST_DEVICE_ACTION "]",
                                       LOG_ERR);
    const char *id = pcmk__xe_get(dev, PCMK__XA_ST_DEVICE_ID);
    const char *action = pcmk__xe_get(op, PCMK__XA_ST_DEVICE_ACTION);
    async_command_t *cmd = NULL;
    fenced_device_t *device = NULL;

    if ((id == NULL) || (action == NULL)) {
        pcmk__info("Malformed API action request: device %s, action %s",
                   pcmk__s(id, "not specified"),
                   pcmk__s(action, "not specified"));
        set_bad_request_result(result);
        return;
    }

    if (pcmk__str_eq(id, STONITH_WATCHDOG_ID, pcmk__str_none)) {
        // Watchdog agent actions are implemented internally
        if (fencing_watchdog_timeout_ms <= 0) {
            pcmk__set_result(result, CRM_EX_ERROR, PCMK_EXEC_NO_FENCE_DEVICE,
                             "Watchdog fence device not configured");
            return;

        } else if (pcmk__str_eq(action, PCMK_ACTION_LIST, pcmk__str_none)) {
            pcmk__set_result(result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);
            pcmk__set_result_output(result,
                                    list_to_string(stonith_watchdog_targets,
                                                   "\n", TRUE),
                                    NULL);
            return;

        } else if (pcmk__str_eq(action, PCMK_ACTION_MONITOR, pcmk__str_none)) {
            pcmk__set_result(result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);
            return;
        }
    }

    device = g_hash_table_lookup(device_table, id);
    if (device == NULL) {
        pcmk__info("Ignoring API '%s' action request because device %s not "
                   "found",
                   action, id);
        pcmk__format_result(result, CRM_EX_ERROR, PCMK_EXEC_NO_FENCE_DEVICE,
                            "'%s' not found", id);
        return;

    } else if (!pcmk__is_set(device->flags, fenced_df_api_registered)
               && (strcmp(action, PCMK_ACTION_MONITOR) == 0)) {
        // Monitors may run only on "started" (API-registered) devices
        pcmk__info("Ignoring API '%s' action request because device %s not "
                   "active",
                   action, id);
        pcmk__format_result(result, CRM_EX_ERROR, PCMK_EXEC_NO_FENCE_DEVICE,
                            "'%s' not active", id);
        return;
    }

    cmd = create_async_command(msg);
    if (cmd == NULL) {
        pcmk__log_xml_warn(msg, "invalid");
        set_bad_request_result(result);
        return;
    }

    schedule_stonith_command(cmd, device);
    pcmk__set_result(result, CRM_EX_OK, PCMK_EXEC_PENDING, NULL);
}

static void
search_devices_record_result(struct device_search_s *search, const char *device, gboolean can_fence)
{
    search->replies_received++;
    if (can_fence && (device != NULL)) {
        if (search->support_action_only != fenced_df_none) {
            fenced_device_t *dev = g_hash_table_lookup(device_table, device);

            if ((dev != NULL) && !pcmk__is_set(dev->flags, search->support_action_only)) {
                return;
            }
        }
        search->capable = g_list_append(search->capable,
                                        pcmk__str_copy(device));
    }

    if (search->replies_needed == search->replies_received) {

        guint ndevices = g_list_length(search->capable);

        pcmk__debug("Search found %d device%s that can perform '%s' targeting "
                    "%s",
                    ndevices, pcmk__plural_s(ndevices),
                    pcmk__s(search->action, "unknown action"),
                    pcmk__s(search->host, "any node"));

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
 * \param[in] device      Fence device to check
 * \param[in] action      Fence action to check
 * \param[in] target      Hostname of fence target
 * \param[in] allow_self  Whether self-fencing is allowed for this operation
 *
 * \return \c true if local host is allowed to execute action, or \c false
 *         otherwise
 */
static bool
localhost_is_eligible(const fenced_device_t *device, const char *action,
                      const char *target, bool allow_self)
{
    bool localhost_is_target = pcmk__str_eq(target, fenced_get_local_node(),
                                            pcmk__str_casei);
    const gchar *const *on_target_actions = NULL;

    CRM_CHECK((device != NULL) && (action != NULL), return true);

    on_target_actions = (const gchar *const *) device->on_target_actions;

    if ((on_target_actions != NULL)
        && pcmk__g_strv_contains(on_target_actions, action)) {

        if (!localhost_is_target) {
            pcmk__trace("Operation '%s' using %s can only be executed for "
                        "local host, not %s", action, device->id, target);
            return false;
        }

    } else if (localhost_is_target && !allow_self) {
        pcmk__trace("'%s' operation does not support self-fencing", action);
        return false;
    }
    return true;
}

/*!
 * \internal
 * \brief Check if local node is allowed to execute (possibly remapped) action
 *
 * \param[in] device      Fence device to check
 * \param[in] action      Fence action to check
 * \param[in] target      Node name of fence target
 * \param[in] allow_self  Whether self-fencing is allowed for this operation
 *
 * \return true if local node is allowed to execute \p action or any actions it
 *         might be remapped to, otherwise false
 */
static bool
localhost_is_eligible_with_remap(const fenced_device_t *device,
                                 const char *action, const char *target,
                                 bool allow_self)
{
    // Check exact action
    if (localhost_is_eligible(device, action, target, allow_self)) {
        return true;
    }

    // Check potential remaps

    if (!pcmk__str_eq(action, PCMK_ACTION_REBOOT, pcmk__str_none)) {
        return false;
    }

    /* "reboot" might get remapped to "off" then "on", so even if reboot is
     * disallowed, return true if either of those is allowed. We'll report
     * the disallowed actions with the results. We never allow self-fencing
     * for remapped "on" actions because the target is off at that point.
     */
    if (localhost_is_eligible(device, PCMK_ACTION_OFF, target, allow_self)
        || localhost_is_eligible(device, PCMK_ACTION_ON, target, FALSE)) {
        return true;
    }

    return false;
}

/*!
 * \internal
 * \brief Check whether we can use a device's cached target list
 *
 * \param[in] dev  Fencing device to check
 *
 * \return \c true if \p dev cached its targets less than a minute ago,
 *         otherwise \c false
 */
static inline bool
can_use_target_cache(const fenced_device_t *dev)
{
    return (dev->targets != NULL) && (time(NULL) < (dev->targets_age + 60));
}

static void
can_fence_host_with_device(fenced_device_t *dev,
                           struct device_search_s *search)
{
    gboolean can = FALSE;
    const char *dev_id = "Unspecified device";
    const char *action = NULL;
    const char *target = NULL;
    const char *check_type = "Internal bug";
    const char *alias = NULL;

    CRM_CHECK((dev != NULL) && (search != NULL) && (search->action != NULL),
              goto search_report_results);

    if (dev->id != NULL) {
        dev_id = dev->id;
    }

    action = search->action;

    target = search->host;
    if (target == NULL) {
        can = TRUE;
        check_type = "No target";
        goto search_report_results;
    }

    /* Answer immediately if the device does not support the action
     * or the local node is not allowed to perform it
     */
    if (pcmk__str_eq(action, PCMK_ACTION_ON, pcmk__str_none)
        && !pcmk__is_set(dev->flags, fenced_df_supports_on)) {
        check_type = "Agent does not support 'on'";
        goto search_report_results;

    } else if (!localhost_is_eligible_with_remap(dev, action, target,
                                                 search->allow_self)) {
        check_type = "This node is not allowed to execute action";
        goto search_report_results;
    }

    // Check eligibility as specified by pcmk_host_check
    check_type = target_list_type(dev);
    alias = g_hash_table_lookup(dev->aliases, target);
    if (pcmk__str_eq(check_type, PCMK_VALUE_NONE, pcmk__str_casei)) {
        can = TRUE;

    } else if (pcmk__str_eq(check_type, PCMK_VALUE_STATIC_LIST,
                            pcmk__str_casei)) {

        if (pcmk__str_in_list(target, dev->targets, pcmk__str_casei)) {
            can = TRUE;
        } else if (g_hash_table_lookup(dev->params, PCMK_FENCING_HOST_MAP)
                   && g_hash_table_lookup(dev->aliases, target)) {
            can = TRUE;
        }

    } else if (pcmk__str_eq(check_type, PCMK_VALUE_DYNAMIC_LIST,
                            pcmk__str_casei)) {
        if (!can_use_target_cache(dev)) {
            int device_timeout = get_action_timeout(dev, PCMK_ACTION_LIST,
                                                    search->per_device_timeout);

            if (device_timeout > search->per_device_timeout) {
                pcmk__notice("Since the pcmk_list_timeout (%ds) parameter of "
                             "%s is larger than " PCMK_OPT_FENCING_TIMEOUT " "
                             "(%ds), timeout may occur",
                             device_timeout, dev_id,
                             search->per_device_timeout);
            }

            pcmk__trace("Running '%s' to check whether %s is eligible to fence "
                        "%s (%s)",
                        check_type, dev_id, target, action);

            schedule_internal_command(__func__, dev, PCMK_ACTION_LIST, NULL,
                                      search->per_device_timeout, search, dynamic_list_search_cb);

            /* we'll respond to this search request async in the cb */
            return;
        }

        if (pcmk__str_in_list(((alias == NULL)? target : alias), dev->targets,
                              pcmk__str_casei)) {
            can = TRUE;
        }

    } else if (pcmk__str_eq(check_type, PCMK_VALUE_STATUS, pcmk__str_casei)) {
        int device_timeout = get_action_timeout(dev, check_type, search->per_device_timeout);

        if (device_timeout > search->per_device_timeout) {
            pcmk__notice("Since the pcmk_status_timeout (%ds) parameter of %s "
                         "is larger than " PCMK_OPT_FENCING_TIMEOUT " (%ds), "
                         "timeout may occur",
                         device_timeout, dev_id, search->per_device_timeout);
        }

        pcmk__trace("Running '%s' to check whether %s is eligible to fence %s "
                    "(%s)",
                    check_type, dev_id, target, action);
        schedule_internal_command(__func__, dev, PCMK_ACTION_STATUS, target,
                                  search->per_device_timeout, search, status_search_cb);
        /* we'll respond to this search request async in the cb */
        return;
    } else {
        pcmk__err("Invalid value for " PCMK_FENCING_HOST_CHECK ": %s",
                  check_type);
        check_type = "Invalid " PCMK_FENCING_HOST_CHECK;
    }

  search_report_results:
    pcmk__info("%s is%s eligible to fence (%s) %s%s%s%s: %s",
               dev_id, (can? "" : " not"),
               pcmk__s(action, "unspecified action"),
               pcmk__s(target, "unspecified target"),
               ((alias != NULL)? " (as '" : ""), pcmk__s(alias, ""),
               ((alias != NULL)? "')" : ""), check_type);
    search_devices_record_result(search, ((dev == NULL)? NULL : dev_id), can);
}

static void
search_devices(gpointer key, gpointer value, gpointer user_data)
{
    fenced_device_t *dev = value;
    struct device_search_s *search = user_data;

    can_fence_host_with_device(dev, search);
}

#define DEFAULT_QUERY_TIMEOUT 20
static void
get_capable_devices(const char *host, const char *action, int timeout,
                    bool allow_self, void *user_data,
                    void (*callback) (GList * devices, void *user_data),
                    uint32_t support_action_only)
{
    struct device_search_s *search;
    guint ndevices = g_hash_table_size(device_table);

    if (ndevices == 0) {
        callback(NULL, user_data);
        return;
    }

    search = pcmk__assert_alloc(1, sizeof(struct device_search_s));

    search->host = pcmk__str_copy(host);
    search->action = pcmk__str_copy(action);
    search->per_device_timeout = timeout;
    search->allow_self = allow_self;
    search->callback = callback;
    search->user_data = user_data;
    search->support_action_only = support_action_only;

    /* We are guaranteed this many replies, even if a device is
     * unregistered while the search is in progress.
     */
    search->replies_needed = ndevices;

    pcmk__debug("Searching %d device%s to see which can execute '%s' "
                "targeting %s", ndevices, pcmk__plural_s(ndevices),
                pcmk__s(search->action, "unknown action"),
                pcmk__s(search->host, "any node"));
    fenced_foreach_device(search_devices, search);
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
                               const fenced_device_t *device,
                               const char *target)
{
    int action_specific_timeout;
    int delay_max;
    int delay_base;

    CRM_CHECK(xml && action && device, return);

    // PCMK__XA_ST_REQUIRED is currently used only for unfencing
    if (is_action_required(action, device)) {
        pcmk__trace("Action '%s' is required using %s", action, device->id);
        pcmk__xe_set_int(xml, PCMK__XA_ST_REQUIRED, 1);
    }

    // pcmk_<action>_timeout if configured
    action_specific_timeout = get_action_timeout(device, action, 0);
    if (action_specific_timeout != 0) {
        pcmk__trace("Action '%s' has timeout %ds using %s",
                    action, action_specific_timeout, device->id);
        pcmk__xe_set_int(xml, PCMK__XA_ST_ACTION_TIMEOUT,
                         action_specific_timeout);
    }

    delay_max = get_action_delay_max(device, action);
    if (delay_max > 0) {
        pcmk__trace("Action '%s' has maximum random delay %ds using %s", action,
                    delay_max, device->id);
        pcmk__xe_set_int(xml, PCMK__XA_ST_DELAY_MAX, delay_max);
    }

    delay_base = get_action_delay_base(device, action, target);
    if (delay_base > 0) {
        pcmk__xe_set_int(xml, PCMK__XA_ST_DELAY_BASE, delay_base);
    }

    if ((delay_max > 0) && (delay_base == 0)) {
        pcmk__trace("Action '%s' has maximum random delay %ds using %s", action,
                    delay_max, device->id);
    } else if ((delay_max == 0) && (delay_base > 0)) {
        pcmk__trace("Action '%s' has a static delay of %ds using %s", action,
                    delay_base, device->id);
    } else if ((delay_max > 0) && (delay_base > 0)) {
        pcmk__trace("Action '%s' has a minimum delay of %ds and a randomly "
                    "chosen maximum delay of %ds using %s",
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
 * \param[in]     allow_self     Whether self-fencing is allowed
 */
static void
add_disallowed(xmlNode *xml, const char *action, const fenced_device_t *device,
               const char *target, bool allow_self)
{
    if (localhost_is_eligible(device, action, target, allow_self)) {
        return;
    }

    pcmk__trace("Action '%s' using %s is disallowed for local host", action,
                device->id);
    pcmk__xe_set_bool(xml, PCMK__XA_ST_ACTION_DISALLOWED, true);
}

/*!
 * \internal
 * \brief Add child element with action-specific values to query reply XML
 *
 * \param[in,out] xml            XML to add attribute to
 * \param[in]     action         Fence action
 * \param[in]     device         Fence device
 * \param[in]     target         Fence target
 * \param[in]     allow_self     Whether self-fencing is allowed
 */
static void
add_action_reply(xmlNode *xml, const char *action,
                 const fenced_device_t *device, const char *target,
                 bool allow_self)
{
    xmlNode *child = pcmk__xe_create(xml, PCMK__XE_ST_DEVICE_ACTION);

    pcmk__xe_set(child, PCMK_XA_ID, action);
    add_action_specific_attributes(child, action, device, target);
    add_disallowed(child, action, device, target, allow_self);
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
stonith_send_reply(const xmlNode *reply, int call_options,
                   const char *remote_peer, pcmk__client_t *client)
{
    const pcmk__node_status_t *node = NULL;

    CRM_CHECK((reply != NULL) && ((remote_peer != NULL) || (client != NULL)),
              return);

    if (remote_peer == NULL) {
        do_local_reply(reply, client, call_options);
        return;
    }

    node = pcmk__get_node(0, remote_peer, NULL, pcmk__node_search_cluster_member);
    pcmk__cluster_send_message(node, pcmk_ipc_fenced, reply);
}

static void
stonith_query_capable_device_cb(GList * devices, void *user_data)
{
    struct st_query_data *query = user_data;
    int available_devices = 0;
    xmlNode *wrapper = NULL;
    xmlNode *list = NULL;
    pcmk__client_t *client = NULL;

    if (query->client_id != NULL) {
        client = pcmk__find_client_by_id(query->client_id);
        if ((client == NULL) && (query->remote_peer == NULL)) {
            pcmk__trace("Skipping reply to %s: no longer a client",
                        query->client_id);
            goto done;
        }
    }

    // Pack the results into XML
    wrapper = pcmk__xe_create(query->reply, PCMK__XE_ST_CALLDATA);
    list = pcmk__xe_create(wrapper, __func__);
    pcmk__xe_set(list, PCMK__XA_ST_TARGET, query->target);

    for (const GList *iter = devices; iter != NULL; iter = iter->next) {
        fenced_device_t *device = g_hash_table_lookup(device_table, iter->data);
        const char *action = query->action;
        xmlNode *dev = NULL;

        if (device == NULL) {
            /* It is possible the device got unregistered while
             * determining who can fence the target */
            continue;
        }

        available_devices++;

        dev = pcmk__xe_create(list, PCMK__XE_ST_DEVICE_ID);
        pcmk__xe_set(dev, PCMK_XA_ID, device->id);
        pcmk__xe_set(dev, PCMK__XA_NAMESPACE, device->namespace);
        pcmk__xe_set(dev, PCMK_XA_AGENT, device->agent);

        // Has had successful monitor, list, or status on this node
        pcmk__xe_set_int(dev, PCMK__XA_ST_MONITOR_VERIFIED,
                         pcmk__is_set(device->flags, fenced_df_verified));

        pcmk__xe_set_int(dev, PCMK__XA_ST_DEVICE_SUPPORT_FLAGS, device->flags);

        /* If the originating fencer wants to reboot the node, and we have a
         * capable device that doesn't support "reboot", remap to "off" instead.
         */
        if (!pcmk__is_set(device->flags, fenced_df_supports_reboot)
            && pcmk__str_eq(query->action, PCMK_ACTION_REBOOT,
                            pcmk__str_none)) {
            pcmk__trace("%s doesn't support reboot, using values for off "
                        "instead",
                        device->id);
            action = PCMK_ACTION_OFF;
        }

        /* Add action-specific values if available */
        add_action_specific_attributes(dev, action, device, query->target);
        if (pcmk__str_eq(query->action, PCMK_ACTION_REBOOT, pcmk__str_none)) {
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
                           pcmk__is_set(query->call_options,
                                        st_opt_allow_self_fencing));
            add_action_reply(dev, PCMK_ACTION_OFF, device, query->target,
                             pcmk__is_set(query->call_options,
                                          st_opt_allow_self_fencing));
            add_action_reply(dev, PCMK_ACTION_ON, device, query->target, false);
        }

        /* A query without a target wants device parameters */
        if (query->target == NULL) {
            xmlNode *attrs = pcmk__xe_create(dev, PCMK__XE_ATTRIBUTES);

            g_hash_table_foreach(device->params, hash2field, attrs);
        }
    }

    pcmk__xe_set_int(list, PCMK__XA_ST_AVAILABLE_DEVICES, available_devices);
    if (query->target != NULL) {
        pcmk__debug("Found %d matching device%s for target '%s'",
                    available_devices, pcmk__plural_s(available_devices),
                    query->target);
    } else {
        pcmk__debug("%d device%s installed", available_devices,
                    pcmk__plural_s(available_devices));
    }

    pcmk__log_xml_trace(list, "query-result");

    stonith_send_reply(query->reply, query->call_options, query->remote_peer,
                       client);

done:
    pcmk__xml_free(query->reply);
    free(query->remote_peer);
    free(query->client_id);
    free(query->target);
    free(query->action);
    free(query);
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
    int output_log_level = PCMK__LOG_NEVER;
    guint devices_remaining = g_list_length(cmd->next_device_iter);

    GString *msg = g_string_sized_new(80); // Reasonable starting size

    // Choose log levels appropriately if we have a result
    if (pcmk__result_ok(result)) {
        log_level = (cmd->target == NULL)? LOG_DEBUG : LOG_NOTICE;
        if ((result->action_stdout != NULL)
            && !pcmk__str_eq(cmd->action, PCMK_ACTION_METADATA,
                             pcmk__str_none)) {
            output_log_level = LOG_DEBUG;
        }
        next = NULL;
    } else {
        log_level = (cmd->target == NULL)? LOG_NOTICE : LOG_ERR;
        if ((result->action_stdout != NULL)
            && !pcmk__str_eq(cmd->action, PCMK_ACTION_METADATA,
                             pcmk__str_none)) {
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
    g_string_append_printf(msg, " " QB_XS " %scall %d from %s",
                           (op_merged? "merged " : ""), cmd->id,
                           cmd->client_name);

    // Log the result
    do_crm_log(log_level, "%s", msg->str);
    g_string_free(msg, TRUE);

    // Log the output (which may have multiple lines), if appropriate
    if (output_log_level != PCMK__LOG_NEVER) {
        char *prefix = pcmk__assert_asprintf("%s[%d]", cmd->device, pid);

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
            pcmk__trace("Skipping reply to %s: no longer a client",
                        cmd->client);
            return;
        }
    }

    reply = construct_async_reply(cmd, result);
    if (merged) {
        pcmk__xe_set_bool(reply, PCMK__XA_ST_OP_MERGED, true);
    }

    if (pcmk__is_fencing_action(cmd->action)
        && pcmk__str_eq(cmd->origin, cmd->target, pcmk__str_casei)) {
        /* The target was also the originator, so broadcast the result on its
         * behalf (since it will be unable to).
         */
        pcmk__trace("Broadcast '%s' result for %s (target was also originator)",
                    cmd->action, cmd->target);
        pcmk__xe_set(reply, PCMK__XA_SUBT, PCMK__VALUE_BROADCAST);
        pcmk__xe_set(reply, PCMK__XA_ST_OP, STONITH_OP_NOTIFY);
        pcmk__cluster_send_message(NULL, pcmk_ipc_fenced, reply);
    } else {
        // Reply only to the originator
        stonith_send_reply(reply, cmd->options, cmd->origin, client);
    }

    pcmk__log_xml_trace(reply, "Reply");
    pcmk__xml_free(reply);
}

static void
cancel_stonith_command(async_command_t * cmd)
{
    fenced_device_t *device = cmd_device(cmd);

    if (device == NULL) {
        return;
    }

    pcmk__trace("Cancel scheduled '%s' action using %s", cmd->action,
                device->id);
    device->pending_ops = g_list_remove(device->pending_ops, cmd);
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
            !pcmk__str_eq(cmd->action, cmd_other->action, pcmk__str_none) ||
            !pcmk__str_eq(cmd->device, cmd_other->device, pcmk__str_casei)) {

            continue;
        }

        pcmk__notice("Merging fencing action '%s'%s%s originating from client "
                     "%s with identical fencing request from client %s",
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
static fenced_device_t *
next_required_device(async_command_t *cmd)
{
    for (const GList *iter = cmd->next_device_iter; iter != NULL;
         iter = iter->next) {
        fenced_device_t *next_device = g_hash_table_lookup(device_table,
                                                           iter->data);

        if (!is_action_required(cmd->action, next_device)) {
            continue;
        }

        /* This is only called for successful actions, so it's OK to skip
         * non-required devices.
         */
        cmd->next_device_iter = iter->next;
        return next_device;
    }

    return NULL;
}

static void
st_child_done(int pid, const pcmk__action_result_t *result, void *user_data)
{
    async_command_t *cmd = user_data;

    fenced_device_t *device = NULL;
    fenced_device_t *next_device = NULL;

    CRM_CHECK(cmd != NULL, return);

    device = cmd_device(cmd);
    cmd->active_on = NULL;

    /* The device is ready to do something else now */
    if (device != NULL) {
        if (!pcmk__is_set(device->flags, fenced_df_verified)
            && pcmk__result_ok(result)
            && pcmk__strcase_any_of(cmd->action, PCMK_ACTION_LIST,
                                    PCMK_ACTION_MONITOR, PCMK_ACTION_STATUS,
                                    NULL)) {

            fenced_device_set_flags(device, fenced_df_verified);
        }

        mainloop_set_trigger(device->work);
    }

    if (pcmk__result_ok(result)) {
        next_device = next_required_device(cmd);

    } else if ((cmd->next_device_iter != NULL)
               && !is_action_required(cmd->action, device)) {
        /* if this device didn't work out, see if there are any others we can try.
         * if the failed device was 'required', we can't pick another device. */
        next_device = g_hash_table_lookup(device_table,
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

static void
stonith_fence_get_devices_cb(GList * devices, void *user_data)
{
    async_command_t *cmd = user_data;
    fenced_device_t *device = NULL;
    guint ndevices = g_list_length(devices);

    pcmk__info("Found %d matching device%s for target '%s'", ndevices,
               pcmk__plural_s(ndevices), cmd->target);

    if (devices != NULL) {
        device = g_hash_table_lookup(device_table, devices->data);
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

    } else {
        /* Device found. Schedule a fencing command for it.
         *
         * Assign devices to device_list so that it will be freed with cmd.
         */
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
    fenced_device_t *device = NULL;
    async_command_t *cmd = NULL;
    xmlNode *dev = NULL;

    CRM_CHECK((msg != NULL) && (result != NULL), return);

    dev = pcmk__xpath_find_one(msg->doc, "//*[@" PCMK__XA_ST_TARGET "]",
                               LOG_ERR);

    cmd = create_async_command(msg);
    if (cmd == NULL) {
        pcmk__log_xml_warn(msg, "invalid");
        set_bad_request_result(result);
        return;
    }

    device_id = pcmk__xe_get(dev, PCMK__XA_ST_DEVICE_ID);
    if (device_id != NULL) {
        device = g_hash_table_lookup(device_table, device_id);
        if (device == NULL) {
            pcmk__err("Requested device '%s' is not available", device_id);
            pcmk__format_result(result, CRM_EX_ERROR, PCMK_EXEC_NO_FENCE_DEVICE,
                                "Requested device '%s' not found", device_id);
            return;
        }
        schedule_stonith_command(cmd, device);

    } else {
        const char *host = pcmk__xe_get(dev, PCMK__XA_ST_TARGET);

        if (pcmk__is_set(cmd->options, st_opt_cs_nodeid)) {
            int nodeid = 0;
            pcmk__node_status_t *node = NULL;

            pcmk__scan_min_int(host, &nodeid, 0);
            node = pcmk__search_node_caches(nodeid, NULL, NULL,
                                            pcmk__node_search_any
                                            |pcmk__node_search_cluster_cib);
            if (node != NULL) {
                host = node->name;
            }
        }

        /* If we get to here, then self-fencing is implicitly allowed */
        get_capable_devices(host, cmd->action, cmd->default_timeout,
                            TRUE, cmd, stonith_fence_get_devices_cb,
                            fenced_support_flag(cmd->action));
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

    reply = pcmk__xe_create(NULL, PCMK__XE_ST_REPLY);

    pcmk__xe_set(reply, PCMK__XA_ST_ORIGIN, __func__);
    pcmk__xe_set(reply, PCMK__XA_T, PCMK__VALUE_STONITH_NG);
    stonith__xe_set_result(reply, result);

    if (request == NULL) {
        /* Most likely, this is the result of a stonith operation that was
         * initiated before we came up. Unfortunately that means we lack enough
         * information to provide clients with a full result.
         *
         * @TODO Maybe synchronize this information at start-up?
         */
        pcmk__warn("Missing request information for client notifications for "
                   "operation with result '%s' (initiated before we came up?)",
                   pcmk_exec_status_str(result->execution_status));

    } else {
        const char *name = NULL;
        const char *value = NULL;

        // Attributes to copy from request to reply
        const char *names[] = {
            PCMK__XA_ST_OP,
            PCMK__XA_ST_CALLID,
            PCMK__XA_ST_CLIENTID,
            PCMK__XA_ST_CLIENTNAME,
            PCMK__XA_ST_REMOTE_OP,
            PCMK__XA_ST_CALLOPT,
        };

        for (int lpc = 0; lpc < PCMK__NELEM(names); lpc++) {
            name = names[lpc];
            value = pcmk__xe_get(request, name);
            pcmk__xe_set(reply, name, value);
        }
        if (data != NULL) {
            xmlNode *wrapper = pcmk__xe_create(reply, PCMK__XE_ST_CALLDATA);

            pcmk__xml_copy(wrapper, data);
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
    xmlNode *reply = pcmk__xe_create(NULL, PCMK__XE_ST_REPLY);

    pcmk__xe_set(reply, PCMK__XA_ST_ORIGIN, __func__);
    pcmk__xe_set(reply, PCMK__XA_T, PCMK__VALUE_STONITH_NG);
    pcmk__xe_set(reply, PCMK__XA_ST_OP, cmd->op);
    pcmk__xe_set(reply, PCMK__XA_ST_DEVICE_ID, cmd->device);
    pcmk__xe_set(reply, PCMK__XA_ST_REMOTE_OP, cmd->remote_op_id);
    pcmk__xe_set(reply, PCMK__XA_ST_CLIENTID, cmd->client);
    pcmk__xe_set(reply, PCMK__XA_ST_CLIENTNAME, cmd->client_name);
    pcmk__xe_set(reply, PCMK__XA_ST_TARGET, cmd->target);
    pcmk__xe_set(reply, PCMK__XA_ST_DEVICE_ACTION, cmd->op);
    pcmk__xe_set(reply, PCMK__XA_ST_ORIGIN, cmd->origin);
    pcmk__xe_set_int(reply, PCMK__XA_ST_CALLID, cmd->id);
    pcmk__xe_set_int(reply, PCMK__XA_ST_CALLOPT, cmd->options);

    stonith__xe_set_result(reply, result);
    return reply;
}

bool
fencing_peer_active(pcmk__node_status_t *peer)
{
    return (peer != NULL) && (peer->name != NULL)
           && pcmk__is_set(peer->processes, crm_get_cluster_proc());
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
    GHashTableIter gIter;
    pcmk__node_status_t *entry = NULL;

    if (!pcmk__str_eq(target, fenced_get_local_node(), pcmk__str_casei)) {
        return NULL;
    }

    g_hash_table_iter_init(&gIter, pcmk__peer_cache);
    while (g_hash_table_iter_next(&gIter, NULL, (void **)&entry)) {
        if (!fencing_peer_active(entry)
            || pcmk__str_eq(entry->name, target, pcmk__str_casei)) {
            continue;
        }

        pcmk__notice("Forwarding self-fencing request to %s", entry->name);
        return entry->name;
    }

    pcmk__warn("Will handle own fencing because no peer can");
    return NULL;
}

static void 
remove_relay_op(xmlNode * request)
{
    xmlNode *dev = pcmk__xpath_find_one(request->doc,
                                        "//*[@" PCMK__XA_ST_DEVICE_ACTION "]",
                                        LOG_TRACE);
    const char *relay_op_id = NULL; 
    const char *op_id = NULL;
    const char *client_name = NULL;
    const char *target = NULL; 
    remote_fencing_op_t *relay_op = NULL; 
    remote_fencing_op_t *list_op = NULL;
    GHashTableIter iter;

    if (dev != NULL) {
        target = pcmk__xe_get(dev, PCMK__XA_ST_TARGET);
    }

    relay_op_id = pcmk__xe_get(request, PCMK__XA_ST_REMOTE_OP_RELAY);
    op_id = pcmk__xe_get(request, PCMK__XA_ST_REMOTE_OP);
    client_name = pcmk__xe_get(request, PCMK__XA_ST_CLIENTNAME);

    if ((relay_op_id == NULL) || (target == NULL)
        || !pcmk__str_eq(target, fenced_get_local_node(), pcmk__str_casei)) {
        return;
    }

    /* Delete RELAY operation. */
    relay_op = g_hash_table_lookup(stonith_remote_op_list, relay_op_id);

    if (relay_op == NULL) {
        return;
    }

    g_hash_table_iter_init(&iter, stonith_remote_op_list);

    /* If the operation to be deleted is registered as a duplicate, delete the registration. */
    while (g_hash_table_iter_next(&iter, NULL, (void **)&list_op)) {
        if (list_op == relay_op) {
            continue;
        }

        for (GList *dup_iter = list_op->duplicates; dup_iter != NULL;
             dup_iter = dup_iter->next) {
            remote_fencing_op_t *other = dup_iter->data;

            if (other != relay_op) {
                continue;
            }

            other->duplicates = g_list_remove(other->duplicates, relay_op);
            break;
        }
    }

    pcmk__debug("Deleting relay op %s ('%s'%s%s for %s), "
                "replaced by op %s ('%s'%s%s for %s)",
                relay_op->id, relay_op->action,
                (relay_op->target == NULL)? "" : " targeting ",
                pcmk__s(relay_op->target, ""),
                relay_op->client_name, op_id, relay_op->action,
                (target == NULL)? "" : " targeting ", pcmk__s(target, ""),
                client_name);

    g_hash_table_remove(stonith_remote_op_list, relay_op_id);
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
    if ((c == NULL) || pcmk__is_set(c->flags, pcmk__client_privileged)) {
        return true;
    }

    pcmk__warn("Rejecting IPC request '%s' from unprivileged client %s",
               pcmk__s(op, ""), pcmk__client_name(c));
    return false;
}

static xmlNode *
handle_unknown_request(pcmk__request_t *request)
{
    pcmk__err("Unknown %s request %s from %s %s",
              (request->ipc_client != NULL) ? "IPC" : "CPG",
              request->op, pcmk__request_origin_type(request),
              pcmk__request_origin(request));
    pcmk__format_result(&request->result, CRM_EX_PROTOCOL, PCMK_EXEC_INVALID,
                        "Unknown request type '%s' (bug?)",
                        pcmk__s(request->op, ""));
    return fenced_construct_reply(request->xml, NULL, &request->result);
}

// CRM_OP_REGISTER
static xmlNode *
handle_register_request(pcmk__request_t *request)
{
    xmlNode *reply = pcmk__xe_create(NULL, "reply");

    if (request->peer != NULL) {
        return handle_unknown_request(request);
    }

    pcmk__xe_set(reply, PCMK__XA_ST_OP, CRM_OP_REGISTER);
    pcmk__xe_set(reply, PCMK__XA_ST_CLIENTID, request->ipc_client->id);
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
    const char *call_id = pcmk__xe_get(request->xml, PCMK__XA_ST_CALLID);
    const char *client_id = pcmk__xe_get(request->xml, PCMK__XA_ST_CLIENTID);
    int op_timeout = 0;

    pcmk__xe_get_int(request->xml, PCMK__XA_ST_TIMEOUT, &op_timeout);
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
    const char *client_id = pcmk__xe_get(request->xml, PCMK__XA_ST_CLIENTID);
    struct st_query_data *query = NULL;

    if (request->peer != NULL) {
        // Record it for the future notification
        create_remote_stonith_op(client_id, request->xml, TRUE);
    }

    /* Delete the DC node RELAY operation. */
    remove_relay_op(request->xml);

    pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);

    dev = pcmk__xpath_find_one(request->xml->doc,
                               "//*[@" PCMK__XA_ST_DEVICE_ACTION "]",
                               PCMK__LOG_NEVER);
    if (dev != NULL) {
        const char *device = pcmk__xe_get(dev, PCMK__XA_ST_DEVICE_ID);

        if (pcmk__str_eq(device, "manual_ack", pcmk__str_casei)) {
            return NULL; // No query or reply necessary
        }
        target = pcmk__xe_get(dev, PCMK__XA_ST_TARGET);
        action = pcmk__xe_get(dev, PCMK__XA_ST_DEVICE_ACTION);
    }

    pcmk__log_xml_trace(request->xml, "Query");

    query = pcmk__assert_alloc(1, sizeof(struct st_query_data));

    query->reply = fenced_construct_reply(request->xml, NULL, &request->result);
    query->remote_peer = pcmk__str_copy(request->peer);
    query->client_id = pcmk__str_copy(client_id);
    query->target = pcmk__str_copy(target);
    query->action = pcmk__str_copy(action);
    query->call_options = request->call_options;

    pcmk__xe_get_int(request->xml, PCMK__XA_ST_TIMEOUT, &timeout);
    get_capable_devices(target, action, timeout,
                        pcmk__is_set(query->call_options,
                                    st_opt_allow_self_fencing),
                        query, stonith_query_capable_device_cb, fenced_df_none);
    return NULL;
}

// STONITH_OP_NOTIFY
static xmlNode *
handle_notify_request(pcmk__request_t *request)
{
    const char *flag_name = NULL;

    if (request->peer != NULL) {
        return handle_unknown_request(request);
    }

    flag_name = pcmk__xe_get(request->xml, PCMK__XA_ST_NOTIFY_ACTIVATE);
    if (flag_name != NULL) {
        pcmk__debug("Enabling %s callbacks for client %s", flag_name,
                    pcmk__request_origin(request));
        pcmk__set_client_flags(request->ipc_client,
                               fenced_parse_notify_flag(flag_name));
    }

    flag_name = pcmk__xe_get(request->xml, PCMK__XA_ST_NOTIFY_DEACTIVATE);
    if (flag_name != NULL) {
        pcmk__debug("Disabling %s callbacks for client %s", flag_name,
                    pcmk__request_origin(request));
        pcmk__clear_client_flags(request->ipc_client,
                                 fenced_parse_notify_flag(flag_name));
    }

    pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);
    pcmk__set_request_flags(request, pcmk__request_reuse_options);

    return pcmk__ipc_create_ack(request->ipc_flags, PCMK__XE_ACK, NULL,
                                CRM_EX_OK);
}

// STONITH_OP_RELAY
static xmlNode *
handle_relay_request(pcmk__request_t *request)
{
    xmlNode *dev = pcmk__xpath_find_one(request->xml->doc,
                                        "//*[@" PCMK__XA_ST_TARGET "]",
                                        LOG_TRACE);

    pcmk__notice("Received forwarded fencing request from %s %s to fence (%s) "
                 "peer %s",
                 pcmk__request_origin_type(request),
                 pcmk__request_origin(request),
                 pcmk__xe_get(dev, PCMK__XA_ST_DEVICE_ACTION),
                 pcmk__xe_get(dev, PCMK__XA_ST_TARGET));

    if (initiate_remote_stonith_op(NULL, request->xml, FALSE) == NULL) {
        set_bad_request_result(&request->result);
        return fenced_construct_reply(request->xml, NULL, &request->result);
    }

    pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_PENDING, NULL);
    return NULL;
}

// STONITH_OP_FENCE
static xmlNode *
handle_fence_request(pcmk__request_t *request)
{
    const char *alternate_host = NULL;
    xmlNode *dev = NULL;
    const char *target = NULL;
    const char *action = NULL;
    const char *device = NULL;

    if (request->peer != NULL) {
        fence_locally(request->xml, &request->result);
        goto done;
    }

    if (pcmk__is_set(request->call_options, st_opt_manual_ack)) {
        int rc = fenced_handle_manual_confirmation(request->ipc_client,
                                                   request->xml);

        if (rc == pcmk_rc_ok) {
            pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);
        } else if (rc == EINPROGRESS) {
            pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_PENDING,
                             NULL);
        } else {
            set_bad_request_result(&request->result);
        }

        goto done;
    }

    dev = pcmk__xpath_find_one(request->xml->doc,
                               "//*[@" PCMK__XA_ST_TARGET "]", LOG_TRACE);
    target = pcmk__xe_get(dev, PCMK__XA_ST_TARGET);
    action = pcmk__xe_get(dev, PCMK__XA_ST_DEVICE_ACTION);
    device = pcmk__xe_get(dev, PCMK__XA_ST_DEVICE_ID);

    if (request->ipc_client != NULL) {
        int tolerance = 0;

        pcmk__notice("Client %s wants to fence (%s) %s using %s",
                     pcmk__request_origin(request), action, target,
                     (device? device : "any device"));
        pcmk__xe_get_int(dev, PCMK__XA_ST_TOLERANCE, &tolerance);
        if (stonith_check_fence_tolerance(tolerance, target, action)) {
            pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);
            return fenced_construct_reply(request->xml, NULL, &request->result);
        }
        alternate_host = check_alternate_host(target);

    } else {
        pcmk__notice("Peer %s wants to fence (%s) '%s' with device '%s'",
                     request->peer, action, target,
                     (device == NULL)? "(any)" : device);
    }

    if (alternate_host != NULL) {
        const char *client_id = NULL;
        remote_fencing_op_t *op = NULL;
        pcmk__node_status_t *node = pcmk__get_node(0, alternate_host, NULL,
                                                   pcmk__node_search_cluster_member);

        if (request->ipc_client->id == 0) {
            client_id = pcmk__xe_get(request->xml, PCMK__XA_ST_CLIENTID);
        } else {
            client_id = request->ipc_client->id;
        }

        /* Create a duplicate fencing operation to relay with the client ID.
         * When a query response is received, this operation should be
         * deleted to avoid keeping the duplicate around.
         */
        op = create_remote_stonith_op(client_id, request->xml, FALSE);

        pcmk__xe_set(request->xml, PCMK__XA_ST_OP, STONITH_OP_RELAY);
        pcmk__xe_set(request->xml, PCMK__XA_ST_CLIENTID,
                     request->ipc_client->id);
        pcmk__xe_set(request->xml, PCMK__XA_ST_REMOTE_OP, op->id);

        // @TODO On failure, fail request immediately, or maybe panic
        pcmk__cluster_send_message(node, pcmk_ipc_fenced, request->xml);

        pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_PENDING, NULL);

    } else if (initiate_remote_stonith_op(request->ipc_client, request->xml,
                                          FALSE) == NULL) {
        set_bad_request_result(&request->result);

    } else {
        pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_PENDING, NULL);
    }

done:
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
    if (!pcmk__is_set(request->call_options, st_opt_discard_reply)) {
        /* When the local node broadcasts its history, it sets
         * st_opt_discard_reply and doesn't need a reply.
         */
        reply = fenced_construct_reply(request->xml, data, &request->result);
    }
    pcmk__xml_free(data);
    return reply;
}

// STONITH_OP_DEVICE_ADD
static xmlNode *
handle_device_add_request(pcmk__request_t *request)
{
    const char *op = pcmk__xe_get(request->xml, PCMK__XA_ST_OP);
    xmlNode *dev = pcmk__xpath_find_one(request->xml->doc,
                                        "//" PCMK__XE_ST_DEVICE_ID, LOG_ERR);

    if (is_privileged(request->ipc_client, op)) {
        int rc = fenced_device_register(dev, false);

        rc = pcmk_rc2legacy(rc);
        pcmk__set_result(&request->result,
                         ((rc == pcmk_ok)? CRM_EX_OK : CRM_EX_ERROR),
                         stonith__legacy2status(rc),
                         ((rc == pcmk_ok)? NULL : pcmk_strerror(rc)));
    } else {
        pcmk__set_result(&request->result, CRM_EX_INSUFFICIENT_PRIV,
                         PCMK_EXEC_INVALID,
                         "Unprivileged users must register device via CIB");
    }
    fenced_send_config_notification(op, &request->result,
                                    (dev == NULL)? NULL : pcmk__xe_id(dev));
    return fenced_construct_reply(request->xml, NULL, &request->result);
}

// STONITH_OP_DEVICE_DEL
static xmlNode *
handle_device_delete_request(pcmk__request_t *request)
{
    xmlNode *dev = pcmk__xpath_find_one(request->xml->doc,
                                        "//" PCMK__XE_ST_DEVICE_ID, LOG_ERR);
    const char *device_id = pcmk__xe_get(dev, PCMK_XA_ID);
    const char *op = pcmk__xe_get(request->xml, PCMK__XA_ST_OP);

    if (is_privileged(request->ipc_client, op)) {
        stonith_device_remove(device_id, false);
        pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);
    } else {
        pcmk__set_result(&request->result, CRM_EX_INSUFFICIENT_PRIV,
                         PCMK_EXEC_INVALID,
                         "Unprivileged users must delete device via CIB");
    }
    fenced_send_config_notification(op, &request->result, device_id);
    return fenced_construct_reply(request->xml, NULL, &request->result);
}

// STONITH_OP_LEVEL_ADD
static xmlNode *
handle_level_add_request(pcmk__request_t *request)
{
    const char *op = pcmk__xe_get(request->xml, PCMK__XA_ST_OP);

    if (is_privileged(request->ipc_client, op)) {
        fenced_register_level(request->xml, &request->result);
    } else {
        unpack_level_request(request->xml, NULL, NULL, NULL);
        pcmk__set_result(&request->result, CRM_EX_INSUFFICIENT_PRIV,
                         PCMK_EXEC_INVALID,
                         "Unprivileged users must add level via CIB");
    }
    return fenced_construct_reply(request->xml, NULL, &request->result);
}

// STONITH_OP_LEVEL_DEL
static xmlNode *
handle_level_delete_request(pcmk__request_t *request)
{
    const char *op = pcmk__xe_get(request->xml, PCMK__XA_ST_OP);

    if (is_privileged(request->ipc_client, op)) {
        fenced_unregister_level(request->xml, &request->result);
    } else {
        unpack_level_request(request->xml, NULL, NULL, NULL);
        pcmk__set_result(&request->result, CRM_EX_INSUFFICIENT_PRIV,
                         PCMK_EXEC_INVALID,
                         "Unprivileged users must delete level via CIB");
    }
    return fenced_construct_reply(request->xml, NULL, &request->result);
}

// CRM_OP_RM_NODE_CACHE
static xmlNode *
handle_cache_request(pcmk__request_t *request)
{
    int node_id = 0;
    const char *name = NULL;

    pcmk__xe_get_int(request->xml, PCMK_XA_ID, &node_id);
    name = pcmk__xe_get(request->xml, PCMK_XA_UNAME);
    pcmk__cluster_forget_cluster_node(node_id, name);
    pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);
    return NULL;
}

static void
fenced_register_handlers(void)
{
    pcmk__server_command_t handlers[] = {
        { CRM_OP_REGISTER, handle_register_request },
        { STONITH_OP_EXEC, handle_agent_request },
        { STONITH_OP_TIMEOUT_UPDATE, handle_update_timeout_request },
        { STONITH_OP_QUERY, handle_query_request },
        { STONITH_OP_NOTIFY, handle_notify_request },
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

void
fenced_handle_request(pcmk__request_t *request)
{
    xmlNode *reply = NULL;
    char *log_msg = NULL;
    const char *exec_status_s = NULL;
    const char *reason = NULL;

    if (fenced_handlers == NULL) {
        fenced_register_handlers();
    }

    reply = pcmk__process_request(request, fenced_handlers);

    if (reply != NULL) {
        pcmk__log_xml_trace(reply, "Reply");

        if (pcmk__is_set(request->flags, pcmk__request_reuse_options)
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
        pcmk__xml_free(reply);
    }

    exec_status_s = pcmk_exec_status_str(request->result.execution_status);
    reason = request->result.exit_reason;
    log_msg = pcmk__assert_asprintf("Processed %s request from %s %s: %s%s%s%s",
                                    request->op,
                                    pcmk__request_origin_type(request),
                                    pcmk__request_origin(request),
                                    exec_status_s,
                                    (reason == NULL)? "" : " (",
                                    pcmk__s(reason, ""),
                                    (reason == NULL)? "" : ")");

    if (!pcmk__result_ok(&request->result)) {
        pcmk__warn("%s", log_msg);
    } else {
        pcmk__debug("%s", log_msg);
    }

    free(log_msg);
    pcmk__reset_request(request);
}
