/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <glib.h>
#include <stdbool.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/scheduler_internal.h>
#include <crm/pengine/internal.h>
#include <crm/common/xml_internal.h>
#include "pe_status_private.h"

static void unpack_operation(pcmk_action_t *action, const xmlNode *xml_obj,
                             guint interval_ms);

static void
add_singleton(pcmk_scheduler_t *scheduler, pcmk_action_t *action)
{
    if (scheduler->singletons == NULL) {
        scheduler->singletons = pcmk__strkey_table(NULL, NULL);
    }
    g_hash_table_insert(scheduler->singletons, action->uuid, action);
}

static pcmk_action_t *
lookup_singleton(pcmk_scheduler_t *scheduler, const char *action_uuid)
{
    if (scheduler->singletons == NULL) {
        return NULL;
    }
    return g_hash_table_lookup(scheduler->singletons, action_uuid);
}

/*!
 * \internal
 * \brief Find an existing action that matches arguments
 *
 * \param[in] key        Action key to match
 * \param[in] rsc        Resource to match (if any)
 * \param[in] node       Node to match (if any)
 * \param[in] scheduler  Scheduler data
 *
 * \return Existing action that matches arguments (or NULL if none)
 */
static pcmk_action_t *
find_existing_action(const char *key, const pcmk_resource_t *rsc,
                     const pcmk_node_t *node, const pcmk_scheduler_t *scheduler)
{
    GList *matches = NULL;
    pcmk_action_t *action = NULL;

    /* When rsc is NULL, it would be quicker to check scheduler->singletons,
     * but checking all scheduler->actions takes the node into account.
     */
    matches = find_actions(((rsc == NULL)? scheduler->actions : rsc->actions),
                           key, node);
    if (matches == NULL) {
        return NULL;
    }
    CRM_LOG_ASSERT(!pcmk__list_of_multiple(matches));

    action = matches->data;
    g_list_free(matches);
    return action;
}

/*!
 * \internal
 * \brief Find the XML configuration corresponding to a specific action key
 *
 * \param[in] rsc               Resource to find action configuration for
 * \param[in] key               "RSC_ACTION_INTERVAL" of action to find
 * \param[in] include_disabled  If false, do not return disabled actions
 *
 * \return XML configuration of desired action if any, otherwise NULL
 */
static xmlNode *
find_exact_action_config(const pcmk_resource_t *rsc, const char *action_name,
                         guint interval_ms, bool include_disabled)
{
    for (xmlNode *operation = first_named_child(rsc->ops_xml, PCMK_XE_OP);
         operation != NULL; operation = crm_next_same_xml(operation)) {

        bool enabled = false;
        const char *config_name = NULL;
        const char *interval_spec = NULL;
        guint tmp_ms = 0U;

        // @TODO This does not consider meta-attributes, rules, defaults, etc.
        if (!include_disabled
            && (pcmk__xe_get_bool_attr(operation, PCMK_META_ENABLED,
                                       &enabled) == pcmk_rc_ok) && !enabled) {
            continue;
        }

        interval_spec = crm_element_value(operation, PCMK_META_INTERVAL);
        pcmk_parse_interval_spec(interval_spec, &tmp_ms);
        if (tmp_ms != interval_ms) {
            continue;
        }

        config_name = crm_element_value(operation, PCMK_XA_NAME);
        if (pcmk__str_eq(action_name, config_name, pcmk__str_none)) {
            return operation;
        }
    }
    return NULL;
}

/*!
 * \internal
 * \brief Find the XML configuration of a resource action
 *
 * \param[in] rsc               Resource to find action configuration for
 * \param[in] action_name       Action name to search for
 * \param[in] interval_ms       Action interval (in milliseconds) to search for
 * \param[in] include_disabled  If false, do not return disabled actions
 *
 * \return XML configuration of desired action if any, otherwise NULL
 */
xmlNode *
pcmk__find_action_config(const pcmk_resource_t *rsc, const char *action_name,
                         guint interval_ms, bool include_disabled)
{
    xmlNode *action_config = NULL;

    // Try requested action first
    action_config = find_exact_action_config(rsc, action_name, interval_ms,
                                             include_disabled);

    // For migrate_to and migrate_from actions, retry with "migrate"
    // @TODO This should be either documented or deprecated
    if ((action_config == NULL)
        && pcmk__str_any_of(action_name, PCMK_ACTION_MIGRATE_TO,
                            PCMK_ACTION_MIGRATE_FROM, NULL)) {
        action_config = find_exact_action_config(rsc, "migrate", 0,
                                                 include_disabled);
    }

    return action_config;
}

/*!
 * \internal
 * \brief Create a new action object
 *
 * \param[in]     key        Action key
 * \param[in]     task       Action name
 * \param[in,out] rsc        Resource that action is for (if any)
 * \param[in]     node       Node that action is on (if any)
 * \param[in]     optional   Whether action should be considered optional
 * \param[in,out] scheduler  Scheduler data
 *
 * \return Newly allocated action
 * \note This function takes ownership of \p key. It is the caller's
 *       responsibility to free the return value with pe_free_action().
 */
static pcmk_action_t *
new_action(char *key, const char *task, pcmk_resource_t *rsc,
           const pcmk_node_t *node, bool optional, pcmk_scheduler_t *scheduler)
{
    pcmk_action_t *action = calloc(1, sizeof(pcmk_action_t));

    CRM_ASSERT(action != NULL);

    action->rsc = rsc;
    action->task = strdup(task); CRM_ASSERT(action->task != NULL);
    action->uuid = key;

    if (node) {
        action->node = pe__copy_node(node);
    }

    if (pcmk__str_eq(task, PCMK_ACTION_LRM_DELETE, pcmk__str_casei)) {
        // Resource history deletion for a node can be done on the DC
        pcmk__set_action_flags(action, pcmk_action_on_dc);
    }

    pcmk__set_action_flags(action, pcmk_action_runnable);
    if (optional) {
        pcmk__set_action_flags(action, pcmk_action_optional);
    } else {
        pcmk__clear_action_flags(action, pcmk_action_optional);
    }

    if (rsc == NULL) {
        action->meta = pcmk__strkey_table(free, free);
    } else {
        guint interval_ms = 0;

        parse_op_key(key, NULL, NULL, &interval_ms);
        action->op_entry = pcmk__find_action_config(rsc, task, interval_ms,
                                                    true);

        /* If the given key is for one of the many notification pseudo-actions
         * (pre_notify_promote, etc.), the actual action name is "notify"
         */
        if ((action->op_entry == NULL) && (strstr(key, "_notify_") != NULL)) {
            action->op_entry = find_exact_action_config(rsc, PCMK_ACTION_NOTIFY,
                                                        0, true);
        }

        unpack_operation(action, action->op_entry, interval_ms);
    }

    pcmk__rsc_trace(rsc, "Created %s action %d (%s): %s for %s on %s",
                    (optional? "optional" : "required"),
                    scheduler->action_id, key, task,
                    ((rsc == NULL)? "no resource" : rsc->id),
                    pe__node_name(node));
    action->id = scheduler->action_id++;

    scheduler->actions = g_list_prepend(scheduler->actions, action);
    if (rsc == NULL) {
        add_singleton(scheduler, action);
    } else {
        rsc->actions = g_list_prepend(rsc->actions, action);
    }
    return action;
}

/*!
 * \internal
 * \brief Unpack a resource's action-specific instance parameters
 *
 * \param[in]     action_xml  XML of action's configuration in CIB (if any)
 * \param[in,out] node_attrs  Table of node attributes (for rule evaluation)
 * \param[in,out] scheduler   Cluster working set (for rule evaluation)
 *
 * \return Newly allocated hash table of action-specific instance parameters
 */
GHashTable *
pcmk__unpack_action_rsc_params(const xmlNode *action_xml,
                               GHashTable *node_attrs,
                               pcmk_scheduler_t *scheduler)
{
    GHashTable *params = pcmk__strkey_table(free, free);

    pe_rule_eval_data_t rule_data = {
        .node_hash = node_attrs,
        .role = pcmk_role_unknown,
        .now = scheduler->now,
        .match_data = NULL,
        .rsc_data = NULL,
        .op_data = NULL
    };

    pe__unpack_dataset_nvpairs(action_xml, XML_TAG_ATTR_SETS,
                               &rule_data, params, NULL,
                               FALSE, scheduler);
    return params;
}

/*!
 * \internal
 * \brief Update an action's optional flag
 *
 * \param[in,out] action    Action to update
 * \param[in]     optional  Requested optional status
 */
static void
update_action_optional(pcmk_action_t *action, gboolean optional)
{
    // Force a non-recurring action to be optional if its resource is unmanaged
    if ((action->rsc != NULL) && (action->node != NULL)
        && !pcmk_is_set(action->flags, pcmk_action_pseudo)
        && !pcmk_is_set(action->rsc->flags, pcmk_rsc_managed)
        && (g_hash_table_lookup(action->meta, PCMK_META_INTERVAL) == NULL)) {
            pcmk__rsc_debug(action->rsc,
                            "%s on %s is optional (%s is unmanaged)",
                            action->uuid, pe__node_name(action->node),
                            action->rsc->id);
            pcmk__set_action_flags(action, pcmk_action_optional);
            // We shouldn't clear runnable here because ... something

    // Otherwise require the action if requested
    } else if (!optional) {
        pcmk__clear_action_flags(action, pcmk_action_optional);
    }
}

static enum pe_quorum_policy
effective_quorum_policy(pcmk_resource_t *rsc, pcmk_scheduler_t *scheduler)
{
    enum pe_quorum_policy policy = scheduler->no_quorum_policy;

    if (pcmk_is_set(scheduler->flags, pcmk_sched_quorate)) {
        policy = pcmk_no_quorum_ignore;

    } else if (scheduler->no_quorum_policy == pcmk_no_quorum_demote) {
        switch (rsc->role) {
            case pcmk_role_promoted:
            case pcmk_role_unpromoted:
                if (rsc->next_role > pcmk_role_unpromoted) {
                    pe__set_next_role(rsc, pcmk_role_unpromoted,
                                      PCMK_OPT_NO_QUORUM_POLICY "=demote");
                }
                policy = pcmk_no_quorum_ignore;
                break;
            default:
                policy = pcmk_no_quorum_stop;
                break;
        }
    }
    return policy;
}

/*!
 * \internal
 * \brief Update a resource action's runnable flag
 *
 * \param[in,out] action     Action to update
 * \param[in,out] scheduler  Scheduler data
 *
 * \note This may also schedule fencing if a stop is unrunnable.
 */
static void
update_resource_action_runnable(pcmk_action_t *action,
                                pcmk_scheduler_t *scheduler)
{
    if (pcmk_is_set(action->flags, pcmk_action_pseudo)) {
        return;
    }

    if (action->node == NULL) {
        pcmk__rsc_trace(action->rsc, "%s is unrunnable (unallocated)",
                        action->uuid);
        pcmk__clear_action_flags(action, pcmk_action_runnable);

    } else if (!pcmk_is_set(action->flags, pcmk_action_on_dc)
               && !(action->node->details->online)
               && (!pe__is_guest_node(action->node)
                   || action->node->details->remote_requires_reset)) {
        pcmk__clear_action_flags(action, pcmk_action_runnable);
        do_crm_log(LOG_WARNING, "%s on %s is unrunnable (node is offline)",
                   action->uuid, pe__node_name(action->node));
        if (pcmk_is_set(action->rsc->flags, pcmk_rsc_managed)
            && pcmk__str_eq(action->task, PCMK_ACTION_STOP, pcmk__str_casei)
            && !(action->node->details->unclean)) {
            pe_fence_node(scheduler, action->node, "stop is unrunnable", false);
        }

    } else if (!pcmk_is_set(action->flags, pcmk_action_on_dc)
               && action->node->details->pending) {
        pcmk__clear_action_flags(action, pcmk_action_runnable);
        do_crm_log(LOG_WARNING,
                   "Action %s on %s is unrunnable (node is pending)",
                   action->uuid, pe__node_name(action->node));

    } else if (action->needs == pcmk_requires_nothing) {
        pe_action_set_reason(action, NULL, TRUE);
        if (pe__is_guest_node(action->node)
            && !pe_can_fence(scheduler, action->node)) {
            /* An action that requires nothing usually does not require any
             * fencing in order to be runnable. However, there is an exception:
             * such an action cannot be completed if it is on a guest node whose
             * host is unclean and cannot be fenced.
             */
            pcmk__rsc_debug(action->rsc,
                            "%s on %s is unrunnable "
                            "(node's host cannot be fenced)",
                            action->uuid, pe__node_name(action->node));
            pcmk__clear_action_flags(action, pcmk_action_runnable);
        } else {
            pcmk__rsc_trace(action->rsc,
                            "%s on %s does not require fencing or quorum",
                            action->uuid, pe__node_name(action->node));
            pcmk__set_action_flags(action, pcmk_action_runnable);
        }

    } else {
        switch (effective_quorum_policy(action->rsc, scheduler)) {
            case pcmk_no_quorum_stop:
                pcmk__rsc_debug(action->rsc,
                                "%s on %s is unrunnable (no quorum)",
                                action->uuid, pe__node_name(action->node));
                pcmk__clear_action_flags(action, pcmk_action_runnable);
                pe_action_set_reason(action, "no quorum", true);
                break;

            case pcmk_no_quorum_freeze:
                if (!action->rsc->fns->active(action->rsc, TRUE)
                    || (action->rsc->next_role > action->rsc->role)) {
                    pcmk__rsc_debug(action->rsc,
                                    "%s on %s is unrunnable (no quorum)",
                                    action->uuid, pe__node_name(action->node));
                    pcmk__clear_action_flags(action, pcmk_action_runnable);
                    pe_action_set_reason(action, "quorum freeze", true);
                }
                break;

            default:
                //pe_action_set_reason(action, NULL, TRUE);
                pcmk__set_action_flags(action, pcmk_action_runnable);
                break;
        }
    }
}

/*!
 * \internal
 * \brief Update a resource object's flags for a new action on it
 *
 * \param[in,out] rsc     Resource that action is for (if any)
 * \param[in]     action  New action
 */
static void
update_resource_flags_for_action(pcmk_resource_t *rsc,
                                 const pcmk_action_t *action)
{
    /* @COMPAT pcmk_rsc_starting and pcmk_rsc_stopping are deprecated and unused
     * within Pacemaker, and will eventually be removed
     */
    if (pcmk__str_eq(action->task, PCMK_ACTION_STOP, pcmk__str_casei)) {
        pcmk__set_rsc_flags(rsc, pcmk_rsc_stopping);

    } else if (pcmk__str_eq(action->task, PCMK_ACTION_START, pcmk__str_casei)) {
        if (pcmk_is_set(action->flags, pcmk_action_runnable)) {
            pcmk__set_rsc_flags(rsc, pcmk_rsc_starting);
        } else {
            pcmk__clear_rsc_flags(rsc, pcmk_rsc_starting);
        }
    }
}

static bool
valid_stop_on_fail(const char *value)
{
    return !pcmk__strcase_any_of(value, "standby", "demote", "stop", NULL);
}

/*!
 * \internal
 * \brief Validate (and possibly reset) resource action's on_fail meta-attribute
 *
 * \param[in]     rsc            Resource that action is for
 * \param[in]     action_name    Action name
 * \param[in]     action_config  Action configuration XML from CIB (if any)
 * \param[in,out] meta           Table of action meta-attributes
 */
static void
validate_on_fail(const pcmk_resource_t *rsc, const char *action_name,
                 const xmlNode *action_config, GHashTable *meta)
{
    const char *name = NULL;
    const char *role = NULL;
    const char *interval_spec = NULL;
    const char *value = g_hash_table_lookup(meta, PCMK_META_ON_FAIL);
    char *key = NULL;
    char *new_value = NULL;
    guint interval_ms = 0U;

    // Stop actions can only use certain on-fail values
    if (pcmk__str_eq(action_name, PCMK_ACTION_STOP, pcmk__str_none)
        && !valid_stop_on_fail(value)) {

        pcmk__config_err("Resetting '" PCMK_META_ON_FAIL "' for %s stop "
                         "action to default value because '%s' is not "
                         "allowed for stop", rsc->id, value);
        g_hash_table_remove(meta, PCMK_META_ON_FAIL);
        return;
    }

    /* Demote actions default on-fail to the on-fail value for the first
     * recurring monitor for the promoted role (if any).
     */
    if (pcmk__str_eq(action_name, PCMK_ACTION_DEMOTE, pcmk__str_none)
        && (value == NULL)) {

        /* @TODO This does not consider promote options set in a meta-attribute
         * block (which may have rules that need to be evaluated) rather than
         * XML properties.
         */
        for (xmlNode *operation = first_named_child(rsc->ops_xml, PCMK_XE_OP);
             operation != NULL; operation = crm_next_same_xml(operation)) {
            bool enabled = false;
            const char *promote_on_fail = NULL;

            /* We only care about explicit on-fail (if promote uses default, so
             * can demote)
             */
            promote_on_fail = crm_element_value(operation, PCMK_META_ON_FAIL);
            if (promote_on_fail == NULL) {
                continue;
            }

            // We only care about recurring monitors for the promoted role
            name = crm_element_value(operation, PCMK_XA_NAME);
            role = crm_element_value(operation, "role");
            if (!pcmk__str_eq(name, PCMK_ACTION_MONITOR, pcmk__str_none)
                || !pcmk__strcase_any_of(role, PCMK__ROLE_PROMOTED,
                                         PCMK__ROLE_PROMOTED_LEGACY, NULL)) {
                continue;
            }
            interval_spec = crm_element_value(operation, PCMK_META_INTERVAL);
            pcmk_parse_interval_spec(interval_spec, &interval_ms);
            if (interval_ms == 0U) {
                continue;
            }

            // We only care about enabled monitors
            if ((pcmk__xe_get_bool_attr(operation, PCMK_META_ENABLED,
                                        &enabled) == pcmk_rc_ok) && !enabled) {
                continue;
            }

            // Demote actions can't default to on-fail="demote"
            if (pcmk__str_eq(promote_on_fail, "demote", pcmk__str_casei)) {
                continue;
            }

            // Use value from first applicable promote action found
            key = strdup(PCMK_META_ON_FAIL);
            new_value = strdup(promote_on_fail);
            CRM_ASSERT((key != NULL) && (new_value != NULL));
            g_hash_table_insert(meta, key, new_value);
        }
        return;
    }

    if (pcmk__str_eq(action_name, PCMK_ACTION_LRM_DELETE, pcmk__str_none)
        && !pcmk__str_eq(value, "ignore", pcmk__str_casei)) {
        key = strdup(PCMK_META_ON_FAIL);
        new_value = strdup("ignore");
        CRM_ASSERT((key != NULL) && (new_value != NULL));
        g_hash_table_insert(meta, key, new_value);
        return;
    }

    // on-fail="demote" is allowed only for certain actions
    if (pcmk__str_eq(value, "demote", pcmk__str_casei)) {
        name = crm_element_value(action_config, PCMK_XA_NAME);
        role = crm_element_value(action_config, "role");
        interval_spec = crm_element_value(action_config, PCMK_META_INTERVAL);
        pcmk_parse_interval_spec(interval_spec, &interval_ms);

        if (!pcmk__str_eq(name, PCMK_ACTION_PROMOTE, pcmk__str_none)
            && ((interval_ms == 0U)
                || !pcmk__str_eq(name, PCMK_ACTION_MONITOR, pcmk__str_none)
                || !pcmk__strcase_any_of(role, PCMK__ROLE_PROMOTED,
                                         PCMK__ROLE_PROMOTED_LEGACY, NULL))) {

            pcmk__config_err("Resetting '" PCMK_META_ON_FAIL "' for %s %s "
                             "action to default value because 'demote' is not "
                             "allowed for it", rsc->id, name);
            g_hash_table_remove(meta, PCMK_META_ON_FAIL);
            return;
        }
    }
}

static int
unpack_timeout(const char *value)
{
    int timeout_ms = crm_get_msec(value);

    if (timeout_ms < 0) {
        timeout_ms = PCMK_DEFAULT_ACTION_TIMEOUT_MS;
    }
    return timeout_ms;
}

// true if value contains valid, non-NULL interval origin for recurring op
static bool
unpack_interval_origin(const char *value, const xmlNode *xml_obj,
                       guint interval_ms, const crm_time_t *now,
                       long long *start_delay)
{
    long long result = 0;
    guint interval_sec = interval_ms / 1000;
    crm_time_t *origin = NULL;

    // Ignore unspecified values and non-recurring operations
    if ((value == NULL) || (interval_ms == 0) || (now == NULL)) {
        return false;
    }

    // Parse interval origin from text
    origin = crm_time_new(value);
    if (origin == NULL) {
        pcmk__config_err("Ignoring '" PCMK_META_INTERVAL_ORIGIN "' for "
                         "operation '%s' because '%s' is not valid",
                         (ID(xml_obj)? ID(xml_obj) : "(missing ID)"), value);
        return false;
    }

    // Get seconds since origin (negative if origin is in the future)
    result = crm_time_get_seconds(now) - crm_time_get_seconds(origin);
    crm_time_free(origin);

    // Calculate seconds from closest interval to now
    result = result % interval_sec;

    // Calculate seconds remaining until next interval
    result = ((result <= 0)? 0 : interval_sec) - result;
    crm_info("Calculated a start delay of %llds for operation '%s'",
             result,
             (ID(xml_obj)? ID(xml_obj) : "(unspecified)"));

    if (start_delay != NULL) {
        *start_delay = result * 1000; // milliseconds
    }
    return true;
}

static int
unpack_start_delay(const char *value, GHashTable *meta)
{
    int start_delay = 0;

    if (value != NULL) {
        start_delay = crm_get_msec(value);

        if (start_delay < 0) {
            start_delay = 0;
        }

        if (meta) {
            g_hash_table_replace(meta, strdup(PCMK_META_START_DELAY),
                                 pcmk__itoa(start_delay));
        }
    }

    return start_delay;
}

/*!
 * \internal
 * \brief Find a resource's most frequent recurring monitor
 *
 * \param[in] rsc  Resource to check
 *
 * \return Operation XML configured for most frequent recurring monitor for
 *         \p rsc (if any)
 */
static xmlNode *
most_frequent_monitor(const pcmk_resource_t *rsc)
{
    guint min_interval_ms = G_MAXUINT;
    xmlNode *op = NULL;

    for (xmlNode *operation = first_named_child(rsc->ops_xml, PCMK_XE_OP);
         operation != NULL; operation = crm_next_same_xml(operation)) {
        bool enabled = false;
        guint interval_ms = 0U;
        const char *interval_spec = crm_element_value(operation,
                                                      PCMK_META_INTERVAL);

        // We only care about enabled recurring monitors
        if (!pcmk__str_eq(crm_element_value(operation, PCMK_XA_NAME),
                          PCMK_ACTION_MONITOR, pcmk__str_none)) {
            continue;
        }

        pcmk_parse_interval_spec(interval_spec, &interval_ms);
        if (interval_ms == 0U) {
            continue;
        }

        // @TODO This does not consider meta-attributes, rules, defaults, etc.
        if ((pcmk__xe_get_bool_attr(operation, PCMK_META_ENABLED,
                                    &enabled) == pcmk_rc_ok) && !enabled) {
            continue;
        }

        if (interval_ms < min_interval_ms) {
            min_interval_ms = interval_ms;
            op = operation;
        }
    }
    return op;
}

/*!
 * \internal
 * \brief Unpack action meta-attributes
 *
 * \param[in,out] rsc            Resource that action is for
 * \param[in]     node           Node that action is on
 * \param[in]     action_name    Action name
 * \param[in]     interval_ms    Action interval (in milliseconds)
 * \param[in]     action_config  Action XML configuration from CIB (if any)
 *
 * Unpack a resource action's meta-attributes (normalizing the interval,
 * timeout, and start delay values as integer milliseconds) from its CIB XML
 * configuration (including defaults).
 *
 * \return Newly allocated hash table with normalized action meta-attributes
 */
GHashTable *
pcmk__unpack_action_meta(pcmk_resource_t *rsc, const pcmk_node_t *node,
                         const char *action_name, guint interval_ms,
                         const xmlNode *action_config)
{
    GHashTable *meta = NULL;
    char *name = NULL;
    char *value = NULL;
    const char *timeout_spec = NULL;
    const char *str = NULL;

    pe_rsc_eval_data_t rsc_rule_data = {
        .standard = crm_element_value(rsc->xml, PCMK_XA_CLASS),
        .provider = crm_element_value(rsc->xml, PCMK_XA_PROVIDER),
        .agent = crm_element_value(rsc->xml, PCMK_XA_TYPE),
    };

    pe_op_eval_data_t op_rule_data = {
        .op_name = action_name,
        .interval = interval_ms,
    };

    pe_rule_eval_data_t rule_data = {
        .node_hash = (node == NULL)? NULL : node->details->attrs,
        .role = pcmk_role_unknown,
        .now = rsc->cluster->now,
        .match_data = NULL,
        .rsc_data = &rsc_rule_data,
        .op_data = &op_rule_data,
    };

    meta = pcmk__strkey_table(free, free);

    // Cluster-wide <op_defaults> <meta_attributes>
    pe__unpack_dataset_nvpairs(rsc->cluster->op_defaults, XML_TAG_META_SETS,
                               &rule_data, meta, NULL, FALSE, rsc->cluster);

    // Derive default timeout for probes from recurring monitor timeouts
    if (pcmk_is_probe(action_name, interval_ms)) {
        xmlNode *min_interval_mon = most_frequent_monitor(rsc);

        if (min_interval_mon != NULL) {
            /* @TODO This does not consider timeouts set in meta_attributes
             * blocks (which may also have rules that need to be evaluated).
             */
            timeout_spec = crm_element_value(min_interval_mon,
                                             PCMK_META_TIMEOUT);
            if (timeout_spec != NULL) {
                pcmk__rsc_trace(rsc,
                                "Setting default timeout for %s probe to "
                                "most frequent monitor's timeout '%s'",
                                rsc->id, timeout_spec);
                name = strdup(PCMK_META_TIMEOUT);
                value = strdup(timeout_spec);
                CRM_ASSERT((name != NULL) && (value != NULL));
                g_hash_table_insert(meta, name, value);
            }
        }
    }

    if (action_config != NULL) {
        // <op> <meta_attributes> take precedence over defaults
        pe__unpack_dataset_nvpairs(action_config, XML_TAG_META_SETS, &rule_data,
                                   meta, NULL, TRUE, rsc->cluster);

        /* Anything set as an <op> XML property has highest precedence.
         * This ensures we use the name and interval from the <op> tag.
         * (See below for the only exception, fence device start/probe timeout.)
         */
        for (xmlAttrPtr attr = action_config->properties;
             attr != NULL; attr = attr->next) {
            name = strdup((const char *) attr->name);
            value = strdup(pcmk__xml_attr_value(attr));

            CRM_ASSERT((name != NULL) && (value != NULL));
            g_hash_table_insert(meta, name, value);
        }
    }

    g_hash_table_remove(meta, PCMK_XA_ID);

    // Normalize interval to milliseconds
    if (interval_ms > 0) {
        name = strdup(PCMK_META_INTERVAL);
        CRM_ASSERT(name != NULL);
        value = crm_strdup_printf("%u", interval_ms);
        g_hash_table_insert(meta, name, value);
    } else {
        g_hash_table_remove(meta, PCMK_META_INTERVAL);
    }

    /* Timeout order of precedence (highest to lowest):
     *   1. pcmk_monitor_timeout resource parameter (only for starts and probes
     *      when rsc has pcmk_ra_cap_fence_params; this gets used for recurring
     *      monitors via the executor instead)
     *   2. timeout configured in <op> (with <op timeout> taking precedence over
     *      <op> <meta_attributes>)
     *   3. timeout configured in <op_defaults> <meta_attributes>
     *   4. PCMK_DEFAULT_ACTION_TIMEOUT_MS
     */

    // Check for pcmk_monitor_timeout
    if (pcmk_is_set(pcmk_get_ra_caps(rsc_rule_data.standard),
                    pcmk_ra_cap_fence_params)
        && (pcmk__str_eq(action_name, PCMK_ACTION_START, pcmk__str_none)
            || pcmk_is_probe(action_name, interval_ms))) {

        GHashTable *params = pe_rsc_params(rsc, node, rsc->cluster);

        timeout_spec = g_hash_table_lookup(params, "pcmk_monitor_timeout");
        if (timeout_spec != NULL) {
            pcmk__rsc_trace(rsc,
                            "Setting timeout for %s %s to "
                            "pcmk_monitor_timeout (%s)",
                            rsc->id, action_name, timeout_spec);
            name = strdup(PCMK_META_TIMEOUT);
            value = strdup(timeout_spec);
            CRM_ASSERT((name != NULL) && (value != NULL));
            g_hash_table_insert(meta, name, value);
        }
    }

    // Normalize timeout to positive milliseconds
    name = strdup(PCMK_META_TIMEOUT);
    CRM_ASSERT(name != NULL);
    timeout_spec = g_hash_table_lookup(meta, PCMK_META_TIMEOUT);
    g_hash_table_insert(meta, name, pcmk__itoa(unpack_timeout(timeout_spec)));

    // Ensure on-fail has a valid value
    validate_on_fail(rsc, action_name, action_config, meta);

    // Normalize PCMK_META_START_DELAY
    str = g_hash_table_lookup(meta, PCMK_META_START_DELAY);
    if (str != NULL) {
        unpack_start_delay(str, meta);
    } else {
        long long start_delay = 0;

        str = g_hash_table_lookup(meta, PCMK_META_INTERVAL_ORIGIN);
        if (unpack_interval_origin(str, action_config, interval_ms,
                                   rsc->cluster->now, &start_delay)) {
            name = strdup(PCMK_META_START_DELAY);
            CRM_ASSERT(name != NULL);
            g_hash_table_insert(meta, name,
                                crm_strdup_printf("%lld", start_delay));
        }
    }
    return meta;
}

/*!
 * \internal
 * \brief Determine an action's quorum and fencing dependency
 *
 * \param[in] rsc          Resource that action is for
 * \param[in] action_name  Name of action being unpacked
 *
 * \return Quorum and fencing dependency appropriate to action
 */
enum rsc_start_requirement
pcmk__action_requires(const pcmk_resource_t *rsc, const char *action_name)
{
    const char *value = NULL;
    enum rsc_start_requirement requires = pcmk_requires_nothing;

    CRM_CHECK((rsc != NULL) && (action_name != NULL), return requires);

    if (!pcmk__strcase_any_of(action_name, PCMK_ACTION_START,
                              PCMK_ACTION_PROMOTE, NULL)) {
        value = "nothing (not start or promote)";

    } else if (pcmk_is_set(rsc->flags, pcmk_rsc_needs_fencing)) {
        requires = pcmk_requires_fencing;
        value = "fencing";

    } else if (pcmk_is_set(rsc->flags, pcmk_rsc_needs_quorum)) {
        requires = pcmk_requires_quorum;
        value = "quorum";

    } else {
        value = "nothing";
    }
    pcmk__rsc_trace(rsc, "%s of %s requires %s", action_name, rsc->id, value);
    return requires;
}

/*!
 * \internal
 * \brief Parse action failure response from a user-provided string
 *
 * \param[in] rsc          Resource that action is for
 * \param[in] action_name  Name of action
 * \param[in] interval_ms  Action interval (in milliseconds)
 * \param[in] value        User-provided configuration value for on-fail
 *
 * \return Action failure response parsed from \p text
 */
enum action_fail_response
pcmk__parse_on_fail(const pcmk_resource_t *rsc, const char *action_name,
                    guint interval_ms, const char *value)
{
    const char *desc = NULL;
    bool needs_remote_reset = false;
    enum action_fail_response on_fail = pcmk_on_fail_ignore;

    if (value == NULL) {
        // Use default

    } else if (pcmk__str_eq(value, "block", pcmk__str_casei)) {
        on_fail = pcmk_on_fail_block;
        desc = "block";

    } else if (pcmk__str_eq(value, "fence", pcmk__str_casei)) {
        if (pcmk_is_set(rsc->cluster->flags, pcmk_sched_fencing_enabled)) {
            on_fail = pcmk_on_fail_fence_node;
            desc = "node fencing";
        } else {
            pcmk__config_err("Resetting '" PCMK_META_ON_FAIL "' for "
                             "%s of %s to 'stop' because 'fence' is not "
                             "valid when fencing is disabled",
                             action_name, rsc->id);
            on_fail = pcmk_on_fail_stop;
            desc = "stop resource";
        }

    } else if (pcmk__str_eq(value, "standby", pcmk__str_casei)) {
        on_fail = pcmk_on_fail_standby_node;
        desc = "node standby";

    } else if (pcmk__strcase_any_of(value, "ignore", PCMK__VALUE_NOTHING,
                                    NULL)) {
        desc = "ignore";

    } else if (pcmk__str_eq(value, "migrate", pcmk__str_casei)) {
        on_fail = pcmk_on_fail_ban;
        desc = "force migration";

    } else if (pcmk__str_eq(value, "stop", pcmk__str_casei)) {
        on_fail = pcmk_on_fail_stop;
        desc = "stop resource";

    } else if (pcmk__str_eq(value, "restart", pcmk__str_casei)) {
        on_fail = pcmk_on_fail_restart;
        desc = "restart (and possibly migrate)";

    } else if (pcmk__str_eq(value, "restart-container", pcmk__str_casei)) {
        if (rsc->container == NULL) {
            pcmk__rsc_debug(rsc,
                            "Using default " PCMK_META_ON_FAIL " for %s "
                            "of %s because it does not have a container",
                            action_name, rsc->id);
        } else {
            on_fail = pcmk_on_fail_restart_container;
            desc = "restart container (and possibly migrate)";
        }

    } else if (pcmk__str_eq(value, "demote", pcmk__str_casei)) {
        on_fail = pcmk_on_fail_demote;
        desc = "demote instance";

    } else {
        pcmk__config_err("Using default '" PCMK_META_ON_FAIL "' for "
                         "%s of %s because '%s' is not valid",
                         action_name, rsc->id, value);
    }

    /* Remote node connections are handled specially. Failures that result
     * in dropping an active connection must result in fencing. The only
     * failures that don't are probes and starts. The user can explicitly set
     * on-fail="fence" to fence after start failures.
     */
    if (pe__resource_is_remote_conn(rsc)
        && !pcmk_is_probe(action_name, interval_ms)
        && !pcmk__str_eq(action_name, PCMK_ACTION_START, pcmk__str_none)) {
        needs_remote_reset = true;
        if (!pcmk_is_set(rsc->flags, pcmk_rsc_managed)) {
            desc = NULL; // Force default for unmanaged connections
        }
    }

    if (desc != NULL) {
        // Explicit value used, default not needed

    } else if (rsc->container != NULL) {
        on_fail = pcmk_on_fail_restart_container;
        desc = "restart container (and possibly migrate) (default)";

    } else if (needs_remote_reset) {
        if (pcmk_is_set(rsc->flags, pcmk_rsc_managed)) {
            if (pcmk_is_set(rsc->cluster->flags,
                            pcmk_sched_fencing_enabled)) {
                desc = "fence remote node (default)";
            } else {
                desc = "recover remote node connection (default)";
            }
            on_fail = pcmk_on_fail_reset_remote;
        } else {
            on_fail = pcmk_on_fail_stop;
            desc = "stop unmanaged remote node (enforcing default)";
        }

    } else if (pcmk__str_eq(action_name, PCMK_ACTION_STOP, pcmk__str_none)) {
        if (pcmk_is_set(rsc->cluster->flags, pcmk_sched_fencing_enabled)) {
            on_fail = pcmk_on_fail_fence_node;
            desc = "resource fence (default)";
        } else {
            on_fail = pcmk_on_fail_block;
            desc = "resource block (default)";
        }

    } else {
        on_fail = pcmk_on_fail_restart;
        desc = "restart (and possibly migrate) (default)";
    }

    pcmk__rsc_trace(rsc, "Failure handling for %s-interval %s of %s: %s",
                    pcmk__readable_interval(interval_ms), action_name,
                    rsc->id, desc);
    return on_fail;
}

/*!
 * \internal
 * \brief Determine a resource's role after failure of an action
 *
 * \param[in] rsc          Resource that action is for
 * \param[in] action_name  Action name
 * \param[in] on_fail      Failure handling for action
 * \param[in] meta         Unpacked action meta-attributes
 *
 * \return Resource role that results from failure of action
 */
enum rsc_role_e
pcmk__role_after_failure(const pcmk_resource_t *rsc, const char *action_name,
                         enum action_fail_response on_fail, GHashTable *meta)
{
    const char *value = NULL;
    enum rsc_role_e role = pcmk_role_unknown;

    // Set default for role after failure specially in certain circumstances
    switch (on_fail) {
        case pcmk_on_fail_stop:
            role = pcmk_role_stopped;
            break;

        case pcmk_on_fail_reset_remote:
            if (rsc->remote_reconnect_ms != 0) {
                role = pcmk_role_stopped;
            }
            break;

        default:
            break;
    }

    // @COMPAT Check for explicitly configured role (deprecated)
    value = g_hash_table_lookup(meta, PCMK__META_ROLE_AFTER_FAILURE);
    if (value != NULL) {
        pcmk__warn_once(pcmk__wo_role_after,
                        "Support for " PCMK__META_ROLE_AFTER_FAILURE " is "
                        "deprecated and will be removed in a future release");
        if (role == pcmk_role_unknown) {
            role = text2role(value);
            if (role == pcmk_role_unknown) {
                pcmk__config_err("Ignoring invalid value %s for "
                                 PCMK__META_ROLE_AFTER_FAILURE,
                                 value);
            }
        }
    }

    if (role == pcmk_role_unknown) {
        // Use default
        if (pcmk__str_eq(action_name, PCMK_ACTION_PROMOTE, pcmk__str_none)) {
            role = pcmk_role_unpromoted;
        } else {
            role = pcmk_role_started;
        }
    }
    pcmk__rsc_trace(rsc, "Role after %s %s failure is: %s",
                    rsc->id, action_name, role2text(role));
    return role;
}

/*!
 * \internal
 * \brief Unpack action configuration
 *
 * Unpack a resource action's meta-attributes (normalizing the interval,
 * timeout, and start delay values as integer milliseconds), requirements, and
 * failure policy from its CIB XML configuration (including defaults).
 *
 * \param[in,out] action       Resource action to unpack into
 * \param[in]     xml_obj      Action configuration XML (NULL for defaults only)
 * \param[in]     interval_ms  How frequently to perform the operation
 */
static void
unpack_operation(pcmk_action_t *action, const xmlNode *xml_obj,
                 guint interval_ms)
{
    const char *value = NULL;

    action->meta = pcmk__unpack_action_meta(action->rsc, action->node,
                                            action->task, interval_ms, xml_obj);
    action->needs = pcmk__action_requires(action->rsc, action->task);

    value = g_hash_table_lookup(action->meta, PCMK_META_ON_FAIL);
    action->on_fail = pcmk__parse_on_fail(action->rsc, action->task,
                                          interval_ms, value);

    action->fail_role = pcmk__role_after_failure(action->rsc, action->task,
                                                 action->on_fail, action->meta);
}

/*!
 * \brief Create or update an action object
 *
 * \param[in,out] rsc          Resource that action is for (if any)
 * \param[in,out] key          Action key (must be non-NULL)
 * \param[in]     task         Action name (must be non-NULL)
 * \param[in]     on_node      Node that action is on (if any)
 * \param[in]     optional     Whether action should be considered optional
 * \param[in,out] scheduler    Scheduler data
 *
 * \return Action object corresponding to arguments (guaranteed not to be
 *         \c NULL)
 * \note This function takes ownership of (and might free) \p key, and
 *       \p scheduler takes ownership of the returned action (the caller should
 *       not free it).
 */
pcmk_action_t *
custom_action(pcmk_resource_t *rsc, char *key, const char *task,
              const pcmk_node_t *on_node, gboolean optional,
              pcmk_scheduler_t *scheduler)
{
    pcmk_action_t *action = NULL;

    CRM_ASSERT((key != NULL) && (task != NULL) && (scheduler != NULL));

    action = find_existing_action(key, rsc, on_node, scheduler);
    if (action == NULL) {
        action = new_action(key, task, rsc, on_node, optional, scheduler);
    } else {
        free(key);
    }

    update_action_optional(action, optional);

    if (rsc != NULL) {
        if ((action->node != NULL) && (action->op_entry != NULL)
            && !pcmk_is_set(action->flags, pcmk_action_attrs_evaluated)) {

            GHashTable *attrs = action->node->details->attrs;

            if (action->extra != NULL) {
                g_hash_table_destroy(action->extra);
            }
            action->extra = pcmk__unpack_action_rsc_params(action->op_entry,
                                                           attrs, scheduler);
            pcmk__set_action_flags(action, pcmk_action_attrs_evaluated);
        }

        update_resource_action_runnable(action, scheduler);
        update_resource_flags_for_action(rsc, action);
    }

    if (action->extra == NULL) {
        action->extra = pcmk__strkey_table(free, free);
    }

    return action;
}

pcmk_action_t *
get_pseudo_op(const char *name, pcmk_scheduler_t *scheduler)
{
    pcmk_action_t *op = lookup_singleton(scheduler, name);

    if (op == NULL) {
        op = custom_action(NULL, strdup(name), name, NULL, TRUE, scheduler);
        pcmk__set_action_flags(op, pcmk_action_pseudo|pcmk_action_runnable);
    }
    return op;
}

static GList *
find_unfencing_devices(GList *candidates, GList *matches) 
{
    for (GList *gIter = candidates; gIter != NULL; gIter = gIter->next) {
        pcmk_resource_t *candidate = gIter->data;

        if (candidate->children != NULL) {
            matches = find_unfencing_devices(candidate->children, matches);

        } else if (!pcmk_is_set(candidate->flags, pcmk_rsc_fence_device)) {
            continue;

        } else if (pcmk_is_set(candidate->flags, pcmk_rsc_needs_unfencing)) {
            matches = g_list_prepend(matches, candidate);

        } else if (pcmk__str_eq(g_hash_table_lookup(candidate->meta,
                                                    PCMK_STONITH_PROVIDES),
                                PCMK__VALUE_UNFENCING,
                                pcmk__str_casei)) {
            matches = g_list_prepend(matches, candidate);
        }
    }
    return matches;
}

static int
node_priority_fencing_delay(const pcmk_node_t *node,
                            const pcmk_scheduler_t *scheduler)
{
    int member_count = 0;
    int online_count = 0;
    int top_priority = 0;
    int lowest_priority = 0;
    GList *gIter = NULL;

    // PCMK_OPT_PRIORITY_FENCING_DELAY is disabled
    if (scheduler->priority_fencing_delay <= 0) {
        return 0;
    }

    /* No need to request a delay if the fencing target is not a normal cluster
     * member, for example if it's a remote node or a guest node. */
    if (node->details->type != pcmk_node_variant_cluster) {
        return 0;
    }

    // No need to request a delay if the fencing target is in our partition
    if (node->details->online) {
        return 0;
    }

    for (gIter = scheduler->nodes; gIter != NULL; gIter = gIter->next) {
        pcmk_node_t *n = gIter->data;

        if (n->details->type != pcmk_node_variant_cluster) {
            continue;
        }

        member_count ++;

        if (n->details->online) {
            online_count++;
        }

        if (member_count == 1
            || n->details->priority > top_priority) {
            top_priority = n->details->priority;
        }

        if (member_count == 1
            || n->details->priority < lowest_priority) {
            lowest_priority = n->details->priority;
        }
    }

    // No need to delay if we have more than half of the cluster members
    if (online_count > member_count / 2) {
        return 0;
    }

    /* All the nodes have equal priority.
     * Any configured corresponding `pcmk_delay_base/max` will be applied. */
    if (lowest_priority == top_priority) {
        return 0;
    }

    if (node->details->priority < top_priority) {
        return 0;
    }

    return scheduler->priority_fencing_delay;
}

pcmk_action_t *
pe_fence_op(pcmk_node_t *node, const char *op, bool optional,
            const char *reason, bool priority_delay,
            pcmk_scheduler_t *scheduler)
{
    char *op_key = NULL;
    pcmk_action_t *stonith_op = NULL;

    if(op == NULL) {
        op = scheduler->stonith_action;
    }

    op_key = crm_strdup_printf("%s-%s-%s",
                               PCMK_ACTION_STONITH, node->details->uname, op);

    stonith_op = lookup_singleton(scheduler, op_key);
    if(stonith_op == NULL) {
        stonith_op = custom_action(NULL, op_key, PCMK_ACTION_STONITH, node,
                                   TRUE, scheduler);

        add_hash_param(stonith_op->meta, XML_LRM_ATTR_TARGET, node->details->uname);
        add_hash_param(stonith_op->meta, XML_LRM_ATTR_TARGET_UUID, node->details->id);
        add_hash_param(stonith_op->meta, "stonith_action", op);

        if (pcmk_is_set(scheduler->flags, pcmk_sched_enable_unfencing)) {
            /* Extra work to detect device changes
             */
            GString *digests_all = g_string_sized_new(1024);
            GString *digests_secure = g_string_sized_new(1024);

            GList *matches = find_unfencing_devices(scheduler->resources, NULL);

            char *key = NULL;
            char *value = NULL;

            for (GList *gIter = matches; gIter != NULL; gIter = gIter->next) {
                pcmk_resource_t *match = gIter->data;
                const char *agent = g_hash_table_lookup(match->meta,
                                                        PCMK_XA_TYPE);
                pcmk__op_digest_t *data = NULL;

                data = pe__compare_fencing_digest(match, agent, node,
                                                  scheduler);
                if (data->rc == pcmk__digest_mismatch) {
                    optional = FALSE;
                    crm_notice("Unfencing node %s because the definition of "
                               "%s changed", pe__node_name(node), match->id);
                    if (!pcmk__is_daemon && scheduler->priv != NULL) {
                        pcmk__output_t *out = scheduler->priv;

                        out->info(out,
                                  "notice: Unfencing node %s because the "
                                  "definition of %s changed",
                                  pe__node_name(node), match->id);
                    }
                }

                pcmk__g_strcat(digests_all,
                               match->id, ":", agent, ":",
                               data->digest_all_calc, ",", NULL);
                pcmk__g_strcat(digests_secure,
                               match->id, ":", agent, ":",
                               data->digest_secure_calc, ",", NULL);
            }
            key = strdup(XML_OP_ATTR_DIGESTS_ALL);
            value = strdup((const char *) digests_all->str);
            CRM_ASSERT((key != NULL) && (value != NULL));
            g_hash_table_insert(stonith_op->meta, key, value);
            g_string_free(digests_all, TRUE);

            key = strdup(XML_OP_ATTR_DIGESTS_SECURE);
            value = strdup((const char *) digests_secure->str);
            CRM_ASSERT((key != NULL) && (value != NULL));
            g_hash_table_insert(stonith_op->meta, key, value);
            g_string_free(digests_secure, TRUE);
        }

    } else {
        free(op_key);
    }

    if (scheduler->priority_fencing_delay > 0

            /* It's a suitable case where PCMK_OPT_PRIORITY_FENCING_DELAY
             * applies. At least add PCMK_OPT_PRIORITY_FENCING_DELAY field as
             * an indicator.
             */
        && (priority_delay

            /* The priority delay needs to be recalculated if this function has
             * been called by schedule_fencing_and_shutdowns() after node
             * priority has already been calculated by native_add_running().
             */
            || g_hash_table_lookup(stonith_op->meta,
                                   PCMK_OPT_PRIORITY_FENCING_DELAY) != NULL)) {

            /* Add PCMK_OPT_PRIORITY_FENCING_DELAY to the fencing op even if
             * it's 0 for the targeting node. So that it takes precedence over
             * any possible `pcmk_delay_base/max`.
             */
            char *delay_s = pcmk__itoa(node_priority_fencing_delay(node,
                                                                   scheduler));

            g_hash_table_insert(stonith_op->meta,
                                strdup(PCMK_OPT_PRIORITY_FENCING_DELAY),
                                delay_s);
    }

    if(optional == FALSE && pe_can_fence(scheduler, node)) {
        pcmk__clear_action_flags(stonith_op, pcmk_action_optional);
        pe_action_set_reason(stonith_op, reason, false);

    } else if(reason && stonith_op->reason == NULL) {
        stonith_op->reason = strdup(reason);
    }

    return stonith_op;
}

void
pe_free_action(pcmk_action_t *action)
{
    if (action == NULL) {
        return;
    }
    g_list_free_full(action->actions_before, free);
    g_list_free_full(action->actions_after, free);
    if (action->extra) {
        g_hash_table_destroy(action->extra);
    }
    if (action->meta) {
        g_hash_table_destroy(action->meta);
    }
    free(action->cancel_task);
    free(action->reason);
    free(action->task);
    free(action->uuid);
    free(action->node);
    free(action);
}

int
pe_get_configured_timeout(pcmk_resource_t *rsc, const char *action,
                          pcmk_scheduler_t *scheduler)
{
    xmlNode *child = NULL;
    GHashTable *action_meta = NULL;
    const char *timeout_spec = NULL;
    int timeout_ms = 0;

    pe_rule_eval_data_t rule_data = {
        .node_hash = NULL,
        .role = pcmk_role_unknown,
        .now = scheduler->now,
        .match_data = NULL,
        .rsc_data = NULL,
        .op_data = NULL
    };

    for (child = first_named_child(rsc->ops_xml, PCMK_XE_OP);
         child != NULL; child = crm_next_same_xml(child)) {
        if (pcmk__str_eq(action, crm_element_value(child, PCMK_XA_NAME),
                pcmk__str_casei)) {
            timeout_spec = crm_element_value(child, PCMK_META_TIMEOUT);
            break;
        }
    }

    if (timeout_spec == NULL && scheduler->op_defaults) {
        action_meta = pcmk__strkey_table(free, free);
        pe__unpack_dataset_nvpairs(scheduler->op_defaults, XML_TAG_META_SETS,
                                   &rule_data, action_meta, NULL, FALSE,
                                   scheduler);
        timeout_spec = g_hash_table_lookup(action_meta, PCMK_META_TIMEOUT);
    }

    // @TODO check meta-attributes
    // @TODO maybe use min-interval monitor timeout as default for monitors

    timeout_ms = crm_get_msec(timeout_spec);
    if (timeout_ms < 0) {
        timeout_ms = PCMK_DEFAULT_ACTION_TIMEOUT_MS;
    }

    if (action_meta != NULL) {
        g_hash_table_destroy(action_meta);
    }
    return timeout_ms;
}

enum action_tasks
get_complex_task(const pcmk_resource_t *rsc, const char *name)
{
    enum action_tasks task = text2task(name);

    if ((rsc != NULL) && (rsc->variant == pcmk_rsc_variant_primitive)) {
        switch (task) {
            case pcmk_action_stopped:
            case pcmk_action_started:
            case pcmk_action_demoted:
            case pcmk_action_promoted:
                crm_trace("Folding %s back into its atomic counterpart for %s",
                          name, rsc->id);
                --task;
                break;
            default:
                break;
        }
    }
    return task;
}

/*!
 * \internal
 * \brief Find first matching action in a list
 *
 * \param[in] input    List of actions to search
 * \param[in] uuid     If not NULL, action must have this UUID
 * \param[in] task     If not NULL, action must have this action name
 * \param[in] on_node  If not NULL, action must be on this node
 *
 * \return First action in list that matches criteria, or NULL if none
 */
pcmk_action_t *
find_first_action(const GList *input, const char *uuid, const char *task,
                  const pcmk_node_t *on_node)
{
    CRM_CHECK(uuid || task, return NULL);

    for (const GList *gIter = input; gIter != NULL; gIter = gIter->next) {
        pcmk_action_t *action = (pcmk_action_t *) gIter->data;

        if (uuid != NULL && !pcmk__str_eq(uuid, action->uuid, pcmk__str_casei)) {
            continue;

        } else if (task != NULL && !pcmk__str_eq(task, action->task, pcmk__str_casei)) {
            continue;

        } else if (on_node == NULL) {
            return action;

        } else if (action->node == NULL) {
            continue;

        } else if (on_node->details == action->node->details) {
            return action;
        }
    }

    return NULL;
}

GList *
find_actions(GList *input, const char *key, const pcmk_node_t *on_node)
{
    GList *gIter = input;
    GList *result = NULL;

    CRM_CHECK(key != NULL, return NULL);

    for (; gIter != NULL; gIter = gIter->next) {
        pcmk_action_t *action = (pcmk_action_t *) gIter->data;

        if (!pcmk__str_eq(key, action->uuid, pcmk__str_casei)) {
            continue;

        } else if (on_node == NULL) {
            crm_trace("Action %s matches (ignoring node)", key);
            result = g_list_prepend(result, action);

        } else if (action->node == NULL) {
            crm_trace("Action %s matches (unallocated, assigning to %s)",
                      key, pe__node_name(on_node));

            action->node = pe__copy_node(on_node);
            result = g_list_prepend(result, action);

        } else if (on_node->details == action->node->details) {
            crm_trace("Action %s on %s matches", key, pe__node_name(on_node));
            result = g_list_prepend(result, action);
        }
    }

    return result;
}

GList *
find_actions_exact(GList *input, const char *key, const pcmk_node_t *on_node)
{
    GList *result = NULL;

    CRM_CHECK(key != NULL, return NULL);

    if (on_node == NULL) {
        return NULL;
    }

    for (GList *gIter = input; gIter != NULL; gIter = gIter->next) {
        pcmk_action_t *action = (pcmk_action_t *) gIter->data;

        if ((action->node != NULL)
            && pcmk__str_eq(key, action->uuid, pcmk__str_casei)
            && pcmk__str_eq(on_node->details->id, action->node->details->id,
                            pcmk__str_casei)) {

            crm_trace("Action %s on %s matches", key, pe__node_name(on_node));
            result = g_list_prepend(result, action);
        }
    }

    return result;
}

/*!
 * \brief Find all actions of given type for a resource
 *
 * \param[in] rsc           Resource to search
 * \param[in] node          Find only actions scheduled on this node
 * \param[in] task          Action name to search for
 * \param[in] require_node  If TRUE, NULL node or action node will not match
 *
 * \return List of actions found (or NULL if none)
 * \note If node is not NULL and require_node is FALSE, matching actions
 *       without a node will be assigned to node.
 */
GList *
pe__resource_actions(const pcmk_resource_t *rsc, const pcmk_node_t *node,
                     const char *task, bool require_node)
{
    GList *result = NULL;
    char *key = pcmk__op_key(rsc->id, task, 0);

    if (require_node) {
        result = find_actions_exact(rsc->actions, key, node);
    } else {
        result = find_actions(rsc->actions, key, node);
    }
    free(key);
    return result;
}

/*!
 * \internal
 * \brief Create an action reason string based on the action itself
 *
 * \param[in] action  Action to create reason string for
 * \param[in] flag    Action flag that was cleared
 *
 * \return Newly allocated string suitable for use as action reason
 * \note It is the caller's responsibility to free() the result.
 */
char *
pe__action2reason(const pcmk_action_t *action, enum pe_action_flags flag)
{
    const char *change = NULL;

    switch (flag) {
        case pcmk_action_runnable:
            change = "unrunnable";
            break;
        case pcmk_action_migratable:
            change = "unmigrateable";
            break;
        case pcmk_action_optional:
            change = "required";
            break;
        default:
            // Bug: caller passed unsupported flag
            CRM_CHECK(change != NULL, change = "");
            break;
    }
    return crm_strdup_printf("%s%s%s %s", change,
                             (action->rsc == NULL)? "" : " ",
                             (action->rsc == NULL)? "" : action->rsc->id,
                             action->task);
}

void pe_action_set_reason(pcmk_action_t *action, const char *reason,
                          bool overwrite)
{
    if (action->reason != NULL && overwrite) {
        pcmk__rsc_trace(action->rsc, "Changing %s reason from '%s' to '%s'",
                        action->uuid, action->reason,
                        pcmk__s(reason, "(none)"));
    } else if (action->reason == NULL) {
        pcmk__rsc_trace(action->rsc, "Set %s reason to '%s'",
                        action->uuid, pcmk__s(reason, "(none)"));
    } else {
        // crm_assert(action->reason != NULL && !overwrite);
        return;
    }

    pcmk__str_update(&action->reason, reason);
}

/*!
 * \internal
 * \brief Create an action to clear a resource's history from CIB
 *
 * \param[in,out] rsc       Resource to clear
 * \param[in]     node      Node to clear history on
 */
void
pe__clear_resource_history(pcmk_resource_t *rsc, const pcmk_node_t *node)
{
    CRM_ASSERT((rsc != NULL) && (node != NULL));

    custom_action(rsc, pcmk__op_key(rsc->id, PCMK_ACTION_LRM_DELETE, 0),
                  PCMK_ACTION_LRM_DELETE, node, FALSE, rsc->cluster);
}

#define sort_return(an_int, why) do {					\
	free(a_uuid);						\
	free(b_uuid);						\
	crm_trace("%s (%d) %c %s (%d) : %s",				\
		  a_xml_id, a_call_id, an_int>0?'>':an_int<0?'<':'=',	\
		  b_xml_id, b_call_id, why);				\
	return an_int;							\
    } while(0)

int
pe__is_newer_op(const xmlNode *xml_a, const xmlNode *xml_b,
                bool same_node_default)
{
    int a_call_id = -1;
    int b_call_id = -1;

    char *a_uuid = NULL;
    char *b_uuid = NULL;

    const char *a_xml_id = crm_element_value(xml_a, PCMK_XA_ID);
    const char *b_xml_id = crm_element_value(xml_b, PCMK_XA_ID);

    const char *a_node = crm_element_value(xml_a, XML_LRM_ATTR_TARGET);
    const char *b_node = crm_element_value(xml_b, XML_LRM_ATTR_TARGET);
    bool same_node = true;

    /* @COMPAT The on_node attribute was added to last_failure as of 1.1.13 (via
     * 8b3ca1c) and the other entries as of 1.1.12 (via 0b07b5c).
     *
     * In case that any of the lrm_rsc_op entries doesn't have on_node
     * attribute, we need to explicitly tell whether the two operations are on
     * the same node.
     */
    if (a_node == NULL || b_node == NULL) {
        same_node = same_node_default;

    } else {
        same_node = pcmk__str_eq(a_node, b_node, pcmk__str_casei);
    }

    if (same_node && pcmk__str_eq(a_xml_id, b_xml_id, pcmk__str_none)) {
        /* We have duplicate lrm_rsc_op entries in the status
         * section which is unlikely to be a good thing
         *    - we can handle it easily enough, but we need to get
         *    to the bottom of why it's happening.
         */
        pcmk__config_err("Duplicate lrm_rsc_op entries named %s", a_xml_id);
        sort_return(0, "duplicate");
    }

    crm_element_value_int(xml_a, XML_LRM_ATTR_CALLID, &a_call_id);
    crm_element_value_int(xml_b, XML_LRM_ATTR_CALLID, &b_call_id);

    if (a_call_id == -1 && b_call_id == -1) {
        /* both are pending ops so it doesn't matter since
         *   stops are never pending
         */
        sort_return(0, "pending");

    } else if (same_node && a_call_id >= 0 && a_call_id < b_call_id) {
        sort_return(-1, "call id");

    } else if (same_node && b_call_id >= 0 && a_call_id > b_call_id) {
        sort_return(1, "call id");

    } else if (a_call_id >= 0 && b_call_id >= 0
               && (!same_node || a_call_id == b_call_id)) {
        /*
         * The op and last_failed_op are the same
         * Order on last-rc-change
         */
        time_t last_a = -1;
        time_t last_b = -1;

        crm_element_value_epoch(xml_a, XML_RSC_OP_LAST_CHANGE, &last_a);
        crm_element_value_epoch(xml_b, XML_RSC_OP_LAST_CHANGE, &last_b);

        crm_trace("rc-change: %lld vs %lld",
                  (long long) last_a, (long long) last_b);
        if (last_a >= 0 && last_a < last_b) {
            sort_return(-1, "rc-change");

        } else if (last_b >= 0 && last_a > last_b) {
            sort_return(1, "rc-change");
        }
        sort_return(0, "rc-change");

    } else {
        /* One of the inputs is a pending operation.
         * Attempt to use PCMK__XA_TRANSITION_MAGIC to determine its age relative
         * to the other.
         */

        int a_id = -1;
        int b_id = -1;

        const char *a_magic = crm_element_value(xml_a,
                                                PCMK__XA_TRANSITION_MAGIC);
        const char *b_magic = crm_element_value(xml_b,
                                                PCMK__XA_TRANSITION_MAGIC);

        CRM_CHECK(a_magic != NULL && b_magic != NULL, sort_return(0, "No magic"));
        if (!decode_transition_magic(a_magic, &a_uuid, &a_id, NULL, NULL, NULL,
                                     NULL)) {
            sort_return(0, "bad magic a");
        }
        if (!decode_transition_magic(b_magic, &b_uuid, &b_id, NULL, NULL, NULL,
                                     NULL)) {
            sort_return(0, "bad magic b");
        }
        /* try to determine the relative age of the operation...
         * some pending operations (e.g. a start) may have been superseded
         *   by a subsequent stop
         *
         * [a|b]_id == -1 means it's a shutdown operation and _always_ comes last
         */
        if (!pcmk__str_eq(a_uuid, b_uuid, pcmk__str_casei) || a_id == b_id) {
            /*
             * some of the logic in here may be redundant...
             *
             * if the UUID from the TE doesn't match then one better
             *   be a pending operation.
             * pending operations don't survive between elections and joins
             *   because we query the LRM directly
             */

            if (b_call_id == -1) {
                sort_return(-1, "transition + call");

            } else if (a_call_id == -1) {
                sort_return(1, "transition + call");
            }

        } else if ((a_id >= 0 && a_id < b_id) || b_id == -1) {
            sort_return(-1, "transition");

        } else if ((b_id >= 0 && a_id > b_id) || a_id == -1) {
            sort_return(1, "transition");
        }
    }

    /* we should never end up here */
    CRM_CHECK(FALSE, sort_return(0, "default"));
}

gint
sort_op_by_callid(gconstpointer a, gconstpointer b)
{
    const xmlNode *xml_a = a;
    const xmlNode *xml_b = b;

    return pe__is_newer_op(xml_a, xml_b, true);
}

/*!
 * \internal
 * \brief Create a new pseudo-action for a resource
 *
 * \param[in,out] rsc       Resource to create action for
 * \param[in]     task      Action name
 * \param[in]     optional  Whether action should be considered optional
 * \param[in]     runnable  Whethe action should be considered runnable
 *
 * \return New action object corresponding to arguments
 */
pcmk_action_t *
pe__new_rsc_pseudo_action(pcmk_resource_t *rsc, const char *task, bool optional,
                          bool runnable)
{
    pcmk_action_t *action = NULL;

    CRM_ASSERT((rsc != NULL) && (task != NULL));

    action = custom_action(rsc, pcmk__op_key(rsc->id, task, 0), task, NULL,
                           optional, rsc->cluster);
    pcmk__set_action_flags(action, pcmk_action_pseudo);
    if (runnable) {
        pcmk__set_action_flags(action, pcmk_action_runnable);
    }
    return action;
}

/*!
 * \internal
 * \brief Add the expected result to an action
 *
 * \param[in,out] action           Action to add expected result to
 * \param[in]     expected_result  Expected result to add
 *
 * \note This is more efficient than calling add_hash_param().
 */
void
pe__add_action_expected_result(pcmk_action_t *action, int expected_result)
{
    char *name = NULL;

    CRM_ASSERT((action != NULL) && (action->meta != NULL));

    name = strdup(XML_ATTR_TE_TARGET_RC);
    CRM_ASSERT (name != NULL);

    g_hash_table_insert(action->meta, name, pcmk__itoa(expected_result));
}
