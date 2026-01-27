/*
 * Copyright 2004-2025 the Pacemaker project contributors
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
#include <crm/common/xml.h>
#include <crm/pengine/internal.h>
#include "pe_status_private.h"

static void unpack_operation(pcmk_action_t *action, const xmlNode *xml_obj,
                             guint interval_ms);

static void
add_singleton(pcmk_scheduler_t *scheduler, pcmk_action_t *action)
{
    if (scheduler->priv->singletons == NULL) {
        scheduler->priv->singletons = pcmk__strkey_table(NULL, NULL);
    }
    g_hash_table_insert(scheduler->priv->singletons, action->uuid, action);
}

static pcmk_action_t *
lookup_singleton(pcmk_scheduler_t *scheduler, const char *action_uuid)
{
    /* @TODO This is the only use of the pcmk_scheduler_t:singletons hash table.
     * Compare the performance of this approach to keeping the
     * pcmk_scheduler_t:actions list sorted by action key and just searching
     * that instead.
     */
    if (scheduler->priv->singletons == NULL) {
        return NULL;
    }
    return g_hash_table_lookup(scheduler->priv->singletons, action_uuid);
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
    /* When rsc is NULL, it would be quicker to check
     * scheduler->priv->singletons, but checking all scheduler->priv->actions
     * takes the node into account.
     */
    GList *actions = (rsc == NULL)? scheduler->priv->actions : rsc->priv->actions;
    GList *matches = find_actions(actions, key, node);
    pcmk_action_t *action = NULL;

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
    for (xmlNode *operation = pcmk__xe_first_child(rsc->priv->ops_xml,
                                                   PCMK_XE_OP, NULL, NULL);
         operation != NULL; operation = pcmk__xe_next(operation, PCMK_XE_OP)) {

        bool enabled = false;
        const char *config_name = NULL;
        const char *interval_spec = NULL;
        guint tmp_ms = 0U;

        // @TODO This does not consider meta-attributes, rules, defaults, etc.
        if (!include_disabled
            && (pcmk__xe_get_bool(operation, PCMK_META_ENABLED,
                                  &enabled) == pcmk_rc_ok)
	        && !enabled) {
            continue;
        }

        interval_spec = pcmk__xe_get(operation, PCMK_META_INTERVAL);
        pcmk_parse_interval_spec(interval_spec, &tmp_ms);
        if (tmp_ms != interval_ms) {
            continue;
        }

        config_name = pcmk__xe_get(operation, PCMK_XA_NAME);
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
 *       responsibility to free the return value using pcmk__free_action().
 */
static pcmk_action_t *
new_action(char *key, const char *task, pcmk_resource_t *rsc,
           const pcmk_node_t *node, bool optional, pcmk_scheduler_t *scheduler)
{
    pcmk_action_t *action = pcmk__assert_alloc(1, sizeof(pcmk_action_t));

    action->rsc = rsc;
    action->task = pcmk__str_copy(task);
    action->uuid = key;
    action->scheduler = scheduler;

    if (node) {
        action->node = pe__copy_node(node);
    }

    if (pcmk__str_eq(task, PCMK_ACTION_LRM_DELETE, pcmk__str_casei)) {
        // Resource history deletion for a node can be done on the DC
        pcmk__set_action_flags(action, pcmk__action_on_dc);
    }

    pcmk__set_action_flags(action, pcmk__action_runnable);
    if (optional) {
        pcmk__set_action_flags(action, pcmk__action_optional);
    } else {
        pcmk__clear_action_flags(action, pcmk__action_optional);
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
                    scheduler->priv->next_action_id, key, task,
                    ((rsc == NULL)? "no resource" : rsc->id),
                    pcmk__node_name(node));
    action->id = scheduler->priv->next_action_id++;

    scheduler->priv->actions = g_list_prepend(scheduler->priv->actions, action);
    if (rsc == NULL) {
        add_singleton(scheduler, action);
    } else {
        rsc->priv->actions = g_list_prepend(rsc->priv->actions, action);
    }
    return action;
}

/*!
 * \internal
 * \brief Unpack a resource's action-specific instance parameters
 *
 * \param[in]     action_xml  XML of action's configuration in CIB (if any)
 * \param[in,out] node_attrs  Table of node attributes (for rule evaluation)
 * \param[in,out] scheduler   Scheduler data (for rule evaluation)
 *
 * \return Newly allocated hash table of action-specific instance parameters
 */
GHashTable *
pcmk__unpack_action_rsc_params(const xmlNode *action_xml,
                               GHashTable *node_attrs,
                               pcmk_scheduler_t *scheduler)
{
    GHashTable *params = pcmk__strkey_table(free, free);

    const pcmk_rule_input_t rule_input = {
        .now = scheduler->priv->now,
        .node_attrs = node_attrs,
    };

    pe__unpack_dataset_nvpairs(action_xml, PCMK_XE_INSTANCE_ATTRIBUTES,
                               &rule_input, params, NULL, scheduler);
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
        && !pcmk__is_set(action->flags, pcmk__action_pseudo)
        && !pcmk__is_set(action->rsc->flags, pcmk__rsc_managed)
        && (g_hash_table_lookup(action->meta, PCMK_META_INTERVAL) == NULL)) {
            pcmk__rsc_debug(action->rsc,
                            "%s on %s is optional (%s is unmanaged)",
                            action->uuid, pcmk__node_name(action->node),
                            action->rsc->id);
            pcmk__set_action_flags(action, pcmk__action_optional);
            // We shouldn't clear runnable here because ... something

    // Otherwise require the action if requested
    } else if (!optional) {
        pcmk__clear_action_flags(action, pcmk__action_optional);
    }
}

static enum pe_quorum_policy
effective_quorum_policy(pcmk_resource_t *rsc, pcmk_scheduler_t *scheduler)
{
    enum pe_quorum_policy policy = scheduler->no_quorum_policy;

    if (pcmk__is_set(scheduler->flags, pcmk__sched_quorate)) {
        policy = pcmk_no_quorum_ignore;

    } else if (scheduler->no_quorum_policy == pcmk_no_quorum_demote) {
        switch (rsc->priv->orig_role) {
            case pcmk_role_promoted:
            case pcmk_role_unpromoted:
                if (rsc->priv->next_role > pcmk_role_unpromoted) {
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
    pcmk_resource_t *rsc = action->rsc;

    if (pcmk__is_set(action->flags, pcmk__action_pseudo)) {
        return;
    }

    if (action->node == NULL) {
        pcmk__rsc_trace(rsc, "%s is unrunnable (unallocated)", action->uuid);
        pcmk__clear_action_flags(action, pcmk__action_runnable);

    } else if (!pcmk__is_set(action->flags, pcmk__action_on_dc)
               && !(action->node->details->online)
               && (!pcmk__is_guest_or_bundle_node(action->node)
                   || pcmk__is_set(action->node->priv->flags,
                                   pcmk__node_remote_reset))) {
        pcmk__clear_action_flags(action, pcmk__action_runnable);
        do_crm_log(LOG_WARNING, "%s on %s is unrunnable (node is offline)",
                   action->uuid, pcmk__node_name(action->node));
        if (pcmk__is_set(rsc->flags, pcmk__rsc_managed)
            && pcmk__str_eq(action->task, PCMK_ACTION_STOP, pcmk__str_casei)
            && !(action->node->details->unclean)) {
            pe_fence_node(scheduler, action->node, "stop is unrunnable", false);
        }

    } else if (!pcmk__is_set(action->flags, pcmk__action_on_dc)
               && action->node->details->pending) {
        pcmk__clear_action_flags(action, pcmk__action_runnable);
        do_crm_log(LOG_WARNING,
                   "Action %s on %s is unrunnable (node is pending)",
                   action->uuid, pcmk__node_name(action->node));

    } else if (action->needs == pcmk__requires_nothing) {
        pe_action_set_reason(action, NULL, TRUE);
        if (pcmk__is_guest_or_bundle_node(action->node)
            && !pe_can_fence(scheduler, action->node)) {
            /* An action that requires nothing usually does not require any
             * fencing in order to be runnable. However, there is an exception:
             * such an action cannot be completed if it is on a guest node whose
             * host is unclean and cannot be fenced.
             */
            pcmk__rsc_debug(rsc,
                            "%s on %s is unrunnable "
                            "(node's host cannot be fenced)",
                            action->uuid, pcmk__node_name(action->node));
            pcmk__clear_action_flags(action, pcmk__action_runnable);
        } else {
            pcmk__rsc_trace(rsc,
                            "%s on %s does not require fencing or quorum",
                            action->uuid, pcmk__node_name(action->node));
            pcmk__set_action_flags(action, pcmk__action_runnable);
        }

    } else {
        switch (effective_quorum_policy(rsc, scheduler)) {
            case pcmk_no_quorum_stop:
                pcmk__rsc_debug(rsc, "%s on %s is unrunnable (no quorum)",
                                action->uuid, pcmk__node_name(action->node));
                pcmk__clear_action_flags(action, pcmk__action_runnable);
                pe_action_set_reason(action, "no quorum", true);
                break;

            case pcmk_no_quorum_freeze:
                if (!rsc->priv->fns->active(rsc, true)
                    || (rsc->priv->next_role > rsc->priv->orig_role)) {
                    pcmk__rsc_debug(rsc, "%s on %s is unrunnable (no quorum)",
                                    action->uuid,
                                    pcmk__node_name(action->node));
                    pcmk__clear_action_flags(action, pcmk__action_runnable);
                    pe_action_set_reason(action, "quorum freeze", true);
                }
                break;

            default:
                //pe_action_set_reason(action, NULL, TRUE);
                pcmk__set_action_flags(action, pcmk__action_runnable);
                break;
        }
    }
}

static bool
valid_stop_on_fail(const char *value)
{
    return !pcmk__strcase_any_of(value,
                                 PCMK_VALUE_STANDBY, PCMK_VALUE_DEMOTE,
                                 PCMK_VALUE_STOP, NULL);
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
        for (xmlNode *operation = pcmk__xe_first_child(rsc->priv->ops_xml,
                                                       PCMK_XE_OP, NULL, NULL);
             operation != NULL;
             operation = pcmk__xe_next(operation, PCMK_XE_OP)) {

            bool enabled = false;
            const char *promote_on_fail = NULL;

            /* We only care about explicit on-fail (if promote uses default, so
             * can demote)
             */
            promote_on_fail = pcmk__xe_get(operation, PCMK_META_ON_FAIL);
            if (promote_on_fail == NULL) {
                continue;
            }

            // We only care about recurring monitors for the promoted role
            name = pcmk__xe_get(operation, PCMK_XA_NAME);
            role = pcmk__xe_get(operation, PCMK_XA_ROLE);
            if (!pcmk__str_eq(name, PCMK_ACTION_MONITOR, pcmk__str_none)
                || !pcmk__strcase_any_of(role, PCMK_ROLE_PROMOTED,
                                         PCMK__ROLE_PROMOTED_LEGACY, NULL)) {
                continue;
            }
            interval_spec = pcmk__xe_get(operation, PCMK_META_INTERVAL);
            pcmk_parse_interval_spec(interval_spec, &interval_ms);
            if (interval_ms == 0U) {
                continue;
            }

            // We only care about enabled monitors
            if ((pcmk__xe_get_bool(operation, PCMK_META_ENABLED,
                                   &enabled) == pcmk_rc_ok)
                && !enabled) {
                continue;
            }

            /* Demote actions can't default to
             * PCMK_META_ON_FAIL=PCMK_VALUE_DEMOTE
             */
            if (pcmk__str_eq(promote_on_fail, PCMK_VALUE_DEMOTE,
                             pcmk__str_casei)) {
                continue;
            }

            // Use value from first applicable promote action found
            pcmk__insert_dup(meta, PCMK_META_ON_FAIL, promote_on_fail);
        }
        return;
    }

    if (pcmk__str_eq(action_name, PCMK_ACTION_LRM_DELETE, pcmk__str_none)
        && !pcmk__str_eq(value, PCMK_VALUE_IGNORE, pcmk__str_casei)) {

        pcmk__insert_dup(meta, PCMK_META_ON_FAIL, PCMK_VALUE_IGNORE);
        return;
    }

    // PCMK_META_ON_FAIL=PCMK_VALUE_DEMOTE is allowed only for certain actions
    if (pcmk__str_eq(value, PCMK_VALUE_DEMOTE, pcmk__str_casei)) {
        name = pcmk__xe_get(action_config, PCMK_XA_NAME);
        role = pcmk__xe_get(action_config, PCMK_XA_ROLE);
        interval_spec = pcmk__xe_get(action_config, PCMK_META_INTERVAL);
        pcmk_parse_interval_spec(interval_spec, &interval_ms);

        if (!pcmk__str_eq(name, PCMK_ACTION_PROMOTE, pcmk__str_none)
            && ((interval_ms == 0U)
                || !pcmk__str_eq(name, PCMK_ACTION_MONITOR, pcmk__str_none)
                || !pcmk__strcase_any_of(role, PCMK_ROLE_PROMOTED,
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
    long long timeout_ms = 0;

    if ((value == NULL) || (pcmk__parse_ms(value, &timeout_ms) != pcmk_rc_ok)
        || (timeout_ms <= 0)) {

        timeout_ms = PCMK_DEFAULT_ACTION_TIMEOUT_MS;
    }
    return (int) QB_MIN(timeout_ms, INT_MAX);
}

// true if value contains valid, non-NULL interval origin for recurring op
static bool
unpack_interval_origin(const char *value, const xmlNode *xml_obj,
                       guint interval_ms, const crm_time_t *now,
                       long long *start_delay)
{
    long long result = 0;
    guint interval_sec = pcmk__timeout_ms2s(interval_ms);
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
                         pcmk__s(pcmk__xe_id(xml_obj), "(missing ID)"), value);
        return false;
    }

    // Get seconds since origin (negative if origin is in the future)
    result = crm_time_get_seconds(now) - crm_time_get_seconds(origin);
    crm_time_free(origin);

    // Calculate seconds from closest interval to now
    result = result % interval_sec;

    // Calculate seconds remaining until next interval
    result = ((result <= 0)? 0 : interval_sec) - result;
    pcmk__info("Calculated a start delay of %llds for operation '%s'", result,
               pcmk__s(pcmk__xe_id(xml_obj), "(unspecified)"));

    if (start_delay != NULL) {
        *start_delay = result * 1000; // milliseconds
    }
    return true;
}

static int
unpack_start_delay(const char *value, GHashTable *meta)
{
    long long start_delay_ms = 0;

    if (value == NULL) {
        return 0;
    }

    if (pcmk__parse_ms(value, &start_delay_ms) == pcmk_rc_ok) {
        start_delay_ms = QB_MAX(start_delay_ms, 0);
        start_delay_ms = QB_MIN(start_delay_ms, INT_MAX);
    }

    if (meta != NULL) {
        g_hash_table_replace(meta, strdup(PCMK_META_START_DELAY),
                             pcmk__itoa((int) start_delay_ms));
    }

    return (int) start_delay_ms;
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

    for (xmlNode *operation = pcmk__xe_first_child(rsc->priv->ops_xml,
                                                   PCMK_XE_OP, NULL, NULL);
         operation != NULL; operation = pcmk__xe_next(operation, PCMK_XE_OP)) {

        bool enabled = false;
        guint interval_ms = 0U;
        const char *interval_spec = pcmk__xe_get(operation, PCMK_META_INTERVAL);

        // We only care about enabled recurring monitors
        if (!pcmk__str_eq(pcmk__xe_get(operation, PCMK_XA_NAME),
                          PCMK_ACTION_MONITOR, pcmk__str_none)) {
            continue;
        }

        pcmk_parse_interval_spec(interval_spec, &interval_ms);
        if (interval_ms == 0U) {
            continue;
        }

        // @TODO This does not consider meta-attributes, rules, defaults, etc.
        if ((pcmk__xe_get_bool(operation, PCMK_META_ENABLED,
                               &enabled) == pcmk_rc_ok)
            && !enabled) {
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
    const char *timeout_spec = NULL;
    const char *str = NULL;

    const pcmk_rule_input_t rule_input = {
        /* Node attributes are not set because node expressions are not allowed
         * for meta-attributes
         */
        .now = rsc->priv->scheduler->priv->now,
        .rsc_standard = pcmk__xe_get(rsc->priv->xml, PCMK_XA_CLASS),
        .rsc_provider = pcmk__xe_get(rsc->priv->xml, PCMK_XA_PROVIDER),
        .rsc_agent = pcmk__xe_get(rsc->priv->xml, PCMK_XA_TYPE),
        .op_name = action_name,
        .op_interval_ms = interval_ms,
    };

    meta = pcmk__strkey_table(free, free);

    if (action_config != NULL) {
        // <op> <meta_attributes> take precedence over defaults
        pe__unpack_dataset_nvpairs(action_config, PCMK_XE_META_ATTRIBUTES,
                                   &rule_input, meta, NULL,
                                   rsc->priv->scheduler);

        /* Anything set as an <op> XML property has highest precedence.
         * This ensures we use the name and interval from the <op> tag.
         * (See below for the only exception, fence device start/probe timeout.)
         */
        pcmk__xe_foreach_const_attr(action_config, pcmk__xa_insert_dup, meta);
    }

    // Derive default timeout for probes from recurring monitor timeouts
    if (pcmk_is_probe(action_name, interval_ms)
        && (g_hash_table_lookup(meta, PCMK_META_TIMEOUT) == NULL)) {

        xmlNode *min_interval_mon = most_frequent_monitor(rsc);

        if (min_interval_mon != NULL) {
            /* @TODO This does not consider timeouts set in
             * PCMK_XE_META_ATTRIBUTES blocks (which may also have rules that
             * need to be evaluated).
             */
            timeout_spec = pcmk__xe_get(min_interval_mon, PCMK_META_TIMEOUT);
            if (timeout_spec != NULL) {
                pcmk__rsc_trace(rsc,
                                "Setting default timeout for %s probe to "
                                "most frequent monitor's timeout '%s'",
                                rsc->id, timeout_spec);
                pcmk__insert_dup(meta, PCMK_META_TIMEOUT, timeout_spec);
            }
        }
    }

    // Cluster-wide <op_defaults> <meta_attributes>
    pe__unpack_dataset_nvpairs(rsc->priv->scheduler->priv->op_defaults,
                               PCMK_XE_META_ATTRIBUTES, &rule_input, meta, NULL,
                               rsc->priv->scheduler);

    g_hash_table_remove(meta, PCMK_XA_ID);

    // Normalize interval to milliseconds
    if (interval_ms > 0) {
        g_hash_table_insert(meta, pcmk__str_copy(PCMK_META_INTERVAL),
                            pcmk__assert_asprintf("%u", interval_ms));
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
    if (pcmk__is_set(pcmk_get_ra_caps(rule_input.rsc_standard),
                     pcmk_ra_cap_fence_params)
        && (pcmk__str_eq(action_name, PCMK_ACTION_START, pcmk__str_none)
            || pcmk_is_probe(action_name, interval_ms))) {

        GHashTable *params = pe_rsc_params(rsc, node, rsc->priv->scheduler);

        timeout_spec = g_hash_table_lookup(params, "pcmk_monitor_timeout");
        if (timeout_spec != NULL) {
            pcmk__rsc_trace(rsc,
                            "Setting timeout for %s %s to "
                            "pcmk_monitor_timeout (%s)",
                            rsc->id, action_name, timeout_spec);
            pcmk__insert_dup(meta, PCMK_META_TIMEOUT, timeout_spec);
        }
    }

    // Normalize timeout to positive milliseconds
    timeout_spec = g_hash_table_lookup(meta, PCMK_META_TIMEOUT);
    g_hash_table_insert(meta, pcmk__str_copy(PCMK_META_TIMEOUT),
                        pcmk__itoa(unpack_timeout(timeout_spec)));

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
                                   rsc->priv->scheduler->priv->now,
                                   &start_delay)) {
            g_hash_table_insert(meta, pcmk__str_copy(PCMK_META_START_DELAY),
                                pcmk__assert_asprintf("%lld", start_delay));
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
enum pcmk__requires
pcmk__action_requires(const pcmk_resource_t *rsc, const char *action_name)
{
    const char *value = NULL;
    enum pcmk__requires requires = pcmk__requires_nothing;

    CRM_CHECK((rsc != NULL) && (action_name != NULL), return requires);

    if (!pcmk__strcase_any_of(action_name, PCMK_ACTION_START,
                              PCMK_ACTION_PROMOTE, NULL)) {
        value = "nothing (not start or promote)";

    } else if (pcmk__is_set(rsc->flags, pcmk__rsc_needs_fencing)) {
        requires = pcmk__requires_fencing;
        value = "fencing";

    } else if (pcmk__is_set(rsc->flags, pcmk__rsc_needs_quorum)) {
        requires = pcmk__requires_quorum;
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
enum pcmk__on_fail
pcmk__parse_on_fail(const pcmk_resource_t *rsc, const char *action_name,
                    guint interval_ms, const char *value)
{
    const char *desc = NULL;
    bool needs_remote_reset = false;
    enum pcmk__on_fail on_fail = pcmk__on_fail_ignore;
    const pcmk_scheduler_t *scheduler = NULL;

    // There's no enum value for unknown or invalid, so assert
    pcmk__assert((rsc != NULL) && (action_name != NULL));
    scheduler = rsc->priv->scheduler;

    if (value == NULL) {
        // Use default

    } else if (pcmk__str_eq(value, PCMK_VALUE_BLOCK, pcmk__str_casei)) {
        on_fail = pcmk__on_fail_block;
        desc = "block";

    } else if (pcmk__str_eq(value, PCMK_VALUE_FENCE, pcmk__str_casei)) {
        if (pcmk__is_set(scheduler->flags, pcmk__sched_fencing_enabled)) {
            on_fail = pcmk__on_fail_fence_node;
            desc = "node fencing";
        } else {
            pcmk__config_err("Resetting '" PCMK_META_ON_FAIL "' for "
                             "%s of %s to 'stop' because 'fence' is not "
                             "valid when fencing is disabled",
                             action_name, rsc->id);
            /* @TODO This should probably do
            g_hash_table_remove(meta, PCMK_META_ON_FAIL);
            like the other "Resetting" spots, to avoid repeating the message
            */
            on_fail = pcmk__on_fail_stop;
            desc = "stop resource";
        }

    } else if (pcmk__str_eq(value, PCMK_VALUE_STANDBY, pcmk__str_casei)) {
        on_fail = pcmk__on_fail_standby_node;
        desc = "node standby";

    } else if (pcmk__strcase_any_of(value,
                                    PCMK_VALUE_IGNORE, PCMK_VALUE_NOTHING,
                                    NULL)) {
        desc = "ignore";

    } else if (pcmk__str_eq(value, "migrate", pcmk__str_casei)) {
        on_fail = pcmk__on_fail_ban;
        desc = "force migration";

    } else if (pcmk__str_eq(value, PCMK_VALUE_STOP, pcmk__str_casei)) {
        on_fail = pcmk__on_fail_stop;
        desc = "stop resource";

    } else if (pcmk__str_eq(value, PCMK_VALUE_RESTART, pcmk__str_casei)) {
        on_fail = pcmk__on_fail_restart;
        desc = "restart (and possibly migrate)";

    } else if (pcmk__str_eq(value, PCMK_VALUE_RESTART_CONTAINER,
                            pcmk__str_casei)) {
        if (rsc->priv->launcher == NULL) {
            pcmk__rsc_debug(rsc,
                            "Using default " PCMK_META_ON_FAIL " for %s "
                            "of %s because it does not have a launcher",
                            action_name, rsc->id);
        } else {
            on_fail = pcmk__on_fail_restart_container;
            desc = "restart container (and possibly migrate)";
        }

    } else if (pcmk__str_eq(value, PCMK_VALUE_DEMOTE, pcmk__str_casei)) {
        on_fail = pcmk__on_fail_demote;
        desc = "demote instance";

    } else {
        pcmk__config_err("Using default '" PCMK_META_ON_FAIL "' for "
                         "%s of %s because '%s' is not valid",
                         action_name, rsc->id, value);
    }

    /* Remote node connections are handled specially. Failures that result
     * in dropping an active connection must result in fencing. The only
     * failures that don't are probes and starts. The user can explicitly set
     * PCMK_META_ON_FAIL=PCMK_VALUE_FENCE to fence after start failures.
     */
    if (pcmk__is_set(rsc->flags, pcmk__rsc_is_remote_connection)
        && pcmk__is_remote_node(pcmk_find_node(scheduler, rsc->id))
        && !pcmk_is_probe(action_name, interval_ms)
        && !pcmk__str_eq(action_name, PCMK_ACTION_START, pcmk__str_none)) {
        needs_remote_reset = true;
        if (!pcmk__is_set(rsc->flags, pcmk__rsc_managed)) {
            desc = NULL; // Force default for unmanaged connections
        }
    }

    if (desc != NULL) {
        // Explicit value used, default not needed

    } else if (rsc->priv->launcher != NULL) {
        on_fail = pcmk__on_fail_restart_container;
        desc = "restart container (and possibly migrate) (default)";

    } else if (needs_remote_reset) {
        if (pcmk__is_set(rsc->flags, pcmk__rsc_managed)) {
            if (pcmk__is_set(scheduler->flags, pcmk__sched_fencing_enabled)) {
                desc = "fence remote node (default)";
            } else {
                desc = "recover remote node connection (default)";
            }
            on_fail = pcmk__on_fail_reset_remote;
        } else {
            on_fail = pcmk__on_fail_stop;
            desc = "stop unmanaged remote node (enforcing default)";
        }

    } else if (pcmk__str_eq(action_name, PCMK_ACTION_STOP, pcmk__str_none)) {
        if (pcmk__is_set(scheduler->flags, pcmk__sched_fencing_enabled)) {
            on_fail = pcmk__on_fail_fence_node;
            desc = "resource fence (default)";
        } else {
            on_fail = pcmk__on_fail_block;
            desc = "resource block (default)";
        }

    } else {
        on_fail = pcmk__on_fail_restart;
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
                         enum pcmk__on_fail on_fail, GHashTable *meta)
{
    enum rsc_role_e role = pcmk_role_unknown;

    // Set default for role after failure specially in certain circumstances
    switch (on_fail) {
        case pcmk__on_fail_stop:
            role = pcmk_role_stopped;
            break;

        case pcmk__on_fail_reset_remote:
            if (rsc->priv->remote_reconnect_ms != 0U) {
                role = pcmk_role_stopped;
            }
            break;

        default:
            break;
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
                    rsc->id, action_name, pcmk_role_text(role));
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

    pcmk__assert((key != NULL) && (task != NULL) && (scheduler != NULL));

    action = find_existing_action(key, rsc, on_node, scheduler);
    if (action == NULL) {
        action = new_action(key, task, rsc, on_node, optional, scheduler);
    } else {
        free(key);
    }

    update_action_optional(action, optional);

    if (rsc != NULL) {
        /* An action can be initially created with a NULL node, and later have
         * the node added via find_existing_action() (above) -> find_actions().
         * That is why the extra parameters are unpacked here rather than in
         * new_action().
         */
        if ((action->node != NULL) && (action->op_entry != NULL)
            && !pcmk__is_set(action->flags, pcmk__action_attrs_evaluated)) {

            GHashTable *attrs = action->node->priv->attrs;

            if (action->extra != NULL) {
                g_hash_table_destroy(action->extra);
            }
            action->extra = pcmk__unpack_action_rsc_params(action->op_entry,
                                                           attrs, scheduler);
            pcmk__set_action_flags(action, pcmk__action_attrs_evaluated);
        }

        update_resource_action_runnable(action, scheduler);
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
        pcmk__set_action_flags(op, pcmk__action_pseudo|pcmk__action_runnable);
    }
    return op;
}

static GList *
find_unfencing_devices(GList *candidates, GList *matches)
{
    for (GList *gIter = candidates; gIter != NULL; gIter = gIter->next) {
        pcmk_resource_t *candidate = gIter->data;

        if (candidate->priv->children != NULL) {
            matches = find_unfencing_devices(candidate->priv->children,
                                             matches);

        } else if (!pcmk__is_set(candidate->flags, pcmk__rsc_fence_device)) {
            continue;

        } else if (pcmk__is_set(candidate->flags, pcmk__rsc_needs_unfencing)) {
            matches = g_list_prepend(matches, candidate);

        } else if (pcmk__str_eq(g_hash_table_lookup(candidate->priv->meta,
                                                    PCMK_FENCING_PROVIDES),
                                PCMK_VALUE_UNFENCING, pcmk__str_casei)) {
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
    if (scheduler->priv->priority_fencing_ms == 0U) {
        return 0;
    }

    /* No need to request a delay if the fencing target is not a normal cluster
     * member, for example if it's a remote node or a guest node. */
    if (node->priv->variant != pcmk__node_variant_cluster) {
        return 0;
    }

    // No need to request a delay if the fencing target is in our partition
    if (node->details->online) {
        return 0;
    }

    for (gIter = scheduler->nodes; gIter != NULL; gIter = gIter->next) {
        pcmk_node_t *n = gIter->data;

        if (n->priv->variant != pcmk__node_variant_cluster) {
            continue;
        }

        member_count ++;

        if (n->details->online) {
            online_count++;
        }

        if (member_count == 1
            || n->priv->priority > top_priority) {
            top_priority = n->priv->priority;
        }

        if (member_count == 1
            || n->priv->priority < lowest_priority) {
            lowest_priority = n->priv->priority;
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

    if (node->priv->priority < top_priority) {
        return 0;
    }

    return pcmk__timeout_ms2s(scheduler->priv->priority_fencing_ms);
}

pcmk_action_t *
pe_fence_op(pcmk_node_t *node, const char *op, bool optional,
            const char *reason, bool priority_delay,
            pcmk_scheduler_t *scheduler)
{
    char *op_key = NULL;
    pcmk_action_t *fencing_op = NULL;

    if(op == NULL) {
        op = scheduler->priv->fence_action;
    }

    op_key = pcmk__assert_asprintf("%s-%s-%s",
                                   PCMK_ACTION_STONITH, node->priv->name, op);

    fencing_op = lookup_singleton(scheduler, op_key);
    if (fencing_op == NULL) {
        fencing_op = custom_action(NULL, op_key, PCMK_ACTION_STONITH, node,
                                   TRUE, scheduler);

        pcmk__insert_meta(fencing_op, PCMK__META_ON_NODE, node->priv->name);
        pcmk__insert_meta(fencing_op, PCMK__META_ON_NODE_UUID, node->priv->id);
        pcmk__insert_meta(fencing_op, PCMK__META_STONITH_ACTION, op);

        if (pcmk__is_set(scheduler->flags, pcmk__sched_enable_unfencing)) {
            /* Extra work to detect device changes
             */
            GString *digests_all = g_string_sized_new(1024);
            GString *digests_secure = g_string_sized_new(1024);

            GList *matches = find_unfencing_devices(scheduler->priv->resources,
                                                    NULL);

            for (GList *gIter = matches; gIter != NULL; gIter = gIter->next) {
                pcmk_resource_t *match = gIter->data;
                const char *agent = g_hash_table_lookup(match->priv->meta,
                                                        PCMK_XA_TYPE);
                pcmk__op_digest_t *data = NULL;

                data = pe__compare_fencing_digest(match, agent, node,
                                                  scheduler);
                if (data->rc == pcmk__digest_mismatch) {
                    optional = FALSE;
                    pcmk__notice("Unfencing node %s because the definition of "
                                 "%s changed",
                                 pcmk__node_name(node), match->id);
                    if (!pcmk__is_daemon && (scheduler->priv->out != NULL)) {
                        pcmk__output_t *out = scheduler->priv->out;

                        out->info(out,
                                  "notice: Unfencing node %s because the "
                                  "definition of %s changed",
                                  pcmk__node_name(node), match->id);
                    }
                }

                pcmk__g_strcat(digests_all,
                               match->id, ":", agent, ":",
                               data->digest_all_calc, ",", NULL);
                pcmk__g_strcat(digests_secure,
                               match->id, ":", agent, ":",
                               data->digest_secure_calc, ",", NULL);
            }
            pcmk__insert_dup(fencing_op->meta, PCMK__META_DIGESTS_ALL,
                             digests_all->str);
            g_string_free(digests_all, TRUE);

            pcmk__insert_dup(fencing_op->meta, PCMK__META_DIGESTS_SECURE,
                             digests_secure->str);
            g_string_free(digests_secure, TRUE);

            g_list_free(matches);
        }

    } else {
        free(op_key);
    }

    if ((scheduler->priv->priority_fencing_ms > 0U)

            /* It's a suitable case where PCMK_OPT_PRIORITY_FENCING_DELAY
             * applies. At least add PCMK_OPT_PRIORITY_FENCING_DELAY field as
             * an indicator.
             */
        && (priority_delay

            /* The priority delay needs to be recalculated if this function has
             * been called by schedule_fencing_and_shutdowns() after node
             * priority has already been calculated by native_add_running().
             */
            || g_hash_table_lookup(fencing_op->meta,
                                   PCMK_OPT_PRIORITY_FENCING_DELAY) != NULL)) {

            /* Add PCMK_OPT_PRIORITY_FENCING_DELAY to the fencing op even if
             * it's 0 for the targeting node. So that it takes precedence over
             * any possible `pcmk_delay_base/max`.
             */
            char *delay_s = pcmk__itoa(node_priority_fencing_delay(node,
                                                                   scheduler));

            g_hash_table_insert(fencing_op->meta,
                                strdup(PCMK_OPT_PRIORITY_FENCING_DELAY),
                                delay_s);
    }

    if(optional == FALSE && pe_can_fence(scheduler, node)) {
        pcmk__clear_action_flags(fencing_op, pcmk__action_optional);
        pe_action_set_reason(fencing_op, reason, false);

    } else if ((reason != NULL) && (fencing_op->reason == NULL)) {
        fencing_op->reason = strdup(reason);
    }

    return fencing_op;
}

enum pcmk__action_type
get_complex_task(const pcmk_resource_t *rsc, const char *name)
{
    enum pcmk__action_type task = pcmk__parse_action(name);

    if (pcmk__is_primitive(rsc)) {
        switch (task) {
            case pcmk__action_stopped:
            case pcmk__action_started:
            case pcmk__action_demoted:
            case pcmk__action_promoted:
                pcmk__trace("Folding %s back into its atomic counterpart for "
                            "%s",
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

        } else if (pcmk__same_node(on_node, action->node)) {
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
            pcmk__trace("Action %s matches (ignoring node)", key);
            result = g_list_prepend(result, action);

        } else if (action->node == NULL) {
            pcmk__trace("Action %s matches (unallocated, assigning to %s)", key,
                        pcmk__node_name(on_node));

            action->node = pe__copy_node(on_node);
            result = g_list_prepend(result, action);

        } else if (pcmk__same_node(on_node, action->node)) {
            pcmk__trace("Action %s on %s matches", key,
                        pcmk__node_name(on_node));
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
            && pcmk__same_node(on_node, action->node)) {

            pcmk__trace("Action %s on %s matches", key,
                        pcmk__node_name(on_node));
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
        result = find_actions_exact(rsc->priv->actions, key, node);
    } else {
        result = find_actions(rsc->priv->actions, key, node);
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
pe__action2reason(const pcmk_action_t *action, enum pcmk__action_flags flag)
{
    const char *change = NULL;

    switch (flag) {
        case pcmk__action_runnable:
            change = "unrunnable";
            break;
        case pcmk__action_migratable:
            change = "unmigrateable";
            break;
        case pcmk__action_optional:
            change = "required";
            break;
        default:
            // Bug: caller passed unsupported flag
            CRM_CHECK(change != NULL, change = "");
            break;
    }
    return pcmk__assert_asprintf("%s%s%s %s", change,
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
    pcmk__assert((rsc != NULL) && (node != NULL));

    custom_action(rsc, pcmk__op_key(rsc->id, PCMK_ACTION_LRM_DELETE, 0),
                  PCMK_ACTION_LRM_DELETE, node, FALSE, rsc->priv->scheduler);
}

#define sort_return(an_int, why) do {                                       \
        free(a_uuid);                                                       \
        free(b_uuid);                                                       \
        pcmk__trace("%s (%d) %c %s (%d) : %s",                              \
                    a_xml_id, a_call_id,                                    \
                    (((an_int) > 0)? '>' : (((an_int) < 0)? '<' : '=')),    \
                    b_xml_id, b_call_id, why);                              \
        return an_int;                                                      \
    } while(0)

int
pe__is_newer_op(const xmlNode *xml_a, const xmlNode *xml_b)
{
    int a_call_id = -1;
    int b_call_id = -1;

    char *a_uuid = NULL;
    char *b_uuid = NULL;

    const char *a_xml_id = pcmk__xe_get(xml_a, PCMK_XA_ID);
    const char *b_xml_id = pcmk__xe_get(xml_b, PCMK_XA_ID);

    const char *a_node = pcmk__xe_get(xml_a, PCMK__META_ON_NODE);
    const char *b_node = pcmk__xe_get(xml_b, PCMK__META_ON_NODE);
    bool same_node = pcmk__str_eq(a_node, b_node, pcmk__str_casei);

    if (same_node && pcmk__str_eq(a_xml_id, b_xml_id, pcmk__str_none)) {
        /* We have duplicate PCMK__XE_LRM_RSC_OP entries in the status
         * section which is unlikely to be a good thing
         *    - we can handle it easily enough, but we need to get
         *    to the bottom of why it's happening.
         */
        pcmk__config_err("Duplicate " PCMK__XE_LRM_RSC_OP " entries named %s",
                         a_xml_id);
        sort_return(0, "duplicate");
    }

    pcmk__xe_get_int(xml_a, PCMK__XA_CALL_ID, &a_call_id);
    pcmk__xe_get_int(xml_b, PCMK__XA_CALL_ID, &b_call_id);

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
        /* The op and last_failed_op are the same. Order on
         * PCMK_XA_LAST_RC_CHANGE.
         */
        time_t last_a = -1;
        time_t last_b = -1;

        pcmk__xe_get_time(xml_a, PCMK_XA_LAST_RC_CHANGE, &last_a);
        pcmk__xe_get_time(xml_b, PCMK_XA_LAST_RC_CHANGE, &last_b);

        pcmk__trace("rc-change: %lld vs %lld",
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

        const char *a_magic = pcmk__xe_get(xml_a, PCMK__XA_TRANSITION_MAGIC);
        const char *b_magic = pcmk__xe_get(xml_b, PCMK__XA_TRANSITION_MAGIC);

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
    return pe__is_newer_op((const xmlNode *) a, (const xmlNode *) b);
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

    pcmk__assert((rsc != NULL) && (task != NULL));

    action = custom_action(rsc, pcmk__op_key(rsc->id, task, 0), task, NULL,
                           optional, rsc->priv->scheduler);
    pcmk__set_action_flags(action, pcmk__action_pseudo);
    if (runnable) {
        pcmk__set_action_flags(action, pcmk__action_runnable);
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
 * \note This is more efficient than calling pcmk__insert_meta().
 */
void
pe__add_action_expected_result(pcmk_action_t *action, int expected_result)
{
    pcmk__assert((action != NULL) && (action->meta != NULL));

    g_hash_table_insert(action->meta, pcmk__str_copy(PCMK__META_OP_TARGET_RC),
                        pcmk__itoa(expected_result));
}
