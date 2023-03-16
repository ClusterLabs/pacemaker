/*
 * Copyright 2004-2022 the Pacemaker project contributors
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
#include <crm/pengine/internal.h>
#include "pe_status_private.h"

static void unpack_operation(pe_action_t *action, const xmlNode *xml_obj,
                             const pe_resource_t *container,
                             pe_working_set_t *data_set, guint interval_ms);

static void
add_singleton(pe_working_set_t *data_set, pe_action_t *action)
{
    if (data_set->singletons == NULL) {
        data_set->singletons = pcmk__strkey_table(NULL, NULL);
    }
    g_hash_table_insert(data_set->singletons, action->uuid, action);
}

static pe_action_t *
lookup_singleton(pe_working_set_t *data_set, const char *action_uuid)
{
    if (data_set->singletons == NULL) {
        return NULL;
    }
    return g_hash_table_lookup(data_set->singletons, action_uuid);
}

/*!
 * \internal
 * \brief Find an existing action that matches arguments
 *
 * \param[in] key        Action key to match
 * \param[in] rsc        Resource to match (if any)
 * \param[in] node       Node to match (if any)
 * \param[in] data_set   Cluster working set
 *
 * \return Existing action that matches arguments (or NULL if none)
 */
static pe_action_t *
find_existing_action(const char *key, const pe_resource_t *rsc,
                     const pe_node_t *node, const pe_working_set_t *data_set)
{
    GList *matches = NULL;
    pe_action_t *action = NULL;

    /* When rsc is NULL, it would be quicker to check data_set->singletons,
     * but checking all data_set->actions takes the node into account.
     */
    matches = find_actions(((rsc == NULL)? data_set->actions : rsc->actions),
                           key, node);
    if (matches == NULL) {
        return NULL;
    }
    CRM_LOG_ASSERT(!pcmk__list_of_multiple(matches));

    action = matches->data;
    g_list_free(matches);
    return action;
}

static xmlNode *
find_rsc_op_entry_helper(const pe_resource_t *rsc, const char *key,
                         gboolean include_disabled)
{
    guint interval_ms = 0;
    gboolean do_retry = TRUE;
    char *local_key = NULL;
    const char *name = NULL;
    const char *interval_spec = NULL;
    char *match_key = NULL;
    xmlNode *op = NULL;
    xmlNode *operation = NULL;

  retry:
    for (operation = pcmk__xe_first_child(rsc->ops_xml); operation != NULL;
         operation = pcmk__xe_next(operation)) {

        if (pcmk__str_eq((const char *)operation->name, "op", pcmk__str_none)) {
            bool enabled = false;

            name = crm_element_value(operation, "name");
            interval_spec = crm_element_value(operation, XML_LRM_ATTR_INTERVAL);
            if (!include_disabled && pcmk__xe_get_bool_attr(operation, "enabled", &enabled) == pcmk_rc_ok &&
                !enabled) {
                continue;
            }

            interval_ms = crm_parse_interval_spec(interval_spec);
            match_key = pcmk__op_key(rsc->id, name, interval_ms);
            if (pcmk__str_eq(key, match_key, pcmk__str_casei)) {
                op = operation;
            }
            free(match_key);

            if (rsc->clone_name) {
                match_key = pcmk__op_key(rsc->clone_name, name, interval_ms);
                if (pcmk__str_eq(key, match_key, pcmk__str_casei)) {
                    op = operation;
                }
                free(match_key);
            }

            if (op != NULL) {
                free(local_key);
                return op;
            }
        }
    }

    free(local_key);
    if (do_retry == FALSE) {
        return NULL;
    }

    do_retry = FALSE;
    if (strstr(key, CRMD_ACTION_MIGRATE) || strstr(key, CRMD_ACTION_MIGRATED)) {
        local_key = pcmk__op_key(rsc->id, "migrate", 0);
        key = local_key;
        goto retry;

    } else if (strstr(key, "_notify_")) {
        local_key = pcmk__op_key(rsc->id, "notify", 0);
        key = local_key;
        goto retry;
    }

    return NULL;
}

xmlNode *
find_rsc_op_entry(const pe_resource_t *rsc, const char *key)
{
    return find_rsc_op_entry_helper(rsc, key, FALSE);
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
 * \param[in]     for_graph  Whether action should be recorded in transition graph
 * \param[in,out] data_set   Cluster working set
 *
 * \return Newly allocated action
 * \note This function takes ownership of \p key. It is the caller's
 *       responsibility to free the return value with pe_free_action().
 */
static pe_action_t *
new_action(char *key, const char *task, pe_resource_t *rsc,
           const pe_node_t *node, bool optional, bool for_graph,
           pe_working_set_t *data_set)
{
    pe_action_t *action = calloc(1, sizeof(pe_action_t));

    CRM_ASSERT(action != NULL);

    action->rsc = rsc;
    action->task = strdup(task); CRM_ASSERT(action->task != NULL);
    action->uuid = key;
    action->extra = pcmk__strkey_table(free, free);
    action->meta = pcmk__strkey_table(free, free);

    if (node) {
        action->node = pe__copy_node(node);
    }

    if (pcmk__str_eq(task, CRM_OP_LRM_DELETE, pcmk__str_casei)) {
        // Resource history deletion for a node can be done on the DC
        pe__set_action_flags(action, pe_action_dc);
    }

    pe__set_action_flags(action, pe_action_runnable);
    if (optional) {
        pe__set_action_flags(action, pe_action_optional);
    } else {
        pe__clear_action_flags(action, pe_action_optional);
    }

    if (rsc != NULL) {
        guint interval_ms = 0;

        action->op_entry = find_rsc_op_entry_helper(rsc, key, TRUE);
        parse_op_key(key, NULL, NULL, &interval_ms);
        unpack_operation(action, action->op_entry, rsc->container, data_set,
                         interval_ms);
    }

    if (for_graph) {
        pe_rsc_trace(rsc, "Created %s action %d (%s): %s for %s on %s",
                     (optional? "optional" : "required"),
                     data_set->action_id, key, task,
                     ((rsc == NULL)? "no resource" : rsc->id),
                     pe__node_name(node));
        action->id = data_set->action_id++;

        data_set->actions = g_list_prepend(data_set->actions, action);
        if (rsc == NULL) {
            add_singleton(data_set, action);
        } else {
            rsc->actions = g_list_prepend(rsc->actions, action);
        }
    }
    return action;
}

/*!
 * \internal
 * \brief Evaluate node attribute values for an action
 *
 * \param[in,out] action    Action to unpack attributes for
 * \param[in,out] data_set  Cluster working set
 */
static void
unpack_action_node_attributes(pe_action_t *action, pe_working_set_t *data_set)
{
    if (!pcmk_is_set(action->flags, pe_action_have_node_attrs)
        && (action->op_entry != NULL)) {

        pe_rule_eval_data_t rule_data = {
            .node_hash = action->node->details->attrs,
            .role = RSC_ROLE_UNKNOWN,
            .now = data_set->now,
            .match_data = NULL,
            .rsc_data = NULL,
            .op_data = NULL
        };

        pe__set_action_flags(action, pe_action_have_node_attrs);
        pe__unpack_dataset_nvpairs(action->op_entry, XML_TAG_ATTR_SETS,
                                   &rule_data, action->extra, NULL,
                                   FALSE, data_set);
    }
}

/*!
 * \internal
 * \brief Update an action's optional flag
 *
 * \param[in,out] action    Action to update
 * \param[in]     optional  Requested optional status
 */
static void
update_action_optional(pe_action_t *action, gboolean optional)
{
    // Force a non-recurring action to be optional if its resource is unmanaged
    if ((action->rsc != NULL) && (action->node != NULL)
        && !pcmk_is_set(action->flags, pe_action_pseudo)
        && !pcmk_is_set(action->rsc->flags, pe_rsc_managed)
        && (g_hash_table_lookup(action->meta,
                                XML_LRM_ATTR_INTERVAL_MS) == NULL)) {
            pe_rsc_debug(action->rsc, "%s on %s is optional (%s is unmanaged)",
                         action->uuid, pe__node_name(action->node),
                         action->rsc->id);
            pe__set_action_flags(action, pe_action_optional);
            // We shouldn't clear runnable here because ... something

    // Otherwise require the action if requested
    } else if (!optional) {
        pe__clear_action_flags(action, pe_action_optional);
    }
}

static enum pe_quorum_policy
effective_quorum_policy(pe_resource_t *rsc, pe_working_set_t *data_set)
{
    enum pe_quorum_policy policy = data_set->no_quorum_policy;

    if (pcmk_is_set(data_set->flags, pe_flag_have_quorum)) {
        policy = no_quorum_ignore;

    } else if (data_set->no_quorum_policy == no_quorum_demote) {
        switch (rsc->role) {
            case RSC_ROLE_PROMOTED:
            case RSC_ROLE_UNPROMOTED:
                if (rsc->next_role > RSC_ROLE_UNPROMOTED) {
                    pe__set_next_role(rsc, RSC_ROLE_UNPROMOTED,
                                      "no-quorum-policy=demote");
                }
                policy = no_quorum_ignore;
                break;
            default:
                policy = no_quorum_stop;
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
 * \param[in]     for_graph  Whether action should be recorded in transition graph
 * \param[in,out] data_set   Cluster working set
 *
 * \note This may also schedule fencing if a stop is unrunnable.
 */
static void
update_resource_action_runnable(pe_action_t *action, bool for_graph,
                                pe_working_set_t *data_set)
{
    if (pcmk_is_set(action->flags, pe_action_pseudo)) {
        return;
    }

    if (action->node == NULL) {
        pe_rsc_trace(action->rsc, "%s is unrunnable (unallocated)",
                     action->uuid);
        pe__clear_action_flags(action, pe_action_runnable);

    } else if (!pcmk_is_set(action->flags, pe_action_dc)
               && !(action->node->details->online)
               && (!pe__is_guest_node(action->node)
                   || action->node->details->remote_requires_reset)) {
        pe__clear_action_flags(action, pe_action_runnable);
        do_crm_log((for_graph? LOG_WARNING: LOG_TRACE),
                   "%s on %s is unrunnable (node is offline)",
                   action->uuid, pe__node_name(action->node));
        if (pcmk_is_set(action->rsc->flags, pe_rsc_managed)
            && for_graph
            && pcmk__str_eq(action->task, CRMD_ACTION_STOP, pcmk__str_casei)
            && !(action->node->details->unclean)) {
            pe_fence_node(data_set, action->node, "stop is unrunnable", false);
        }

    } else if (!pcmk_is_set(action->flags, pe_action_dc)
               && action->node->details->pending) {
        pe__clear_action_flags(action, pe_action_runnable);
        do_crm_log((for_graph? LOG_WARNING: LOG_TRACE),
                   "Action %s on %s is unrunnable (node is pending)",
                   action->uuid, pe__node_name(action->node));

    } else if (action->needs == rsc_req_nothing) {
        pe_action_set_reason(action, NULL, TRUE);
        if (pe__is_guest_node(action->node)
            && !pe_can_fence(data_set, action->node)) {
            /* An action that requires nothing usually does not require any
             * fencing in order to be runnable. However, there is an exception:
             * such an action cannot be completed if it is on a guest node whose
             * host is unclean and cannot be fenced.
             */
            pe_rsc_debug(action->rsc, "%s on %s is unrunnable "
                         "(node's host cannot be fenced)",
                         action->uuid, pe__node_name(action->node));
            pe__clear_action_flags(action, pe_action_runnable);
        } else {
            pe_rsc_trace(action->rsc,
                         "%s on %s does not require fencing or quorum",
                         action->uuid, pe__node_name(action->node));
            pe__set_action_flags(action, pe_action_runnable);
        }

    } else {
        switch (effective_quorum_policy(action->rsc, data_set)) {
            case no_quorum_stop:
                pe_rsc_debug(action->rsc, "%s on %s is unrunnable (no quorum)",
                             action->uuid, pe__node_name(action->node));
                pe__clear_action_flags(action, pe_action_runnable);
                pe_action_set_reason(action, "no quorum", true);
                break;

            case no_quorum_freeze:
                if (!action->rsc->fns->active(action->rsc, TRUE)
                    || (action->rsc->next_role > action->rsc->role)) {
                    pe_rsc_debug(action->rsc,
                                 "%s on %s is unrunnable (no quorum)",
                                 action->uuid, pe__node_name(action->node));
                    pe__clear_action_flags(action, pe_action_runnable);
                    pe_action_set_reason(action, "quorum freeze", true);
                }
                break;

            default:
                //pe_action_set_reason(action, NULL, TRUE);
                pe__set_action_flags(action, pe_action_runnable);
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
update_resource_flags_for_action(pe_resource_t *rsc, const pe_action_t *action)
{
    /* @COMPAT pe_rsc_starting and pe_rsc_stopping are not actually used
     * within Pacemaker, and should be deprecated and eventually removed
     */
    if (pcmk__str_eq(action->task, CRMD_ACTION_STOP, pcmk__str_casei)) {
        pe__set_resource_flags(rsc, pe_rsc_stopping);

    } else if (pcmk__str_eq(action->task, CRMD_ACTION_START, pcmk__str_casei)) {
        if (pcmk_is_set(action->flags, pe_action_runnable)) {
            pe__set_resource_flags(rsc, pe_rsc_starting);
        } else {
            pe__clear_resource_flags(rsc, pe_rsc_starting);
        }
    }
}

static bool
valid_stop_on_fail(const char *value)
{
    return !pcmk__strcase_any_of(value, "standby", "demote", "stop", NULL);
}

static const char *
unpack_operation_on_fail(pe_action_t * action)
{
    const char *name = NULL;
    const char *role = NULL;
    const char *on_fail = NULL;
    const char *interval_spec = NULL;
    const char *value = g_hash_table_lookup(action->meta, XML_OP_ATTR_ON_FAIL);

    if (pcmk__str_eq(action->task, CRMD_ACTION_STOP, pcmk__str_casei)
        && !valid_stop_on_fail(value)) {

        pcmk__config_err("Resetting '" XML_OP_ATTR_ON_FAIL "' for %s stop "
                         "action to default value because '%s' is not "
                         "allowed for stop", action->rsc->id, value);
        return NULL;

    } else if (pcmk__str_eq(action->task, CRMD_ACTION_DEMOTE, pcmk__str_casei) && !value) {
        // demote on_fail defaults to monitor value for promoted role if present
        xmlNode *operation = NULL;

        CRM_CHECK(action->rsc != NULL, return NULL);

        for (operation = pcmk__xe_first_child(action->rsc->ops_xml);
             (operation != NULL) && (value == NULL);
             operation = pcmk__xe_next(operation)) {
            bool enabled = false;

            if (!pcmk__str_eq((const char *)operation->name, "op", pcmk__str_none)) {
                continue;
            }
            name = crm_element_value(operation, "name");
            role = crm_element_value(operation, "role");
            on_fail = crm_element_value(operation, XML_OP_ATTR_ON_FAIL);
            interval_spec = crm_element_value(operation, XML_LRM_ATTR_INTERVAL);
            if (!on_fail) {
                continue;
            } else if (pcmk__xe_get_bool_attr(operation, "enabled", &enabled) == pcmk_rc_ok && !enabled) {
                continue;
            } else if (!pcmk__str_eq(name, "monitor", pcmk__str_casei)
                       || !pcmk__strcase_any_of(role, RSC_ROLE_PROMOTED_S,
                                                RSC_ROLE_PROMOTED_LEGACY_S,
                                                NULL)) {
                continue;
            } else if (crm_parse_interval_spec(interval_spec) == 0) {
                continue;
            } else if (pcmk__str_eq(on_fail, "demote", pcmk__str_casei)) {
                continue;
            }

            value = on_fail;
        }
    } else if (pcmk__str_eq(action->task, CRM_OP_LRM_DELETE, pcmk__str_casei)) {
        value = "ignore";

    } else if (pcmk__str_eq(value, "demote", pcmk__str_casei)) {
        name = crm_element_value(action->op_entry, "name");
        role = crm_element_value(action->op_entry, "role");
        interval_spec = crm_element_value(action->op_entry,
                                          XML_LRM_ATTR_INTERVAL);

        if (!pcmk__str_eq(name, CRMD_ACTION_PROMOTE, pcmk__str_casei)
            && (!pcmk__str_eq(name, CRMD_ACTION_STATUS, pcmk__str_casei)
                || !pcmk__strcase_any_of(role, RSC_ROLE_PROMOTED_S,
                                         RSC_ROLE_PROMOTED_LEGACY_S, NULL)
                || (crm_parse_interval_spec(interval_spec) == 0))) {
            pcmk__config_err("Resetting '" XML_OP_ATTR_ON_FAIL "' for %s %s "
                             "action to default value because 'demote' is not "
                             "allowed for it", action->rsc->id, name);
            return NULL;
        }
    }

    return value;
}

static int
unpack_timeout(const char *value)
{
    int timeout_ms = crm_get_msec(value);

    if (timeout_ms < 0) {
        timeout_ms = crm_get_msec(CRM_DEFAULT_OP_TIMEOUT_S);
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
        pcmk__config_err("Ignoring '" XML_OP_ATTR_ORIGIN "' for operation "
                         "'%s' because '%s' is not valid",
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
            g_hash_table_replace(meta, strdup(XML_OP_ATTR_START_DELAY),
                                 pcmk__itoa(start_delay));
        }
    }

    return start_delay;
}

static xmlNode *
find_min_interval_mon(pe_resource_t * rsc, gboolean include_disabled)
{
    guint interval_ms = 0;
    guint min_interval_ms = G_MAXUINT;
    const char *name = NULL;
    const char *interval_spec = NULL;
    xmlNode *op = NULL;
    xmlNode *operation = NULL;

    for (operation = pcmk__xe_first_child(rsc->ops_xml);
         operation != NULL;
         operation = pcmk__xe_next(operation)) {

        if (pcmk__str_eq((const char *)operation->name, "op", pcmk__str_none)) {
            bool enabled = false;

            name = crm_element_value(operation, "name");
            interval_spec = crm_element_value(operation, XML_LRM_ATTR_INTERVAL);
            if (!include_disabled && pcmk__xe_get_bool_attr(operation, "enabled", &enabled) == pcmk_rc_ok &&
                !enabled) {
                continue;
            }

            if (!pcmk__str_eq(name, RSC_STATUS, pcmk__str_casei)) {
                continue;
            }

            interval_ms = crm_parse_interval_spec(interval_spec);

            if (interval_ms && (interval_ms < min_interval_ms)) {
                min_interval_ms = interval_ms;
                op = operation;
            }
        }
    }

    return op;
}

/*!
 * \brief Unpack operation XML into an action structure
 *
 * Unpack an operation's meta-attributes (normalizing the interval, timeout,
 * and start delay values as integer milliseconds), requirements, and
 * failure policy.
 *
 * \param[in,out] action       Action to unpack into
 * \param[in]     xml_obj      Operation XML (or NULL if all defaults)
 * \param[in]     container    Resource that contains affected resource, if any
 * \param[in,out] data_set     Cluster state
 * \param[in]     interval_ms  How frequently to perform the operation
 */
static void
unpack_operation(pe_action_t *action, const xmlNode *xml_obj,
                 const pe_resource_t *container,
                 pe_working_set_t *data_set, guint interval_ms)
{
    int timeout_ms = 0;
    const char *value = NULL;
    bool is_probe = false;

    pe_rsc_eval_data_t rsc_rule_data = {
        .standard = crm_element_value(action->rsc->xml, XML_AGENT_ATTR_CLASS),
        .provider = crm_element_value(action->rsc->xml, XML_AGENT_ATTR_PROVIDER),
        .agent = crm_element_value(action->rsc->xml, XML_EXPR_ATTR_TYPE)
    };

    pe_op_eval_data_t op_rule_data = {
        .op_name = action->task,
        .interval = interval_ms
    };

    pe_rule_eval_data_t rule_data = {
        .node_hash = NULL,
        .role = RSC_ROLE_UNKNOWN,
        .now = data_set->now,
        .match_data = NULL,
        .rsc_data = &rsc_rule_data,
        .op_data = &op_rule_data
    };

    CRM_CHECK(action && action->rsc, return);

    is_probe = pcmk_is_probe(action->task, interval_ms);

    // Cluster-wide <op_defaults> <meta_attributes>
    pe__unpack_dataset_nvpairs(data_set->op_defaults, XML_TAG_META_SETS, &rule_data,
                               action->meta, NULL, FALSE, data_set);

    // Determine probe default timeout differently
    if (is_probe) {
        xmlNode *min_interval_mon = find_min_interval_mon(action->rsc, FALSE);

        if (min_interval_mon) {
            value = crm_element_value(min_interval_mon, XML_ATTR_TIMEOUT);
            if (value) {
                crm_trace("\t%s: Setting default timeout to minimum-interval "
                          "monitor's timeout '%s'", action->uuid, value);
                g_hash_table_replace(action->meta, strdup(XML_ATTR_TIMEOUT),
                                     strdup(value));
            }
        }
    }

    if (xml_obj) {
        xmlAttrPtr xIter = NULL;

        // <op> <meta_attributes> take precedence over defaults
        pe__unpack_dataset_nvpairs(xml_obj, XML_TAG_META_SETS, &rule_data,
                                   action->meta, NULL, TRUE, data_set);

        /* Anything set as an <op> XML property has highest precedence.
         * This ensures we use the name and interval from the <op> tag.
         */
        for (xIter = xml_obj->properties; xIter; xIter = xIter->next) {
            const char *prop_name = (const char *)xIter->name;
            const char *prop_value = crm_element_value(xml_obj, prop_name);

            g_hash_table_replace(action->meta, strdup(prop_name), strdup(prop_value));
        }
    }

    g_hash_table_remove(action->meta, "id");

    // Normalize interval to milliseconds
    if (interval_ms > 0) {
        g_hash_table_replace(action->meta, strdup(XML_LRM_ATTR_INTERVAL),
                             crm_strdup_printf("%u", interval_ms));
    } else {
        g_hash_table_remove(action->meta, XML_LRM_ATTR_INTERVAL);
    }

    /*
     * Timeout order of precedence:
     *   1. pcmk_monitor_timeout (if rsc has pcmk_ra_cap_fence_params
     *      and task is start or a probe; pcmk_monitor_timeout works
     *      by default for a recurring monitor)
     *   2. explicit op timeout on the primitive
     *   3. default op timeout
     *      a. if probe, then min-interval monitor's timeout
     *      b. else, in XML_CIB_TAG_OPCONFIG
     *   4. CRM_DEFAULT_OP_TIMEOUT_S
     *
     * #1 overrides general rule of <op> XML property having highest
     * precedence.
     */
    if (pcmk_is_set(pcmk_get_ra_caps(rsc_rule_data.standard),
                    pcmk_ra_cap_fence_params)
        && (pcmk__str_eq(action->task, RSC_START, pcmk__str_casei)
            || is_probe)) {

        GHashTable *params = pe_rsc_params(action->rsc, action->node, data_set);

        value = g_hash_table_lookup(params, "pcmk_monitor_timeout");

        if (value) {
            crm_trace("\t%s: Setting timeout to pcmk_monitor_timeout '%s', "
                      "overriding default", action->uuid, value);
            g_hash_table_replace(action->meta, strdup(XML_ATTR_TIMEOUT),
                                 strdup(value));
        }
    }

    // Normalize timeout to positive milliseconds
    value = g_hash_table_lookup(action->meta, XML_ATTR_TIMEOUT);
    timeout_ms = unpack_timeout(value);
    g_hash_table_replace(action->meta, strdup(XML_ATTR_TIMEOUT),
                         pcmk__itoa(timeout_ms));

    if (!pcmk__strcase_any_of(action->task, RSC_START, RSC_PROMOTE, NULL)) {
        action->needs = rsc_req_nothing;
        value = "nothing (not start or promote)";

    } else if (pcmk_is_set(action->rsc->flags, pe_rsc_needs_fencing)) {
        action->needs = rsc_req_stonith;
        value = "fencing";

    } else if (pcmk_is_set(action->rsc->flags, pe_rsc_needs_quorum)) {
        action->needs = rsc_req_quorum;
        value = "quorum";

    } else {
        action->needs = rsc_req_nothing;
        value = "nothing";
    }
    pe_rsc_trace(action->rsc, "%s requires %s", action->uuid, value);

    value = unpack_operation_on_fail(action);

    if (value == NULL) {

    } else if (pcmk__str_eq(value, "block", pcmk__str_casei)) {
        action->on_fail = action_fail_block;
        g_hash_table_insert(action->meta, strdup(XML_OP_ATTR_ON_FAIL), strdup("block"));
        value = "block"; // The above could destroy the original string

    } else if (pcmk__str_eq(value, "fence", pcmk__str_casei)) {
        action->on_fail = action_fail_fence;
        value = "node fencing";

        if (!pcmk_is_set(data_set->flags, pe_flag_stonith_enabled)) {
            pcmk__config_err("Resetting '" XML_OP_ATTR_ON_FAIL "' for "
                             "operation '%s' to 'stop' because 'fence' is not "
                             "valid when fencing is disabled", action->uuid);
            action->on_fail = action_fail_stop;
            action->fail_role = RSC_ROLE_STOPPED;
            value = "stop resource";
        }

    } else if (pcmk__str_eq(value, "standby", pcmk__str_casei)) {
        action->on_fail = action_fail_standby;
        value = "node standby";

    } else if (pcmk__strcase_any_of(value, "ignore", PCMK__VALUE_NOTHING,
                                    NULL)) {
        action->on_fail = action_fail_ignore;
        value = "ignore";

    } else if (pcmk__str_eq(value, "migrate", pcmk__str_casei)) {
        action->on_fail = action_fail_migrate;
        value = "force migration";

    } else if (pcmk__str_eq(value, "stop", pcmk__str_casei)) {
        action->on_fail = action_fail_stop;
        action->fail_role = RSC_ROLE_STOPPED;
        value = "stop resource";

    } else if (pcmk__str_eq(value, "restart", pcmk__str_casei)) {
        action->on_fail = action_fail_recover;
        value = "restart (and possibly migrate)";

    } else if (pcmk__str_eq(value, "restart-container", pcmk__str_casei)) {
        if (container) {
            action->on_fail = action_fail_restart_container;
            value = "restart container (and possibly migrate)";

        } else {
            value = NULL;
        }

    } else if (pcmk__str_eq(value, "demote", pcmk__str_casei)) {
        action->on_fail = action_fail_demote;
        value = "demote instance";

    } else {
        pe_err("Resource %s: Unknown failure type (%s)", action->rsc->id, value);
        value = NULL;
    }

    /* defaults */
    if (value == NULL && container) {
        action->on_fail = action_fail_restart_container;
        value = "restart container (and possibly migrate) (default)";

    /* For remote nodes, ensure that any failure that results in dropping an
     * active connection to the node results in fencing of the node.
     *
     * There are only two action failures that don't result in fencing.
     * 1. probes - probe failures are expected.
     * 2. start - a start failure indicates that an active connection does not already
     * exist. The user can set op on-fail=fence if they really want to fence start
     * failures. */
    } else if (((value == NULL) || !pcmk_is_set(action->rsc->flags, pe_rsc_managed))
               && pe__resource_is_remote_conn(action->rsc, data_set)
               && !(pcmk__str_eq(action->task, CRMD_ACTION_STATUS, pcmk__str_casei)
                    && (interval_ms == 0))
               && !pcmk__str_eq(action->task, CRMD_ACTION_START, pcmk__str_casei)) {

        if (!pcmk_is_set(action->rsc->flags, pe_rsc_managed)) {
            action->on_fail = action_fail_stop;
            action->fail_role = RSC_ROLE_STOPPED;
            value = "stop unmanaged remote node (enforcing default)";

        } else {
            if (pcmk_is_set(data_set->flags, pe_flag_stonith_enabled)) {
                value = "fence remote node (default)";
            } else {
                value = "recover remote node connection (default)";
            }

            if (action->rsc->remote_reconnect_ms) {
                action->fail_role = RSC_ROLE_STOPPED;
            }
            action->on_fail = action_fail_reset_remote;
        }

    } else if (value == NULL && pcmk__str_eq(action->task, CRMD_ACTION_STOP, pcmk__str_casei)) {
        if (pcmk_is_set(data_set->flags, pe_flag_stonith_enabled)) {
            action->on_fail = action_fail_fence;
            value = "resource fence (default)";

        } else {
            action->on_fail = action_fail_block;
            value = "resource block (default)";
        }

    } else if (value == NULL) {
        action->on_fail = action_fail_recover;
        value = "restart (and possibly migrate) (default)";
    }

    pe_rsc_trace(action->rsc, "%s failure handling: %s",
                 action->uuid, value);

    value = NULL;
    if (xml_obj != NULL) {
        value = g_hash_table_lookup(action->meta, "role_after_failure");
        if (value) {
            pe_warn_once(pe_wo_role_after,
                        "Support for role_after_failure is deprecated and will be removed in a future release");
        }
    }
    if (value != NULL && action->fail_role == RSC_ROLE_UNKNOWN) {
        action->fail_role = text2role(value);
    }
    /* defaults */
    if (action->fail_role == RSC_ROLE_UNKNOWN) {
        if (pcmk__str_eq(action->task, CRMD_ACTION_PROMOTE, pcmk__str_casei)) {
            action->fail_role = RSC_ROLE_UNPROMOTED;
        } else {
            action->fail_role = RSC_ROLE_STARTED;
        }
    }
    pe_rsc_trace(action->rsc, "%s failure results in: %s",
                 action->uuid, role2text(action->fail_role));

    value = g_hash_table_lookup(action->meta, XML_OP_ATTR_START_DELAY);
    if (value) {
        unpack_start_delay(value, action->meta);
    } else {
        long long start_delay = 0;

        value = g_hash_table_lookup(action->meta, XML_OP_ATTR_ORIGIN);
        if (unpack_interval_origin(value, xml_obj, interval_ms, data_set->now,
                                   &start_delay)) {
            g_hash_table_replace(action->meta, strdup(XML_OP_ATTR_START_DELAY),
                                 crm_strdup_printf("%lld", start_delay));
        }
    }
}

/*!
 * \brief Create or update an action object
 *
 * \param[in,out] rsc          Resource that action is for (if any)
 * \param[in,out] key          Action key (must be non-NULL)
 * \param[in]     task         Action name (must be non-NULL)
 * \param[in]     on_node      Node that action is on (if any)
 * \param[in]     optional     Whether action should be considered optional
 * \param[in]     save_action  Whether action should be recorded in transition graph
 * \param[in,out] data_set     Cluster working set
 *
 * \return Action object corresponding to arguments
 * \note This function takes ownership of (and might free) \p key. If
 *       \p save_action is true, \p data_set will own the returned action,
 *       otherwise it is the caller's responsibility to free the return value
 *       with pe_free_action().
 */
pe_action_t *
custom_action(pe_resource_t *rsc, char *key, const char *task,
              const pe_node_t *on_node, gboolean optional, gboolean save_action,
              pe_working_set_t *data_set)
{
    pe_action_t *action = NULL;

    CRM_ASSERT((key != NULL) && (task != NULL) && (data_set != NULL));

    if (save_action) {
        action = find_existing_action(key, rsc, on_node, data_set);
    }

    if (action == NULL) {
        action = new_action(key, task, rsc, on_node, optional, save_action,
                            data_set);
    } else {
        free(key);
    }

    update_action_optional(action, optional);

    if (rsc != NULL) {
        if (action->node != NULL) {
            unpack_action_node_attributes(action, data_set);
        }

        update_resource_action_runnable(action, save_action, data_set);

        if (save_action) {
            update_resource_flags_for_action(rsc, action);
        }
    }

    return action;
}

pe_action_t *
get_pseudo_op(const char *name, pe_working_set_t * data_set)
{
    pe_action_t *op = lookup_singleton(data_set, name);

    if (op == NULL) {
        op = custom_action(NULL, strdup(name), name, NULL, TRUE, TRUE, data_set);
        pe__set_action_flags(op, pe_action_pseudo|pe_action_runnable);
    }
    return op;
}

static GList *
find_unfencing_devices(GList *candidates, GList *matches) 
{
    for (GList *gIter = candidates; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *candidate = gIter->data;

        if (candidate->children != NULL) {
            matches = find_unfencing_devices(candidate->children, matches);

        } else if (!pcmk_is_set(candidate->flags, pe_rsc_fence_device)) {
            continue;

        } else if (pcmk_is_set(candidate->flags, pe_rsc_needs_unfencing)) {
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
node_priority_fencing_delay(const pe_node_t *node,
                            const pe_working_set_t *data_set)
{
    int member_count = 0;
    int online_count = 0;
    int top_priority = 0;
    int lowest_priority = 0;
    GList *gIter = NULL;

    // `priority-fencing-delay` is disabled
    if (data_set->priority_fencing_delay <= 0) {
        return 0;
    }

    /* No need to request a delay if the fencing target is not a normal cluster
     * member, for example if it's a remote node or a guest node. */
    if (node->details->type != node_member) {
        return 0;
    }

    // No need to request a delay if the fencing target is in our partition
    if (node->details->online) {
        return 0;
    }

    for (gIter = data_set->nodes; gIter != NULL; gIter = gIter->next) {
        pe_node_t *n =  gIter->data;

        if (n->details->type != node_member) {
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

    return data_set->priority_fencing_delay;
}

pe_action_t *
pe_fence_op(pe_node_t *node, const char *op, bool optional,
            const char *reason, bool priority_delay, pe_working_set_t *data_set)
{
    char *op_key = NULL;
    pe_action_t *stonith_op = NULL;

    if(op == NULL) {
        op = data_set->stonith_action;
    }

    op_key = crm_strdup_printf("%s-%s-%s", CRM_OP_FENCE, node->details->uname, op);

    stonith_op = lookup_singleton(data_set, op_key);
    if(stonith_op == NULL) {
        stonith_op = custom_action(NULL, op_key, CRM_OP_FENCE, node, TRUE, TRUE, data_set);

        add_hash_param(stonith_op->meta, XML_LRM_ATTR_TARGET, node->details->uname);
        add_hash_param(stonith_op->meta, XML_LRM_ATTR_TARGET_UUID, node->details->id);
        add_hash_param(stonith_op->meta, "stonith_action", op);

        if (pcmk_is_set(data_set->flags, pe_flag_enable_unfencing)) {
            /* Extra work to detect device changes
             */
            GString *digests_all = g_string_sized_new(1024);
            GString *digests_secure = g_string_sized_new(1024);

            GList *matches = find_unfencing_devices(data_set->resources, NULL);

            char *key = NULL;
            char *value = NULL;

            for (GList *gIter = matches; gIter != NULL; gIter = gIter->next) {
                pe_resource_t *match = gIter->data;
                const char *agent = g_hash_table_lookup(match->meta,
                                                        XML_ATTR_TYPE);
                op_digest_cache_t *data = NULL;

                data = pe__compare_fencing_digest(match, agent, node, data_set);
                if(data->rc == RSC_DIGEST_ALL) {
                    optional = FALSE;
                    crm_notice("Unfencing node %s because the definition of "
                               "%s changed", pe__node_name(node), match->id);
                    if (!pcmk__is_daemon && data_set->priv != NULL) {
                        pcmk__output_t *out = data_set->priv;

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

    if (data_set->priority_fencing_delay > 0

            /* It's a suitable case where `priority-fencing-delay` applies.
             * At least add `priority-fencing-delay` field as an indicator. */
        && (priority_delay

            /* The priority delay needs to be recalculated if this function has
             * been called by schedule_fencing_and_shutdowns() after node
             * priority has already been calculated by native_add_running().
             */
            || g_hash_table_lookup(stonith_op->meta,
                                   XML_CONFIG_ATTR_PRIORITY_FENCING_DELAY) != NULL)) {

            /* Add `priority-fencing-delay` to the fencing op even if it's 0 for
             * the targeting node. So that it takes precedence over any possible
             * `pcmk_delay_base/max`.
             */
            char *delay_s = pcmk__itoa(node_priority_fencing_delay(node, data_set));

            g_hash_table_insert(stonith_op->meta,
                                strdup(XML_CONFIG_ATTR_PRIORITY_FENCING_DELAY),
                                delay_s);
    }

    if(optional == FALSE && pe_can_fence(data_set, node)) {
        pe__clear_action_flags(stonith_op, pe_action_optional);
        pe_action_set_reason(stonith_op, reason, false);

    } else if(reason && stonith_op->reason == NULL) {
        stonith_op->reason = strdup(reason);
    }

    return stonith_op;
}

void
pe_free_action(pe_action_t * action)
{
    if (action == NULL) {
        return;
    }
    g_list_free_full(action->actions_before, free);     /* pe_action_wrapper_t* */
    g_list_free_full(action->actions_after, free);      /* pe_action_wrapper_t* */
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
pe_get_configured_timeout(pe_resource_t *rsc, const char *action, pe_working_set_t *data_set)
{
    xmlNode *child = NULL;
    GHashTable *action_meta = NULL;
    const char *timeout_spec = NULL;
    int timeout_ms = 0;

    pe_rule_eval_data_t rule_data = {
        .node_hash = NULL,
        .role = RSC_ROLE_UNKNOWN,
        .now = data_set->now,
        .match_data = NULL,
        .rsc_data = NULL,
        .op_data = NULL
    };

    for (child = first_named_child(rsc->ops_xml, XML_ATTR_OP);
         child != NULL; child = crm_next_same_xml(child)) {
        if (pcmk__str_eq(action, crm_element_value(child, XML_NVPAIR_ATTR_NAME),
                pcmk__str_casei)) {
            timeout_spec = crm_element_value(child, XML_ATTR_TIMEOUT);
            break;
        }
    }

    if (timeout_spec == NULL && data_set->op_defaults) {
        action_meta = pcmk__strkey_table(free, free);
        pe__unpack_dataset_nvpairs(data_set->op_defaults, XML_TAG_META_SETS,
                                   &rule_data, action_meta, NULL, FALSE, data_set);
        timeout_spec = g_hash_table_lookup(action_meta, XML_ATTR_TIMEOUT);
    }

    // @TODO check meta-attributes
    // @TODO maybe use min-interval monitor timeout as default for monitors

    timeout_ms = crm_get_msec(timeout_spec);
    if (timeout_ms < 0) {
        timeout_ms = crm_get_msec(CRM_DEFAULT_OP_TIMEOUT_S);
    }

    if (action_meta != NULL) {
        g_hash_table_destroy(action_meta);
    }
    return timeout_ms;
}

enum action_tasks
get_complex_task(const pe_resource_t *rsc, const char *name)
{
    enum action_tasks task = text2task(name);

    if ((rsc != NULL) && (rsc->variant == pe_native)) {
        switch (task) {
            case stopped_rsc:
            case started_rsc:
            case action_demoted:
            case action_promoted:
                crm_trace("Folding %s back into its atomic counterpart for %s",
                          name, rsc->id);
                --task;
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
pe_action_t *
find_first_action(const GList *input, const char *uuid, const char *task,
                  const pe_node_t *on_node)
{
    CRM_CHECK(uuid || task, return NULL);

    for (const GList *gIter = input; gIter != NULL; gIter = gIter->next) {
        pe_action_t *action = (pe_action_t *) gIter->data;

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
find_actions(GList *input, const char *key, const pe_node_t *on_node)
{
    GList *gIter = input;
    GList *result = NULL;

    CRM_CHECK(key != NULL, return NULL);

    for (; gIter != NULL; gIter = gIter->next) {
        pe_action_t *action = (pe_action_t *) gIter->data;

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
find_actions_exact(GList *input, const char *key, const pe_node_t *on_node)
{
    GList *result = NULL;

    CRM_CHECK(key != NULL, return NULL);

    if (on_node == NULL) {
        return NULL;
    }

    for (GList *gIter = input; gIter != NULL; gIter = gIter->next) {
        pe_action_t *action = (pe_action_t *) gIter->data;

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
pe__resource_actions(const pe_resource_t *rsc, const pe_node_t *node,
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
pe__action2reason(const pe_action_t *action, enum pe_action_flags flag)
{
    const char *change = NULL;

    switch (flag) {
        case pe_action_runnable:
        case pe_action_migrate_runnable:
            change = "unrunnable";
            break;
        case pe_action_optional:
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

void pe_action_set_reason(pe_action_t *action, const char *reason, bool overwrite) 
{
    if (action->reason != NULL && overwrite) {
        pe_rsc_trace(action->rsc, "Changing %s reason from '%s' to '%s'",
                     action->uuid, action->reason, pcmk__s(reason, "(none)"));
    } else if (action->reason == NULL) {
        pe_rsc_trace(action->rsc, "Set %s reason to '%s'",
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
 * \param[in,out] data_set  Cluster working set
 *
 * \return New action to clear resource history
 */
pe_action_t *
pe__clear_resource_history(pe_resource_t *rsc, const pe_node_t *node,
                           pe_working_set_t *data_set)
{
    char *key = NULL;

    CRM_ASSERT(rsc && node);
    key = pcmk__op_key(rsc->id, CRM_OP_LRM_DELETE, 0);
    return custom_action(rsc, key, CRM_OP_LRM_DELETE, node, FALSE, TRUE,
                         data_set);
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

    const char *a_xml_id = crm_element_value(xml_a, XML_ATTR_ID);
    const char *b_xml_id = crm_element_value(xml_b, XML_ATTR_ID);

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
        pe_err("Duplicate lrm_rsc_op entries named %s", a_xml_id);
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
        /* One of the inputs is a pending operation
         * Attempt to use XML_ATTR_TRANSITION_MAGIC to determine its age relative to the other
         */

        int a_id = -1;
        int b_id = -1;

        const char *a_magic = crm_element_value(xml_a, XML_ATTR_TRANSITION_MAGIC);
        const char *b_magic = crm_element_value(xml_b, XML_ATTR_TRANSITION_MAGIC);

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
pe_action_t *
pe__new_rsc_pseudo_action(pe_resource_t *rsc, const char *task, bool optional,
                          bool runnable)
{
    pe_action_t *action = NULL;

    CRM_ASSERT((rsc != NULL) && (task != NULL));

    action = custom_action(rsc, pcmk__op_key(rsc->id, task, 0), task, NULL,
                           optional, TRUE, rsc->cluster);
    pe__set_action_flags(action, pe_action_pseudo);
    if (runnable) {
        pe__set_action_flags(action, pe_action_runnable);
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
pe__add_action_expected_result(pe_action_t *action, int expected_result)
{
    char *name = NULL;

    CRM_ASSERT((action != NULL) && (action->meta != NULL));

    name = strdup(XML_ATTR_TE_TARGET_RC);
    CRM_ASSERT (name != NULL);

    g_hash_table_insert(action->meta, name, pcmk__itoa(expected_result));
}
