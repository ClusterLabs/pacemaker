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
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <glib.h>
#include <libxml/tree.h>                // xmlNode
#include <libxml/xpath.h>               // xmlXPathObject, etc.

#include <crm/crm.h>
#include <crm/services.h>
#include <crm/common/xml.h>

#include <crm/common/util.h>
#include <crm/pengine/internal.h>
#include <pe_status_private.h>

// A (parsed) resource action history entry
struct action_history {
    pcmk_resource_t *rsc;       // Resource that history is for
    pcmk_node_t *node;        // Node that history is for
    xmlNode *xml;             // History entry XML

    // Parsed from entry XML
    const char *id;           // XML ID of history entry
    const char *key;          // Operation key of action
    const char *task;         // Action name
    const char *exit_reason;  // Exit reason given for result
    guint interval_ms;        // Action interval
    int call_id;              // Call ID of action
    int expected_exit_status; // Expected exit status of action
    int exit_status;          // Actual exit status of action
    int execution_status;     // Execution status of action
};

/* This uses pcmk__set_flags_as()/pcmk__clear_flags_as() directly rather than
 * use pcmk__set_scheduler_flags()/pcmk__clear_scheduler_flags() so that the
 * flag is stringified more readably in log messages.
 */
#define set_config_flag(scheduler, option, flag) do {                         \
        GHashTable *config_hash = (scheduler)->priv->options;                 \
        const char *scf_value = pcmk__cluster_option(config_hash, (option));  \
                                                                              \
        if (scf_value != NULL) {                                              \
            if (pcmk__is_true(scf_value)) {                                   \
                (scheduler)->flags = pcmk__set_flags_as(__func__, __LINE__,   \
                                    LOG_TRACE, "Scheduler",                   \
                                    crm_system_name, (scheduler)->flags,      \
                                    (flag), #flag);                           \
            } else {                                                          \
                (scheduler)->flags = pcmk__clear_flags_as(__func__, __LINE__, \
                                    LOG_TRACE, "Scheduler",                   \
                                    crm_system_name, (scheduler)->flags,      \
                                    (flag), #flag);                           \
            }                                                                 \
        }                                                                     \
    } while(0)

static void unpack_rsc_op(pcmk_resource_t *rsc, pcmk_node_t *node,
                          xmlNode *xml_op, xmlNode **last_failure,
                          enum pcmk__on_fail *failed);
static void determine_remote_online_status(pcmk_scheduler_t *scheduler,
                                           pcmk_node_t *this_node);
static void add_node_attrs(const xmlNode *xml_obj, pcmk_node_t *node,
                           bool overwrite, pcmk_scheduler_t *scheduler);
static void determine_online_status(const xmlNode *node_state,
                                    pcmk_node_t *this_node,
                                    pcmk_scheduler_t *scheduler);

static void unpack_node_lrm(pcmk_node_t *node, const xmlNode *xml,
                            pcmk_scheduler_t *scheduler);


/*!
 * \internal
 * \brief Check whether a node is a dangling guest node
 *
 * \param[in] node  Node to check
 *
 * \return true if \p node had a Pacemaker Remote connection resource with a
 *         launcher that was removed from the CIB, otherwise false.
 */
static bool
is_dangling_guest_node(pcmk_node_t *node)
{
    return pcmk__is_pacemaker_remote_node(node)
           && (node->priv->remote != NULL)
           && (node->priv->remote->priv->launcher == NULL)
           && pcmk__is_set(node->priv->remote->flags,
                           pcmk__rsc_removed_launched);
}

/*!
 * \brief Schedule a fence action for a node
 *
 * \param[in,out] scheduler       Scheduler data
 * \param[in,out] node            Node to fence
 * \param[in]     reason          Text description of why fencing is needed
 * \param[in]     priority_delay  Whether to consider
 *                                \c PCMK_OPT_PRIORITY_FENCING_DELAY
 */
void
pe_fence_node(pcmk_scheduler_t *scheduler, pcmk_node_t *node,
              const char *reason, bool priority_delay)
{
    CRM_CHECK(node, return);

    if (pcmk__is_guest_or_bundle_node(node)) {
        // Fence a guest or bundle node by marking its launcher as failed
        pcmk_resource_t *rsc = node->priv->remote->priv->launcher;

        if (!pcmk__is_set(rsc->flags, pcmk__rsc_failed)) {
            if (!pcmk__is_set(rsc->flags, pcmk__rsc_managed)) {
                pcmk__notice("Not fencing guest node %s (otherwise would "
                             "because %s): its guest resource %s is unmanaged",
                             pcmk__node_name(node), reason, rsc->id);
            } else {
                pcmk__sched_warn(scheduler,
                                 "Guest node %s will be fenced "
                                 "(by recovering its guest resource %s): %s",
                                 pcmk__node_name(node), rsc->id, reason);

                /* We don't mark the node as unclean because that would prevent the
                 * node from running resources. We want to allow it to run resources
                 * in this transition if the recovery succeeds.
                 */
                pcmk__set_node_flags(node, pcmk__node_remote_reset);
                pcmk__set_rsc_flags(rsc,
                                    pcmk__rsc_failed|pcmk__rsc_stop_if_failed);
            }
        }

    } else if (is_dangling_guest_node(node)) {
        pcmk__info("Cleaning up dangling connection for guest node %s: fencing "
                   "was already done because %s, and guest resource no longer "
                   "exists",
                   pcmk__node_name(node), reason);
        pcmk__set_rsc_flags(node->priv->remote,
                            pcmk__rsc_failed|pcmk__rsc_stop_if_failed);

    } else if (pcmk__is_remote_node(node)) {
        pcmk_resource_t *rsc = node->priv->remote;

        if ((rsc != NULL) && !pcmk__is_set(rsc->flags, pcmk__rsc_managed)) {
            pcmk__notice("Not fencing remote node %s (otherwise would because "
                         "%s): connection is unmanaged",
                         pcmk__node_name(node), reason);
        } else if (!pcmk__is_set(node->priv->flags, pcmk__node_remote_reset)) {
            pcmk__set_node_flags(node, pcmk__node_remote_reset);
            pcmk__sched_warn(scheduler, "Remote node %s %s: %s",
                             pcmk__node_name(node),
                             pe_can_fence(scheduler, node)? "will be fenced" : "is unclean",
                             reason);
        }
        node->details->unclean = TRUE;
        // No need to apply PCMK_OPT_PRIORITY_FENCING_DELAY for remote nodes
        pe_fence_op(node, NULL, TRUE, reason, FALSE, scheduler);

    } else if (node->details->unclean) {
        const char *fenced_s = "also is unclean";

        if (pe_can_fence(scheduler, node)) {
            fenced_s = "would also be fenced";
        }
        pcmk__trace("Cluster node %s %s because %s",
                    pcmk__node_name(node), fenced_s, reason);

    } else {
        pcmk__sched_warn(scheduler, "Cluster node %s %s: %s",
                         pcmk__node_name(node),
                         pe_can_fence(scheduler, node)? "will be fenced" : "is unclean",
                         reason);
        node->details->unclean = TRUE;
        pe_fence_op(node, NULL, TRUE, reason, priority_delay, scheduler);
    }
}

// @TODO xpaths can't handle templates, rules, or id-refs

// nvpair with provides or requires set to unfencing
#define XPATH_UNFENCING_NVPAIR PCMK_XE_NVPAIR           \
    "[(@" PCMK_XA_NAME "='" PCMK_FENCING_PROVIDES "'"   \
    "or @" PCMK_XA_NAME "='" PCMK_META_REQUIRES "') "   \
    "and @" PCMK_XA_VALUE "='" PCMK_VALUE_UNFENCING "']"

// unfencing in rsc_defaults or any resource
#define XPATH_ENABLE_UNFENCING \
    "/" PCMK_XE_CIB "/" PCMK_XE_CONFIGURATION "/" PCMK_XE_RESOURCES     \
    "//" PCMK_XE_META_ATTRIBUTES "/" XPATH_UNFENCING_NVPAIR             \
    "|/" PCMK_XE_CIB "/" PCMK_XE_CONFIGURATION "/" PCMK_XE_RSC_DEFAULTS \
    "/" PCMK_XE_META_ATTRIBUTES "/" XPATH_UNFENCING_NVPAIR

static void
set_if_xpath(uint64_t flag, const char *xpath, pcmk_scheduler_t *scheduler)
{
    xmlXPathObject *result = NULL;

    if (!pcmk__is_set(scheduler->flags, flag)) {
        result = pcmk__xpath_search(scheduler->input->doc, xpath);
        if (pcmk__xpath_num_results(result) > 0) {
            pcmk__set_scheduler_flags(scheduler, flag);
        }
        xmlXPathFreeObject(result);
    }
}

gboolean
unpack_config(xmlNode *config, pcmk_scheduler_t *scheduler)
{
    const char *value = NULL;
    GHashTable *config_hash = pcmk__strkey_table(free, free);

    const pcmk_rule_input_t rule_input = {
        .now = scheduler->priv->now,
    };

    scheduler->priv->options = config_hash;

    pe__unpack_dataset_nvpairs(config, PCMK_XE_CLUSTER_PROPERTY_SET,
                               &rule_input, config_hash,
                               PCMK_VALUE_CIB_BOOTSTRAP_OPTIONS, scheduler);

    pcmk__validate_cluster_options(config_hash);

    set_config_flag(scheduler, PCMK__OPT_ENABLE_STARTUP_PROBES,
                    pcmk__sched_probe_resources);
    if (!pcmk__is_set(scheduler->flags, pcmk__sched_probe_resources)) {
        pcmk__warn_once(pcmk__wo_enable_startup_probes,
                        "Support for the " PCMK__OPT_ENABLE_STARTUP_PROBES " "
                        "cluster property is deprecated and will be removed "
                        "(and behave as true) in a future release. Use a "
                        "location constraint with "
                        PCMK_XA_RESOURCE_DISCOVERY "=" PCMK_VALUE_NEVER " "
                        "instead to disable probes where desired.");
    }

    value = pcmk__cluster_option(config_hash, PCMK_OPT_HAVE_WATCHDOG);
    if (pcmk__is_true(value)) {
        pcmk__info("Watchdog-based self-fencing will be performed via SBD if "
                   "fencing is required and " PCMK_OPT_FENCING_WATCHDOG_TIMEOUT
                   " is nonzero");
        pcmk__set_scheduler_flags(scheduler, pcmk__sched_have_fencing);
    }

    /* Set certain flags via xpath here, so they can be used before the relevant
     * configuration sections are unpacked.
     */
    set_if_xpath(pcmk__sched_enable_unfencing, XPATH_ENABLE_UNFENCING,
                 scheduler);

    value = pcmk__cluster_option(config_hash, PCMK_OPT_FENCING_TIMEOUT);
    pcmk_parse_interval_spec(value, &(scheduler->priv->fence_timeout_ms));

    pcmk__debug("Default fencing action timeout: %s",
                pcmk__readable_interval(scheduler->priv->fence_timeout_ms));

    set_config_flag(scheduler, PCMK_OPT_FENCING_ENABLED,
                    pcmk__sched_fencing_enabled);
    if (pcmk__is_set(scheduler->flags, pcmk__sched_fencing_enabled)) {
        pcmk__debug("Fencing of failed nodes is enabled");
    } else {
        pcmk__debug("Fencing of failed nodes is disabled");
    }

    scheduler->priv->fence_action =
        pcmk__cluster_option(config_hash, PCMK_OPT_FENCING_ACTION);
    pcmk__trace("Fencing will %s nodes", scheduler->priv->fence_action);

    set_config_flag(scheduler, PCMK__OPT_CONCURRENT_FENCING,
                    pcmk__sched_concurrent_fencing);
    if (pcmk__is_set(scheduler->flags, pcmk__sched_concurrent_fencing)) {
        pcmk__debug("Concurrent fencing is enabled");

    } else {
        pcmk__warn_once(pcmk__wo_concurrent_fencing,
                        "Support for the " PCMK__OPT_CONCURRENT_FENCING " "
                        "cluster property is deprecated and will be removed "
                        "(and behave as true) in a future release.");
    }

    value = pcmk__cluster_option(config_hash, PCMK_OPT_PRIORITY_FENCING_DELAY);
    if (value) {
        guint *delay_ms = &(scheduler->priv->priority_fencing_ms);

        pcmk_parse_interval_spec(value, delay_ms);
        pcmk__trace("Priority fencing delay is %s",
                    pcmk__readable_interval(*delay_ms));
    }

    set_config_flag(scheduler, PCMK_OPT_STOP_ALL_RESOURCES,
                    pcmk__sched_stop_all);
    pcmk__debug("Stop all active resources: %s",
                pcmk__flag_text(scheduler->flags, pcmk__sched_stop_all));

    set_config_flag(scheduler, PCMK_OPT_SYMMETRIC_CLUSTER,
                    pcmk__sched_symmetric_cluster);
    if (pcmk__is_set(scheduler->flags, pcmk__sched_symmetric_cluster)) {
        pcmk__debug("Cluster is symmetric - resources can run anywhere by "
                    "default");
    }

    value = pcmk__cluster_option(config_hash, PCMK_OPT_NO_QUORUM_POLICY);

    if (pcmk__str_eq(value, PCMK_VALUE_IGNORE, pcmk__str_casei)) {
        scheduler->no_quorum_policy = pcmk_no_quorum_ignore;

    } else if (pcmk__str_eq(value, PCMK_VALUE_FREEZE, pcmk__str_casei)) {
        scheduler->no_quorum_policy = pcmk_no_quorum_freeze;

    } else if (pcmk__str_eq(value, PCMK_VALUE_DEMOTE, pcmk__str_casei)) {
        scheduler->no_quorum_policy = pcmk_no_quorum_demote;

    } else if (pcmk__strcase_any_of(value, PCMK_VALUE_FENCE,
                                    PCMK_VALUE_FENCE_LEGACY, NULL)) {
        if (pcmk__is_set(scheduler->flags, pcmk__sched_fencing_enabled)) {
            int do_panic = 0;

            pcmk__xe_get_int(scheduler->input, PCMK_XA_NO_QUORUM_PANIC,
                             &do_panic);
            if (do_panic
                || pcmk__is_set(scheduler->flags, pcmk__sched_quorate)) {
                scheduler->no_quorum_policy = pcmk_no_quorum_fence;
            } else {
                pcmk__notice("Resetting " PCMK_OPT_NO_QUORUM_POLICY " to "
                             "'" PCMK_VALUE_STOP "': cluster has never had "
                             "quorum");
                scheduler->no_quorum_policy = pcmk_no_quorum_stop;
            }
        } else {
            pcmk__config_err("Resetting " PCMK_OPT_NO_QUORUM_POLICY
                             " to 'stop' because fencing is disabled");
            scheduler->no_quorum_policy = pcmk_no_quorum_stop;
        }

    } else {
        scheduler->no_quorum_policy = pcmk_no_quorum_stop;
    }

    switch (scheduler->no_quorum_policy) {
        case pcmk_no_quorum_freeze:
            pcmk__debug("On loss of quorum: Freeze resources that require "
                        "quorum");
            break;
        case pcmk_no_quorum_stop:
            pcmk__debug("On loss of quorum: Stop resources that require "
                        "quorum");
            break;
        case pcmk_no_quorum_demote:
            pcmk__debug("On loss of quorum: Demote promotable resources and "
                        "stop other resources");
            break;
        case pcmk_no_quorum_fence:
            pcmk__notice("On loss of quorum: Fence all remaining nodes");
            break;
        case pcmk_no_quorum_ignore:
            pcmk__notice("On loss of quorum: Ignore");
            break;
    }

    set_config_flag(scheduler, PCMK__OPT_STOP_REMOVED_RESOURCES,
                    pcmk__sched_stop_removed_resources);
    if (pcmk__is_set(scheduler->flags, pcmk__sched_stop_removed_resources)) {
        pcmk__trace("Removed resources are stopped");
    } else {
        pcmk__warn_once(pcmk__wo_stop_removed_resources,
                        "Support for the " PCMK__OPT_STOP_REMOVED_RESOURCES " "
                        "cluster property is deprecated and will be removed "
                        "(and behave as true) in a future release.");
    }

    set_config_flag(scheduler, PCMK__OPT_CANCEL_REMOVED_ACTIONS,
                    pcmk__sched_cancel_removed_actions);
    if (pcmk__is_set(scheduler->flags, pcmk__sched_cancel_removed_actions)) {
        pcmk__trace("Removed resource actions are stopped");
    } else {
        pcmk__warn_once(pcmk__wo_cancel_removed_actions,
                        "Support for the " PCMK__OPT_CANCEL_REMOVED_ACTIONS " "
                        "cluster property is deprecated and will be removed "
                        "(and behave as true) in a future release.");
    }

    set_config_flag(scheduler, PCMK_OPT_MAINTENANCE_MODE,
                    pcmk__sched_in_maintenance);
    pcmk__trace("Maintenance mode: %s",
                pcmk__flag_text(scheduler->flags, pcmk__sched_in_maintenance));

    set_config_flag(scheduler, PCMK_OPT_START_FAILURE_IS_FATAL,
                    pcmk__sched_start_failure_fatal);
    if (pcmk__is_set(scheduler->flags, pcmk__sched_start_failure_fatal)) {
        pcmk__trace("Start failures are always fatal");
    } else {
        pcmk__trace("Start failures are handled by failcount");
    }

    if (pcmk__is_set(scheduler->flags, pcmk__sched_fencing_enabled)) {
        set_config_flag(scheduler, PCMK_OPT_STARTUP_FENCING,
                        pcmk__sched_startup_fencing);
    }
    if (pcmk__is_set(scheduler->flags, pcmk__sched_startup_fencing)) {
        pcmk__trace("Unseen nodes will be fenced");
    } else {
        pcmk__warn_once(pcmk__wo_blind,
                        "Blind faith: not fencing unseen nodes");
    }

    pe__unpack_node_health_scores(scheduler);

    scheduler->priv->placement_strategy =
        pcmk__cluster_option(config_hash, PCMK_OPT_PLACEMENT_STRATEGY);
    pcmk__trace("Placement strategy: %s", scheduler->priv->placement_strategy);

    set_config_flag(scheduler, PCMK_OPT_SHUTDOWN_LOCK,
                    pcmk__sched_shutdown_lock);
    if (pcmk__is_set(scheduler->flags, pcmk__sched_shutdown_lock)) {
        value = pcmk__cluster_option(config_hash, PCMK_OPT_SHUTDOWN_LOCK_LIMIT);
        pcmk_parse_interval_spec(value, &(scheduler->priv->shutdown_lock_ms));
        pcmk__trace("Resources will be locked to nodes that were cleanly "
                    "shut down (locks expire after %s)",
                    pcmk__readable_interval(scheduler->priv->shutdown_lock_ms));
    } else {
        pcmk__trace("Resources will not be locked to nodes that were cleanly "
                    "shut down");
    }

    value = pcmk__cluster_option(config_hash, PCMK_OPT_NODE_PENDING_TIMEOUT);
    pcmk_parse_interval_spec(value, &(scheduler->priv->node_pending_ms));
    if (scheduler->priv->node_pending_ms == 0U) {
        pcmk__trace("Do not fence pending nodes");
    } else {
        pcmk__trace("Fence pending nodes after %s",
                    pcmk__readable_interval(scheduler->priv->node_pending_ms));
    }

    set_config_flag(scheduler, PCMK_OPT_FENCE_REMOTE_WITHOUT_QUORUM,
                    pcmk__sched_fence_remote_no_quorum);
    if (pcmk__is_set(scheduler->flags, pcmk__sched_fence_remote_no_quorum)) {
        pcmk__trace("Pacemaker Remote nodes may be fenced without quorum");

    } else {
        pcmk__trace("Pacemaker Remote nodes require quorum to be fenced");
    }

    return TRUE;
}

/*!
 * \internal
 * \brief Create a new node object in scheduler data
 *
 * \param[in]     id         ID of new node
 * \param[in]     uname      Name of new node
 * \param[in]     type       Type of new node
 * \param[in]     score      Score of new node
 * \param[in,out] scheduler  Scheduler data
 *
 * \return Newly created node object
 * \note The returned object is part of the scheduler data and should not be
 *       freed separately.
 */
pcmk_node_t *
pe_create_node(const char *id, const char *uname, const char *type,
               int score, pcmk_scheduler_t *scheduler)
{
    enum pcmk__node_variant variant = pcmk__node_variant_cluster;
    pcmk_node_t *new_node = NULL;

    if (pcmk_find_node(scheduler, uname) != NULL) {
        pcmk__config_warn("More than one node entry has name '%s'", uname);
    }

    if (pcmk__str_eq(type, PCMK_VALUE_MEMBER,
                     pcmk__str_null_matches|pcmk__str_casei)) {
        variant = pcmk__node_variant_cluster;

    } else if (pcmk__str_eq(type, PCMK_VALUE_REMOTE, pcmk__str_casei)) {
        variant = pcmk__node_variant_remote;

    } else {
        pcmk__config_err("Ignoring node %s with unrecognized type '%s'",
                         pcmk__s(uname, "without name"), type);
        return NULL;
    }

    new_node = calloc(1, sizeof(pcmk_node_t));
    if (new_node == NULL) {
        pcmk__sched_err(scheduler, "Could not allocate memory for node %s",
                        uname);
        return NULL;
    }

    new_node->assign = calloc(1, sizeof(struct pcmk__node_assignment));
    new_node->details = calloc(1, sizeof(struct pcmk__node_details));
    new_node->priv = calloc(1, sizeof(pcmk__node_private_t));
    if ((new_node->assign == NULL) || (new_node->details == NULL)
        || (new_node->priv == NULL)) {
        free(new_node->assign);
        free(new_node->details);
        free(new_node->priv);
        free(new_node);
        pcmk__sched_err(scheduler, "Could not allocate memory for node %s",
                        uname);
        return NULL;
    }

    pcmk__trace("Creating node for entry %s/%s", uname, id);
    new_node->assign->score = score;
    new_node->priv->id = id;
    new_node->priv->name = uname;
    new_node->priv->flags = pcmk__node_probes_allowed;
    new_node->details->online = FALSE;
    new_node->details->shutdown = FALSE;
    new_node->details->running_rsc = NULL;
    new_node->priv->scheduler = scheduler;
    new_node->priv->variant = variant;
    new_node->priv->attrs = pcmk__strkey_table(free, free);
    new_node->priv->utilization = pcmk__strkey_table(free, free);
    new_node->priv->digest_cache = pcmk__strkey_table(free, pe__free_digests);

    if (pcmk__is_pacemaker_remote_node(new_node)) {
        pcmk__insert_dup(new_node->priv->attrs, CRM_ATTR_KIND, "remote");
        pcmk__set_scheduler_flags(scheduler, pcmk__sched_have_remote_nodes);
    } else {
        pcmk__insert_dup(new_node->priv->attrs, CRM_ATTR_KIND, "cluster");
    }

    scheduler->nodes = g_list_insert_sorted(scheduler->nodes, new_node,
                                            pe__cmp_node_name);
    return new_node;
}

static const char *
expand_remote_rsc_meta(xmlNode *xml_obj, xmlNode *parent, pcmk_scheduler_t *data)
{
    xmlNode *attr_set = NULL;
    xmlNode *attr = NULL;

    const char *container_id = pcmk__xe_id(xml_obj);
    const char *remote_name = NULL;
    const char *remote_server = NULL;
    const char *remote_port = NULL;
    const char *connect_timeout = "60s";
    const char *remote_allow_migrate=NULL;
    const char *is_managed = NULL;

    // @TODO This doesn't handle rules or id-ref
    for (attr_set = pcmk__xe_first_child(xml_obj, PCMK_XE_META_ATTRIBUTES,
                                         NULL, NULL);
         attr_set != NULL;
         attr_set = pcmk__xe_next(attr_set, PCMK_XE_META_ATTRIBUTES)) {

        for (attr = pcmk__xe_first_child(attr_set, NULL, NULL, NULL);
             attr != NULL; attr = pcmk__xe_next(attr, NULL)) {

            const char *value = pcmk__xe_get(attr, PCMK_XA_VALUE);
            const char *name = pcmk__xe_get(attr, PCMK_XA_NAME);

            if (name == NULL) { // Sanity
                continue;
            }

            if (strcmp(name, PCMK_META_REMOTE_NODE) == 0) {
                remote_name = value;

            } else if (strcmp(name, PCMK_META_REMOTE_ADDR) == 0) {
                remote_server = value;

            } else if (strcmp(name, PCMK_META_REMOTE_PORT) == 0) {
                remote_port = value;

            } else if (strcmp(name, PCMK_META_REMOTE_CONNECT_TIMEOUT) == 0) {
                connect_timeout = value;

            } else if (strcmp(name, PCMK_META_REMOTE_ALLOW_MIGRATE) == 0) {
                remote_allow_migrate = value;

            } else if (strcmp(name, PCMK_META_IS_MANAGED) == 0) {
                is_managed = value;
            }
        }
    }

    if (remote_name == NULL) {
        return NULL;
    }

    if (pe_find_resource(data->priv->resources, remote_name) != NULL) {
        return NULL;
    }

    pe_create_remote_xml(parent, remote_name, container_id,
                         remote_allow_migrate, is_managed,
                         connect_timeout, remote_server, remote_port);
    return remote_name;
}

static void
handle_startup_fencing(pcmk_scheduler_t *scheduler, pcmk_node_t *new_node)
{
    if ((new_node->priv->variant == pcmk__node_variant_remote)
        && (new_node->priv->remote == NULL)) {
        /* Ignore fencing for remote nodes that don't have a connection resource
         * associated with them. This happens when remote node entries get left
         * in the nodes section after the connection resource is removed.
         */
        return;
    }

    if (pcmk__is_set(scheduler->flags, pcmk__sched_startup_fencing)) {
        // All nodes are unclean until we've seen their status entry
        new_node->details->unclean = TRUE;

    } else {
        // Blind faith ...
        new_node->details->unclean = FALSE;
    }
}

gboolean
unpack_nodes(xmlNode *xml_nodes, pcmk_scheduler_t *scheduler)
{
    xmlNode *xml_obj = NULL;
    pcmk_node_t *new_node = NULL;
    const char *id = NULL;
    const char *uname = NULL;
    const char *type = NULL;

    for (xml_obj = pcmk__xe_first_child(xml_nodes, PCMK_XE_NODE, NULL, NULL);
         xml_obj != NULL; xml_obj = pcmk__xe_next(xml_obj, PCMK_XE_NODE)) {

        int score = 0;
        int rc = pcmk__xe_get_score(xml_obj, PCMK_XA_SCORE, &score, 0);

        new_node = NULL;

        id = pcmk__xe_get(xml_obj, PCMK_XA_ID);
        uname = pcmk__xe_get(xml_obj, PCMK_XA_UNAME);
        type = pcmk__xe_get(xml_obj, PCMK_XA_TYPE);
        pcmk__trace("Processing node %s/%s", uname, id);

        if (id == NULL) {
            pcmk__config_err("Ignoring <" PCMK_XE_NODE
                             "> entry in configuration without id");
            continue;
        }
        if (rc != pcmk_rc_ok) {
            // Not possible with schema validation enabled
            pcmk__config_warn("Using 0 as score for node %s "
                              "because '%s' is not a valid score: %s",
                              pcmk__s(uname, "without name"),
                              pcmk__xe_get(xml_obj, PCMK_XA_SCORE),
                              pcmk_rc_str(rc));
        }
        new_node = pe_create_node(id, uname, type, score, scheduler);

        if (new_node == NULL) {
            return FALSE;
        }

        handle_startup_fencing(scheduler, new_node);

        add_node_attrs(xml_obj, new_node, FALSE, scheduler);

        pcmk__trace("Done with node %s", pcmk__xe_get(xml_obj, PCMK_XA_UNAME));
    }

    return TRUE;
}

static void
unpack_launcher(pcmk_resource_t *rsc, pcmk_scheduler_t *scheduler)
{
    const char *launcher_id = NULL;

    if (rsc->priv->children != NULL) {
        g_list_foreach(rsc->priv->children, (GFunc) unpack_launcher,
                       scheduler);
        return;
    }

    launcher_id = g_hash_table_lookup(rsc->priv->meta, PCMK__META_CONTAINER);
    if ((launcher_id != NULL)
        && !pcmk__str_eq(launcher_id, rsc->id, pcmk__str_none)) {
        pcmk_resource_t *launcher = pe_find_resource(scheduler->priv->resources,
                                                     launcher_id);

        if (launcher != NULL) {
            rsc->priv->launcher = launcher;
            launcher->priv->launched =
                g_list_append(launcher->priv->launched, rsc);
            pcmk__rsc_trace(rsc, "Resource %s's launcher is %s",
                            rsc->id, launcher_id);
        } else {
            pcmk__config_err("Resource %s: Unknown " PCMK__META_CONTAINER " %s",
                             rsc->id, launcher_id);
        }
    }
}

gboolean
unpack_remote_nodes(xmlNode *xml_resources, pcmk_scheduler_t *scheduler)
{
    xmlNode *xml_obj = NULL;

    /* Create remote nodes and guest nodes from the resource configuration
     * before unpacking resources.
     */
    for (xml_obj = pcmk__xe_first_child(xml_resources, NULL, NULL, NULL);
         xml_obj != NULL; xml_obj = pcmk__xe_next(xml_obj, NULL)) {

        const char *new_node_id = NULL;

        /* Check for remote nodes, which are defined by ocf:pacemaker:remote
         * primitives.
         */
        if (xml_contains_remote_node(xml_obj)) {
            new_node_id = pcmk__xe_id(xml_obj);
            /* The pcmk_find_node() check ensures we don't iterate over an
             * expanded node that has already been added to the node list
             */
            if (new_node_id
                && (pcmk_find_node(scheduler, new_node_id) == NULL)) {
                pcmk__trace("Found remote node %s defined by resource %s",
                            new_node_id, pcmk__xe_id(xml_obj));
                pe_create_node(new_node_id, new_node_id, PCMK_VALUE_REMOTE,
                               0, scheduler);
            }
            continue;
        }

        /* Check for guest nodes, which are defined by special meta-attributes
         * of a primitive of any type (for example, VirtualDomain or Xen).
         */
        if (pcmk__xe_is(xml_obj, PCMK_XE_PRIMITIVE)) {
            /* This will add an ocf:pacemaker:remote primitive to the
             * configuration for the guest node's connection, to be unpacked
             * later.
             */
            new_node_id = expand_remote_rsc_meta(xml_obj, xml_resources,
                                                 scheduler);
            if (new_node_id
                && (pcmk_find_node(scheduler, new_node_id) == NULL)) {
                pcmk__trace("Found guest node %s in resource %s",
                            new_node_id, pcmk__xe_id(xml_obj));
                pe_create_node(new_node_id, new_node_id, PCMK_VALUE_REMOTE,
                               0, scheduler);
            }
            continue;
        }

        /* Check for guest nodes inside a group. Clones are currently not
         * supported as guest nodes.
         */
        if (pcmk__xe_is(xml_obj, PCMK_XE_GROUP)) {
            xmlNode *xml_obj2 = NULL;
            for (xml_obj2 = pcmk__xe_first_child(xml_obj, NULL, NULL, NULL);
                 xml_obj2 != NULL; xml_obj2 = pcmk__xe_next(xml_obj2, NULL)) {

                new_node_id = expand_remote_rsc_meta(xml_obj2, xml_resources,
                                                     scheduler);

                if (new_node_id
                    && (pcmk_find_node(scheduler, new_node_id) == NULL)) {
                    pcmk__trace("Found guest node %s in resource %s inside "
                                "group %s",
                                new_node_id, pcmk__xe_id(xml_obj2),
                                pcmk__xe_id(xml_obj));
                    pe_create_node(new_node_id, new_node_id, PCMK_VALUE_REMOTE,
                                   0, scheduler);
                }
            }
        }
    }
    return TRUE;
}

/* Call this after all the nodes and resources have been
 * unpacked, but before the status section is read.
 *
 * A remote node's online status is reflected by the state
 * of the remote node's connection resource. We need to link
 * the remote node to this connection resource so we can have
 * easy access to the connection resource during the scheduler calculations.
 */
static void
link_rsc2remotenode(pcmk_scheduler_t *scheduler, pcmk_resource_t *new_rsc)
{
    pcmk_node_t *remote_node = NULL;

    if (!pcmk__is_set(new_rsc->flags, pcmk__rsc_is_remote_connection)) {
        return;
    }

    if (pcmk__is_set(scheduler->flags, pcmk__sched_location_only)) {
        /* remote_nodes and remote_resources are not linked in quick location calculations */
        return;
    }

    remote_node = pcmk_find_node(scheduler, new_rsc->id);
    CRM_CHECK(remote_node != NULL, return);

    pcmk__rsc_trace(new_rsc, "Linking remote connection resource %s to %s",
                    new_rsc->id, pcmk__node_name(remote_node));
    remote_node->priv->remote = new_rsc;

    if (new_rsc->priv->launcher == NULL) {
        /* Handle start-up fencing for remote nodes (as opposed to guest nodes)
         * the same as is done for cluster nodes.
         */
        handle_startup_fencing(scheduler, remote_node);

    } else {
        /* pe_create_node() marks the new node as "remote" or "cluster"; now
         * that we know the node is a guest node, update it correctly.
         */
        pcmk__insert_dup(remote_node->priv->attrs,
                         CRM_ATTR_KIND, "container");
    }
}

/*!
 * \internal
 * \brief Parse configuration XML for resource information
 *
 * \param[in]     xml_resources  Top of resource configuration XML
 * \param[in,out] scheduler      Scheduler data
 *
 * \return TRUE
 *
 * \note unpack_remote_nodes() MUST be called before this, so that the nodes can
 *       be used when pe__unpack_resource() calls resource_location()
 */
gboolean
unpack_resources(const xmlNode *xml_resources, pcmk_scheduler_t *scheduler)
{
    xmlNode *xml_obj = NULL;
    GList *gIter = NULL;

    scheduler->priv->templates = pcmk__strkey_table(free, pcmk__free_idref);

    for (xml_obj = pcmk__xe_first_child(xml_resources, NULL, NULL, NULL);
         xml_obj != NULL; xml_obj = pcmk__xe_next(xml_obj, NULL)) {

        pcmk_resource_t *new_rsc = NULL;
        const char *id = pcmk__xe_id(xml_obj);

        if (pcmk__str_empty(id)) {
            pcmk__config_err("Ignoring <%s> resource without ID",
                             xml_obj->name);
            continue;
        }

        if (pcmk__xe_is(xml_obj, PCMK_XE_TEMPLATE)) {
            if (g_hash_table_lookup_extended(scheduler->priv->templates, id,
                                             NULL, NULL) == FALSE) {
                /* Record the template's ID for the knowledge of its existence anyway. */
                pcmk__insert_dup(scheduler->priv->templates, id, NULL);
            }
            continue;
        }

        pcmk__trace("Unpacking <%s " PCMK_XA_ID "='%s'>", xml_obj->name, id);
        if (pe__unpack_resource(xml_obj, &new_rsc, NULL,
                                scheduler) == pcmk_rc_ok) {
            scheduler->priv->resources =
                g_list_append(scheduler->priv->resources, new_rsc);
            pcmk__rsc_trace(new_rsc, "Added resource %s", new_rsc->id);

        } else {
            pcmk__config_err("Ignoring <%s> resource '%s' "
                             "because configuration is invalid",
                             xml_obj->name, id);
        }
    }

    for (gIter = scheduler->priv->resources;
         gIter != NULL; gIter = gIter->next) {

        pcmk_resource_t *rsc = (pcmk_resource_t *) gIter->data;

        unpack_launcher(rsc, scheduler);
        link_rsc2remotenode(scheduler, rsc);
    }

    scheduler->priv->resources = g_list_sort(scheduler->priv->resources,
                                             pe__cmp_rsc_priority);
    if (pcmk__is_set(scheduler->flags, pcmk__sched_location_only)) {
        /* Ignore */

    } else if (pcmk__is_set(scheduler->flags, pcmk__sched_fencing_enabled)
               && !pcmk__is_set(scheduler->flags, pcmk__sched_have_fencing)) {

        /* pcs's CI tests look for this specific error message. Confer with the
         * pcs team before changing it. If the dependency still exists, bump the
         * CRM_FEATURE_SET and inform the pcs maintainers.
         *
         * Also, ResyncCIB.errors_to_ignore() looks for this specific error
         * message as well.
         */
        pcmk__config_err("Resource start-up disabled since no fencing "
                         "resources have been defined. Either configure some "
                         "or disable fencing with the "
                         PCMK_OPT_FENCING_ENABLED " option. NOTE: Clusters "
                         "with shared data need fencing to ensure data "
                         "integrity.");
    }

    return TRUE;
}

/*!
 * \internal
 * \brief Validate the levels in a fencing topology
 *
 * \param[in] xml  \c PCMK_XE_FENCING_TOPOLOGY element
 */
void
pcmk__validate_fencing_topology(const xmlNode *xml)
{
    if (xml == NULL) {
        return;
    }

    CRM_CHECK(pcmk__xe_is(xml, PCMK_XE_FENCING_TOPOLOGY), return);

    for (const xmlNode *level = pcmk__xe_first_child(xml, PCMK_XE_FENCING_LEVEL,
                                                     NULL, NULL);
         level != NULL; level = pcmk__xe_next(level, PCMK_XE_FENCING_LEVEL)) {

        const char *id = pcmk__xe_id(level);
        int index = 0;

        if (pcmk__str_empty(id)) {
            pcmk__config_err("Ignoring fencing level without ID");
            continue;
        }

        if (pcmk__xe_get_int(level, PCMK_XA_INDEX, &index) != pcmk_rc_ok) {
            pcmk__config_err("Ignoring fencing level %s with invalid index",
                             id);
            continue;
        }

        if ((index < ST__LEVEL_MIN) || (index > ST__LEVEL_MAX)) {
            pcmk__config_err("Ignoring fencing level %s with out-of-range "
                             "index %d",
                             id, index);
        }
    }
}

gboolean
unpack_tags(xmlNode *xml_tags, pcmk_scheduler_t *scheduler)
{
    xmlNode *xml_tag = NULL;

    scheduler->priv->tags = pcmk__strkey_table(free, pcmk__free_idref);

    for (xml_tag = pcmk__xe_first_child(xml_tags, PCMK_XE_TAG, NULL, NULL);
         xml_tag != NULL; xml_tag = pcmk__xe_next(xml_tag, PCMK_XE_TAG)) {

        xmlNode *xml_obj_ref = NULL;
        const char *tag_id = pcmk__xe_id(xml_tag);

        if (tag_id == NULL) {
            pcmk__config_err("Ignoring <%s> without " PCMK_XA_ID,
                             (const char *) xml_tag->name);
            continue;
        }

        for (xml_obj_ref = pcmk__xe_first_child(xml_tag, PCMK_XE_OBJ_REF,
                                                NULL, NULL);
             xml_obj_ref != NULL;
             xml_obj_ref = pcmk__xe_next(xml_obj_ref, PCMK_XE_OBJ_REF)) {

            const char *obj_ref = pcmk__xe_id(xml_obj_ref);

            if (obj_ref == NULL) {
                pcmk__config_err("Ignoring <%s> for tag '%s' without " PCMK_XA_ID,
                                 xml_obj_ref->name, tag_id);
                continue;
            }

            pcmk__add_idref(scheduler->priv->tags, tag_id, obj_ref);
        }
    }

    return TRUE;
}

/*!
 * \internal
 * \brief Unpack a ticket state entry
 *
 * \param[in]     xml_ticket  XML ticket state to unpack
 * \param[in,out] userdata    Scheduler data
 *
 * \return pcmk_rc_ok (to always continue unpacking further entries)
 */
static int
unpack_ticket_state(xmlNode *xml_ticket, void *userdata)
{
    pcmk_scheduler_t *scheduler = userdata;

    const char *ticket_id = NULL;
    const char *granted = NULL;
    const char *last_granted = NULL;
    const char *standby = NULL;
    xmlAttrPtr xIter = NULL;

    pcmk__ticket_t *ticket = NULL;

    ticket_id = pcmk__xe_id(xml_ticket);
    if (pcmk__str_empty(ticket_id)) {
        return pcmk_rc_ok;
    }

    pcmk__trace("Processing ticket state for %s", ticket_id);

    ticket = g_hash_table_lookup(scheduler->priv->ticket_constraints,
                                 ticket_id);
    if (ticket == NULL) {
        ticket = ticket_new(ticket_id, scheduler);
        if (ticket == NULL) {
            return pcmk_rc_ok;
        }
    }

    for (xIter = xml_ticket->properties; xIter; xIter = xIter->next) {
        const char *prop_name = (const char *)xIter->name;
        const char *prop_value = pcmk__xml_attr_value(xIter);

        if (pcmk__str_eq(prop_name, PCMK_XA_ID, pcmk__str_none)) {
            continue;
        }
        pcmk__insert_dup(ticket->state, prop_name, prop_value);
    }

    granted = g_hash_table_lookup(ticket->state, PCMK__XA_GRANTED);
    if (pcmk__is_true(granted)) {
        pcmk__set_ticket_flags(ticket, pcmk__ticket_granted);
        pcmk__info("We have ticket '%s'", ticket->id);
    } else {
        pcmk__clear_ticket_flags(ticket, pcmk__ticket_granted);
        pcmk__info("We do not have ticket '%s'", ticket->id);
    }

    last_granted = g_hash_table_lookup(ticket->state, PCMK_XA_LAST_GRANTED);
    if (last_granted) {
        long long last_granted_ll = 0LL;
        int rc = pcmk__scan_ll(last_granted, &last_granted_ll, 0LL);

        if (rc != pcmk_rc_ok) {
            pcmk__warn("Using %lld instead of invalid " PCMK_XA_LAST_GRANTED
                       " value '%s' in state for ticket %s: %s",
                       last_granted_ll, last_granted, ticket->id,
                       pcmk_rc_str(rc));
        }
        ticket->last_granted = (time_t) last_granted_ll;
    }

    standby = g_hash_table_lookup(ticket->state, PCMK_XA_STANDBY);
    if (pcmk__is_true(standby)) {
        pcmk__set_ticket_flags(ticket, pcmk__ticket_standby);
        if (pcmk__is_set(ticket->flags, pcmk__ticket_granted)) {
            pcmk__info("Granted ticket '%s' is in standby-mode", ticket->id);
        }
    } else {
        pcmk__clear_ticket_flags(ticket, pcmk__ticket_standby);
    }

    pcmk__trace("Done with ticket state for %s", ticket_id);

    return pcmk_rc_ok;
}

static void
unpack_handle_remote_attrs(pcmk_node_t *this_node, const xmlNode *state,
                           pcmk_scheduler_t *scheduler)
{
    const char *discovery = NULL;
    const xmlNode *attrs = NULL;
    pcmk_resource_t *rsc = NULL;
    int maint = 0;

    if (!pcmk__xe_is(state, PCMK__XE_NODE_STATE)) {
        return;
    }

    if ((this_node == NULL) || !pcmk__is_pacemaker_remote_node(this_node)) {
        return;
    }
    pcmk__trace("Processing Pacemaker Remote node %s",
                pcmk__node_name(this_node));

    pcmk__scan_min_int(pcmk__xe_get(state, PCMK__XA_NODE_IN_MAINTENANCE),
                       &maint, 0);
    if (maint) {
        pcmk__set_node_flags(this_node, pcmk__node_remote_maint);
    } else {
        pcmk__clear_node_flags(this_node, pcmk__node_remote_maint);
    }

    rsc = this_node->priv->remote;
    if (!pcmk__is_set(this_node->priv->flags, pcmk__node_remote_reset)) {
        this_node->details->unclean = FALSE;
        pcmk__set_node_flags(this_node, pcmk__node_seen);
    }
    attrs = pcmk__xe_first_child(state, PCMK__XE_TRANSIENT_ATTRIBUTES, NULL,
                                 NULL);
    add_node_attrs(attrs, this_node, TRUE, scheduler);

    if (pe__shutdown_requested(this_node)) {
        pcmk__info("%s is shutting down", pcmk__node_name(this_node));
        this_node->details->shutdown = TRUE;
    }

    if (pcmk__is_true(pcmk__node_attr(this_node, PCMK_NODE_ATTR_STANDBY, NULL,
                                      pcmk__rsc_node_current))) {
        pcmk__info("%s is in standby mode", pcmk__node_name(this_node));
        pcmk__set_node_flags(this_node, pcmk__node_standby);
    }

    if (pcmk__is_true(pcmk__node_attr(this_node, PCMK_NODE_ATTR_MAINTENANCE,
                                      NULL, pcmk__rsc_node_current))
        || ((rsc != NULL) && !pcmk__is_set(rsc->flags, pcmk__rsc_managed))) {
        pcmk__info("%s is in maintenance mode", pcmk__node_name(this_node));
        this_node->details->maintenance = TRUE;
    }

    discovery = pcmk__node_attr(this_node,
                                PCMK__NODE_ATTR_RESOURCE_DISCOVERY_ENABLED,
                                NULL, pcmk__rsc_node_current);
    if ((discovery != NULL) && !pcmk__is_true(discovery)) {
        pcmk__warn_once(pcmk__wo_rdisc_enabled,
                        "Support for the "
                        PCMK__NODE_ATTR_RESOURCE_DISCOVERY_ENABLED
                        " node attribute is deprecated and will be removed"
                        " (and behave as 'true') in a future release.");

        if (pcmk__is_remote_node(this_node)
            && !pcmk__is_set(scheduler->flags, pcmk__sched_fencing_enabled)) {
            pcmk__config_warn("Ignoring "
                              PCMK__NODE_ATTR_RESOURCE_DISCOVERY_ENABLED
                              " attribute on Pacemaker Remote node %s"
                              " because fencing is disabled",
                              pcmk__node_name(this_node));
        } else {
            /* This is either a remote node with fencing enabled, or a guest
             * node. We don't care whether fencing is enabled when fencing guest
             * nodes, because they are "fenced" by recovering their containing
             * resource.
             */
            pcmk__info("%s has resource discovery disabled",
                       pcmk__node_name(this_node));
            pcmk__clear_node_flags(this_node, pcmk__node_probes_allowed);
        }
    }
}

/*!
 * \internal
 * \brief Unpack a cluster node's transient attributes
 *
 * \param[in]     state      CIB node state XML
 * \param[in,out] node       Cluster node whose attributes are being unpacked
 * \param[in,out] scheduler  Scheduler data
 */
static void
unpack_transient_attributes(const xmlNode *state, pcmk_node_t *node,
                            pcmk_scheduler_t *scheduler)
{
    const char *discovery = NULL;
    const xmlNode *attrs = pcmk__xe_first_child(state,
                                                PCMK__XE_TRANSIENT_ATTRIBUTES,
                                                NULL, NULL);

    add_node_attrs(attrs, node, TRUE, scheduler);

    if (pcmk__is_true(pcmk__node_attr(node, PCMK_NODE_ATTR_STANDBY, NULL,
                                      pcmk__rsc_node_current))) {
        pcmk__info("%s is in standby mode", pcmk__node_name(node));
        pcmk__set_node_flags(node, pcmk__node_standby);
    }

    if (pcmk__is_true(pcmk__node_attr(node, PCMK_NODE_ATTR_MAINTENANCE, NULL,
                                      pcmk__rsc_node_current))) {
        pcmk__info("%s is in maintenance mode", pcmk__node_name(node));
        node->details->maintenance = TRUE;
    }

    discovery = pcmk__node_attr(node,
                                PCMK__NODE_ATTR_RESOURCE_DISCOVERY_ENABLED,
                                NULL, pcmk__rsc_node_current);
    if ((discovery != NULL) && !pcmk__is_true(discovery)) {
        pcmk__config_warn("Ignoring "
                          PCMK__NODE_ATTR_RESOURCE_DISCOVERY_ENABLED
                          " attribute for %s because disabling resource"
                          " discovery is not allowed for cluster nodes",
                          pcmk__node_name(node));
    }
}

/*!
 * \internal
 * \brief Unpack a node state entry (first pass)
 *
 * Unpack one node state entry from status. This unpacks information from the
 * \C PCMK__XE_NODE_STATE element itself and node attributes inside it, but not
 * the resource history inside it. Multiple passes through the status are needed
 * to fully unpack everything.
 *
 * \param[in]     state      CIB node state XML
 * \param[in,out] scheduler  Scheduler data
 */
static void
unpack_node_state(const xmlNode *state, pcmk_scheduler_t *scheduler)
{
    const char *id = NULL;
    const char *uname = NULL;
    pcmk_node_t *this_node = NULL;

    id = pcmk__xe_get(state, PCMK_XA_ID);
    if (id == NULL) {
        pcmk__config_err("Ignoring invalid " PCMK__XE_NODE_STATE " entry without "
                         PCMK_XA_ID);
        pcmk__log_xml_info(state, "missing-id");
        return;
    }

    uname = pcmk__xe_get(state, PCMK_XA_UNAME);
    if (uname == NULL) {
        /* If a joining peer makes the cluster acquire the quorum from Corosync
         * but has not joined the controller CPG membership yet, it's possible
         * that the created PCMK__XE_NODE_STATE entry doesn't have a
         * PCMK_XA_UNAME yet. Recognize the node as pending and wait for it to
         * join CPG.
         */
        pcmk__trace("Handling " PCMK__XE_NODE_STATE " entry with id=\"%s\" "
                    "without " PCMK_XA_UNAME,
                    id);
    }

    this_node = pe_find_node_any(scheduler->nodes, id, uname);
    if (this_node == NULL) {
        pcmk__notice("Ignoring recorded state for removed node with name %s "
                     "and " PCMK_XA_ID " %s",
                     pcmk__s(uname, "unknown"), id);
        return;
    }

    if (pcmk__is_pacemaker_remote_node(this_node)) {
        int remote_fenced = 0;

        /* We can't determine the online status of Pacemaker Remote nodes until
         * after all resource history has been unpacked. In this first pass, we
         * do need to mark whether the node has been fenced, as this plays a
         * role during unpacking cluster node resource state.
         */
        pcmk__scan_min_int(pcmk__xe_get(state, PCMK__XA_NODE_FENCED),
                           &remote_fenced, 0);
        if (remote_fenced) {
            pcmk__set_node_flags(this_node, pcmk__node_remote_fenced);
        } else {
            pcmk__clear_node_flags(this_node, pcmk__node_remote_fenced);
        }
        return;
    }

    unpack_transient_attributes(state, this_node, scheduler);

    /* Provisionally mark this cluster node as clean. We have at least seen it
     * in the current cluster's lifetime.
     */
    this_node->details->unclean = FALSE;
    pcmk__set_node_flags(this_node, pcmk__node_seen);

    pcmk__trace("Determining online status of cluster node %s (id %s)",
                pcmk__node_name(this_node), id);
    determine_online_status(state, this_node, scheduler);

    if (!pcmk__is_set(scheduler->flags, pcmk__sched_quorate)
        && this_node->details->online
        && (scheduler->no_quorum_policy == pcmk_no_quorum_fence)) {
        /* Everything else should flow from this automatically
         * (at least until the scheduler becomes able to migrate off
         * healthy resources)
         */
        pe_fence_node(scheduler, this_node, "cluster does not have quorum",
                      FALSE);
    }
}

/*!
 * \internal
 * \brief Unpack nodes' resource history as much as possible
 *
 * Unpack as many nodes' resource history as possible in one pass through the
 * status. We need to process Pacemaker Remote nodes' connections/containers
 * before unpacking their history; the connection/container history will be
 * in another node's history, so it might take multiple passes to unpack
 * everything.
 *
 * \param[in]     status     CIB XML status section
 * \param[in]     fence      If true, treat any not-yet-unpacked nodes as unseen
 * \param[in,out] scheduler  Scheduler data
 *
 * \return Standard Pacemaker return code (specifically pcmk_rc_ok if done,
 *         or EAGAIN if more unpacking remains to be done)
 */
static int
unpack_node_history(const xmlNode *status, bool fence,
                    pcmk_scheduler_t *scheduler)
{
    int rc = pcmk_rc_ok;

    // Loop through all PCMK__XE_NODE_STATE entries in CIB status
    for (const xmlNode *state = pcmk__xe_first_child(status,
                                                     PCMK__XE_NODE_STATE, NULL,
                                                     NULL);
         state != NULL; state = pcmk__xe_next(state, PCMK__XE_NODE_STATE)) {

        const char *id = pcmk__xe_id(state);
        const char *uname = pcmk__xe_get(state, PCMK_XA_UNAME);
        pcmk_node_t *this_node = NULL;

        if ((id == NULL) || (uname == NULL)) {
            // Warning already logged in first pass through status section
            pcmk__trace("Not unpacking resource history from malformed "
                        PCMK__XE_NODE_STATE " without id and/or uname");
            continue;
        }

        this_node = pe_find_node_any(scheduler->nodes, id, uname);
        if (this_node == NULL) {
            // Warning already logged in first pass through status section
            pcmk__trace("Not unpacking resource history for node %s because "
                        "no longer in configuration",
                        id);
            continue;
        }

        if (pcmk__is_set(this_node->priv->flags, pcmk__node_unpacked)) {
            pcmk__trace("Not unpacking resource history for node %s because "
                        "already unpacked",
                        id);
            continue;
        }

        if (fence) {
            // We're processing all remaining nodes

        } else if (pcmk__is_guest_or_bundle_node(this_node)) {
            /* We can unpack a guest node's history only after we've unpacked
             * other resource history to the point that we know that the node's
             * connection and containing resource are both up.
             */
            const pcmk_resource_t *remote = this_node->priv->remote;
            const pcmk_resource_t *launcher = remote->priv->launcher;

            if ((remote->priv->orig_role != pcmk_role_started)
                || (launcher->priv->orig_role != pcmk_role_started)) {
                pcmk__trace("Not unpacking resource history for guest node %s "
                            "because launcher and connection are not known to "
                            "be up",
                            id);
                continue;
            }

        } else if (pcmk__is_remote_node(this_node)) {
            /* We can unpack a remote node's history only after we've unpacked
             * other resource history to the point that we know that the node's
             * connection is up, with the exception of when shutdown locks are
             * in use.
             */
            pcmk_resource_t *rsc = this_node->priv->remote;

            if ((rsc == NULL)
                || (!pcmk__is_set(scheduler->flags, pcmk__sched_shutdown_lock)
                    && (rsc->priv->orig_role != pcmk_role_started))) {
                pcmk__trace("Not unpacking resource history for remote node %s "
                            "because connection is not known to be up",
                            id);
                continue;
            }

        /* If fencing and shutdown locks are disabled and we're not processing
         * unseen nodes, then we don't want to unpack offline nodes until online
         * nodes have been unpacked. This allows us to number active clone
         * instances first.
         */
        } else if (!pcmk__any_flags_set(scheduler->flags,
                                        pcmk__sched_fencing_enabled
                                        |pcmk__sched_shutdown_lock)
                   && !this_node->details->online) {
            pcmk__trace("Not unpacking resource history for offline "
                        "cluster node %s",
                        id);
            continue;
        }

        if (pcmk__is_pacemaker_remote_node(this_node)) {
            determine_remote_online_status(scheduler, this_node);
            unpack_handle_remote_attrs(this_node, state, scheduler);
        }

        pcmk__trace("Unpacking resource history for %snode %s",
                    (fence? "unseen " : ""), id);

        pcmk__set_node_flags(this_node, pcmk__node_unpacked);
        unpack_node_lrm(this_node, state, scheduler);

        rc = EAGAIN; // Other node histories might depend on this one
    }
    return rc;
}

/* remove nodes that are down, stopping */
/* create positive rsc_to_node constraints between resources and the nodes they are running on */
/* anything else? */
gboolean
unpack_status(xmlNode *status, pcmk_scheduler_t *scheduler)
{
    xmlNode *state = NULL;

    pcmk__trace("Beginning unpack");

    if (scheduler->priv->ticket_constraints == NULL) {
        scheduler->priv->ticket_constraints =
            pcmk__strkey_table(free, destroy_ticket);
    }

    for (state = pcmk__xe_first_child(status, NULL, NULL, NULL); state != NULL;
         state = pcmk__xe_next(state, NULL)) {

        if (pcmk__xe_is(state, PCMK_XE_TICKETS)) {
            pcmk__xe_foreach_child(state, PCMK__XE_TICKET_STATE,
                                   unpack_ticket_state, scheduler);

        } else if (pcmk__xe_is(state, PCMK__XE_NODE_STATE)) {
            unpack_node_state(state, scheduler);
        }
    }

    while (unpack_node_history(status, FALSE, scheduler) == EAGAIN) {
        pcmk__trace("Another pass through node resource histories is needed");
    }

    // Now catch any nodes we didn't see
    unpack_node_history(status,
                        pcmk__is_set(scheduler->flags,
                                     pcmk__sched_fencing_enabled),
                        scheduler);

    /* Now that we know where resources are, we can schedule stops of containers
     * with failed bundle connections
     */
    if (scheduler->priv->stop_needed != NULL) {
        for (GList *item = scheduler->priv->stop_needed;
             item != NULL; item = item->next) {

            pcmk_resource_t *container = item->data;
            pcmk_node_t *node = pcmk__current_node(container);

            if (node) {
                stop_action(container, node, FALSE);
            }
        }
        g_list_free(scheduler->priv->stop_needed);
        scheduler->priv->stop_needed = NULL;
    }

    /* Now that we know status of all Pacemaker Remote connections and nodes,
     * we can stop connections for node shutdowns, and check the online status
     * of remote/guest nodes that didn't have any node history to unpack.
     */
    for (GList *gIter = scheduler->nodes; gIter != NULL; gIter = gIter->next) {
        pcmk_node_t *this_node = gIter->data;

        if (!pcmk__is_pacemaker_remote_node(this_node)) {
            continue;
        }
        if (this_node->details->shutdown
            && (this_node->priv->remote != NULL)) {
            pe__set_next_role(this_node->priv->remote, pcmk_role_stopped,
                              "remote shutdown");
        }
        if (!pcmk__is_set(this_node->priv->flags, pcmk__node_unpacked)) {
            determine_remote_online_status(scheduler, this_node);
        }
    }

    return TRUE;
}

/*!
 * \internal
 * \brief Unpack node's time when it became a member at the cluster layer
 *
 * \param[in]     node_state  Node's \c PCMK__XE_NODE_STATE entry
 * \param[in,out] scheduler   Scheduler data
 *
 * \return Epoch time when node became a cluster member
 *         (or scheduler effective time for legacy entries) if a member,
 *         0 if not a member, or -1 if no valid information available
 */
static long long
unpack_node_member(const xmlNode *node_state, pcmk_scheduler_t *scheduler)
{
    const char *member_time = pcmk__xe_get(node_state, PCMK__XA_IN_CCM);
    bool is_member = false;

    if (member_time == NULL) {
        return -1LL;
    }

    if (pcmk__parse_bool(member_time, &is_member) != pcmk_rc_ok) {
        long long when_member = 0LL;

        if ((pcmk__scan_ll(member_time, &when_member,
                           0LL) != pcmk_rc_ok) || (when_member < 0LL)) {
            pcmk__warn("Unrecognized value '%s' for " PCMK__XA_IN_CCM " in "
                       PCMK__XE_NODE_STATE " entry",
                       member_time);
            return -1LL;
        }
        return when_member;
    }

    /* If in_ccm=0, we'll return 0 here. If in_ccm=1, either the entry was
     * recorded as a boolean for a DC < 2.1.7, or the node is pending shutdown
     * and has left the CPG, in which case it was set to 1 to avoid fencing for
     * PCMK_OPT_NODE_PENDING_TIMEOUT.
     *
     * We return the effective time for in_ccm=1 because what's important to
     * avoid fencing is that effective time minus this value is less than the
     * pending node timeout.
     */
    return is_member? (long long) pcmk__scheduler_epoch_time(scheduler) : 0LL;
}

/*!
 * \internal
 * \brief Unpack node's time when it became online in process group
 *
 * \param[in] node_state  Node's \c PCMK__XE_NODE_STATE entry
 *
 * \return Epoch time when node became online in process group (or 0 if not
 *         online, or 1 for legacy online entries)
 */
static long long
unpack_node_online(const xmlNode *node_state)
{
    const char *peer_time = pcmk__xe_get(node_state, PCMK_XA_CRMD);

    // @COMPAT Entries recorded for DCs < 2.1.7 have "online" or "offline"
    if (pcmk__str_eq(peer_time, PCMK_VALUE_OFFLINE,
                     pcmk__str_casei|pcmk__str_null_matches)) {
        return 0LL;

    } else if (pcmk__str_eq(peer_time, PCMK_VALUE_ONLINE, pcmk__str_casei)) {
        return 1LL;

    } else {
        long long when_online = 0LL;

        if ((pcmk__scan_ll(peer_time, &when_online, 0LL) != pcmk_rc_ok)
            || (when_online < 0)) {
            pcmk__warn("Unrecognized value '%s' for " PCMK_XA_CRMD " in "
                       PCMK__XE_NODE_STATE " entry, assuming offline",
                       peer_time);
            return 0LL;
        }
        return when_online;
    }
}

/*!
 * \internal
 * \brief Unpack node attribute for user-requested fencing
 *
 * \param[in] node        Node to check
 * \param[in] node_state  Node's \c PCMK__XE_NODE_STATE entry in CIB status
 *
 * \return \c true if fencing has been requested for \p node, otherwise \c false
 */
static bool
unpack_node_terminate(const pcmk_node_t *node, const xmlNode *node_state)
{
    bool value_b = false;
    long long value_ll = 0LL;
    int rc = pcmk_rc_ok;
    const char *value_s = pcmk__node_attr(node, PCMK_NODE_ATTR_TERMINATE,
                                          NULL, pcmk__rsc_node_current);

    // Value may be boolean or an epoch time
    if ((value_s != NULL)
        && (pcmk__parse_bool(value_s, &value_b) == pcmk_rc_ok)) {
        return value_b;
    }

    rc = pcmk__scan_ll(value_s, &value_ll, 0LL);
    if (rc == pcmk_rc_ok) {
        return (value_ll > 0);
    }
    pcmk__warn("Ignoring unrecognized value '%s' for " PCMK_NODE_ATTR_TERMINATE
               "node attribute for %s: %s",
               value_s, pcmk__node_name(node), pcmk_rc_str(rc));
    return false;
}

static gboolean
determine_online_status_no_fencing(pcmk_scheduler_t *scheduler,
                                   const xmlNode *node_state,
                                   pcmk_node_t *this_node)
{
    gboolean online = FALSE;
    const char *join = pcmk__xe_get(node_state, PCMK__XA_JOIN);
    const char *exp_state = pcmk__xe_get(node_state, PCMK_XA_EXPECTED);
    long long when_member = unpack_node_member(node_state, scheduler);
    long long when_online = unpack_node_online(node_state);

    if (when_member <= 0) {
        pcmk__trace("Node %s is %sdown", pcmk__node_name(this_node),
                    ((when_member < 0)? "presumed " : ""));

    } else if (when_online > 0) {
        if (pcmk__str_eq(join, CRMD_JOINSTATE_MEMBER, pcmk__str_casei)) {
            online = TRUE;
        } else {
            pcmk__debug("Node %s is not ready to run resources: %s",
                        pcmk__node_name(this_node), join);
        }

    } else if (!pcmk__is_set(this_node->priv->flags,
                             pcmk__node_expected_up)) {
        pcmk__trace("Node %s controller is down: "
                    "member@%lld online@%lld join=%s expected=%s",
                    pcmk__node_name(this_node), when_member, when_online,
                    pcmk__s(join, "<null>"), pcmk__s(exp_state, "<null>"));

    } else {
        /* mark it unclean */
        pe_fence_node(scheduler, this_node, "peer is unexpectedly down", FALSE);
        pcmk__info("Node %s member@%lld online@%lld join=%s expected=%s",
                   pcmk__node_name(this_node), when_member, when_online,
                   pcmk__s(join, "<null>"), pcmk__s(exp_state, "<null>"));
    }
    return online;
}

/*!
 * \internal
 * \brief Check whether a node has taken too long to join controller group
 *
 * \param[in,out] scheduler    Scheduler data
 * \param[in]     node         Node to check
 * \param[in]     when_member  Epoch time when node became a cluster member
 * \param[in]     when_online  Epoch time when node joined controller group
 *
 * \return true if node has been pending (on the way up) longer than
 *         \c PCMK_OPT_NODE_PENDING_TIMEOUT, otherwise false
 * \note This will also update the cluster's recheck time if appropriate.
 */
static inline bool
pending_too_long(pcmk_scheduler_t *scheduler, const pcmk_node_t *node,
                 long long when_member, long long when_online)
{
    if ((scheduler->priv->node_pending_ms > 0U)
        && (when_member > 0) && (when_online <= 0)) {
        // There is a timeout on pending nodes, and node is pending

        time_t timeout = when_member
                         + pcmk__timeout_ms2s(scheduler->priv->node_pending_ms);

        if (pcmk__scheduler_epoch_time(node->priv->scheduler) >= timeout) {
            return true; // Node has timed out
        }

        // Node is pending, but still has time
        pcmk__update_recheck_time(timeout, scheduler, "pending node timeout");
    }
    return false;
}

static bool
determine_online_status_fencing(pcmk_scheduler_t *scheduler,
                                const xmlNode *node_state,
                                pcmk_node_t *this_node)
{
    bool termination_requested = unpack_node_terminate(this_node, node_state);
    const char *join = pcmk__xe_get(node_state, PCMK__XA_JOIN);
    const char *exp_state = pcmk__xe_get(node_state, PCMK_XA_EXPECTED);
    long long when_member = unpack_node_member(node_state, scheduler);
    long long when_online = unpack_node_online(node_state);

/*
  - PCMK__XA_JOIN          ::= member|down|pending|banned
  - PCMK_XA_EXPECTED       ::= member|down

  @COMPAT with entries recorded for DCs < 2.1.7
  - PCMK__XA_IN_CCM        ::= true|false
  - PCMK_XA_CRMD           ::= online|offline

  Since crm_feature_set 3.18.0 (pacemaker-2.1.7):
  - PCMK__XA_IN_CCM        ::= <timestamp>|0
  Since when node has been a cluster member. A value 0 of means the node is not
  a cluster member.

  - PCMK_XA_CRMD           ::= <timestamp>|0
  Since when peer has been online in CPG. A value 0 means the peer is offline
  in CPG.
*/

    pcmk__trace("Node %s member@%lld online@%lld join=%s expected=%s%s",
                pcmk__node_name(this_node), when_member, when_online,
                pcmk__s(join, "<null>"), pcmk__s(exp_state, "<null>"),
                (termination_requested? " (termination requested)" : ""));

    if (this_node->details->shutdown) {
        pcmk__debug("%s is shutting down", pcmk__node_name(this_node));

        /* Slightly different criteria since we can't shut down a dead peer */
        return (when_online > 0);
    }

    if (when_member < 0) {
        pe_fence_node(scheduler, this_node,
                      "peer has not been seen by the cluster", FALSE);
        return false;
    }

    if (pcmk__str_eq(join, CRMD_JOINSTATE_NACK, pcmk__str_none)) {
        pe_fence_node(scheduler, this_node,
                      "peer failed Pacemaker membership criteria", FALSE);

    } else if (termination_requested) {
        if ((when_member <= 0) && (when_online <= 0)
            && pcmk__str_eq(join, CRMD_JOINSTATE_DOWN, pcmk__str_none)) {
            pcmk__info("%s was fenced as requested",
                       pcmk__node_name(this_node));
            return false;
        }
        pe_fence_node(scheduler, this_node, "fencing was requested", false);

    } else if (pcmk__str_eq(exp_state, CRMD_JOINSTATE_DOWN,
                            pcmk__str_null_matches)) {

        if (pending_too_long(scheduler, this_node, when_member, when_online)) {
            pe_fence_node(scheduler, this_node,
                          "peer pending timed out on joining the process group",
                          FALSE);

        } else if ((when_member > 0) || (when_online > 0)) {
            pcmk__info("- %s is not ready to run resources",
                       pcmk__node_name(this_node));
            pcmk__set_node_flags(this_node, pcmk__node_standby);
            this_node->details->pending = TRUE;

        } else {
            pcmk__trace("%s is down or still coming up",
                        pcmk__node_name(this_node));
        }

    } else if (when_member <= 0) {
        // Consider PCMK_OPT_PRIORITY_FENCING_DELAY for lost nodes
        pe_fence_node(scheduler, this_node,
                      "peer is no longer part of the cluster", TRUE);

    } else if (when_online <= 0) {
        pe_fence_node(scheduler, this_node,
                      "peer process is no longer available", FALSE);

        /* Everything is running at this point, now check join state */

    } else if (pcmk__str_eq(join, CRMD_JOINSTATE_MEMBER, pcmk__str_none)) {
        pcmk__info("%s is active", pcmk__node_name(this_node));

    } else if (pcmk__str_any_of(join, CRMD_JOINSTATE_PENDING,
                                CRMD_JOINSTATE_DOWN, NULL)) {
        pcmk__info("%s is not ready to run resources",
                   pcmk__node_name(this_node));
        pcmk__set_node_flags(this_node, pcmk__node_standby);
        this_node->details->pending = TRUE;

    } else {
        pe_fence_node(scheduler, this_node, "peer was in an unknown state",
                      FALSE);
    }

    return (when_member > 0);
}

static void
determine_remote_online_status(pcmk_scheduler_t *scheduler,
                               pcmk_node_t *this_node)
{
    pcmk_resource_t *rsc = this_node->priv->remote;
    pcmk_resource_t *launcher = NULL;
    pcmk_node_t *host = NULL;
    const char *node_type = "Remote";

    if (rsc == NULL) {
        /* This is a leftover node state entry for a former Pacemaker Remote
         * node whose connection resource was removed. Consider it offline.
         */
        pcmk__trace("Pacemaker Remote node %s is considered OFFLINE because "
                    "its connection resource has been removed from the CIB",
                    this_node->priv->id);
        this_node->details->online = FALSE;
        return;
    }

    launcher = rsc->priv->launcher;
    if (launcher != NULL) {
        node_type = "Guest";
        if (pcmk__list_of_1(rsc->priv->active_nodes)) {
            host = rsc->priv->active_nodes->data;
        }
    }

    /* If the resource is currently started, mark it online. */
    if (rsc->priv->orig_role == pcmk_role_started) {
        this_node->details->online = TRUE;
    }

    /* consider this node shutting down if transitioning start->stop */
    if ((rsc->priv->orig_role == pcmk_role_started)
        && (rsc->priv->next_role == pcmk_role_stopped)) {

        pcmk__trace("%s node %s shutting down because connection resource is "
                    "stopping",
                    node_type, this_node->priv->id);
        this_node->details->shutdown = TRUE;
    }

    /* Now check all the failure conditions. */
    if ((launcher != NULL) && pcmk__is_set(launcher->flags, pcmk__rsc_failed)) {
        pcmk__trace("Guest node %s UNCLEAN because guest resource failed",
                    this_node->priv->id);
        this_node->details->online = FALSE;
        pcmk__set_node_flags(this_node, pcmk__node_remote_reset);

    } else if (pcmk__is_set(rsc->flags, pcmk__rsc_failed)) {
        pcmk__trace("%s node %s OFFLINE because connection resource failed",
                    node_type, this_node->priv->id);
        this_node->details->online = FALSE;

    } else if ((rsc->priv->orig_role == pcmk_role_stopped)
               || ((launcher != NULL)
                   && (launcher->priv->orig_role == pcmk_role_stopped))) {

        pcmk__trace("%s node %s OFFLINE because its resource is stopped",
                    node_type, this_node->priv->id);
        this_node->details->online = FALSE;
        pcmk__clear_node_flags(this_node, pcmk__node_remote_reset);

    } else if (host && (host->details->online == FALSE)
               && host->details->unclean) {
        pcmk__trace("Guest node %s UNCLEAN because host is unclean",
                    this_node->priv->id);
        this_node->details->online = FALSE;
        pcmk__set_node_flags(this_node, pcmk__node_remote_reset);

    } else {
        pcmk__trace("%s node %s is %s",
                    node_type, this_node->priv->id,
                    (this_node->details->online? "ONLINE" : "OFFLINE"));
    }
}

static void
determine_online_status(const xmlNode *node_state, pcmk_node_t *this_node,
                        pcmk_scheduler_t *scheduler)
{
    gboolean online = FALSE;
    const char *exp_state = pcmk__xe_get(node_state, PCMK_XA_EXPECTED);

    CRM_CHECK(this_node != NULL, return);

    this_node->details->shutdown = FALSE;

    if (pe__shutdown_requested(this_node)) {
        this_node->details->shutdown = TRUE;

    } else if (pcmk__str_eq(exp_state, CRMD_JOINSTATE_MEMBER, pcmk__str_casei)) {
        pcmk__set_node_flags(this_node, pcmk__node_expected_up);
    }

    if (!pcmk__is_set(scheduler->flags, pcmk__sched_fencing_enabled)) {
        online = determine_online_status_no_fencing(scheduler, node_state,
                                                    this_node);

    } else {
        online = determine_online_status_fencing(scheduler, node_state,
                                                 this_node);
    }

    if (online) {
        this_node->details->online = TRUE;

    } else {
        /* remove node from contention */
        this_node->assign->score = -PCMK_SCORE_INFINITY;
    }

    if (online && this_node->details->shutdown) {
        /* don't run resources here */
        this_node->assign->score = -PCMK_SCORE_INFINITY;
    }

    if (this_node->details->unclean) {
        pcmk__sched_warn(scheduler, "%s is unclean",
                         pcmk__node_name(this_node));

    } else if (!this_node->details->online) {
        pcmk__trace("%s is offline", pcmk__node_name(this_node));

    } else if (this_node->details->shutdown) {
        pcmk__info("%s is shutting down", pcmk__node_name(this_node));

    } else if (this_node->details->pending) {
        pcmk__info("%s is pending", pcmk__node_name(this_node));

    } else if (pcmk__is_set(this_node->priv->flags, pcmk__node_standby)) {
        pcmk__info("%s is in standby", pcmk__node_name(this_node));

    } else if (this_node->details->maintenance) {
        pcmk__info("%s is in maintenance", pcmk__node_name(this_node));

    } else {
        pcmk__info("%s is online", pcmk__node_name(this_node));
    }
}

/*!
 * \internal
 * \brief Find the end of a resource's name, excluding any clone suffix
 *
 * \param[in] id  Resource ID to check
 *
 * \return Pointer to last character of resource's base name
 */
const char *
pe_base_name_end(const char *id)
{
    if (!pcmk__str_empty(id)) {
        const char *end = id + strlen(id) - 1;

        for (const char *s = end; s > id; --s) {
            switch (*s) {
                case '0':
                case '1':
                case '2':
                case '3':
                case '4':
                case '5':
                case '6':
                case '7':
                case '8':
                case '9':
                    break;
                case ':':
                    return (s == end)? s : (s - 1);
                default:
                    return end;
            }
        }
        return end;
    }
    return NULL;
}

/*!
 * \internal
 * \brief Get a resource name excluding any clone suffix
 *
 * \param[in] last_rsc_id  Resource ID to check
 *
 * \return Pointer to newly allocated string with resource's base name
 * \note It is the caller's responsibility to free() the result.
 *       This asserts on error, so callers can assume result is not NULL.
 */
char *
clone_strip(const char *last_rsc_id)
{
    const char *end = pe_base_name_end(last_rsc_id);
    char *basename = NULL;

    pcmk__assert(end != NULL);
    basename = strndup(last_rsc_id, end - last_rsc_id + 1);
    pcmk__assert(basename != NULL);
    return basename;
}

/*!
 * \internal
 * \brief Get the name of the first instance of a cloned resource
 *
 * \param[in] last_rsc_id  Resource ID to check
 *
 * \return Pointer to newly allocated string with resource's base name plus :0
 * \note It is the caller's responsibility to free() the result.
 *       This asserts on error, so callers can assume result is not NULL.
 */
char *
clone_zero(const char *last_rsc_id)
{
    const char *end = pe_base_name_end(last_rsc_id);
    size_t base_name_len = end - last_rsc_id + 1;
    char *zero = NULL;

    pcmk__assert(end != NULL);
    zero = pcmk__assert_alloc(base_name_len + 3, sizeof(char));
    memcpy(zero, last_rsc_id, base_name_len);
    zero[base_name_len] = ':';
    zero[base_name_len + 1] = '0';
    return zero;
}

static pcmk_resource_t *
create_fake_resource(const char *rsc_id, const xmlNode *rsc_entry,
                     pcmk_scheduler_t *scheduler)
{
    pcmk_resource_t *rsc = NULL;
    xmlNode *xml_rsc = pcmk__xe_create(NULL, PCMK_XE_PRIMITIVE);

    pcmk__xe_copy_attrs(xml_rsc, rsc_entry, pcmk__xaf_none);
    pcmk__xe_set(xml_rsc, PCMK_XA_ID, rsc_id);
    pcmk__log_xml_debug(xml_rsc, "Removed resource");

    if (pe__unpack_resource(xml_rsc, &rsc, NULL, scheduler) != pcmk_rc_ok) {
        return NULL;
    }

    if (xml_contains_remote_node(xml_rsc)) {
        pcmk_node_t *node;

        pcmk__debug("Detected removed remote node %s", rsc_id);
        node = pcmk_find_node(scheduler, rsc_id);
        if (node == NULL) {
            node = pe_create_node(rsc_id, rsc_id, PCMK_VALUE_REMOTE, 0,
                                  scheduler);
        }
        link_rsc2remotenode(scheduler, rsc);

        if (node) {
            pcmk__trace("Setting node %s as shutting down due to removed "
                        "connection resource", rsc_id);
            node->details->shutdown = TRUE;
        }
    }

    if (pcmk__xe_get(rsc_entry, PCMK__META_CONTAINER)) {
        // This removed resource needs to be mapped to a launcher
        pcmk__trace("Launched resource %s was removed from the configuration",
                    rsc_id);
        pcmk__set_rsc_flags(rsc, pcmk__rsc_removed_launched);
    }
    pcmk__set_rsc_flags(rsc, pcmk__rsc_removed);
    scheduler->priv->resources = g_list_append(scheduler->priv->resources, rsc);
    return rsc;
}

/*!
 * \internal
 * \brief Create "removed" instance for anonymous clone resource history
 *
 * \param[in,out] parent     Clone resource that instance will be added to
 * \param[in]     rsc_id     Instance's resource ID
 * \param[in]     node       Where instance is active (for logging only)
 * \param[in,out] scheduler  Scheduler data
 *
 * \return Newly created "removed" instance of \p parent
 */
static pcmk_resource_t *
create_anonymous_removed_instance(pcmk_resource_t *parent, const char *rsc_id,
                                  const pcmk_node_t *node,
                                  pcmk_scheduler_t *scheduler)
{
    pcmk_resource_t *top = pe__create_clone_child(parent, scheduler);
    pcmk_resource_t *instance = NULL;

    // find_rsc() because we might be a cloned group
    instance = top->priv->fns->find_rsc(top, rsc_id, NULL,
                                        pcmk_rsc_match_clone_only);

    pcmk__rsc_debug(parent, "Created \"removed\" instance %s for %s: %s on %s",
                    top->id, parent->id, rsc_id, pcmk__node_name(node));
    return instance;
}

/*!
 * \internal
 * \brief Check a node for an instance of an anonymous clone
 *
 * Return a child instance of the specified anonymous clone, in order of
 * preference: (1) the instance running on the specified node, if any;
 * (2) an inactive instance (i.e. within the total of \c PCMK_META_CLONE_MAX
 * instances); (3) a newly created "removed" instance (that is,
 * \c PCMK_META_CLONE_MAX instances are already active).
 *
 * \param[in,out] scheduler  Scheduler data
 * \param[in]     node       Node on which to check for instance
 * \param[in,out] parent     Clone to check
 * \param[in]     rsc_id     Name of cloned resource in history (no instance)
 */
static pcmk_resource_t *
find_anonymous_clone(pcmk_scheduler_t *scheduler, const pcmk_node_t *node,
                     pcmk_resource_t *parent, const char *rsc_id)
{
    GList *rIter = NULL;
    pcmk_resource_t *rsc = NULL;
    pcmk_resource_t *inactive_instance = NULL;
    gboolean skip_inactive = FALSE;

    pcmk__assert(pcmk__is_anonymous_clone(parent));

    // Check for active (or partially active, for cloned groups) instance
    pcmk__rsc_trace(parent, "Looking for %s on %s in %s",
                    rsc_id, pcmk__node_name(node), parent->id);

    for (rIter = parent->priv->children;
         (rIter != NULL) && (rsc == NULL); rIter = rIter->next) {

        GList *locations = NULL;
        pcmk_resource_t *child = rIter->data;

        /* Check whether this instance is already known to be active or pending
         * anywhere, at this stage of unpacking. Because this function is called
         * for a resource before the resource's individual operation history
         * entries are unpacked, locations will generally not contain the
         * desired node.
         *
         * However, there are three exceptions:
         * (1) when child is a cloned group and we have already unpacked the
         *     history of another member of the group on the same node;
         * (2) when we've already unpacked the history of another numbered
         *     instance on the same node (which can happen if
         *     PCMK_META_GLOBALLY_UNIQUE was flipped from true to false); and
         * (3) when we re-run calculations on the same scheduler data as part of
         *     a simulation.
         */
        child->priv->fns->location(child, &locations, pcmk__rsc_node_current
                                                      |pcmk__rsc_node_pending);
        if (locations) {
            /* We should never associate the same numbered anonymous clone
             * instance with multiple nodes, and clone instances can't migrate,
             * so there must be only one location, regardless of history.
             */
            CRM_LOG_ASSERT(locations->next == NULL);

            if (pcmk__same_node((pcmk_node_t *) locations->data, node)) {
                /* This child instance is active on the requested node, so check
                 * for a corresponding configured resource. We use find_rsc()
                 * instead of child because child may be a cloned group, and we
                 * need the particular member corresponding to rsc_id.
                 *
                 * If the history entry represents a removed instance, rsc will
                 * be NULL.
                 */
                rsc = parent->priv->fns->find_rsc(child, rsc_id, NULL,
                                                  pcmk_rsc_match_clone_only);
                if (rsc) {
                    /* If there are multiple instance history entries for an
                     * anonymous clone in a single node's history (which can
                     * happen if PCMK_META_GLOBALLY_UNIQUE is switched from true
                     * to false), we want to consider the instances beyond the
                     * first as removed, even if there are inactive instance
                     * numbers available.
                     */
                    if (rsc->priv->active_nodes != NULL) {
                        pcmk__notice("Active (now-)anonymous clone %s has "
                                     "multiple \"removed\" instance histories "
                                     "on %s",
                                     parent->id, pcmk__node_name(node));
                        skip_inactive = TRUE;
                        rsc = NULL;
                    } else {
                        pcmk__rsc_trace(parent, "Resource %s, active", rsc->id);
                    }
                }
            }
            g_list_free(locations);

        } else {
            pcmk__rsc_trace(parent, "Resource %s, skip inactive", child->id);
            if (!skip_inactive && !inactive_instance
                && !pcmk__is_set(child->flags, pcmk__rsc_blocked)) {
                // Remember one inactive instance in case we don't find active
                inactive_instance =
                    parent->priv->fns->find_rsc(child, rsc_id, NULL,
                                                pcmk_rsc_match_clone_only);

                /* ... but don't use it if it was already associated with a
                 * pending action on another node
                 */
                if (inactive_instance != NULL) {
                    const pcmk_node_t *pending_node = NULL;

                    pending_node = inactive_instance->priv->pending_node;
                    if ((pending_node != NULL)
                        && !pcmk__same_node(pending_node, node)) {
                        inactive_instance = NULL;
                    }
                }
            }
        }
    }

    if ((rsc == NULL) && !skip_inactive && (inactive_instance != NULL)) {
        pcmk__rsc_trace(parent, "Resource %s, empty slot",
                        inactive_instance->id);
        rsc = inactive_instance;
    }

    /* If the resource has PCMK_META_REQUIRES set to PCMK_VALUE_QUORUM or
     * PCMK_VALUE_NOTHING, and we don't have a clone instance for every node, we
     * don't want to consume a valid instance number for unclean nodes. Such
     * instances may appear to be active according to the history, but should be
     * considered inactive, so we can start an instance elsewhere. Treat such
     * instances as removed.
     *
     * An exception is instances running on guest nodes -- since guest node
     * "fencing" is actually just a resource stop, requires shouldn't apply.
     *
     * @TODO Ideally, we'd use an inactive instance number if it is not needed
     * for any clean instances. However, we don't know that at this point.
     */
    if ((rsc != NULL) && !pcmk__is_set(rsc->flags, pcmk__rsc_needs_fencing)
        && (!node->details->online || node->details->unclean)
        && !pcmk__is_guest_or_bundle_node(node)
        && !pe__is_universal_clone(parent, scheduler)) {

        rsc = NULL;
    }

    if (rsc == NULL) {
        rsc = create_anonymous_removed_instance(parent, rsc_id, node,
                                                scheduler);
        pcmk__rsc_trace(parent, "Resource %s, removed", rsc->id);
    }
    return rsc;
}

static pcmk_resource_t *
unpack_find_resource(pcmk_scheduler_t *scheduler, const pcmk_node_t *node,
                     const char *rsc_id)
{
    pcmk_resource_t *rsc = NULL;
    pcmk_resource_t *parent = NULL;

    pcmk__trace("looking for %s", rsc_id);
    rsc = pe_find_resource(scheduler->priv->resources, rsc_id);

    if (rsc == NULL) {
        /* If we didn't find the resource by its name in the operation history,
         * check it again as a clone instance. Even when PCMK_META_CLONE_MAX=0,
         * we create a single :0 "removed" instance to match against here.
         */
        char *clone0_id = clone_zero(rsc_id);
        pcmk_resource_t *clone0 = pe_find_resource(scheduler->priv->resources,
                                                   clone0_id);

        if ((clone0 != NULL)
            && !pcmk__is_set(clone0->flags, pcmk__rsc_unique)) {

            rsc = clone0;
            parent = uber_parent(clone0);
            pcmk__trace("%s found as %s (%s)", rsc_id, clone0_id, parent->id);
        } else {
            pcmk__trace("%s is not known as %s either (removed)", rsc_id,
                        clone0_id);
        }
        free(clone0_id);

    } else if (rsc->priv->variant > pcmk__rsc_variant_primitive) {
        pcmk__trace("Resource history for %s is considered removed "
                    "because it is no longer primitive", rsc_id);
        return NULL;

    } else {
        parent = uber_parent(rsc);
    }

    if (pcmk__is_anonymous_clone(parent)) {

        if (pcmk__is_bundled(parent)) {
            rsc = pe__find_bundle_replica(parent->priv->parent, node);
        } else {
            char *base = clone_strip(rsc_id);

            rsc = find_anonymous_clone(scheduler, node, parent, base);
            free(base);
            pcmk__assert(rsc != NULL);
        }
    }

    if (rsc && !pcmk__str_eq(rsc_id, rsc->id, pcmk__str_none)
        && !pcmk__str_eq(rsc_id, rsc->priv->history_id, pcmk__str_none)) {

        const bool removed = pcmk__is_set(rsc->flags, pcmk__rsc_removed);

        pcmk__str_update(&(rsc->priv->history_id), rsc_id);
        pcmk__rsc_debug(rsc, "Internally renamed %s on %s to %s%s",
                        rsc_id, pcmk__node_name(node), rsc->id,
                        (removed? " (removed)" : ""));
    }
    return rsc;
}

static pcmk_resource_t *
process_removed_resource(const xmlNode *rsc_entry, const pcmk_node_t *node,
                        pcmk_scheduler_t *scheduler)
{
    pcmk_resource_t *rsc = NULL;
    const char *rsc_id = pcmk__xe_get(rsc_entry, PCMK_XA_ID);

    pcmk__debug("Detected removed resource %s on %s", rsc_id,
                pcmk__node_name(node));
    rsc = create_fake_resource(rsc_id, rsc_entry, scheduler);
    if (rsc == NULL) {
        return NULL;
    }

    if (!pcmk__is_set(scheduler->flags, pcmk__sched_stop_removed_resources)) {
        pcmk__clear_rsc_flags(rsc, pcmk__rsc_managed);

    } else {
        CRM_CHECK(rsc != NULL, return NULL);
        pcmk__rsc_trace(rsc, "Added \"removed\" resource %s", rsc->id);
        resource_location(rsc, NULL, -PCMK_SCORE_INFINITY,
                          "__removed_do_not_run__", scheduler);
    }
    return rsc;
}

static void
process_rsc_state(pcmk_resource_t *rsc, pcmk_node_t *node,
                  enum pcmk__on_fail on_fail)
{
    pcmk_node_t *tmpnode = NULL;
    char *reason = NULL;
    enum pcmk__on_fail save_on_fail = pcmk__on_fail_ignore;
    pcmk_scheduler_t *scheduler = NULL;
    bool known_active = false;

    pcmk__assert(rsc != NULL);
    scheduler = rsc->priv->scheduler;
    known_active = (rsc->priv->orig_role > pcmk_role_stopped);
    pcmk__rsc_trace(rsc, "Resource %s is %s on %s: on_fail=%s",
                    rsc->id, pcmk_role_text(rsc->priv->orig_role),
                    pcmk__node_name(node), pcmk__on_fail_text(on_fail));

    /* process current state */
    if (rsc->priv->orig_role != pcmk_role_unknown) {
        pcmk_resource_t *iter = rsc;

        while (iter) {
            if (g_hash_table_lookup(iter->priv->probed_nodes,
                                    node->priv->id) == NULL) {
                pcmk_node_t *n = pe__copy_node(node);

                pcmk__rsc_trace(rsc, "%s (%s in history) known on %s",
                                rsc->id,
                                pcmk__s(rsc->priv->history_id, "the same"),
                                pcmk__node_name(n));
                g_hash_table_insert(iter->priv->probed_nodes,
                                    (gpointer) n->priv->id, n);
            }
            if (pcmk__is_set(iter->flags, pcmk__rsc_unique)) {
                break;
            }
            iter = iter->priv->parent;
        }
    }

    /* If a managed resource is believed to be running, but node is down ... */
    if (known_active && !node->details->online && !node->details->maintenance
        && pcmk__is_set(rsc->flags, pcmk__rsc_managed)) {

        gboolean should_fence = FALSE;

        /* If this is a guest node, fence it (regardless of whether fencing is
         * enabled, because guest node fencing is done by recovery of the
         * container resource rather than by the fencer). Mark the resource
         * we're processing as failed. When the guest comes back up, its
         * operation history in the CIB will be cleared, freeing the affected
         * resource to run again once we are sure we know its state.
         */
        if (pcmk__is_guest_or_bundle_node(node)) {
            pcmk__set_rsc_flags(rsc, pcmk__rsc_failed|pcmk__rsc_stop_if_failed);
            should_fence = TRUE;

        } else if (pcmk__is_set(scheduler->flags,
                                pcmk__sched_fencing_enabled)) {
            if (pcmk__is_remote_node(node)
                && (node->priv->remote != NULL)
                && !pcmk__is_set(node->priv->remote->flags,
                                 pcmk__rsc_failed)) {

                /* Setting unseen means that fencing of the remote node will
                 * occur only if the connection resource is not going to start
                 * somewhere. This allows connection resources on a failed
                 * cluster node to move to another node without requiring the
                 * remote nodes to be fenced as well.
                 */
                pcmk__clear_node_flags(node, pcmk__node_seen);
                reason = pcmk__assert_asprintf("%s is active there (fencing "
                                               "will be revoked if remote "
                                               "connection can be "
                                               "re-established elsewhere)",
                                               rsc->id);
            }
            should_fence = TRUE;
        }

        if (should_fence) {
            if (reason == NULL) {
               reason = pcmk__assert_asprintf("%s is thought to be active "
                                              "there",
                                              rsc->id);
            }
            pe_fence_node(scheduler, node, reason, FALSE);
        }
        free(reason);
    }

    /* In order to calculate priority_fencing_delay correctly, save the failure information and pass it to native_add_running(). */
    save_on_fail = on_fail;

    if (node->details->unclean) {
        /* No extra processing needed
         * Also allows resources to be started again after a node is shot
         */
        on_fail = pcmk__on_fail_ignore;
    }

    switch (on_fail) {
        case pcmk__on_fail_ignore:
            /* nothing to do */
            break;

        case pcmk__on_fail_demote:
            pcmk__set_rsc_flags(rsc, pcmk__rsc_failed);
            demote_action(rsc, node, FALSE);
            break;

        case pcmk__on_fail_fence_node:
            /* treat it as if it is still running
             * but also mark the node as unclean
             */
            reason = pcmk__assert_asprintf("%s failed there", rsc->id);
            pe_fence_node(scheduler, node, reason, FALSE);
            free(reason);
            break;

        case pcmk__on_fail_standby_node:
            pcmk__set_node_flags(node,
                                 pcmk__node_standby|pcmk__node_fail_standby);
            break;

        case pcmk__on_fail_block:
            /* is_managed == FALSE will prevent any
             * actions being sent for the resource
             */
            pcmk__clear_rsc_flags(rsc, pcmk__rsc_managed);
            pcmk__set_rsc_flags(rsc, pcmk__rsc_blocked);
            break;

        case pcmk__on_fail_ban:
            /* make sure it comes up somewhere else
             * or not at all
             */
            resource_location(rsc, node, -PCMK_SCORE_INFINITY,
                              "__action_migration_auto__", scheduler);
            break;

        case pcmk__on_fail_stop:
            pe__set_next_role(rsc, pcmk_role_stopped,
                              PCMK_META_ON_FAIL "=" PCMK_VALUE_STOP);
            break;

        case pcmk__on_fail_restart:
            if (known_active) {
                pcmk__set_rsc_flags(rsc,
                                    pcmk__rsc_failed|pcmk__rsc_stop_if_failed);
                stop_action(rsc, node, FALSE);
            }
            break;

        case pcmk__on_fail_restart_container:
            pcmk__set_rsc_flags(rsc, pcmk__rsc_failed|pcmk__rsc_stop_if_failed);
            if ((rsc->priv->launcher != NULL) && pcmk__is_bundled(rsc)) {
                /* A bundle's remote connection can run on a different node than
                 * the bundle's container. We don't necessarily know where the
                 * container is running yet, so remember it and add a stop
                 * action for it later.
                 */
                scheduler->priv->stop_needed =
                    g_list_prepend(scheduler->priv->stop_needed,
                                   rsc->priv->launcher);
            } else if (rsc->priv->launcher != NULL) {
                stop_action(rsc->priv->launcher, node, FALSE);
            } else if (known_active) {
                stop_action(rsc, node, FALSE);
            }
            break;

        case pcmk__on_fail_reset_remote:
            pcmk__set_rsc_flags(rsc, pcmk__rsc_failed|pcmk__rsc_stop_if_failed);
            if (pcmk__is_set(scheduler->flags, pcmk__sched_fencing_enabled)) {
                tmpnode = NULL;
                if (pcmk__is_set(rsc->flags, pcmk__rsc_is_remote_connection)) {
                    tmpnode = pcmk_find_node(scheduler, rsc->id);
                }
                if (pcmk__is_remote_node(tmpnode)
                    && !pcmk__is_set(tmpnode->priv->flags,
                                     pcmk__node_remote_fenced)) {
                    /* The remote connection resource failed in a way that
                     * should result in fencing the remote node.
                     */
                    pe_fence_node(scheduler, tmpnode,
                                  "remote connection is unrecoverable", FALSE);
                }
            }

            /* require the stop action regardless if fencing is occurring or not. */
            if (known_active) {
                stop_action(rsc, node, FALSE);
            }

            /* if reconnect delay is in use, prevent the connection from exiting the
             * "STOPPED" role until the failure is cleared by the delay timeout. */
            if (rsc->priv->remote_reconnect_ms > 0U) {
                pe__set_next_role(rsc, pcmk_role_stopped, "remote reset");
            }
            break;
    }

    /* Ensure a remote connection failure forces an unclean Pacemaker Remote
     * node to be fenced. By marking the node as seen, the failure will result
     * in a fencing operation regardless if we're going to attempt to reconnect
     * in this transition.
     */
    if (pcmk__all_flags_set(rsc->flags,
                            pcmk__rsc_failed|pcmk__rsc_is_remote_connection)) {
        tmpnode = pcmk_find_node(scheduler, rsc->id);
        if (tmpnode && tmpnode->details->unclean) {
            pcmk__set_node_flags(tmpnode, pcmk__node_seen);
        }
    }

    if (known_active) {
        if (pcmk__is_set(rsc->flags, pcmk__rsc_removed)) {
            if (pcmk__is_set(rsc->flags, pcmk__rsc_managed)) {
                pcmk__notice("Removed resource %s is active on %s and will be "
                             "stopped when possible",
                             rsc->id, pcmk__node_name(node));

            } else {
                pcmk__notice("Removed resource %s must be stopped manually on "
                             "%s because " PCMK__OPT_STOP_REMOVED_RESOURCES
                             " is set to false",
                             rsc->id, pcmk__node_name(node));
            }
        }

        native_add_running(rsc, node, scheduler,
                           (save_on_fail != pcmk__on_fail_ignore));
        switch (on_fail) {
            case pcmk__on_fail_ignore:
                break;
            case pcmk__on_fail_demote:
            case pcmk__on_fail_block:
                pcmk__set_rsc_flags(rsc, pcmk__rsc_failed);
                break;
            default:
                pcmk__set_rsc_flags(rsc,
                                    pcmk__rsc_failed|pcmk__rsc_stop_if_failed);
                break;
        }

    } else if ((rsc->priv->history_id != NULL)
               && (strchr(rsc->priv->history_id, ':') != NULL)) {
        /* @COMPAT This is for older (<1.1.8) status sections that included
         * instance numbers, otherwise stopped instances are considered removed.
         *
         * @TODO We should be able to drop this, but some old regression tests
         * will need to be updated. Double-check that this is not still needed
         * for unique clones (which may have been later converted to anonymous).
         */
        pcmk__rsc_trace(rsc, "Clearing history ID %s for %s (stopped)",
                        rsc->priv->history_id, rsc->id);
        free(rsc->priv->history_id);
        rsc->priv->history_id = NULL;

    } else {
        GList *possible_matches = pe__resource_actions(rsc, node,
                                                       PCMK_ACTION_STOP, FALSE);
        GList *gIter = possible_matches;

        for (; gIter != NULL; gIter = gIter->next) {
            pcmk_action_t *stop = (pcmk_action_t *) gIter->data;

            pcmk__set_action_flags(stop, pcmk__action_optional);
        }

        g_list_free(possible_matches);
    }

    /* A successful stop after migrate_to on the migration source doesn't make
     * the partially migrated resource stopped on the migration target.
     */
    if ((rsc->priv->orig_role == pcmk_role_stopped)
        && (rsc->priv->active_nodes != NULL)
        && (rsc->priv->partial_migration_target != NULL)
        && pcmk__same_node(rsc->priv->partial_migration_source, node)) {

        rsc->priv->orig_role = pcmk_role_started;
    }
}

/* create active recurring operations as optional */
static void
process_recurring(pcmk_node_t *node, pcmk_resource_t *rsc,
                  int start_index, int stop_index,
                  GList *sorted_op_list, pcmk_scheduler_t *scheduler)
{
    int counter = -1;
    const char *task = NULL;
    const char *status = NULL;
    GList *gIter = sorted_op_list;

    pcmk__assert(rsc != NULL);
    pcmk__rsc_trace(rsc, "%s: Start index %d, stop index = %d",
                    rsc->id, start_index, stop_index);

    for (; gIter != NULL; gIter = gIter->next) {
        xmlNode *rsc_op = (xmlNode *) gIter->data;

        guint interval_ms = 0;
        char *key = NULL;
        const char *id = pcmk__xe_id(rsc_op);

        counter++;

        if (node->details->online == FALSE) {
            pcmk__rsc_trace(rsc, "Skipping %s on %s: node is offline",
                            rsc->id, pcmk__node_name(node));
            break;

            /* Need to check if there's a monitor for role="Stopped" */
        } else if (start_index < stop_index && counter <= stop_index) {
            pcmk__rsc_trace(rsc, "Skipping %s on %s: resource is not active",
                            id, pcmk__node_name(node));
            continue;

        } else if (counter < start_index) {
            pcmk__rsc_trace(rsc, "Skipping %s on %s: old %d",
                            id, pcmk__node_name(node), counter);
            continue;
        }

        pcmk__xe_get_guint(rsc_op, PCMK_META_INTERVAL, &interval_ms);
        if (interval_ms == 0) {
            pcmk__rsc_trace(rsc, "Skipping %s on %s: non-recurring",
                            id, pcmk__node_name(node));
            continue;
        }

        status = pcmk__xe_get(rsc_op, PCMK__XA_OP_STATUS);
        if (pcmk__str_eq(status, "-1", pcmk__str_casei)) {
            pcmk__rsc_trace(rsc, "Skipping %s on %s: status",
                            id, pcmk__node_name(node));
            continue;
        }
        task = pcmk__xe_get(rsc_op, PCMK_XA_OPERATION);
        /* create the action */
        key = pcmk__op_key(rsc->id, task, interval_ms);
        pcmk__rsc_trace(rsc, "Creating %s on %s", key, pcmk__node_name(node));
        custom_action(rsc, key, task, node, TRUE, scheduler);
    }
}

void
calculate_active_ops(const GList *sorted_op_list, int *start_index,
                     int *stop_index)
{
    int counter = -1;
    int implied_monitor_start = -1;
    int implied_clone_start = -1;
    const char *task = NULL;
    const char *status = NULL;

    *stop_index = -1;
    *start_index = -1;

    for (const GList *iter = sorted_op_list; iter != NULL; iter = iter->next) {
        const xmlNode *rsc_op = (const xmlNode *) iter->data;

        counter++;

        task = pcmk__xe_get(rsc_op, PCMK_XA_OPERATION);
        status = pcmk__xe_get(rsc_op, PCMK__XA_OP_STATUS);

        if (pcmk__str_eq(task, PCMK_ACTION_STOP, pcmk__str_casei)
            && pcmk__str_eq(status, "0", pcmk__str_casei)) {
            *stop_index = counter;

        } else if (pcmk__strcase_any_of(task, PCMK_ACTION_START,
                                        PCMK_ACTION_MIGRATE_FROM, NULL)) {
            *start_index = counter;

        } else if ((implied_monitor_start <= *stop_index)
                   && pcmk__str_eq(task, PCMK_ACTION_MONITOR,
                                   pcmk__str_casei)) {
            const char *rc = pcmk__xe_get(rsc_op, PCMK__XA_RC_CODE);

            if (pcmk__strcase_any_of(rc, "0", "8", NULL)) {
                implied_monitor_start = counter;
            }
        } else if (pcmk__strcase_any_of(task, PCMK_ACTION_PROMOTE,
                                        PCMK_ACTION_DEMOTE, NULL)) {
            implied_clone_start = counter;
        }
    }

    if (*start_index == -1) {
        if (implied_clone_start != -1) {
            *start_index = implied_clone_start;
        } else if (implied_monitor_start != -1) {
            *start_index = implied_monitor_start;
        }
    }
}

// If resource history entry has shutdown lock, remember lock node and time
static void
unpack_shutdown_lock(const xmlNode *rsc_entry, pcmk_resource_t *rsc,
                     const pcmk_node_t *node, pcmk_scheduler_t *scheduler)
{
    time_t lock_time = 0;   // When lock started (i.e. node shutdown time)
    time_t sched_time = 0;
    guint shutdown_lock_ms = scheduler->priv->shutdown_lock_ms;

    pcmk__xe_get_time(rsc_entry, PCMK_OPT_SHUTDOWN_LOCK, &lock_time);
    if (lock_time == 0) {
        return;
    }

    sched_time = pcmk__scheduler_epoch_time(scheduler);
    if ((shutdown_lock_ms > 0U)
        && (sched_time > (lock_time + pcmk__timeout_ms2s(shutdown_lock_ms)))) {

        pcmk__rsc_info(rsc, "Shutdown lock for %s on %s expired",
                       rsc->id, pcmk__node_name(node));
        pe__clear_resource_history(rsc, node);

    } else {
        rsc->priv->lock_node = node;
        rsc->priv->lock_time = lock_time;
    }
}

/*!
 * \internal
 * \brief Unpack one \c PCMK__XE_LRM_RESOURCE entry from a node's CIB status
 *
 * \param[in,out] node       Node whose status is being unpacked
 * \param[in]     rsc_entry  \c PCMK__XE_LRM_RESOURCE XML being unpacked
 * \param[in,out] scheduler  Scheduler data
 *
 * \return Resource corresponding to the entry, or NULL if no operation history
 */
static pcmk_resource_t *
unpack_lrm_resource(pcmk_node_t *node, const xmlNode *lrm_resource,
                    pcmk_scheduler_t *scheduler)
{
    GList *gIter = NULL;
    int stop_index = -1;
    int start_index = -1;
    enum rsc_role_e req_role = pcmk_role_unknown;

    const char *rsc_id = pcmk__xe_id(lrm_resource);

    pcmk_resource_t *rsc = NULL;
    GList *op_list = NULL;
    GList *sorted_op_list = NULL;

    xmlNode *rsc_op = NULL;
    xmlNode *last_failure = NULL;

    enum pcmk__on_fail on_fail = pcmk__on_fail_ignore;
    enum rsc_role_e saved_role = pcmk_role_unknown;

    if (rsc_id == NULL) {
        pcmk__config_err("Ignoring invalid " PCMK__XE_LRM_RESOURCE
                         " entry: No " PCMK_XA_ID);
        pcmk__log_xml_info(lrm_resource, "missing-id");
        return NULL;
    }
    pcmk__trace("Unpacking " PCMK__XE_LRM_RESOURCE " for %s on %s", rsc_id,
                pcmk__node_name(node));

    /* Build a list of individual PCMK__XE_LRM_RSC_OP entries, so we can sort
     * them
     */
    for (rsc_op = pcmk__xe_first_child(lrm_resource, PCMK__XE_LRM_RSC_OP, NULL,
                                       NULL);
         rsc_op != NULL; rsc_op = pcmk__xe_next(rsc_op, PCMK__XE_LRM_RSC_OP)) {

        op_list = g_list_prepend(op_list, rsc_op);
    }

    if (!pcmk__is_set(scheduler->flags, pcmk__sched_shutdown_lock)) {
        if (op_list == NULL) {
            // If there are no operations, there is nothing to do
            return NULL;
        }
    }

    /* find the resource */
    rsc = unpack_find_resource(scheduler, node, rsc_id);
    if (rsc == NULL) {
        if (op_list == NULL) {
            // If there are no operations, there is nothing to do
            return NULL;
        } else {
            rsc = process_removed_resource(lrm_resource, node, scheduler);
        }
    }
    pcmk__assert(rsc != NULL);

    // Check whether the resource is "shutdown-locked" to this node
    if (pcmk__is_set(scheduler->flags, pcmk__sched_shutdown_lock)) {
        unpack_shutdown_lock(lrm_resource, rsc, node, scheduler);
    }

    /* process operations */
    saved_role = rsc->priv->orig_role;
    rsc->priv->orig_role = pcmk_role_unknown;
    sorted_op_list = g_list_sort(op_list, sort_op_by_callid);

    for (gIter = sorted_op_list; gIter != NULL; gIter = gIter->next) {
        xmlNode *rsc_op = (xmlNode *) gIter->data;

        unpack_rsc_op(rsc, node, rsc_op, &last_failure, &on_fail);
    }

    /* create active recurring operations as optional */
    calculate_active_ops(sorted_op_list, &start_index, &stop_index);
    process_recurring(node, rsc, start_index, stop_index, sorted_op_list,
                      scheduler);

    /* no need to free the contents */
    g_list_free(sorted_op_list);

    process_rsc_state(rsc, node, on_fail);

    if (get_target_role(rsc, &req_role)) {
        if ((rsc->priv->next_role == pcmk_role_unknown)
            || (req_role < rsc->priv->next_role)) {

            pe__set_next_role(rsc, req_role, PCMK_META_TARGET_ROLE);

        } else if (req_role > rsc->priv->next_role) {
            pcmk__rsc_info(rsc,
                           "%s: Not overwriting calculated next role %s"
                           " with requested next role %s",
                           rsc->id, pcmk_role_text(rsc->priv->next_role),
                           pcmk_role_text(req_role));
        }
    }

    if (saved_role > rsc->priv->orig_role) {
        rsc->priv->orig_role = saved_role;
    }

    return rsc;
}

static void
handle_removed_launched_resources(const xmlNode *lrm_rsc_list,
                                  pcmk_scheduler_t *scheduler)
{
    for (const xmlNode *rsc_entry = pcmk__xe_first_child(lrm_rsc_list,
                                                         PCMK__XE_LRM_RESOURCE,
                                                         NULL, NULL);
         rsc_entry != NULL;
         rsc_entry = pcmk__xe_next(rsc_entry, PCMK__XE_LRM_RESOURCE)) {

        pcmk_resource_t *rsc;
        pcmk_resource_t *launcher = NULL;
        const char *rsc_id;
        const char *launcher_id = NULL;

        launcher_id = pcmk__xe_get(rsc_entry, PCMK__META_CONTAINER);
        rsc_id = pcmk__xe_get(rsc_entry, PCMK_XA_ID);
        if ((launcher_id == NULL) || (rsc_id == NULL)) {
            continue;
        }

        launcher = pe_find_resource(scheduler->priv->resources, launcher_id);
        if (launcher == NULL) {
            continue;
        }

        rsc = pe_find_resource(scheduler->priv->resources, rsc_id);
        if ((rsc == NULL) || (rsc->priv->launcher != NULL)
            || !pcmk__is_set(rsc->flags, pcmk__rsc_removed_launched)) {
            continue;
        }

        pcmk__rsc_trace(rsc, "Mapped launcher of removed resource %s to %s",
                        rsc->id, launcher_id);
        rsc->priv->launcher = launcher;
        launcher->priv->launched = g_list_append(launcher->priv->launched,
                                                    rsc);
    }
}

/*!
 * \internal
 * \brief Unpack one node's lrm status section
 *
 * \param[in,out] node       Node whose status is being unpacked
 * \param[in]     xml        CIB node state XML
 * \param[in,out] scheduler  Scheduler data
 */
static void
unpack_node_lrm(pcmk_node_t *node, const xmlNode *xml,
                pcmk_scheduler_t *scheduler)
{
    bool found_removed_launched_resource = false;

    // Drill down to PCMK__XE_LRM_RESOURCES section
    xml = pcmk__xe_first_child(xml, PCMK__XE_LRM, NULL, NULL);
    if (xml == NULL) {
        return;
    }
    xml = pcmk__xe_first_child(xml, PCMK__XE_LRM_RESOURCES, NULL, NULL);
    if (xml == NULL) {
        return;
    }

    // Unpack each PCMK__XE_LRM_RESOURCE entry
    for (const xmlNode *rsc_entry = pcmk__xe_first_child(xml,
                                                         PCMK__XE_LRM_RESOURCE,
                                                         NULL, NULL);
         rsc_entry != NULL;
         rsc_entry = pcmk__xe_next(rsc_entry, PCMK__XE_LRM_RESOURCE)) {

        pcmk_resource_t *rsc = unpack_lrm_resource(node, rsc_entry, scheduler);

        if ((rsc != NULL)
            && pcmk__is_set(rsc->flags, pcmk__rsc_removed_launched)) {
            found_removed_launched_resource = true;
        }
    }

    /* Now that all resource state has been unpacked for this node, map any
     * removed launched resources to their launchers.
     */
    if (found_removed_launched_resource) {
        handle_removed_launched_resources(xml, scheduler);
    }
}

static void
set_active(pcmk_resource_t *rsc)
{
    const pcmk_resource_t *top = pe__const_top_resource(rsc, false);

    if ((top != NULL) && pcmk__is_set(top->flags, pcmk__rsc_promotable)) {
        rsc->priv->orig_role = pcmk_role_unpromoted;
    } else {
        rsc->priv->orig_role = pcmk_role_started;
    }
}

static void
set_node_score(gpointer key, gpointer value, gpointer user_data)
{
    pcmk_node_t *node = value;
    int *score = user_data;

    node->assign->score = *score;
}

#define XPATH_NODE_STATE "/" PCMK_XE_CIB "/" PCMK_XE_STATUS \
                         "/" PCMK__XE_NODE_STATE
#define SUB_XPATH_LRM_RESOURCE "/" PCMK__XE_LRM             \
                               "/" PCMK__XE_LRM_RESOURCES   \
                               "/" PCMK__XE_LRM_RESOURCE
#define SUB_XPATH_LRM_RSC_OP "/" PCMK__XE_LRM_RSC_OP

static xmlNode *
find_lrm_op(const char *resource, const char *op, const char *node, const char *source,
            int target_rc, pcmk_scheduler_t *scheduler)
{
    GString *xpath = NULL;
    xmlNode *xml = NULL;

    CRM_CHECK((resource != NULL) && (op != NULL) && (node != NULL),
              return NULL);

    xpath = g_string_sized_new(256);
    pcmk__g_strcat(xpath,
                   XPATH_NODE_STATE "[@" PCMK_XA_UNAME "='", node, "']"
                   SUB_XPATH_LRM_RESOURCE "[@" PCMK_XA_ID "='", resource, "']"
                   SUB_XPATH_LRM_RSC_OP "[@" PCMK_XA_OPERATION "='", op, "'",
                   NULL);

    /* Need to check against transition_magic too? */
    if ((source != NULL) && (strcmp(op, PCMK_ACTION_MIGRATE_TO) == 0)) {
        pcmk__g_strcat(xpath,
                       " and @" PCMK__META_MIGRATE_TARGET "='", source, "']",
                       NULL);

    } else if ((source != NULL)
               && (strcmp(op, PCMK_ACTION_MIGRATE_FROM) == 0)) {
        pcmk__g_strcat(xpath,
                       " and @" PCMK__META_MIGRATE_SOURCE "='", source, "']",
                       NULL);
    } else {
        g_string_append_c(xpath, ']');
    }

    xml = pcmk__xpath_find_one(scheduler->input->doc, xpath->str, LOG_DEBUG);
    g_string_free(xpath, TRUE);

    if (xml && target_rc >= 0) {
        int rc = PCMK_OCF_UNKNOWN_ERROR;
        int status = PCMK_EXEC_ERROR;

        pcmk__xe_get_int(xml, PCMK__XA_RC_CODE, &rc);
        pcmk__xe_get_int(xml, PCMK__XA_OP_STATUS, &status);
        if ((rc != target_rc) || (status != PCMK_EXEC_DONE)) {
            return NULL;
        }
    }
    return xml;
}

static xmlNode *
find_lrm_resource(const char *rsc_id, const char *node_name,
                  pcmk_scheduler_t *scheduler)
{
    GString *xpath = NULL;
    xmlNode *xml = NULL;

    CRM_CHECK((rsc_id != NULL) && (node_name != NULL), return NULL);

    xpath = g_string_sized_new(256);
    pcmk__g_strcat(xpath,
                   XPATH_NODE_STATE "[@" PCMK_XA_UNAME "='", node_name, "']"
                   SUB_XPATH_LRM_RESOURCE "[@" PCMK_XA_ID "='", rsc_id, "']",
                   NULL);

    xml = pcmk__xpath_find_one(scheduler->input->doc, xpath->str, LOG_DEBUG);

    g_string_free(xpath, TRUE);
    return xml;
}

/*!
 * \internal
 * \brief Check whether a resource has no completed action history on a node
 *
 * \param[in,out] rsc        Resource to check
 * \param[in]     node_name  Node to check
 *
 * \return true if \p rsc_id is unknown on \p node_name, otherwise false
 */
static bool
unknown_on_node(pcmk_resource_t *rsc, const char *node_name)
{
    bool result = false;
    xmlXPathObject *search;
    char *xpath = NULL;

    xpath = pcmk__assert_asprintf(XPATH_NODE_STATE "[@" PCMK_XA_UNAME "='%s']"
                                  SUB_XPATH_LRM_RESOURCE
                                  "[@" PCMK_XA_ID "='%s']"
                                  SUB_XPATH_LRM_RSC_OP
                                  "[@" PCMK__XA_RC_CODE "!='%d']",
                                  node_name, rsc->id, PCMK_OCF_UNKNOWN);

    search = pcmk__xpath_search(rsc->priv->scheduler->input->doc, xpath);
    result = (pcmk__xpath_num_results(search) == 0);
    xmlXPathFreeObject(search);
    free(xpath);
    return result;
}

/*!
 * \internal
 * \brief Check whether a probe/monitor indicating the resource was not running
 *        on a node happened after some event
 *
 * \param[in]     rsc_id     Resource being checked
 * \param[in]     node_name  Node being checked
 * \param[in]     xml_op     Event that monitor is being compared to
 * \param[in,out] scheduler  Scheduler data
 *
 * \return true if such a monitor happened after event, false otherwise
 */
static bool
monitor_not_running_after(const char *rsc_id, const char *node_name,
                          const xmlNode *xml_op, pcmk_scheduler_t *scheduler)
{
    /* Any probe/monitor operation on the node indicating it was not running
     * there
     */
    xmlNode *monitor = find_lrm_op(rsc_id, PCMK_ACTION_MONITOR, node_name,
                                   NULL, PCMK_OCF_NOT_RUNNING, scheduler);

    return (monitor != NULL) && (pe__is_newer_op(monitor, xml_op) > 0);
}

/*!
 * \internal
 * \brief Check whether any non-monitor operation on a node happened after some
 *        event
 *
 * \param[in]     rsc_id     Resource being checked
 * \param[in]     node_name  Node being checked
 * \param[in]     xml_op     Event that non-monitor is being compared to
 * \param[in,out] scheduler  Scheduler data
 *
 * \return true if such a operation happened after event, false otherwise
 */
static bool
non_monitor_after(const char *rsc_id, const char *node_name,
                  const xmlNode *xml_op, pcmk_scheduler_t *scheduler)
{
    xmlNode *lrm_resource = NULL;

    lrm_resource = find_lrm_resource(rsc_id, node_name, scheduler);
    if (lrm_resource == NULL) {
        return false;
    }

    for (xmlNode *op = pcmk__xe_first_child(lrm_resource, PCMK__XE_LRM_RSC_OP,
                                            NULL, NULL);
         op != NULL; op = pcmk__xe_next(op, PCMK__XE_LRM_RSC_OP)) {

        const char * task = NULL;

        if (op == xml_op) {
            continue;
        }

        task = pcmk__xe_get(op, PCMK_XA_OPERATION);

        if (pcmk__str_any_of(task, PCMK_ACTION_START, PCMK_ACTION_STOP,
                             PCMK_ACTION_MIGRATE_TO, PCMK_ACTION_MIGRATE_FROM,
                             NULL)
            && pe__is_newer_op(op, xml_op) > 0) {
            return true;
        }
    }

    return false;
}

/*!
 * \internal
 * \brief Check whether the resource has newer state on a node after a migration
 *        attempt
 *
 * \param[in]     rsc_id        Resource being checked
 * \param[in]     node_name     Node being checked
 * \param[in]     migrate_to    Any migrate_to event that is being compared to
 * \param[in]     migrate_from  Any migrate_from event that is being compared to
 * \param[in,out] scheduler     Scheduler data
 *
 * \return true if such a operation happened after event, false otherwise
 */
static bool
newer_state_after_migrate(const char *rsc_id, const char *node_name,
                          const xmlNode *migrate_to,
                          const xmlNode *migrate_from,
                          pcmk_scheduler_t *scheduler)
{
    const xmlNode *xml_op = (migrate_from != NULL)? migrate_from : migrate_to;
    const char *source = pcmk__xe_get(xml_op, PCMK__META_MIGRATE_SOURCE);

    /* It's preferred to compare to the migrate event on the same node if
     * existing, since call ids are more reliable.
     */
    if ((xml_op != migrate_to) && (migrate_to != NULL)
        && pcmk__str_eq(node_name, source, pcmk__str_casei)) {

        xml_op = migrate_to;
    }

    /* If there's any newer non-monitor operation on the node, or any newer
     * probe/monitor operation on the node indicating it was not running there,
     * the migration events potentially no longer matter for the node.
     */
    return non_monitor_after(rsc_id, node_name, xml_op, scheduler)
           || monitor_not_running_after(rsc_id, node_name, xml_op, scheduler);
}

/*!
 * \internal
 * \brief Parse migration source and target node names from history entry
 *
 * \param[in]  entry        Resource history entry for a migration action
 * \param[in]  source_node  If not NULL, source must match this node
 * \param[in]  target_node  If not NULL, target must match this node
 * \param[out] source_name  Where to store migration source node name
 * \param[out] target_name  Where to store migration target node name
 *
 * \return Standard Pacemaker return code
 */
static int
get_migration_node_names(const xmlNode *entry, const pcmk_node_t *source_node,
                         const pcmk_node_t *target_node,
                         const char **source_name, const char **target_name)
{
    *source_name = pcmk__xe_get(entry, PCMK__META_MIGRATE_SOURCE);
    *target_name = pcmk__xe_get(entry, PCMK__META_MIGRATE_TARGET);
    if ((*source_name == NULL) || (*target_name == NULL)) {
        pcmk__config_err("Ignoring resource history entry %s without "
                         PCMK__META_MIGRATE_SOURCE " and "
                         PCMK__META_MIGRATE_TARGET, pcmk__xe_id(entry));
        return pcmk_rc_unpack_error;
    }

    if ((source_node != NULL)
        && !pcmk__str_eq(*source_name, source_node->priv->name,
                         pcmk__str_casei|pcmk__str_null_matches)) {
        pcmk__config_err("Ignoring resource history entry %s because "
                         PCMK__META_MIGRATE_SOURCE "='%s' does not match %s",
                         pcmk__xe_id(entry), *source_name,
                         pcmk__node_name(source_node));
        return pcmk_rc_unpack_error;
    }

    if ((target_node != NULL)
        && !pcmk__str_eq(*target_name, target_node->priv->name,
                         pcmk__str_casei|pcmk__str_null_matches)) {
        pcmk__config_err("Ignoring resource history entry %s because "
                         PCMK__META_MIGRATE_TARGET "='%s' does not match %s",
                         pcmk__xe_id(entry), *target_name,
                         pcmk__node_name(target_node));
        return pcmk_rc_unpack_error;
    }

    return pcmk_rc_ok;
}

/*
 * \internal
 * \brief Add a migration source to a resource's list of dangling migrations
 *
 * If the migrate_to and migrate_from actions in a live migration both
 * succeeded, but there is no stop on the source, the migration is considered
 * "dangling." Add the source to the resource's dangling migration list, which
 * will be used to schedule a stop on the source without affecting the target.
 *
 * \param[in,out] rsc   Resource involved in migration
 * \param[in]     node  Migration source
 */
static void
add_dangling_migration(pcmk_resource_t *rsc, const pcmk_node_t *node)
{
    pcmk__rsc_trace(rsc, "Dangling migration of %s requires stop on %s",
                    rsc->id, pcmk__node_name(node));
    rsc->priv->orig_role = pcmk_role_stopped;
    rsc->priv->dangling_migration_sources =
        g_list_prepend(rsc->priv->dangling_migration_sources,
                       (gpointer) node);
}

/*!
 * \internal
 * \brief Update resource role etc. after a successful migrate_to action
 *
 * \param[in,out] history  Parsed action result history
 */
static void
unpack_migrate_to_success(struct action_history *history)
{
    /* A complete migration sequence is:
     * 1. migrate_to on source node (which succeeded if we get to this function)
     * 2. migrate_from on target node
     * 3. stop on source node
     *
     * If no migrate_from has happened, the migration is considered to be
     * "partial". If the migrate_from succeeded but no stop has happened, the
     * migration is considered to be "dangling".
     *
     * If a successful migrate_to and stop have happened on the source node, we
     * still need to check for a partial migration, due to scenarios (easier to
     * produce with batch-limit=1) like:
     *
     * - A resource is migrating from node1 to node2, and a migrate_to is
     *   initiated for it on node1.
     *
     * - node2 goes into standby mode while the migrate_to is pending, which
     *   aborts the transition.
     *
     * - Upon completion of the migrate_to, a new transition schedules a stop
     *   on both nodes and a start on node1.
     *
     * - If the new transition is aborted for any reason while the resource is
     *   stopping on node1, the transition after that stop completes will see
     *   the migrate_to and stop on the source, but it's still a partial
     *   migration, and the resource must be stopped on node2 because it is
     *   potentially active there due to the migrate_to.
     *
     *   We also need to take into account that either node's history may be
     *   cleared at any point in the migration process.
     */
    int from_rc = PCMK_OCF_OK;
    int from_status = PCMK_EXEC_PENDING;
    pcmk_node_t *target_node = NULL;
    xmlNode *migrate_from = NULL;
    const char *source = NULL;
    const char *target = NULL;
    bool source_newer_op = false;
    bool target_newer_state = false;
    bool active_on_target = false;
    pcmk_scheduler_t *scheduler = history->rsc->priv->scheduler;

    // Get source and target node names from XML
    if (get_migration_node_names(history->xml, history->node, NULL, &source,
                                 &target) != pcmk_rc_ok) {
        return;
    }

    // Check for newer state on the source
    source_newer_op = non_monitor_after(history->rsc->id, source, history->xml,
                                        scheduler);

    // Check for a migrate_from action from this source on the target
    migrate_from = find_lrm_op(history->rsc->id, PCMK_ACTION_MIGRATE_FROM,
                               target, source, -1, scheduler);
    if (migrate_from != NULL) {
        if (source_newer_op) {
            /* There's a newer non-monitor operation on the source and a
             * migrate_from on the target, so this migrate_to is irrelevant to
             * the resource's state.
             */
            return;
        }
        pcmk__xe_get_int(migrate_from, PCMK__XA_RC_CODE, &from_rc);
        pcmk__xe_get_int(migrate_from, PCMK__XA_OP_STATUS, &from_status);
    }

    /* If the resource has newer state on both the source and target after the
     * migration events, this migrate_to is irrelevant to the resource's state.
     */
    target_newer_state = newer_state_after_migrate(history->rsc->id, target,
                                                   history->xml, migrate_from,
                                                   scheduler);
    if (source_newer_op && target_newer_state) {
        return;
    }

    /* Check for dangling migration (migrate_from succeeded but stop not done).
     * We know there's no stop because we already returned if the target has a
     * migrate_from and the source has any newer non-monitor operation.
     */
    if ((from_rc == PCMK_OCF_OK) && (from_status == PCMK_EXEC_DONE)) {
        add_dangling_migration(history->rsc, history->node);
        return;
    }

    /* Without newer state, this migrate_to implies the resource is active.
     * (Clones are not allowed to migrate, so role can't be promoted.)
     */
    history->rsc->priv->orig_role = pcmk_role_started;

    target_node = pcmk_find_node(scheduler, target);
    active_on_target = !target_newer_state && (target_node != NULL)
                       && target_node->details->online;

    if (from_status != PCMK_EXEC_PENDING) { // migrate_from failed on target
        if (active_on_target) {
            native_add_running(history->rsc, target_node, scheduler, TRUE);
        } else {
            // Mark resource as failed, require recovery, and prevent migration
            pcmk__set_rsc_flags(history->rsc,
                                pcmk__rsc_failed|pcmk__rsc_stop_if_failed);
            pcmk__clear_rsc_flags(history->rsc, pcmk__rsc_migratable);
        }
        return;
    }

    // The migrate_from is pending, complete but erased, or to be scheduled

    /* If there is no history at all for the resource on an online target, then
     * it was likely cleaned. Just return, and we'll schedule a probe. Once we
     * have the probe result, it will be reflected in target_newer_state.
     */
    if ((target_node != NULL) && target_node->details->online
        && unknown_on_node(history->rsc, target)) {
        return;
    }

    if (active_on_target) {
        pcmk_node_t *source_node = pcmk_find_node(scheduler, source);

        native_add_running(history->rsc, target_node, scheduler, FALSE);
        if ((source_node != NULL) && source_node->details->online) {
            /* This is a partial migration: the migrate_to completed
             * successfully on the source, but the migrate_from has not
             * completed. Remember the source and target; if the newly
             * chosen target remains the same when we schedule actions
             * later, we may continue with the migration.
             */
            history->rsc->priv->partial_migration_target = target_node;
            history->rsc->priv->partial_migration_source = source_node;
        }

    } else if (!source_newer_op) {
        // Mark resource as failed, require recovery, and prevent migration
        pcmk__set_rsc_flags(history->rsc,
                            pcmk__rsc_failed|pcmk__rsc_stop_if_failed);
        pcmk__clear_rsc_flags(history->rsc, pcmk__rsc_migratable);
    }
}

/*!
 * \internal
 * \brief Update resource role etc. after a failed migrate_to action
 *
 * \param[in,out] history  Parsed action result history
 */
static void
unpack_migrate_to_failure(struct action_history *history)
{
    xmlNode *target_migrate_from = NULL;
    const char *source = NULL;
    const char *target = NULL;
    pcmk_scheduler_t *scheduler = history->rsc->priv->scheduler;

    // Get source and target node names from XML
    if (get_migration_node_names(history->xml, history->node, NULL, &source,
                                 &target) != pcmk_rc_ok) {
        return;
    }

    /* If a migration failed, we have to assume the resource is active. Clones
     * are not allowed to migrate, so role can't be promoted.
     */
    history->rsc->priv->orig_role = pcmk_role_started;

    // Check for migrate_from on the target
    target_migrate_from = find_lrm_op(history->rsc->id,
                                      PCMK_ACTION_MIGRATE_FROM, target, source,
                                      PCMK_OCF_OK, scheduler);

    if (/* If the resource state is unknown on the target, it will likely be
         * probed there.
         * Don't just consider it running there. We will get back here anyway in
         * case the probe detects it's running there.
         */
        !unknown_on_node(history->rsc, target)
        /* If the resource has newer state on the target after the migration
         * events, this migrate_to no longer matters for the target.
         */
        && !newer_state_after_migrate(history->rsc->id, target, history->xml,
                                      target_migrate_from, scheduler)) {
        /* The resource has no newer state on the target, so assume it's still
         * active there.
         * (if it is up).
         */
        pcmk_node_t *target_node = pcmk_find_node(scheduler, target);

        if (target_node && target_node->details->online) {
            native_add_running(history->rsc, target_node, scheduler, FALSE);
        }

    } else if (!non_monitor_after(history->rsc->id, source, history->xml,
                                  scheduler)) {
        /* We know the resource has newer state on the target, but this
         * migrate_to still matters for the source as long as there's no newer
         * non-monitor operation there.
         */

        // Mark node as having dangling migration so we can force a stop later
        history->rsc->priv->dangling_migration_sources =
            g_list_prepend(history->rsc->priv->dangling_migration_sources,
                           (gpointer) history->node);
    }
}

/*!
 * \internal
 * \brief Update resource role etc. after a failed migrate_from action
 *
 * \param[in,out] history  Parsed action result history
 */
static void
unpack_migrate_from_failure(struct action_history *history)
{
    xmlNode *source_migrate_to = NULL;
    const char *source = NULL;
    const char *target = NULL;
    pcmk_scheduler_t *scheduler = history->rsc->priv->scheduler;

    // Get source and target node names from XML
    if (get_migration_node_names(history->xml, NULL, history->node, &source,
                                 &target) != pcmk_rc_ok) {
        return;
    }

    /* If a migration failed, we have to assume the resource is active. Clones
     * are not allowed to migrate, so role can't be promoted.
     */
    history->rsc->priv->orig_role = pcmk_role_started;

    // Check for a migrate_to on the source
    source_migrate_to = find_lrm_op(history->rsc->id, PCMK_ACTION_MIGRATE_TO,
                                    source, target, PCMK_OCF_OK, scheduler);

    if (/* If the resource state is unknown on the source, it will likely be
         * probed there.
         * Don't just consider it running there. We will get back here anyway in
         * case the probe detects it's running there.
         */
        !unknown_on_node(history->rsc, source)
        /* If the resource has newer state on the source after the migration
         * events, this migrate_from no longer matters for the source.
         */
        && !newer_state_after_migrate(history->rsc->id, source,
                                      source_migrate_to, history->xml,
                                      scheduler)) {
        /* The resource has no newer state on the source, so assume it's still
         * active there (if it is up).
         */
        pcmk_node_t *source_node = pcmk_find_node(scheduler, source);

        if (source_node && source_node->details->online) {
            native_add_running(history->rsc, source_node, scheduler, TRUE);
        }
    }
}

/*!
 * \internal
 * \brief Add an action to cluster's list of failed actions
 *
 * \param[in,out] history  Parsed action result history
 */
static void
record_failed_op(struct action_history *history)
{
    const pcmk_scheduler_t *scheduler = history->rsc->priv->scheduler;

    if (!(history->node->details->online)) {
        return;
    }

    for (const xmlNode *xIter = scheduler->priv->failed->children;
         xIter != NULL; xIter = xIter->next) {

        const char *key = pcmk__xe_history_key(xIter);
        const char *uname = pcmk__xe_get(xIter, PCMK_XA_UNAME);

        if (pcmk__str_eq(history->key, key, pcmk__str_none)
            && pcmk__str_eq(uname, history->node->priv->name,
                            pcmk__str_casei)) {
            pcmk__trace("Skipping duplicate entry %s on %s", history->key,
                        pcmk__node_name(history->node));
            return;
        }
    }

    pcmk__trace("Adding entry for %s on %s to failed action list",
                history->key, pcmk__node_name(history->node));
    pcmk__xe_set(history->xml, PCMK_XA_UNAME, history->node->priv->name);
    pcmk__xe_set(history->xml, PCMK__XA_RSC_ID, history->rsc->id);
    pcmk__xml_copy(scheduler->priv->failed, history->xml);
}

static char *
last_change_str(const xmlNode *xml_op)
{
    time_t when;
    char *result = NULL;

    if (pcmk__xe_get_time(xml_op, PCMK_XA_LAST_RC_CHANGE,
                          &when) == pcmk_rc_ok) {
        char *when_s = pcmk__epoch2str(&when, 0);
        const char *p = strchr(when_s, ' ');

        // Skip day of week to make message shorter
        if ((p != NULL) && (*(++p) != '\0')) {
            result = pcmk__str_copy(p);
        }
        free(when_s);
    }

    if (result == NULL) {
        result = pcmk__str_copy("unknown_time");
    }

    return result;
}

/*!
 * \internal
 * \brief Ban a resource (or its clone if an anonymous instance) from all nodes
 *
 * \param[in,out] rsc  Resource to ban
 */
static void
ban_from_all_nodes(pcmk_resource_t *rsc)
{
    int score = -PCMK_SCORE_INFINITY;
    const pcmk_scheduler_t *scheduler = rsc->priv->scheduler;

    if (rsc->priv->parent != NULL) {
        pcmk_resource_t *parent = uber_parent(rsc);

        if (pcmk__is_anonymous_clone(parent)) {
            /* For anonymous clones, if an operation with
             * PCMK_META_ON_FAIL=PCMK_VALUE_STOP fails for any instance, the
             * entire clone must stop.
             */
            rsc = parent;
        }
    }

    // Ban the resource from all nodes
    pcmk__notice("%s will not be started under current conditions", rsc->id);
    if (rsc->priv->allowed_nodes != NULL) {
        g_hash_table_destroy(rsc->priv->allowed_nodes);
    }
    rsc->priv->allowed_nodes = pe__node_list2table(scheduler->nodes);
    g_hash_table_foreach(rsc->priv->allowed_nodes, set_node_score, &score);
}

/*!
 * \internal
 * \brief Get configured failure handling and role after failure for an action
 *
 * \param[in,out] history    Unpacked action history entry
 * \param[out]    on_fail    Where to set configured failure handling
 * \param[out]    fail_role  Where to set to role after failure
 */
static void
unpack_failure_handling(struct action_history *history,
                        enum pcmk__on_fail *on_fail,
                        enum rsc_role_e *fail_role)
{
    xmlNode *config = pcmk__find_action_config(history->rsc, history->task,
                                               history->interval_ms, true);

    GHashTable *meta = pcmk__unpack_action_meta(history->rsc, history->node,
                                                history->task,
                                                history->interval_ms, config);

    const char *on_fail_str = g_hash_table_lookup(meta, PCMK_META_ON_FAIL);

    *on_fail = pcmk__parse_on_fail(history->rsc, history->task,
                                   history->interval_ms, on_fail_str);
    *fail_role = pcmk__role_after_failure(history->rsc, history->task, *on_fail,
                                          meta);
    g_hash_table_destroy(meta);
}

/*!
 * \internal
 * \brief Update resource role, failure handling, etc., after a failed action
 *
 * \param[in,out] history         Parsed action result history
 * \param[in]     config_on_fail  Action failure handling from configuration
 * \param[in]     fail_role       Resource's role after failure of this action
 * \param[out]    last_failure    This will be set to the history XML
 * \param[in,out] on_fail         Actual handling of action result
 */
static void
unpack_rsc_op_failure(struct action_history *history,
                      enum pcmk__on_fail config_on_fail,
                      enum rsc_role_e fail_role, xmlNode **last_failure,
                      enum pcmk__on_fail *on_fail)
{
    bool is_probe = false;
    char *last_change_s = NULL;
    pcmk_scheduler_t *scheduler = history->rsc->priv->scheduler;

    *last_failure = history->xml;

    is_probe = pcmk_xe_is_probe(history->xml);
    last_change_s = last_change_str(history->xml);

    if (!pcmk__is_set(scheduler->flags, pcmk__sched_symmetric_cluster)
        && (history->exit_status == PCMK_OCF_NOT_INSTALLED)) {
        pcmk__trace("Unexpected result (%s%s%s) was recorded for "
                    "%s of %s on %s at %s " QB_XS " exit-status=%d id=%s",
                    crm_exit_str(history->exit_status),
                    (pcmk__str_empty(history->exit_reason)? "" : ": "),
                    pcmk__s(history->exit_reason, ""),
                    (is_probe? "probe" : history->task), history->rsc->id,
                    pcmk__node_name(history->node), last_change_s,
                    history->exit_status, history->id);
    } else {
        pcmk__sched_warn(scheduler,
                         "Unexpected result (%s%s%s) was recorded for %s of "
                         "%s on %s at %s " QB_XS " exit-status=%d id=%s",
                         crm_exit_str(history->exit_status),
                         (pcmk__str_empty(history->exit_reason)? "" : ": "),
                         pcmk__s(history->exit_reason, ""),
                         (is_probe? "probe" : history->task), history->rsc->id,
                         pcmk__node_name(history->node), last_change_s,
                         history->exit_status, history->id);

        if (is_probe && (history->exit_status != PCMK_OCF_OK)
            && (history->exit_status != PCMK_OCF_NOT_RUNNING)
            && (history->exit_status != PCMK_OCF_RUNNING_PROMOTED)) {

            /* A failed (not just unexpected) probe result could mean the user
             * didn't know resources will be probed even where they can't run.
             */
            pcmk__notice("If it is not possible for %s to run on %s, see the "
                         PCMK_XA_RESOURCE_DISCOVERY " option for location "
                         "constraints",
                         history->rsc->id, pcmk__node_name(history->node));
        }

        record_failed_op(history);
    }

    free(last_change_s);

    if (*on_fail < config_on_fail) {
        pcmk__rsc_trace(history->rsc, "on-fail %s -> %s for %s",
                        pcmk__on_fail_text(*on_fail),
                        pcmk__on_fail_text(config_on_fail), history->key);
        *on_fail = config_on_fail;
    }

    if (strcmp(history->task, PCMK_ACTION_STOP) == 0) {
        resource_location(history->rsc, history->node, -PCMK_SCORE_INFINITY,
                          "__stop_fail__", scheduler);

    } else if (strcmp(history->task, PCMK_ACTION_MIGRATE_TO) == 0) {
        unpack_migrate_to_failure(history);

    } else if (strcmp(history->task, PCMK_ACTION_MIGRATE_FROM) == 0) {
        unpack_migrate_from_failure(history);

    } else if (strcmp(history->task, PCMK_ACTION_PROMOTE) == 0) {
        history->rsc->priv->orig_role = pcmk_role_promoted;

    } else if (strcmp(history->task, PCMK_ACTION_DEMOTE) == 0) {
        if (config_on_fail == pcmk__on_fail_block) {
            history->rsc->priv->orig_role = pcmk_role_promoted;
            pe__set_next_role(history->rsc, pcmk_role_stopped,
                              "demote with " PCMK_META_ON_FAIL "=block");

        } else if (history->exit_status == PCMK_OCF_NOT_RUNNING) {
            history->rsc->priv->orig_role = pcmk_role_stopped;

        } else {
            /* Staying in the promoted role would put the scheduler and
             * controller into a loop. Setting the role to unpromoted is not
             * dangerous because the resource will be stopped as part of
             * recovery, and any promotion will be ordered after that stop.
             */
            history->rsc->priv->orig_role = pcmk_role_unpromoted;
        }
    }

    if (is_probe && (history->exit_status == PCMK_OCF_NOT_INSTALLED)) {
        /* leave stopped */
        pcmk__rsc_trace(history->rsc, "Leaving %s stopped", history->rsc->id);
        history->rsc->priv->orig_role = pcmk_role_stopped;

    } else if (history->rsc->priv->orig_role < pcmk_role_started) {
        pcmk__rsc_trace(history->rsc, "Setting %s active", history->rsc->id);
        set_active(history->rsc);
    }

    pcmk__rsc_trace(history->rsc,
                    "Resource %s: role=%s unclean=%s on_fail=%s fail_role=%s",
                    history->rsc->id,
                    pcmk_role_text(history->rsc->priv->orig_role),
                    pcmk__btoa(history->node->details->unclean),
                    pcmk__on_fail_text(config_on_fail),
                    pcmk_role_text(fail_role));

    if ((fail_role != pcmk_role_started)
        && (history->rsc->priv->next_role < fail_role)) {
        pe__set_next_role(history->rsc, fail_role, "failure");
    }

    if (fail_role == pcmk_role_stopped) {
        ban_from_all_nodes(history->rsc);
    }
}

/*!
 * \internal
 * \brief Block a resource with a failed action if it cannot be recovered
 *
 * If resource action is a failed stop and fencing is not possible, mark the
 * resource as unmanaged and blocked, since recovery cannot be done.
 *
 * \param[in,out] history  Parsed action history entry
 */
static void
block_if_unrecoverable(struct action_history *history)
{
    char *last_change_s = NULL;

    if (strcmp(history->task, PCMK_ACTION_STOP) != 0) {
        return; // All actions besides stop are always recoverable
    }
    if (pe_can_fence(history->node->priv->scheduler, history->node)) {
        return; // Failed stops are recoverable via fencing
    }

    last_change_s = last_change_str(history->xml);
    pcmk__sched_err(history->node->priv->scheduler,
                    "No further recovery can be attempted for %s "
                    "because %s on %s failed (%s%s%s) at %s "
                    QB_XS " rc=%d id=%s",
                    history->rsc->id, history->task,
                    pcmk__node_name(history->node),
                    crm_exit_str(history->exit_status),
                    (pcmk__str_empty(history->exit_reason)? "" : ": "),
                    pcmk__s(history->exit_reason, ""),
                    last_change_s, history->exit_status, history->id);

    free(last_change_s);

    pcmk__clear_rsc_flags(history->rsc, pcmk__rsc_managed);
    pcmk__set_rsc_flags(history->rsc, pcmk__rsc_blocked);
}

/*!
 * \internal
 * \brief Update action history's execution status and why
 *
 * \param[in,out] history  Parsed action history entry
 * \param[out]    why      Where to store reason for update
 * \param[in]     value    New value
 * \param[in]     reason   Description of why value was changed
 */
static inline void
remap_because(struct action_history *history, const char **why, int value,
              const char *reason)
{
    if (history->execution_status != value) {
        history->execution_status = value;
        *why = reason;
    }
}

/*!
 * \internal
 * \brief Remap informational monitor results and operation status
 *
 * For the monitor results, certain OCF codes are for providing extended information
 * to the user about services that aren't yet failed but not entirely healthy either.
 * These must be treated as the "normal" result by Pacemaker.
 *
 * For operation status, the action result can be used to determine an appropriate
 * status for the purposes of responding to the action.  The status provided by the
 * executor is not directly usable since the executor does not know what was expected.
 *
 * \param[in,out] history  Parsed action history entry
 * \param[in,out] on_fail  What should be done about the result
 * \param[in]     expired  Whether result is expired
 *
 * \note If the result is remapped and the node is not shutting down or failed,
 *       the operation will be recorded in the scheduler data's list of failed
 *       operations to highlight it for the user.
 *
 * \note This may update the resource's current and next role.
 */
static void
remap_operation(struct action_history *history,
                enum pcmk__on_fail *on_fail, bool expired)
{
    /* @TODO It would probably also be a good idea to map an exit status of
     * CRM_EX_PROMOTED or CRM_EX_DEGRADED_PROMOTED to CRM_EX_OK for promote
     * actions
     */

    bool is_probe = false;
    int orig_exit_status = history->exit_status;
    int orig_exec_status = history->execution_status;
    const char *why = NULL;
    const char *task = history->task;

    // Remap degraded results to their successful counterparts
    history->exit_status = pcmk__effective_rc(history->exit_status);
    if (history->exit_status != orig_exit_status) {
        why = "degraded result";
        if (!expired && (!history->node->details->shutdown
                         || history->node->details->online)) {
            record_failed_op(history);
        }
    }

    if (!pcmk__is_bundled(history->rsc)
        && pcmk_xe_mask_probe_failure(history->xml)
        && ((history->execution_status != PCMK_EXEC_DONE)
            || (history->exit_status != PCMK_OCF_NOT_RUNNING))) {
        history->execution_status = PCMK_EXEC_DONE;
        history->exit_status = PCMK_OCF_NOT_RUNNING;
        why = "equivalent probe result";
    }

    /* If the executor reported an execution status of anything but done or
     * error, consider that final. But for done or error, we know better whether
     * it should be treated as a failure or not, because we know the expected
     * result.
     */
    switch (history->execution_status) {
        case PCMK_EXEC_DONE:
        case PCMK_EXEC_ERROR:
            break;

        // These should be treated as node-fatal
        case PCMK_EXEC_NO_FENCE_DEVICE:
        case PCMK_EXEC_NO_SECRETS:
            remap_because(history, &why, PCMK_EXEC_ERROR_HARD,
                          "node-fatal error");
            goto remap_done;

        default:
            goto remap_done;
    }

    is_probe = pcmk_xe_is_probe(history->xml);
    if (is_probe) {
        task = "probe";
    }

    if (history->expected_exit_status < 0) {
        /* Pre-1.0 Pacemaker versions, and Pacemaker 1.1.6 or earlier with
         * Heartbeat 2.0.7 or earlier as the cluster layer, did not include the
         * expected exit status in the transition key, which (along with the
         * similar case of a corrupted transition key in the CIB) will be
         * reported to this function as -1. Pacemaker 2.0+ does not support
         * rolling upgrades from those versions or processing of saved CIB files
         * from those versions, so we do not need to care much about this case.
         */
        remap_because(history, &why, PCMK_EXEC_ERROR,
                      "obsolete history format");
        pcmk__config_warn("Expected result not found for %s on %s "
                          "(corrupt or obsolete CIB?)",
                          history->key, pcmk__node_name(history->node));

    } else if (history->exit_status == history->expected_exit_status) {
        remap_because(history, &why, PCMK_EXEC_DONE, "expected result");

    } else {
        remap_because(history, &why, PCMK_EXEC_ERROR, "unexpected result");
        pcmk__rsc_debug(history->rsc,
                        "%s on %s: expected %d (%s), got %d (%s%s%s)",
                        history->key, pcmk__node_name(history->node),
                        history->expected_exit_status,
                        crm_exit_str(history->expected_exit_status),
                        history->exit_status,
                        crm_exit_str(history->exit_status),
                        (pcmk__str_empty(history->exit_reason)? "" : ": "),
                        pcmk__s(history->exit_reason, ""));
    }

    switch (history->exit_status) {
        case PCMK_OCF_OK:
            if (is_probe
                && (history->expected_exit_status == PCMK_OCF_NOT_RUNNING)) {
                char *last_change_s = last_change_str(history->xml);

                remap_because(history, &why, PCMK_EXEC_DONE, "probe");
                pcmk__rsc_info(history->rsc,
                               "Probe found %s active on %s at %s",
                               history->rsc->id, pcmk__node_name(history->node),
                               last_change_s);
                free(last_change_s);
            }
            break;

        case PCMK_OCF_NOT_RUNNING:
            if (is_probe
                || (history->expected_exit_status == history->exit_status)
                || !pcmk__is_set(history->rsc->flags, pcmk__rsc_managed)) {

                /* For probes, recurring monitors for the Stopped role, and
                 * unmanaged resources, "not running" is not considered a
                 * failure.
                 */
                remap_because(history, &why, PCMK_EXEC_DONE, "exit status");
                history->rsc->priv->orig_role = pcmk_role_stopped;
                *on_fail = pcmk__on_fail_ignore;
                pe__set_next_role(history->rsc, pcmk_role_unknown,
                                  "not running");
            }
            break;

        case PCMK_OCF_RUNNING_PROMOTED:
            if (is_probe
                && (history->exit_status != history->expected_exit_status)) {
                char *last_change_s = last_change_str(history->xml);

                remap_because(history, &why, PCMK_EXEC_DONE, "probe");
                pcmk__rsc_info(history->rsc,
                               "Probe found %s active and promoted on %s at %s",
                                history->rsc->id,
                                pcmk__node_name(history->node), last_change_s);
                free(last_change_s);
            }
            if (!expired
                || (history->exit_status == history->expected_exit_status)) {
                history->rsc->priv->orig_role = pcmk_role_promoted;
            }
            break;

        case PCMK_OCF_FAILED_PROMOTED:
            if (!expired) {
                history->rsc->priv->orig_role = pcmk_role_promoted;
            }
            remap_because(history, &why, PCMK_EXEC_ERROR, "exit status");
            break;

        case PCMK_OCF_NOT_CONFIGURED:
            remap_because(history, &why, PCMK_EXEC_ERROR_FATAL, "exit status");
            break;

        case PCMK_OCF_UNIMPLEMENT_FEATURE:
            {
                guint interval_ms = 0;
                pcmk__xe_get_guint(history->xml, PCMK_META_INTERVAL,
                                   &interval_ms);

                if (interval_ms == 0) {
                    if (!expired) {
                        block_if_unrecoverable(history);
                    }
                    remap_because(history, &why, PCMK_EXEC_ERROR_HARD,
                                  "exit status");
                } else {
                    remap_because(history, &why, PCMK_EXEC_NOT_SUPPORTED,
                                  "exit status");
                }
            }
            break;

        case PCMK_OCF_NOT_INSTALLED:
        case PCMK_OCF_INVALID_PARAM:
        case PCMK_OCF_INSUFFICIENT_PRIV:
            if (!expired) {
                block_if_unrecoverable(history);
            }
            remap_because(history, &why, PCMK_EXEC_ERROR_HARD, "exit status");
            break;

        default:
            if (history->execution_status == PCMK_EXEC_DONE) {
                char *last_change_s = last_change_str(history->xml);

                pcmk__info("Treating unknown exit status %d from %s of %s on "
                           "%s at %s as failure",
                           history->exit_status, task, history->rsc->id,
                           pcmk__node_name(history->node), last_change_s);
                remap_because(history, &why, PCMK_EXEC_ERROR,
                              "unknown exit status");
                free(last_change_s);
            }
            break;
    }

remap_done:
    if (why != NULL) {
        pcmk__rsc_trace(history->rsc,
                        "Remapped %s result from [%s: %s] to [%s: %s] "
                        "because of %s",
                        history->key, pcmk_exec_status_str(orig_exec_status),
                        crm_exit_str(orig_exit_status),
                        pcmk_exec_status_str(history->execution_status),
                        crm_exit_str(history->exit_status), why);
    }
}

// return TRUE if start or monitor last failure but parameters changed
static bool
should_clear_for_param_change(const xmlNode *xml_op, const char *task,
                              pcmk_resource_t *rsc, pcmk_node_t *node)
{
    if (pcmk__str_any_of(task, PCMK_ACTION_START, PCMK_ACTION_MONITOR, NULL)) {
        if (pe__bundle_needs_remote_name(rsc)) {
            /* We haven't allocated resources yet, so we can't reliably
             * substitute addr parameters for the REMOTE_CONTAINER_HACK.
             * When that's needed, defer the check until later.
             */
            pcmk__add_param_check(xml_op, rsc, node, pcmk__check_last_failure);

        } else {
            pcmk__op_digest_t *digest_data = NULL;

            digest_data = rsc_action_digest_cmp(rsc, xml_op, node,
                                                rsc->priv->scheduler);
            switch (digest_data->rc) {
                case pcmk__digest_unknown:
                    pcmk__trace("Resource %s history entry %s on %s"
                                " has no digest to compare",
                                rsc->id, pcmk__xe_history_key(xml_op),
                                node->priv->id);
                    break;
                case pcmk__digest_match:
                    break;
                default:
                    return TRUE;
            }
        }
    }
    return FALSE;
}

// Order action after fencing of remote node, given connection rsc
static void
order_after_remote_fencing(pcmk_action_t *action, pcmk_resource_t *remote_conn,
                           pcmk_scheduler_t *scheduler)
{
    pcmk_node_t *remote_node = pcmk_find_node(scheduler, remote_conn->id);

    if (remote_node) {
        pcmk_action_t *fence = pe_fence_op(remote_node, NULL, TRUE, NULL,
                                           FALSE, scheduler);

        order_actions(fence, action, pcmk__ar_first_implies_then);
    }
}

static bool
should_ignore_failure_timeout(const pcmk_resource_t *rsc, const char *task,
                              guint interval_ms, bool is_last_failure)
{
    /* Clearing failures of recurring monitors has special concerns. The
     * executor reports only changes in the monitor result, so if the
     * monitor is still active and still getting the same failure result,
     * that will go undetected after the failure is cleared.
     *
     * Also, the operation history will have the time when the recurring
     * monitor result changed to the given code, not the time when the
     * result last happened.
     *
     * @TODO We probably should clear such failures only when the failure
     * timeout has passed since the last occurrence of the failed result.
     * However we don't record that information. We could maybe approximate
     * that by clearing only if there is a more recent successful monitor or
     * stop result, but we don't even have that information at this point
     * since we are still unpacking the resource's operation history.
     *
     * This is especially important for remote connection resources with a
     * reconnect interval, so in that case, we skip clearing failures
     * if the remote node hasn't been fenced.
     */
    if ((rsc->priv->remote_reconnect_ms > 0U)
        && pcmk__is_set(rsc->priv->scheduler->flags,
                        pcmk__sched_fencing_enabled)
        && (interval_ms != 0)
        && pcmk__str_eq(task, PCMK_ACTION_MONITOR, pcmk__str_casei)) {

        pcmk_node_t *remote_node = pcmk_find_node(rsc->priv->scheduler,
                                                  rsc->id);

        if (remote_node && !pcmk__is_set(remote_node->priv->flags,
                                         pcmk__node_remote_fenced)) {
            if (is_last_failure) {
                pcmk__info("Waiting to clear monitor failure for remote node %s"
                           " until fencing has occurred",
                           rsc->id);
            }
            return TRUE;
        }
    }
    return FALSE;
}

/*!
 * \internal
 * \brief Check operation age and schedule failure clearing when appropriate
 *
 * This function has two distinct purposes. The first is to check whether an
 * operation history entry is expired (i.e. the resource has a failure timeout,
 * the entry is older than the timeout, and the resource either has no fail
 * count or its fail count is entirely older than the timeout). The second is to
 * schedule fail count clearing when appropriate (i.e. the operation is expired
 * and either the resource has an expired fail count or the operation is a
 * last_failure for a remote connection resource with a reconnect interval,
 * or the operation is a last_failure for a start or monitor operation and the
 * resource's parameters have changed since the operation).
 *
 * \param[in,out] history  Parsed action result history
 *
 * \return true if operation history entry is expired, otherwise false
 */
static bool
check_operation_expiry(struct action_history *history)
{
    bool expired = false;
    bool is_last_failure = (history->id != NULL)
                           && g_str_has_suffix(history->id, "_last_failure_0");
    time_t last_run = 0;
    int unexpired_fail_count = 0;
    const char *clear_reason = NULL;
    const guint expiration_sec =
        pcmk__timeout_ms2s(history->rsc->priv->failure_expiration_ms);
    pcmk_scheduler_t *scheduler = history->rsc->priv->scheduler;

    if (history->execution_status == PCMK_EXEC_NOT_INSTALLED) {
        pcmk__rsc_trace(history->rsc,
                        "Resource history entry %s on %s is not expired: "
                        "Not Installed does not expire",
                        history->id, pcmk__node_name(history->node));
        return false; // "Not installed" must always be cleared manually
    }

    if ((expiration_sec > 0)
        && (pcmk__xe_get_time(history->xml, PCMK_XA_LAST_RC_CHANGE,
                              &last_run) == pcmk_rc_ok)) {

        /* Resource has a PCMK_META_FAILURE_TIMEOUT and history entry has a
         * timestamp
         */

        time_t now = pcmk__scheduler_epoch_time(scheduler);
        time_t last_failure = 0;

        // Is this particular operation history older than the failure timeout?
        if ((now >= (last_run + expiration_sec))
            && !should_ignore_failure_timeout(history->rsc, history->task,
                                              history->interval_ms,
                                              is_last_failure)) {
            expired = true;
        }

        // Does the resource as a whole have an unexpired fail count?
        unexpired_fail_count = pe_get_failcount(history->node, history->rsc,
                                                &last_failure,
                                                pcmk__fc_effective,
                                                history->xml);

        // Update scheduler recheck time according to *last* failure
        pcmk__trace("%s@%lld is %sexpired @%lld with unexpired_failures=%d "
                    "expiration=%s last-failure@%lld",
                    history->id, (long long) last_run, (expired? "" : "not "),
                    (long long) now, unexpired_fail_count,
                    pcmk__readable_interval(expiration_sec * 1000),
                    (long long) last_failure);
        last_failure += expiration_sec + 1;
        if (unexpired_fail_count && (now < last_failure)) {
            pcmk__update_recheck_time(last_failure, scheduler,
                                      "fail count expiration");
        }
    }

    if (expired) {
        if (pe_get_failcount(history->node, history->rsc, NULL,
                             pcmk__fc_default, history->xml)) {
            // There is a fail count ignoring timeout

            if (unexpired_fail_count == 0) {
                // There is no fail count considering timeout
                clear_reason = "it expired";

            } else {
                /* This operation is old, but there is an unexpired fail count.
                 * In a properly functioning cluster, this should only be
                 * possible if this operation is not a failure (otherwise the
                 * fail count should be expired too), so this is really just a
                 * failsafe.
                 */
                pcmk__rsc_trace(history->rsc,
                                "Resource history entry %s on %s is not "
                                "expired: Unexpired fail count",
                                history->id, pcmk__node_name(history->node));
                expired = false;
            }

        } else if (is_last_failure
                   && (history->rsc->priv->remote_reconnect_ms > 0U)) {
            /* Clear any expired last failure when reconnect interval is set,
             * even if there is no fail count.
             */
            clear_reason = "reconnect interval is set";
        }
    }

    if (!expired && is_last_failure
        && should_clear_for_param_change(history->xml, history->task,
                                         history->rsc, history->node)) {
        clear_reason = "resource parameters have changed";
    }

    if (clear_reason != NULL) {
        pcmk_action_t *clear_op = NULL;

        // Schedule clearing of the fail count
        clear_op = pe__clear_failcount(history->rsc, history->node,
                                       clear_reason, scheduler);

        if (pcmk__is_set(scheduler->flags, pcmk__sched_fencing_enabled)
            && (history->rsc->priv->remote_reconnect_ms > 0)) {
            /* If we're clearing a remote connection due to a reconnect
             * interval, we want to wait until any scheduled fencing
             * completes.
             *
             * We could limit this to remote_node->details->unclean, but at
             * this point, that's always true (it won't be reliable until
             * after unpack_node_history() is done).
             */
            pcmk__info("Clearing %s failure will wait until any scheduled "
                       "fencing of %s completes",
                       history->task, history->rsc->id);
            order_after_remote_fencing(clear_op, history->rsc, scheduler);
        }
    }

    if (expired && (history->interval_ms == 0)
        && pcmk__str_eq(history->task, PCMK_ACTION_MONITOR, pcmk__str_none)) {
        switch (history->exit_status) {
            case PCMK_OCF_OK:
            case PCMK_OCF_NOT_RUNNING:
            case PCMK_OCF_RUNNING_PROMOTED:
            case PCMK_OCF_DEGRADED:
            case PCMK_OCF_DEGRADED_PROMOTED:
                // Don't expire probes that return these values
                pcmk__rsc_trace(history->rsc,
                                "Resource history entry %s on %s is not "
                                "expired: Probe result",
                             history->id, pcmk__node_name(history->node));
                expired = false;
                break;
        }
    }

    return expired;
}

int
pe__target_rc_from_xml(const xmlNode *xml_op)
{
    int target_rc = 0;
    const char *key = pcmk__xe_get(xml_op, PCMK__XA_TRANSITION_KEY);

    if (key == NULL) {
        return -1;
    }
    decode_transition_key(key, NULL, NULL, NULL, &target_rc);
    return target_rc;
}

/*!
 * \internal
 * \brief Update a resource's state for an action result
 *
 * \param[in,out] history       Parsed action history entry
 * \param[in]     exit_status   Exit status to base new state on
 * \param[in]     last_failure  Resource's last_failure entry, if known
 * \param[in,out] on_fail       Resource's current failure handling
 */
static void
update_resource_state(struct action_history *history, int exit_status,
                      const xmlNode *last_failure,
                      enum pcmk__on_fail *on_fail)
{
    bool clear_past_failure = false;

    if ((exit_status == PCMK_OCF_NOT_INSTALLED)
        || (!pcmk__is_bundled(history->rsc)
            && pcmk_xe_mask_probe_failure(history->xml))) {
        history->rsc->priv->orig_role = pcmk_role_stopped;

    } else if (exit_status == PCMK_OCF_NOT_RUNNING) {
        clear_past_failure = true;

    } else if (pcmk__str_eq(history->task, PCMK_ACTION_MONITOR,
                            pcmk__str_none)) {
        if ((last_failure != NULL)
            && pcmk__str_eq(history->key, pcmk__xe_history_key(last_failure),
                            pcmk__str_none)) {
            clear_past_failure = true;
        }
        if (history->rsc->priv->orig_role < pcmk_role_started) {
            set_active(history->rsc);
        }

    } else if (pcmk__str_eq(history->task, PCMK_ACTION_START, pcmk__str_none)) {
        history->rsc->priv->orig_role = pcmk_role_started;
        clear_past_failure = true;

    } else if (pcmk__str_eq(history->task, PCMK_ACTION_STOP, pcmk__str_none)) {
        history->rsc->priv->orig_role = pcmk_role_stopped;
        clear_past_failure = true;

    } else if (pcmk__str_eq(history->task, PCMK_ACTION_PROMOTE,
                            pcmk__str_none)) {
        history->rsc->priv->orig_role = pcmk_role_promoted;
        clear_past_failure = true;

    } else if (pcmk__str_eq(history->task, PCMK_ACTION_DEMOTE,
                            pcmk__str_none)) {
        if (*on_fail == pcmk__on_fail_demote) {
            /* Demote clears an error only if
             * PCMK_META_ON_FAIL=PCMK_VALUE_DEMOTE
             */
            clear_past_failure = true;
        }
        history->rsc->priv->orig_role = pcmk_role_unpromoted;

    } else if (pcmk__str_eq(history->task, PCMK_ACTION_MIGRATE_FROM,
                            pcmk__str_none)) {
        history->rsc->priv->orig_role = pcmk_role_started;
        clear_past_failure = true;

    } else if (pcmk__str_eq(history->task, PCMK_ACTION_MIGRATE_TO,
                            pcmk__str_none)) {
        unpack_migrate_to_success(history);

    } else if (history->rsc->priv->orig_role < pcmk_role_started) {
        pcmk__rsc_trace(history->rsc, "%s active on %s",
                        history->rsc->id, pcmk__node_name(history->node));
        set_active(history->rsc);
    }

    if (!clear_past_failure) {
        return;
    }

    switch (*on_fail) {
        case pcmk__on_fail_stop:
        case pcmk__on_fail_ban:
        case pcmk__on_fail_standby_node:
        case pcmk__on_fail_fence_node:
            pcmk__rsc_trace(history->rsc,
                            "%s (%s) is not cleared by a completed %s",
                            history->rsc->id, pcmk__on_fail_text(*on_fail),
                            history->task);
            break;

        case pcmk__on_fail_block:
        case pcmk__on_fail_ignore:
        case pcmk__on_fail_demote:
        case pcmk__on_fail_restart:
        case pcmk__on_fail_restart_container:
            *on_fail = pcmk__on_fail_ignore;
            pe__set_next_role(history->rsc, pcmk_role_unknown,
                              "clear past failures");
            break;

        case pcmk__on_fail_reset_remote:
            if (history->rsc->priv->remote_reconnect_ms == 0U) {
                /* With no reconnect interval, the connection is allowed to
                 * start again after the remote node is fenced and
                 * completely stopped. (With a reconnect interval, we wait
                 * for the failure to be cleared entirely before attempting
                 * to reconnect.)
                 */
                *on_fail = pcmk__on_fail_ignore;
                pe__set_next_role(history->rsc, pcmk_role_unknown,
                                  "clear past failures and reset remote");
            }
            break;
    }
}

/*!
 * \internal
 * \brief Check whether a given history entry matters for resource state
 *
 * \param[in] history  Parsed action history entry
 *
 * \return true if action can affect resource state, otherwise false
 */
static inline bool
can_affect_state(struct action_history *history)
{
     return pcmk__str_any_of(history->task, PCMK_ACTION_MONITOR,
                             PCMK_ACTION_START, PCMK_ACTION_STOP,
                             PCMK_ACTION_PROMOTE, PCMK_ACTION_DEMOTE,
                             PCMK_ACTION_MIGRATE_TO, PCMK_ACTION_MIGRATE_FROM,
                             "asyncmon", NULL);
}

/*!
 * \internal
 * \brief Unpack execution/exit status and exit reason from a history entry
 *
 * \param[in,out] history  Action history entry to unpack
 *
 * \return Standard Pacemaker return code
 */
static int
unpack_action_result(struct action_history *history)
{
    if ((pcmk__xe_get_int(history->xml, PCMK__XA_OP_STATUS,
                          &(history->execution_status)) != pcmk_rc_ok)
        || (history->execution_status < PCMK_EXEC_PENDING)
        || (history->execution_status > PCMK_EXEC_MAX)
        || (history->execution_status == PCMK_EXEC_CANCELLED)) {
        pcmk__config_err("Ignoring resource history entry %s for %s on %s "
                         "with invalid " PCMK__XA_OP_STATUS " '%s'",
                         history->id, history->rsc->id,
                         pcmk__node_name(history->node),
                         pcmk__s(pcmk__xe_get(history->xml, PCMK__XA_OP_STATUS),
                                 ""));
        return pcmk_rc_unpack_error;
    }
    if ((pcmk__xe_get_int(history->xml, PCMK__XA_RC_CODE,
                          &(history->exit_status)) != pcmk_rc_ok)
        || (history->exit_status < 0) || (history->exit_status > CRM_EX_MAX)) {
        pcmk__config_err("Ignoring resource history entry %s for %s on %s "
                         "with invalid " PCMK__XA_RC_CODE " '%s'",
                         history->id, history->rsc->id,
                         pcmk__node_name(history->node),
                         pcmk__s(pcmk__xe_get(history->xml, PCMK__XA_RC_CODE),
                                 ""));
        return pcmk_rc_unpack_error;
    }
    history->exit_reason = pcmk__xe_get(history->xml, PCMK_XA_EXIT_REASON);
    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Process an action history entry whose result expired
 *
 * \param[in,out] history           Parsed action history entry
 * \param[in]     orig_exit_status  Action exit status before remapping
 *
 * \return Standard Pacemaker return code (in particular, pcmk_rc_ok means the
 *         entry needs no further processing)
 */
static int
process_expired_result(struct action_history *history, int orig_exit_status)
{
    if (!pcmk__is_bundled(history->rsc)
        && pcmk_xe_mask_probe_failure(history->xml)
        && (orig_exit_status != history->expected_exit_status)) {

        if (history->rsc->priv->orig_role <= pcmk_role_stopped) {
            history->rsc->priv->orig_role = pcmk_role_unknown;
        }
        pcmk__trace("Ignoring resource history entry %s for probe of %s on %s: "
                    "Masked failure expired",
                    history->id, history->rsc->id,
                    pcmk__node_name(history->node));
        return pcmk_rc_ok;
    }

    if (history->exit_status == history->expected_exit_status) {
        return pcmk_rc_undetermined; // Only failures expire
    }

    if (history->interval_ms == 0) {
        pcmk__notice("Ignoring resource history entry %s for %s of %s on %s: "
                     "Expired failure",
                     history->id, history->task, history->rsc->id,
                     pcmk__node_name(history->node));
        return pcmk_rc_ok;
    }

    if (history->node->details->online && !history->node->details->unclean) {
        /* Reschedule the recurring action. schedule_cancel() won't work at
         * this stage, so as a hacky workaround, forcibly change the restart
         * digest so pcmk__check_action_config() does what we want later.
         *
         * @TODO We should skip this if there is a newer successful monitor.
         *       Also, this causes rescheduling only if the history entry
         *       has a PCMK__XA_OP_DIGEST (which the expire-non-blocked-failure
         *       scheduler regression test doesn't, but that may not be a
         *       realistic scenario in production).
         */
        pcmk__notice("Rescheduling %s-interval %s of %s on %s after failure "
                     "expired",
                     pcmk__readable_interval(history->interval_ms),
                     history->task, history->rsc->id,
                     pcmk__node_name(history->node));
        pcmk__xe_set(history->xml, PCMK__XA_OP_RESTART_DIGEST,
                     "calculated-failure-timeout");
        return pcmk_rc_ok;
    }

    return pcmk_rc_undetermined;
}

/*!
 * \internal
 * \brief Process a masked probe failure
 *
 * \param[in,out] history           Parsed action history entry
 * \param[in]     orig_exit_status  Action exit status before remapping
 * \param[in]     last_failure      Resource's last_failure entry, if known
 * \param[in,out] on_fail           Resource's current failure handling
 */
static void
mask_probe_failure(struct action_history *history, int orig_exit_status,
                   const xmlNode *last_failure,
                   enum pcmk__on_fail *on_fail)
{
    pcmk_resource_t *ban_rsc = history->rsc;

    if (!pcmk__is_set(history->rsc->flags, pcmk__rsc_unique)) {
        ban_rsc = uber_parent(history->rsc);
    }

    pcmk__notice("Treating probe result '%s' for %s on %s as 'not running'",
                 crm_exit_str(orig_exit_status), history->rsc->id,
                 pcmk__node_name(history->node));
    update_resource_state(history, history->expected_exit_status, last_failure,
                          on_fail);
    pcmk__xe_set(history->xml, PCMK_XA_UNAME, history->node->priv->name);

    record_failed_op(history);
    resource_location(ban_rsc, history->node, -PCMK_SCORE_INFINITY,
                      "masked-probe-failure", ban_rsc->priv->scheduler);
}

/*!
 * \internal Check whether a given failure is for a given pending action
 *
 * \param[in] history       Parsed history entry for pending action
 * \param[in] last_failure  Resource's last_failure entry, if known
 *
 * \return true if \p last_failure is failure of pending action in \p history,
 *         otherwise false
 * \note Both \p history and \p last_failure must come from the same
 *       \c PCMK__XE_LRM_RESOURCE block, as node and resource are assumed to be
 *       the same.
 */
static bool
failure_is_newer(const struct action_history *history,
                 const xmlNode *last_failure)
{
    guint failure_interval_ms = 0U;
    long long failure_change = 0LL;
    long long this_change = 0LL;

    if (last_failure == NULL) {
        return false; // Resource has no last_failure entry
    }

    if (!pcmk__str_eq(history->task,
                      pcmk__xe_get(last_failure, PCMK_XA_OPERATION),
                      pcmk__str_none)) {
        return false; // last_failure is for different action
    }

    if ((pcmk__xe_get_guint(last_failure, PCMK_META_INTERVAL,
                            &failure_interval_ms) != pcmk_rc_ok)
        || (history->interval_ms != failure_interval_ms)) {
        return false; // last_failure is for action with different interval
    }

    if ((pcmk__scan_ll(pcmk__xe_get(history->xml, PCMK_XA_LAST_RC_CHANGE),
                       &this_change, 0LL) != pcmk_rc_ok)
        || (pcmk__scan_ll(pcmk__xe_get(last_failure, PCMK_XA_LAST_RC_CHANGE),
                          &failure_change, 0LL) != pcmk_rc_ok)
        || (failure_change < this_change)) {
        return false; // Failure is not known to be newer
    }

    return true;
}

/*!
 * \internal
 * \brief Update a resource's role etc. for a pending action
 *
 * \param[in,out] history       Parsed history entry for pending action
 * \param[in]     last_failure  Resource's last_failure entry, if known
 */
static void
process_pending_action(struct action_history *history,
                       const xmlNode *last_failure)
{
    /* For recurring monitors, a failure is recorded only in RSC_last_failure_0,
     * and there might be a RSC_monitor_INTERVAL entry with the last successful
     * or pending result.
     *
     * If last_failure contains the failure of the pending recurring monitor
     * we're processing here, and is newer, the action is no longer pending.
     * (Pending results have call ID -1, which sorts last, so the last failure
     * if any should be known.)
     */
    if (failure_is_newer(history, last_failure)) {
        return;
    }

    if (strcmp(history->task, PCMK_ACTION_START) == 0) {
        pcmk__set_rsc_flags(history->rsc, pcmk__rsc_start_pending);
        set_active(history->rsc);

    } else if (strcmp(history->task, PCMK_ACTION_PROMOTE) == 0) {
        history->rsc->priv->orig_role = pcmk_role_promoted;

    } else if ((strcmp(history->task, PCMK_ACTION_MIGRATE_TO) == 0)
               && history->node->details->unclean) {
        /* A migrate_to action is pending on a unclean source, so force a stop
         * on the target.
         */
        const char *migrate_target = NULL;
        pcmk_node_t *target = NULL;

        migrate_target = pcmk__xe_get(history->xml, PCMK__META_MIGRATE_TARGET);
        target = pcmk_find_node(history->rsc->priv->scheduler,
                                migrate_target);
        if (target != NULL) {
            stop_action(history->rsc, target, FALSE);
        }
    }

    if (history->rsc->priv->pending_action != NULL) {
        /* There should never be multiple pending actions, but as a failsafe,
         * just remember the first one processed for display purposes.
         */
        return;
    }

    if (pcmk_is_probe(history->task, history->interval_ms)) {
        /* Pending probes are currently never displayed, even if pending
         * operations are requested. If we ever want to change that,
         * enable the below and the corresponding part of
         * native.c:native_pending_action().
         */
#if 0
        history->rsc->private->pending_action = strdup("probe");
        history->rsc->private->pending_node = history->node;
#endif
    } else {
        history->rsc->priv->pending_action = strdup(history->task);
        history->rsc->priv->pending_node = history->node;
    }
}

static void
unpack_rsc_op(pcmk_resource_t *rsc, pcmk_node_t *node, xmlNode *xml_op,
              xmlNode **last_failure, enum pcmk__on_fail *on_fail)
{
    int old_rc = 0;
    bool expired = false;
    pcmk_resource_t *parent = rsc;
    enum rsc_role_e fail_role = pcmk_role_unknown;
    enum pcmk__on_fail failure_strategy = pcmk__on_fail_restart;

    struct action_history history = {
        .rsc = rsc,
        .node = node,
        .xml = xml_op,
        .execution_status = PCMK_EXEC_UNKNOWN,
    };

    CRM_CHECK(rsc && node && xml_op, return);

    history.id = pcmk__xe_id(xml_op);
    if (history.id == NULL) {
        pcmk__config_err("Ignoring resource history entry for %s on %s "
                         "without ID", rsc->id, pcmk__node_name(node));
        return;
    }

    // Task and interval
    history.task = pcmk__xe_get(xml_op, PCMK_XA_OPERATION);
    if (history.task == NULL) {
        pcmk__config_err("Ignoring resource history entry %s for %s on %s "
                         "without " PCMK_XA_OPERATION,
                         history.id, rsc->id, pcmk__node_name(node));
        return;
    }
    pcmk__xe_get_guint(xml_op, PCMK_META_INTERVAL, &(history.interval_ms));
    if (!can_affect_state(&history)) {
        pcmk__rsc_trace(rsc,
                        "Ignoring resource history entry %s for %s on %s "
                        "with irrelevant action '%s'",
                        history.id, rsc->id, pcmk__node_name(node),
                        history.task);
        return;
    }

    if (unpack_action_result(&history) != pcmk_rc_ok) {
        return; // Error already logged
    }

    history.expected_exit_status = pe__target_rc_from_xml(xml_op);
    history.key = pcmk__xe_history_key(xml_op);
    pcmk__xe_get_int(xml_op, PCMK__XA_CALL_ID, &(history.call_id));

    pcmk__rsc_trace(rsc, "Unpacking %s (%s call %d on %s): %s (%s)",
                    history.id, history.task, history.call_id,
                    pcmk__node_name(node),
                    pcmk_exec_status_str(history.execution_status),
                    crm_exit_str(history.exit_status));

    if (node->details->unclean) {
        pcmk__rsc_trace(rsc,
                        "%s is running on %s, which is unclean (further action "
                        "depends on value of stop's on-fail attribute)",
                        rsc->id, pcmk__node_name(node));
    }

    expired = check_operation_expiry(&history);
    old_rc = history.exit_status;

    remap_operation(&history, on_fail, expired);

    if (expired && (process_expired_result(&history, old_rc) == pcmk_rc_ok)) {
        goto done;
    }

    if (!pcmk__is_bundled(rsc) && pcmk_xe_mask_probe_failure(xml_op)) {
        mask_probe_failure(&history, old_rc, *last_failure, on_fail);
        goto done;
    }

    if (!pcmk__is_set(rsc->flags, pcmk__rsc_unique)) {
        parent = uber_parent(rsc);
    }

    switch (history.execution_status) {
        case PCMK_EXEC_PENDING:
            process_pending_action(&history, *last_failure);
            goto done;

        case PCMK_EXEC_DONE:
            update_resource_state(&history, history.exit_status, *last_failure,
                                  on_fail);
            goto done;

        case PCMK_EXEC_NOT_INSTALLED:
            unpack_failure_handling(&history, &failure_strategy, &fail_role);
            if (failure_strategy == pcmk__on_fail_ignore) {
                pcmk__warn("Cannot ignore failed %s of %s on %s: Resource "
                           "agent doesn't exist "
                           QB_XS " status=%d rc=%d id=%s",
                           history.task, rsc->id, pcmk__node_name(node),
                           history.execution_status, history.exit_status,
                           history.id);
                /* Also for printing it as "FAILED" by marking it as
                 * pcmk__rsc_failed later
                 */
                *on_fail = pcmk__on_fail_ban;
            }
            resource_location(parent, node, -PCMK_SCORE_INFINITY,
                              "hard-error", rsc->priv->scheduler);
            unpack_rsc_op_failure(&history, failure_strategy, fail_role,
                                  last_failure, on_fail);
            goto done;

        case PCMK_EXEC_NOT_CONNECTED:
            if (pcmk__is_pacemaker_remote_node(node)
                && pcmk__is_set(node->priv->remote->flags,
                                pcmk__rsc_managed)) {
                /* We should never get into a situation where a managed remote
                 * connection resource is considered OK but a resource action
                 * behind the connection gets a "not connected" status. But as a
                 * fail-safe in case a bug or unusual circumstances do lead to
                 * that, ensure the remote connection is considered failed.
                 */
                pcmk__set_rsc_flags(node->priv->remote,
                                    pcmk__rsc_failed|pcmk__rsc_stop_if_failed);
            }
            break; // Not done, do error handling

        case PCMK_EXEC_ERROR:
        case PCMK_EXEC_ERROR_HARD:
        case PCMK_EXEC_ERROR_FATAL:
        case PCMK_EXEC_TIMEOUT:
        case PCMK_EXEC_NOT_SUPPORTED:
        case PCMK_EXEC_INVALID:
            break; // Not done, do error handling

        default: // No other value should be possible at this point
            break;
    }

    unpack_failure_handling(&history, &failure_strategy, &fail_role);
    if ((failure_strategy == pcmk__on_fail_ignore)
        || ((failure_strategy == pcmk__on_fail_restart_container)
            && (strcmp(history.task, PCMK_ACTION_STOP) == 0))) {

        char *last_change_s = last_change_str(xml_op);

        pcmk__warn("Pretending failed %s (%s%s%s) of %s on %s at %s succeeded "
                   QB_XS " %s",
                   history.task, crm_exit_str(history.exit_status),
                   (pcmk__str_empty(history.exit_reason)? "" : ": "),
                   pcmk__s(history.exit_reason, ""), rsc->id,
                   pcmk__node_name(node), last_change_s, history.id);
        free(last_change_s);

        update_resource_state(&history, history.expected_exit_status,
                              *last_failure, on_fail);
        pcmk__xe_set(xml_op, PCMK_XA_UNAME, node->priv->name);
        pcmk__set_rsc_flags(rsc, pcmk__rsc_ignore_failure);

        record_failed_op(&history);

        if ((failure_strategy == pcmk__on_fail_restart_container)
            && (*on_fail <= pcmk__on_fail_restart)) {
            *on_fail = failure_strategy;
        }

    } else {
        unpack_rsc_op_failure(&history, failure_strategy, fail_role,
                              last_failure, on_fail);

        if (history.execution_status == PCMK_EXEC_ERROR_HARD) {
            uint8_t log_level = LOG_ERR;

            if (history.exit_status == PCMK_OCF_NOT_INSTALLED) {
                log_level = LOG_NOTICE;
            }
            do_crm_log(log_level,
                       "Preventing %s from restarting on %s because "
                       "of hard failure (%s%s%s) " QB_XS " %s",
                       parent->id, pcmk__node_name(node),
                       crm_exit_str(history.exit_status),
                       (pcmk__str_empty(history.exit_reason)? "" : ": "),
                       pcmk__s(history.exit_reason, ""), history.id);
            resource_location(parent, node, -PCMK_SCORE_INFINITY,
                              "hard-error", rsc->priv->scheduler);

        } else if (history.execution_status == PCMK_EXEC_ERROR_FATAL) {
            pcmk__sched_err(rsc->priv->scheduler,
                            "Preventing %s from restarting anywhere because "
                            "of fatal failure (%s%s%s) " QB_XS " %s",
                            parent->id, crm_exit_str(history.exit_status),
                            (pcmk__str_empty(history.exit_reason)? "" : ": "),
                            pcmk__s(history.exit_reason, ""), history.id);
            resource_location(parent, NULL, -PCMK_SCORE_INFINITY,
                              "fatal-error", rsc->priv->scheduler);
        }
    }

done:
    pcmk__rsc_trace(rsc, "%s role on %s after %s is %s (next %s)",
                    rsc->id, pcmk__node_name(node), history.id,
                    pcmk_role_text(rsc->priv->orig_role),
                    pcmk_role_text(rsc->priv->next_role));
}

/*!
 * \internal
 * \brief Insert a node attribute with value into a \c GHashTable
 *
 * \param[in,out] key        Key to insert (either freed or owned by
 *                           \p user_data upon return)
 * \param[in]     value      Value to insert (owned by \p user_data upon return)
 * \param[in]     user_data  \c GHashTable to insert into
 */
static gboolean
insert_attr(gpointer key, gpointer value, gpointer user_data)
{
    GHashTable *table = user_data;

    g_hash_table_insert(table, key, value);
    return TRUE;
}

static void
add_node_attrs(const xmlNode *xml_obj, pcmk_node_t *node, bool overwrite,
               pcmk_scheduler_t *scheduler)
{
    const char *cluster_name = NULL;
    const char *dc_id = pcmk__xe_get(scheduler->input, PCMK_XA_DC_UUID);
    const pcmk_rule_input_t rule_input = {
        .now = scheduler->priv->now,
    };

    pcmk__insert_dup(node->priv->attrs,
                     CRM_ATTR_UNAME, node->priv->name);

    pcmk__insert_dup(node->priv->attrs, CRM_ATTR_ID, node->priv->id);

    if ((scheduler->dc_node == NULL)
        && pcmk__str_eq(node->priv->id, dc_id, pcmk__str_casei)) {

        scheduler->dc_node = node;
        pcmk__insert_dup(node->priv->attrs,
                         CRM_ATTR_IS_DC, PCMK_VALUE_TRUE);

    } else if (!pcmk__same_node(node, scheduler->dc_node)) {
        pcmk__insert_dup(node->priv->attrs,
                         CRM_ATTR_IS_DC, PCMK_VALUE_FALSE);
    }

    cluster_name = g_hash_table_lookup(scheduler->priv->options,
                                       PCMK_OPT_CLUSTER_NAME);
    if (cluster_name) {
        pcmk__insert_dup(node->priv->attrs, CRM_ATTR_CLUSTER_NAME,
                         cluster_name);
    }

    if (overwrite) {
        /* @TODO Try to reorder some unpacking so that we don't need the
         * overwrite argument or to unpack into a temporary table
         */
        GHashTable *unpacked = pcmk__strkey_table(free, free);

        pe__unpack_dataset_nvpairs(xml_obj, PCMK_XE_INSTANCE_ATTRIBUTES,
                                   &rule_input, unpacked, NULL, scheduler);
        g_hash_table_foreach_steal(unpacked, insert_attr, node->priv->attrs);
        g_hash_table_destroy(unpacked);

    } else {
        pe__unpack_dataset_nvpairs(xml_obj, PCMK_XE_INSTANCE_ATTRIBUTES,
                                   &rule_input, node->priv->attrs, NULL,
                                   scheduler);
    }

    pe__unpack_dataset_nvpairs(xml_obj, PCMK_XE_UTILIZATION, &rule_input,
                               node->priv->utilization, NULL, scheduler);

    if (pcmk__node_attr(node, CRM_ATTR_SITE_NAME, NULL,
                        pcmk__rsc_node_current) == NULL) {
        const char *site_name = pcmk__node_attr(node, "site-name", NULL,
                                                pcmk__rsc_node_current);

        if (site_name) {
            pcmk__insert_dup(node->priv->attrs,
                             CRM_ATTR_SITE_NAME, site_name);

        } else if (cluster_name) {
            /* Default to cluster-name if unset */
            pcmk__insert_dup(node->priv->attrs,
                             CRM_ATTR_SITE_NAME, cluster_name);
        }
    }
}

static GList *
extract_operations(const char *node, const char *rsc, xmlNode * rsc_entry, gboolean active_filter)
{
    int counter = -1;
    int stop_index = -1;
    int start_index = -1;

    xmlNode *rsc_op = NULL;

    GList *gIter = NULL;
    GList *op_list = NULL;
    GList *sorted_op_list = NULL;

    /* extract operations */
    op_list = NULL;
    sorted_op_list = NULL;

    for (rsc_op = pcmk__xe_first_child(rsc_entry, PCMK__XE_LRM_RSC_OP, NULL,
                                       NULL);
         rsc_op != NULL; rsc_op = pcmk__xe_next(rsc_op, PCMK__XE_LRM_RSC_OP)) {

        pcmk__xe_set(rsc_op, PCMK_XA_RESOURCE, rsc);
        pcmk__xe_set(rsc_op, PCMK_XA_UNAME, node);
        op_list = g_list_prepend(op_list, rsc_op);
    }

    if (op_list == NULL) {
        /* if there are no operations, there is nothing to do */
        return NULL;
    }

    sorted_op_list = g_list_sort(op_list, sort_op_by_callid);

    /* create active recurring operations as optional */
    if (active_filter == FALSE) {
        return sorted_op_list;
    }

    op_list = NULL;

    calculate_active_ops(sorted_op_list, &start_index, &stop_index);

    for (gIter = sorted_op_list; gIter != NULL; gIter = gIter->next) {
        xmlNode *rsc_op = (xmlNode *) gIter->data;

        counter++;

        if (start_index < stop_index) {
            pcmk__trace("Skipping %s: not active", pcmk__xe_id(rsc_entry));
            break;

        } else if (counter < start_index) {
            pcmk__trace("Skipping %s: old", pcmk__xe_id(rsc_op));
            continue;
        }
        op_list = g_list_append(op_list, rsc_op);
    }

    g_list_free(sorted_op_list);
    return op_list;
}

GList *
find_operations(const char *rsc, const char *node, gboolean active_filter,
                pcmk_scheduler_t *scheduler)
{
    GList *output = NULL;
    GList *intermediate = NULL;

    xmlNode *tmp = NULL;
    xmlNode *status = pcmk__xe_first_child(scheduler->input, PCMK_XE_STATUS,
                                           NULL, NULL);

    pcmk_node_t *this_node = NULL;

    xmlNode *node_state = NULL;

    CRM_CHECK(status != NULL, return NULL);

    for (node_state = pcmk__xe_first_child(status, PCMK__XE_NODE_STATE, NULL,
                                           NULL);
         node_state != NULL;
         node_state = pcmk__xe_next(node_state, PCMK__XE_NODE_STATE)) {

        const char *uname = pcmk__xe_get(node_state, PCMK_XA_UNAME);

        if (node != NULL && !pcmk__str_eq(uname, node, pcmk__str_casei)) {
            continue;
        }

        this_node = pcmk_find_node(scheduler, uname);
        if(this_node == NULL) {
            CRM_LOG_ASSERT(this_node != NULL);
            continue;

        } else if (pcmk__is_pacemaker_remote_node(this_node)) {
            determine_remote_online_status(scheduler, this_node);

        } else {
            determine_online_status(node_state, this_node, scheduler);
        }

        if (this_node->details->online
            || pcmk__is_set(scheduler->flags, pcmk__sched_fencing_enabled)) {

            /* Offline nodes run no resources if fencing is disabled. If fencing
             * is enabled, we need to ensure that resource start events happen
             * after the fencing event.
             */
            xmlNode *lrm_rsc = NULL;

            tmp = pcmk__xe_first_child(node_state, PCMK__XE_LRM, NULL,
                                       NULL);
            tmp = pcmk__xe_first_child(tmp, PCMK__XE_LRM_RESOURCES, NULL,
                                       NULL);

            for (lrm_rsc = pcmk__xe_first_child(tmp, PCMK__XE_LRM_RESOURCE,
                                                NULL, NULL);
                 lrm_rsc != NULL;
                 lrm_rsc = pcmk__xe_next(lrm_rsc, PCMK__XE_LRM_RESOURCE)) {

                const char *rsc_id = pcmk__xe_get(lrm_rsc, PCMK_XA_ID);

                if ((rsc != NULL)
                    && !pcmk__str_eq(rsc_id, rsc, pcmk__str_none)) {
                    continue;
                }

                intermediate = extract_operations(uname, rsc_id, lrm_rsc, active_filter);
                output = g_list_concat(output, intermediate);
            }
        }
    }

    return output;
}
