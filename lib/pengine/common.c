/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/util.h>

#include <glib.h>

#include <crm/common/scheduler_internal.h>
#include <crm/pengine/internal.h>

static bool
check_placement_strategy(const char *value)
{
    return pcmk__strcase_any_of(value, "default", "utilization", "minimal",
                           "balanced", NULL);
}

static pcmk__cluster_option_t pe_opts[] = {
    /* name, old name, type, allowed values,
     * default value, validator,
     * short description,
     * long description
     */
    {
        PCMK_OPT_NO_QUORUM_POLICY, NULL, "select",
            "stop, freeze, ignore, demote, suicide",
        "stop", pcmk__valid_quorum,
        N_("What to do when the cluster does not have quorum"),
        NULL
    },
    {
        PCMK_OPT_SYMMETRIC_CLUSTER, NULL, "boolean", NULL,
        "true", pcmk__valid_boolean,
        N_("Whether resources can run on any node by default"),
        NULL
    },
    {
        PCMK_OPT_MAINTENANCE_MODE, NULL, "boolean", NULL,
        "false", pcmk__valid_boolean,
        N_("Whether the cluster should refrain from monitoring, starting, "
            "and stopping resources"),
        NULL
    },
    {
        PCMK_OPT_START_FAILURE_IS_FATAL, NULL, "boolean", NULL,
        "true", pcmk__valid_boolean,
        N_("Whether a start failure should prevent a resource from being "
            "recovered on the same node"),
        N_("When true, the cluster will immediately ban a resource from a node "
            "if it fails to start there. When false, the cluster will instead "
            "check the resource's fail count against its migration-threshold.")
    },
    {
        PCMK_OPT_ENABLE_STARTUP_PROBES, NULL, "boolean", NULL,
        "true", pcmk__valid_boolean,
        N_("Whether the cluster should check for active resources during start-up"),
        NULL
    },
    {
        PCMK_OPT_SHUTDOWN_LOCK, NULL, "boolean", NULL,
        "false", pcmk__valid_boolean,
        N_("Whether to lock resources to a cleanly shut down node"),
        N_("When true, resources active on a node when it is cleanly shut down "
            "are kept \"locked\" to that node (not allowed to run elsewhere) "
            "until they start again on that node after it rejoins (or for at "
            "most shutdown-lock-limit, if set). Stonith resources and "
            "Pacemaker Remote connections are never locked. Clone and bundle "
            "instances and the promoted role of promotable clones are "
            "currently never locked, though support could be added in a future "
            "release.")
    },
    {
        PCMK_OPT_SHUTDOWN_LOCK_LIMIT, NULL, "time", NULL,
        "0", pcmk__valid_interval_spec,
        N_("Do not lock resources to a cleanly shut down node longer than "
           "this"),
        N_("If shutdown-lock is true and this is set to a nonzero time "
            "duration, shutdown locks will expire after this much time has "
            "passed since the shutdown was initiated, even if the node has not "
            "rejoined.")
    },

    // Fencing-related options
    {
        PCMK_OPT_STONITH_ENABLED, NULL, "boolean", NULL,
        "true", pcmk__valid_boolean,
        N_("*** Advanced Use Only *** "
            "Whether nodes may be fenced as part of recovery"),
        N_("If false, unresponsive nodes are immediately assumed to be harmless, "
            "and resources that were active on them may be recovered "
            "elsewhere. This can result in a \"split-brain\" situation, "
            "potentially leading to data loss and/or service unavailability.")
    },
    {
        PCMK_OPT_STONITH_ACTION, NULL, "select", "reboot, off, poweroff",
        PCMK_ACTION_REBOOT, pcmk__is_fencing_action,
        N_("Action to send to fence device when a node needs to be fenced "
            "(\"poweroff\" is a deprecated alias for \"off\")"),
        NULL
    },
    {
        PCMK_OPT_STONITH_TIMEOUT, NULL, "time", NULL,
        "60s", pcmk__valid_interval_spec,
        N_("*** Advanced Use Only *** Unused by Pacemaker"),
        N_("This value is not used by Pacemaker, but is kept for backward "
            "compatibility, and certain legacy fence agents might use it.")
    },
    {
        PCMK_OPT_HAVE_WATCHDOG, NULL, "boolean", NULL,
        "false", pcmk__valid_boolean,
        N_("Whether watchdog integration is enabled"),
        N_("This is set automatically by the cluster according to whether SBD "
            "is detected to be in use. User-configured values are ignored. "
            "The value `true` is meaningful if diskless SBD is used and "
            "`stonith-watchdog-timeout` is nonzero. In that case, if fencing "
            "is required, watchdog-based self-fencing will be performed via "
            "SBD without requiring a fencing resource explicitly configured.")
    },
    {
        PCMK_OPT_CONCURRENT_FENCING, NULL, "boolean", NULL,
        PCMK__CONCURRENT_FENCING_DEFAULT, pcmk__valid_boolean,
        N_("Allow performing fencing operations in parallel"),
        NULL
    },
    {
        PCMK_OPT_STARTUP_FENCING, NULL, "boolean", NULL,
        "true", pcmk__valid_boolean,
        N_("*** Advanced Use Only *** Whether to fence unseen nodes at start-up"),
        N_("Setting this to false may lead to a \"split-brain\" situation,"
            "potentially leading to data loss and/or service unavailability.")
    },
    {
        PCMK_OPT_PRIORITY_FENCING_DELAY, NULL, "time", NULL,
        "0", pcmk__valid_interval_spec,
        N_("Apply fencing delay targeting the lost nodes with the highest total resource priority"),
        N_("Apply specified delay for the fencings that are targeting the lost "
            "nodes with the highest total resource priority in case we don't "
            "have the majority of the nodes in our cluster partition, so that "
            "the more significant nodes potentially win any fencing match, "
            "which is especially meaningful under split-brain of 2-node "
            "cluster. A promoted resource instance takes the base priority + 1 "
            "on calculation if the base priority is not 0. Any static/random "
            "delays that are introduced by `pcmk_delay_base/max` configured "
            "for the corresponding fencing resources will be added to this "
            "delay. This delay should be significantly greater than, safely "
            "twice, the maximum `pcmk_delay_base/max`. By default, priority "
            "fencing delay is disabled.")
    },
    {
        PCMK_OPT_NODE_PENDING_TIMEOUT, NULL, "time", NULL,
        "0", pcmk__valid_interval_spec,
        N_("How long to wait for a node that has joined the cluster to join "
           "the controller process group"),
        N_("Fence nodes that do not join the controller process group within "
           "this much time after joining the cluster, to allow the cluster "
           "to continue managing resources. A value of 0 means never fence "
           "pending nodes. Setting the value to 2h means fence nodes after "
           "2 hours.")
    },
    {
        PCMK_OPT_CLUSTER_DELAY, NULL, "time", NULL,
        "60s", pcmk__valid_interval_spec,
        N_("Maximum time for node-to-node communication"),
        N_("The node elected Designated Controller (DC) will consider an action "
            "failed if it does not get a response from the node executing the "
            "action within this time (after considering the action's own "
            "timeout). The \"correct\" value will depend on the speed and "
            "load of your network and cluster nodes.")
    },
    {
        PCMK_OPT_BATCH_LIMIT, NULL, "integer", NULL,
        "0", pcmk__valid_number,
        N_("Maximum number of jobs that the cluster may execute in parallel "
            "across all nodes"),
        N_("The \"correct\" value will depend on the speed and load of your "
            "network and cluster nodes. If set to 0, the cluster will "
            "impose a dynamically calculated limit when any node has a "
            "high load.")
    },
    {
        PCMK_OPT_MIGRATION_LIMIT, NULL, "integer", NULL,
        "-1", pcmk__valid_number,
        N_("The number of live migration actions that the cluster is allowed "
            "to execute in parallel on a node (-1 means no limit)")
    },

    /* Orphans and stopping */
    {
        PCMK_OPT_STOP_ALL_RESOURCES, NULL, "boolean", NULL,
        "false", pcmk__valid_boolean,
        N_("Whether the cluster should stop all active resources"),
        NULL
    },
    {
        PCMK_OPT_STOP_ORPHAN_RESOURCES, NULL, "boolean", NULL,
        "true", pcmk__valid_boolean,
        N_("Whether to stop resources that were removed from the configuration"),
        NULL
    },
    {
        PCMK_OPT_STOP_ORPHAN_ACTIONS, NULL, "boolean", NULL,
        "true", pcmk__valid_boolean,
        N_("Whether to cancel recurring actions removed from the configuration"),
        NULL
    },
    {
        PCMK__OPT_REMOVE_AFTER_STOP, NULL, "boolean", NULL,
        "false", pcmk__valid_boolean,
        N_("*** Deprecated *** Whether to remove stopped resources from "
            "the executor"),
        N_("Values other than default are poorly tested and potentially dangerous."
            " This option will be removed in a future release.")
    },

    /* Storing inputs */
    {
        PCMK_OPT_PE_ERROR_SERIES_MAX, NULL, "integer", NULL,
        "-1", pcmk__valid_number,
        N_("The number of scheduler inputs resulting in errors to save"),
        N_("Zero to disable, -1 to store unlimited.")
    },
    {
        PCMK_OPT_PE_WARN_SERIES_MAX, NULL, "integer", NULL,
        "5000", pcmk__valid_number,
        N_("The number of scheduler inputs resulting in warnings to save"),
        N_("Zero to disable, -1 to store unlimited.")
    },
    {
        PCMK_OPT_PE_INPUT_SERIES_MAX, NULL, "integer", NULL,
        "4000", pcmk__valid_number,
        N_("The number of scheduler inputs without errors or warnings to save"),
        N_("Zero to disable, -1 to store unlimited.")
    },

    /* Node health */
    {
        PCMK__OPT_NODE_HEALTH_STRATEGY, NULL, "select",
        PCMK__VALUE_NONE ", " PCMK__VALUE_MIGRATE_ON_RED ", "
            PCMK__VALUE_ONLY_GREEN ", " PCMK__VALUE_PROGRESSIVE ", "
            PCMK__VALUE_CUSTOM,
        PCMK__VALUE_NONE, pcmk__validate_health_strategy,
        N_("How cluster should react to node health attributes"),
        N_("Requires external entities to create node attributes (named with "
            "the prefix \"#health\") with values \"red\", "
            "\"yellow\", or \"green\".")
    },
    {
        PCMK_OPT_NODE_HEALTH_BASE, NULL, "integer", NULL,
        "0", pcmk__valid_number,
        N_("Base health score assigned to a node"),
        N_("Only used when \"node-health-strategy\" is set to \"progressive\".")
    },
    {
        PCMK__OPT_NODE_HEALTH_GREEN, NULL, "integer", NULL,
        "0", pcmk__valid_number,
        N_("The score to use for a node health attribute whose value is \"green\""),
        N_("Only used when \"node-health-strategy\" is set to \"custom\" or \"progressive\".")
    },
    {
        PCMK__OPT_NODE_HEALTH_YELLOW, NULL, "integer", NULL,
        "0", pcmk__valid_number,
        N_("The score to use for a node health attribute whose value is \"yellow\""),
        N_("Only used when \"node-health-strategy\" is set to \"custom\" or \"progressive\".")
    },
    {
        PCMK__OPT_NODE_HEALTH_RED, NULL, "integer", NULL,
        "-INFINITY", pcmk__valid_number,
        N_("The score to use for a node health attribute whose value is \"red\""),
        N_("Only used when \"node-health-strategy\" is set to \"custom\" or \"progressive\".")
    },

    /*Placement Strategy*/
    {
        PCMK_OPT_PLACEMENT_STRATEGY, NULL, "select",
            "default, utilization, minimal, balanced",
        "default", check_placement_strategy,
        N_("How the cluster should allocate resources to nodes"),
        NULL
    },
};

void
pe_metadata(pcmk__output_t *out)
{
    const char *desc_short = "Pacemaker scheduler options";
    const char *desc_long = "Cluster options used by Pacemaker's scheduler";

    gchar *s = pcmk__format_option_metadata("pacemaker-schedulerd", desc_short,
                                            desc_long, pe_opts,
                                            PCMK__NELEM(pe_opts));
    out->output_xml(out, "metadata", s);
    g_free(s);
}

void
verify_pe_options(GHashTable * options)
{
    pcmk__validate_cluster_options(options, pe_opts, PCMK__NELEM(pe_opts));
}

const char *
pe_pref(GHashTable * options, const char *name)
{
    return pcmk__cluster_option(options, pe_opts, PCMK__NELEM(pe_opts), name);
}

const char *
fail2text(enum action_fail_response fail)
{
    const char *result = "<unknown>";

    switch (fail) {
        case pcmk_on_fail_ignore:
            result = "ignore";
            break;
        case pcmk_on_fail_demote:
            result = "demote";
            break;
        case pcmk_on_fail_block:
            result = "block";
            break;
        case pcmk_on_fail_restart:
            result = "recover";
            break;
        case pcmk_on_fail_ban:
            result = "migrate";
            break;
        case pcmk_on_fail_stop:
            result = "stop";
            break;
        case pcmk_on_fail_fence_node:
            result = "fence";
            break;
        case pcmk_on_fail_standby_node:
            result = "standby";
            break;
        case pcmk_on_fail_restart_container:
            result = "restart-container";
            break;
        case pcmk_on_fail_reset_remote:
            result = "reset-remote";
            break;
    }
    return result;
}

enum action_tasks
text2task(const char *task)
{
    if (pcmk__str_eq(task, PCMK_ACTION_STOP, pcmk__str_casei)) {
        return pcmk_action_stop;

    } else if (pcmk__str_eq(task, PCMK_ACTION_STOPPED, pcmk__str_casei)) {
        return pcmk_action_stopped;

    } else if (pcmk__str_eq(task, PCMK_ACTION_START, pcmk__str_casei)) {
        return pcmk_action_start;

    } else if (pcmk__str_eq(task, PCMK_ACTION_RUNNING, pcmk__str_casei)) {
        return pcmk_action_started;

    } else if (pcmk__str_eq(task, PCMK_ACTION_DO_SHUTDOWN, pcmk__str_casei)) {
        return pcmk_action_shutdown;

    } else if (pcmk__str_eq(task, PCMK_ACTION_STONITH, pcmk__str_casei)) {
        return pcmk_action_fence;

    } else if (pcmk__str_eq(task, PCMK_ACTION_MONITOR, pcmk__str_casei)) {
        return pcmk_action_monitor;

    } else if (pcmk__str_eq(task, PCMK_ACTION_NOTIFY, pcmk__str_casei)) {
        return pcmk_action_notify;

    } else if (pcmk__str_eq(task, PCMK_ACTION_NOTIFIED, pcmk__str_casei)) {
        return pcmk_action_notified;

    } else if (pcmk__str_eq(task, PCMK_ACTION_PROMOTE, pcmk__str_casei)) {
        return pcmk_action_promote;

    } else if (pcmk__str_eq(task, PCMK_ACTION_DEMOTE, pcmk__str_casei)) {
        return pcmk_action_demote;

    } else if (pcmk__str_eq(task, PCMK_ACTION_PROMOTED, pcmk__str_casei)) {
        return pcmk_action_promoted;

    } else if (pcmk__str_eq(task, PCMK_ACTION_DEMOTED, pcmk__str_casei)) {
        return pcmk_action_demoted;
    }
    return pcmk_action_unspecified;
}

const char *
task2text(enum action_tasks task)
{
    const char *result = "<unknown>";

    switch (task) {
        case pcmk_action_unspecified:
            result = "no_action";
            break;
        case pcmk_action_stop:
            result = PCMK_ACTION_STOP;
            break;
        case pcmk_action_stopped:
            result = PCMK_ACTION_STOPPED;
            break;
        case pcmk_action_start:
            result = PCMK_ACTION_START;
            break;
        case pcmk_action_started:
            result = PCMK_ACTION_RUNNING;
            break;
        case pcmk_action_shutdown:
            result = PCMK_ACTION_DO_SHUTDOWN;
            break;
        case pcmk_action_fence:
            result = PCMK_ACTION_STONITH;
            break;
        case pcmk_action_monitor:
            result = PCMK_ACTION_MONITOR;
            break;
        case pcmk_action_notify:
            result = PCMK_ACTION_NOTIFY;
            break;
        case pcmk_action_notified:
            result = PCMK_ACTION_NOTIFIED;
            break;
        case pcmk_action_promote:
            result = PCMK_ACTION_PROMOTE;
            break;
        case pcmk_action_promoted:
            result = PCMK_ACTION_PROMOTED;
            break;
        case pcmk_action_demote:
            result = PCMK_ACTION_DEMOTE;
            break;
        case pcmk_action_demoted:
            result = PCMK_ACTION_DEMOTED;
            break;
    }

    return result;
}

const char *
role2text(enum rsc_role_e role)
{
    switch (role) {
        case pcmk_role_stopped:
            return PCMK__ROLE_STOPPED;

        case pcmk_role_started:
            return PCMK__ROLE_STARTED;

        case pcmk_role_unpromoted:
#ifdef PCMK__COMPAT_2_0
            return PCMK__ROLE_UNPROMOTED_LEGACY;
#else
            return PCMK__ROLE_UNPROMOTED;
#endif

        case pcmk_role_promoted:
#ifdef PCMK__COMPAT_2_0
            return PCMK__ROLE_PROMOTED_LEGACY;
#else
            return PCMK__ROLE_PROMOTED;
#endif

        default: // pcmk_role_unknown
            return PCMK__ROLE_UNKNOWN;
    }
}

enum rsc_role_e
text2role(const char *role)
{
    if (pcmk__str_eq(role, PCMK__ROLE_UNKNOWN,
                     pcmk__str_casei|pcmk__str_null_matches)) {
        return pcmk_role_unknown;
    } else if (pcmk__str_eq(role, PCMK__ROLE_STOPPED, pcmk__str_casei)) {
        return pcmk_role_stopped;
    } else if (pcmk__str_eq(role, PCMK__ROLE_STARTED, pcmk__str_casei)) {
        return pcmk_role_started;
    } else if (pcmk__strcase_any_of(role, PCMK__ROLE_UNPROMOTED,
                                    PCMK__ROLE_UNPROMOTED_LEGACY, NULL)) {
        return pcmk_role_unpromoted;
    } else if (pcmk__strcase_any_of(role, PCMK__ROLE_PROMOTED,
                                    PCMK__ROLE_PROMOTED_LEGACY, NULL)) {
        return pcmk_role_promoted;
    }
    return pcmk_role_unknown; // Invalid role given
}

void
add_hash_param(GHashTable * hash, const char *name, const char *value)
{
    CRM_CHECK(hash != NULL, return);

    crm_trace("Adding name='%s' value='%s' to hash table",
              pcmk__s(name, "<null>"), pcmk__s(value, "<null>"));
    if (name == NULL || value == NULL) {
        return;

    } else if (pcmk__str_eq(value, "#default", pcmk__str_casei)) {
        return;

    } else if (g_hash_table_lookup(hash, name) == NULL) {
        g_hash_table_insert(hash, strdup(name), strdup(value));
    }
}

/*!
 * \internal
 * \brief Look up an attribute value on the appropriate node
 *
 * If \p node is a guest node and either the \c XML_RSC_ATTR_TARGET meta
 * attribute is set to "host" for \p rsc or \p force_host is \c true, query the
 * attribute on the node's host. Otherwise, query the attribute on \p node
 * itself.
 *
 * \param[in] node        Node to query attribute value on by default
 * \param[in] name        Name of attribute to query
 * \param[in] rsc         Resource on whose behalf we're querying
 * \param[in] node_type   Type of resource location lookup
 * \param[in] force_host  Force a lookup on the guest node's host, regardless of
 *                        the \c XML_RSC_ATTR_TARGET value
 *
 * \return Value of the attribute on \p node or on the host of \p node
 *
 * \note If \p force_host is \c true, \p node \e must be a guest node.
 */
const char *
pe__node_attribute_calculated(const pcmk_node_t *node, const char *name,
                              const pcmk_resource_t *rsc,
                              enum pcmk__rsc_node node_type,
                              bool force_host)
{
    // @TODO: Use pe__is_guest_node() after merging libpe_{rules,status}
    bool is_guest = (node != NULL)
                    && (node->details->type == pcmk_node_variant_remote)
                    && (node->details->remote_rsc != NULL)
                    && (node->details->remote_rsc->container != NULL);
    const char *source = NULL;
    const char *node_type_s = NULL;
    const char *reason = NULL;

    const pcmk_resource_t *container = NULL;
    const pcmk_node_t *host = NULL;

    CRM_ASSERT((node != NULL) && (name != NULL) && (rsc != NULL)
               && (!force_host || is_guest));

    /* Ignore XML_RSC_ATTR_TARGET if node is not a guest node. This represents a
     * user configuration error.
     */
    source = g_hash_table_lookup(rsc->meta, XML_RSC_ATTR_TARGET);
    if (!force_host
        && (!is_guest || !pcmk__str_eq(source, "host", pcmk__str_casei))) {

        return g_hash_table_lookup(node->details->attrs, name);
    }

    container = node->details->remote_rsc->container;

    switch (node_type) {
        case pcmk__rsc_node_assigned:
            node_type_s = "assigned";
            host = container->allocated_to;
            if (host == NULL) {
                reason = "not assigned";
            }
            break;

        case pcmk__rsc_node_current:
            node_type_s = "current";

            if (container->running_on != NULL) {
                host = container->running_on->data;
            }
            if (host == NULL) {
                reason = "inactive";
            }
            break;

        default:
            // Add support for other enum pcmk__rsc_node values if needed
            CRM_ASSERT(false);
            break;
    }

    if (host != NULL) {
        const char *value = g_hash_table_lookup(host->details->attrs, name);

        pcmk__rsc_trace(rsc,
                        "%s: Value lookup for %s on %s container host %s %s%s",
                        rsc->id, name, node_type_s, pe__node_name(host),
                        ((value != NULL)? "succeeded: " : "failed"),
                        pcmk__s(value, ""));
        return value;
    }
    pcmk__rsc_trace(rsc,
                    "%s: Not looking for %s on %s container host: %s is %s",
                    rsc->id, name, node_type_s, container->id, reason);
    return NULL;
}

const char *
pe_node_attribute_raw(const pcmk_node_t *node, const char *name)
{
    if(node == NULL) {
        return NULL;
    }
    return g_hash_table_lookup(node->details->attrs, name);
}
