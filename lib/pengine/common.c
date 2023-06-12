/*
 * Copyright 2004-2022 the Pacemaker project contributors
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

#include <crm/pengine/internal.h>

gboolean was_processing_error = FALSE;
gboolean was_processing_warning = FALSE;

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
        "no-quorum-policy", NULL, "select", "stop, freeze, ignore, demote, suicide",
        "stop", pcmk__valid_quorum,
        N_("What to do when the cluster does not have quorum"),
        NULL
    },
    {
        "symmetric-cluster", NULL, "boolean", NULL,
        "true", pcmk__valid_boolean,
        N_("Whether resources can run on any node by default"),
        NULL
    },
    {
        "maintenance-mode", NULL, "boolean", NULL,
        "false", pcmk__valid_boolean,
        N_("Whether the cluster should refrain from monitoring, starting, "
            "and stopping resources"),
        NULL
    },
    {
        "start-failure-is-fatal", NULL, "boolean", NULL,
        "true", pcmk__valid_boolean,
        N_("Whether a start failure should prevent a resource from being "
            "recovered on the same node"),
        N_("When true, the cluster will immediately ban a resource from a node "
            "if it fails to start there. When false, the cluster will instead "
            "check the resource's fail count against its migration-threshold.")
    },
    {
        "enable-startup-probes", NULL, "boolean", NULL,
        "true", pcmk__valid_boolean,
        N_("Whether the cluster should check for active resources during start-up"),
        NULL
    },
    {
        XML_CONFIG_ATTR_SHUTDOWN_LOCK, NULL, "boolean", NULL,
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
        XML_CONFIG_ATTR_SHUTDOWN_LOCK_LIMIT, NULL, "time", NULL,
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
        "stonith-enabled", NULL, "boolean", NULL,
        "true", pcmk__valid_boolean,
        N_("*** Advanced Use Only *** "
            "Whether nodes may be fenced as part of recovery"),
        N_("If false, unresponsive nodes are immediately assumed to be harmless, "
            "and resources that were active on them may be recovered "
            "elsewhere. This can result in a \"split-brain\" situation, "
            "potentially leading to data loss and/or service unavailability.")
    },
    {
        "stonith-action", NULL, "select", "reboot, off, poweroff",
        "reboot", pcmk__is_fencing_action,
        N_("Action to send to fence device when a node needs to be fenced "
            "(\"poweroff\" is a deprecated alias for \"off\")"),
        NULL
    },
    {
        "stonith-timeout", NULL, "time", NULL,
        "60s", pcmk__valid_interval_spec,
        N_("*** Advanced Use Only *** Unused by Pacemaker"),
        N_("This value is not used by Pacemaker, but is kept for backward "
            "compatibility, and certain legacy fence agents might use it.")
    },
    {
        XML_ATTR_HAVE_WATCHDOG, NULL, "boolean", NULL,
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
        "concurrent-fencing", NULL, "boolean", NULL,
        PCMK__CONCURRENT_FENCING_DEFAULT, pcmk__valid_boolean,
        N_("Allow performing fencing operations in parallel"),
        NULL
    },
    {
        "startup-fencing", NULL, "boolean", NULL,
        "true", pcmk__valid_boolean,
        N_("*** Advanced Use Only *** Whether to fence unseen nodes at start-up"),
        N_("Setting this to false may lead to a \"split-brain\" situation,"
            "potentially leading to data loss and/or service unavailability.")
    },
    {
        XML_CONFIG_ATTR_PRIORITY_FENCING_DELAY, NULL, "time", NULL,
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
        XML_CONFIG_ATTR_NODE_PENDING_TIMEOUT, NULL, "time", NULL,
        "10min", pcmk__valid_interval_spec,
        N_("How long to wait for a node that has joined the cluster to join "
           "the process group"),
        N_("A node that has joined the cluster can be pending on joining the "
           "process group. We wait up to this much time for it. If it times "
           "out, fencing targeting the node will be issued if enabled.")
    },
    {
        "cluster-delay", NULL, "time", NULL,
        "60s", pcmk__valid_interval_spec,
        N_("Maximum time for node-to-node communication"),
        N_("The node elected Designated Controller (DC) will consider an action "
            "failed if it does not get a response from the node executing the "
            "action within this time (after considering the action's own "
            "timeout). The \"correct\" value will depend on the speed and "
            "load of your network and cluster nodes.")
    },
    {
        "batch-limit", NULL, "integer", NULL,
        "0", pcmk__valid_number,
        N_("Maximum number of jobs that the cluster may execute in parallel "
            "across all nodes"),
        N_("The \"correct\" value will depend on the speed and load of your "
            "network and cluster nodes. If set to 0, the cluster will "
            "impose a dynamically calculated limit when any node has a "
            "high load.")
    },
    {
        "migration-limit", NULL, "integer", NULL,
        "-1", pcmk__valid_number,
        N_("The number of live migration actions that the cluster is allowed "
            "to execute in parallel on a node (-1 means no limit)")
    },

    /* Orphans and stopping */
    {
        "stop-all-resources", NULL, "boolean", NULL,
        "false", pcmk__valid_boolean,
        N_("Whether the cluster should stop all active resources"),
        NULL
    },
    {
        "stop-orphan-resources", NULL, "boolean", NULL,
        "true", pcmk__valid_boolean,
        N_("Whether to stop resources that were removed from the configuration"),
        NULL
    },
    {
        "stop-orphan-actions", NULL, "boolean", NULL,
        "true", pcmk__valid_boolean,
        N_("Whether to cancel recurring actions removed from the configuration"),
        NULL
    },
    {
        "remove-after-stop", NULL, "boolean", NULL,
        "false", pcmk__valid_boolean,
        N_("*** Deprecated *** Whether to remove stopped resources from "
            "the executor"),
        N_("Values other than default are poorly tested and potentially dangerous."
            " This option will be removed in a future release.")
    },

    /* Storing inputs */
    {
        "pe-error-series-max", NULL, "integer", NULL,
        "-1", pcmk__valid_number,
        N_("The number of scheduler inputs resulting in errors to save"),
        N_("Zero to disable, -1 to store unlimited.")
    },
    {
        "pe-warn-series-max",  NULL, "integer", NULL,
        "5000", pcmk__valid_number,
        N_("The number of scheduler inputs resulting in warnings to save"),
        N_("Zero to disable, -1 to store unlimited.")
    },
    {
        "pe-input-series-max", NULL, "integer", NULL,
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
        PCMK__OPT_NODE_HEALTH_BASE, NULL, "integer", NULL,
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
        "placement-strategy", NULL, "select",
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
        case action_fail_ignore:
            result = "ignore";
            break;
        case action_fail_demote:
            result = "demote";
            break;
        case action_fail_block:
            result = "block";
            break;
        case action_fail_recover:
            result = "recover";
            break;
        case action_fail_migrate:
            result = "migrate";
            break;
        case action_fail_stop:
            result = "stop";
            break;
        case action_fail_fence:
            result = "fence";
            break;
        case action_fail_standby:
            result = "standby";
            break;
        case action_fail_restart_container:
            result = "restart-container";
            break;
        case action_fail_reset_remote:
            result = "reset-remote";
            break;
    }
    return result;
}

enum action_tasks
text2task(const char *task)
{
    if (pcmk__str_eq(task, CRMD_ACTION_STOP, pcmk__str_casei)) {
        return stop_rsc;
    } else if (pcmk__str_eq(task, CRMD_ACTION_STOPPED, pcmk__str_casei)) {
        return stopped_rsc;
    } else if (pcmk__str_eq(task, CRMD_ACTION_START, pcmk__str_casei)) {
        return start_rsc;
    } else if (pcmk__str_eq(task, CRMD_ACTION_STARTED, pcmk__str_casei)) {
        return started_rsc;
    } else if (pcmk__str_eq(task, CRM_OP_SHUTDOWN, pcmk__str_casei)) {
        return shutdown_crm;
    } else if (pcmk__str_eq(task, CRM_OP_FENCE, pcmk__str_casei)) {
        return stonith_node;
    } else if (pcmk__str_eq(task, CRMD_ACTION_STATUS, pcmk__str_casei)) {
        return monitor_rsc;
    } else if (pcmk__str_eq(task, CRMD_ACTION_NOTIFY, pcmk__str_casei)) {
        return action_notify;
    } else if (pcmk__str_eq(task, CRMD_ACTION_NOTIFIED, pcmk__str_casei)) {
        return action_notified;
    } else if (pcmk__str_eq(task, CRMD_ACTION_PROMOTE, pcmk__str_casei)) {
        return action_promote;
    } else if (pcmk__str_eq(task, CRMD_ACTION_DEMOTE, pcmk__str_casei)) {
        return action_demote;
    } else if (pcmk__str_eq(task, CRMD_ACTION_PROMOTED, pcmk__str_casei)) {
        return action_promoted;
    } else if (pcmk__str_eq(task, CRMD_ACTION_DEMOTED, pcmk__str_casei)) {
        return action_demoted;
    }
#if SUPPORT_TRACING
    if (pcmk__str_eq(task, CRMD_ACTION_CANCEL, pcmk__str_casei)) {
        return no_action;
    } else if (pcmk__str_eq(task, CRMD_ACTION_DELETE, pcmk__str_casei)) {
        return no_action;
    } else if (pcmk__str_eq(task, CRMD_ACTION_STATUS, pcmk__str_casei)) {
        return no_action;
    } else if (pcmk__str_eq(task, CRMD_ACTION_MIGRATE, pcmk__str_casei)) {
        return no_action;
    } else if (pcmk__str_eq(task, CRMD_ACTION_MIGRATED, pcmk__str_casei)) {
        return no_action;
    }
    crm_trace("Unsupported action: %s", task);
#endif

    return no_action;
}

const char *
task2text(enum action_tasks task)
{
    const char *result = "<unknown>";

    switch (task) {
        case no_action:
            result = "no_action";
            break;
        case stop_rsc:
            result = CRMD_ACTION_STOP;
            break;
        case stopped_rsc:
            result = CRMD_ACTION_STOPPED;
            break;
        case start_rsc:
            result = CRMD_ACTION_START;
            break;
        case started_rsc:
            result = CRMD_ACTION_STARTED;
            break;
        case shutdown_crm:
            result = CRM_OP_SHUTDOWN;
            break;
        case stonith_node:
            result = CRM_OP_FENCE;
            break;
        case monitor_rsc:
            result = CRMD_ACTION_STATUS;
            break;
        case action_notify:
            result = CRMD_ACTION_NOTIFY;
            break;
        case action_notified:
            result = CRMD_ACTION_NOTIFIED;
            break;
        case action_promote:
            result = CRMD_ACTION_PROMOTE;
            break;
        case action_promoted:
            result = CRMD_ACTION_PROMOTED;
            break;
        case action_demote:
            result = CRMD_ACTION_DEMOTE;
            break;
        case action_demoted:
            result = CRMD_ACTION_DEMOTED;
            break;
    }

    return result;
}

const char *
role2text(enum rsc_role_e role)
{
    switch (role) {
        case RSC_ROLE_UNKNOWN:
            return RSC_ROLE_UNKNOWN_S;
        case RSC_ROLE_STOPPED:
            return RSC_ROLE_STOPPED_S;
        case RSC_ROLE_STARTED:
            return RSC_ROLE_STARTED_S;
        case RSC_ROLE_UNPROMOTED:
#ifdef PCMK__COMPAT_2_0
            return RSC_ROLE_UNPROMOTED_LEGACY_S;
#else
            return RSC_ROLE_UNPROMOTED_S;
#endif
        case RSC_ROLE_PROMOTED:
#ifdef PCMK__COMPAT_2_0
            return RSC_ROLE_PROMOTED_LEGACY_S;
#else
            return RSC_ROLE_PROMOTED_S;
#endif
    }
    CRM_CHECK(role >= RSC_ROLE_UNKNOWN, return RSC_ROLE_UNKNOWN_S);
    CRM_CHECK(role < RSC_ROLE_MAX, return RSC_ROLE_UNKNOWN_S);
    // coverity[dead_error_line]
    return RSC_ROLE_UNKNOWN_S;
}

enum rsc_role_e
text2role(const char *role)
{
    CRM_ASSERT(role != NULL);
    if (pcmk__str_eq(role, RSC_ROLE_STOPPED_S, pcmk__str_casei)) {
        return RSC_ROLE_STOPPED;
    } else if (pcmk__str_eq(role, RSC_ROLE_STARTED_S, pcmk__str_casei)) {
        return RSC_ROLE_STARTED;
    } else if (pcmk__strcase_any_of(role, RSC_ROLE_UNPROMOTED_S,
                                    RSC_ROLE_UNPROMOTED_LEGACY_S, NULL)) {
        return RSC_ROLE_UNPROMOTED;
    } else if (pcmk__strcase_any_of(role, RSC_ROLE_PROMOTED_S,
                                    RSC_ROLE_PROMOTED_LEGACY_S, NULL)) {
        return RSC_ROLE_PROMOTED;
    } else if (pcmk__str_eq(role, RSC_ROLE_UNKNOWN_S, pcmk__str_casei)) {
        return RSC_ROLE_UNKNOWN;
    }
    crm_err("Unknown role: %s", role);
    return RSC_ROLE_UNKNOWN;
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

const char *
pe_node_attribute_calculated(const pe_node_t *node, const char *name,
                             const pe_resource_t *rsc)
{
    const char *source;

    if(node == NULL) {
        return NULL;

    } else if(rsc == NULL) {
        return g_hash_table_lookup(node->details->attrs, name);
    }

    source = g_hash_table_lookup(rsc->meta, XML_RSC_ATTR_TARGET);
    if(source == NULL || !pcmk__str_eq("host", source, pcmk__str_casei)) {
        return g_hash_table_lookup(node->details->attrs, name);
    }

    /* Use attributes set for the containers location
     * instead of for the container itself
     *
     * Useful when the container is using the host's local
     * storage
     */

    CRM_ASSERT(node->details->remote_rsc);
    CRM_ASSERT(node->details->remote_rsc->container);

    if(node->details->remote_rsc->container->running_on) {
        pe_node_t *host = node->details->remote_rsc->container->running_on->data;
        pe_rsc_trace(rsc, "%s: Looking for %s on the container host %s",
                     rsc->id, name, pe__node_name(host));
        return g_hash_table_lookup(host->details->attrs, name);
    }

    pe_rsc_trace(rsc, "%s: Not looking for %s on the container host: %s is inactive",
                 rsc->id, name, node->details->remote_rsc->container->id);
    return NULL;
}

const char *
pe_node_attribute_raw(const pe_node_t *node, const char *name)
{
    if(node == NULL) {
        return NULL;
    }
    return g_hash_table_lookup(node->details->attrs, name);
}
