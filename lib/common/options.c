/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif

#include <crm_internal.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>

void
pcmk__cli_help(char cmd)
{
    if (cmd == 'v' || cmd == '$') {
        printf("Pacemaker %s\n", PACEMAKER_VERSION);
        printf("Written by Andrew Beekhof and "
               "the Pacemaker project contributors\n");

    } else if (cmd == '!') {
        printf("Pacemaker %s (Build: %s): %s\n", PACEMAKER_VERSION, BUILD_VERSION, CRM_FEATURES);
    }

    crm_exit(CRM_EX_OK);
    while(1); // above does not return
}


/*
 * Option metadata
 */

static pcmk__cluster_option_t cluster_options[] = {
    /* name, old name, type, allowed values,
     * default value, validator,
     * context,
     * short description,
     * long description
     */
    {
        PCMK_OPT_DC_VERSION, NULL, "string", NULL,
        PCMK__VALUE_NONE, NULL,
        pcmk__opt_context_controld,
        N_("Pacemaker version on cluster node elected Designated Controller "
            "(DC)"),
        N_("Includes a hash which identifies the exact changeset the code was "
            "built from. Used for diagnostic purposes."),
    },
    {
        PCMK_OPT_CLUSTER_INFRASTRUCTURE, NULL, "string", NULL,
        "corosync", NULL,
        pcmk__opt_context_controld,
        N_("The messaging stack on which Pacemaker is currently running"),
        N_("Used for informational and diagnostic purposes."),
    },
    {
        PCMK_OPT_CLUSTER_NAME, NULL, "string", NULL,
        NULL, NULL,
        pcmk__opt_context_controld,
        N_("An arbitrary name for the cluster"),
        N_("This optional value is mostly for users' convenience as desired "
            "in administration, but may also be used in Pacemaker "
            "configuration rules via the #cluster-name node attribute, and "
            "by higher-level tools and resource agents."),
    },
    {
        PCMK_OPT_DC_DEADTIME, NULL, "time", NULL,
        "20s", pcmk__valid_interval_spec,
        pcmk__opt_context_controld,
        N_("How long to wait for a response from other nodes during start-up"),
        N_("The optimal value will depend on the speed and load of your "
            "network and the type of switches used."),
    },
    {
        PCMK_OPT_CLUSTER_RECHECK_INTERVAL, NULL, "time",
        N_("Zero disables polling, while positive values are an interval in "
            "seconds (unless other units are specified, for example \"5min\")"),
        "15min", pcmk__valid_interval_spec,
        pcmk__opt_context_controld,
        N_("Polling interval to recheck cluster state and evaluate rules "
            "with date specifications"),
        N_("Pacemaker is primarily event-driven, and looks ahead to know when "
            "to recheck cluster state for failure timeouts and most time-based "
            "rules. However, it will also recheck the cluster after this "
            "amount of inactivity, to evaluate rules with date specifications "
            "and serve as a fail-safe for certain types of scheduler bugs."),
    },
    {
        PCMK_OPT_FENCE_REACTION, NULL, "select", PCMK_VALUE_STOP ", panic",
        PCMK_VALUE_STOP, NULL,
        pcmk__opt_context_controld,
        N_("How a cluster node should react if notified of its own fencing"),
        N_("A cluster node may receive notification of its own fencing if "
            "fencing is misconfigured, or if fabric fencing is in use that "
            "doesn't cut cluster communication. Use \"stop\" to attempt to "
            "immediately stop Pacemaker and stay stopped, or \"panic\" to "
            "attempt to immediately reboot the local node, falling back to "
            "stop on failure."),
    },
    {
        PCMK_OPT_ELECTION_TIMEOUT, NULL, "time", NULL,
        "2min", pcmk__valid_interval_spec,
        pcmk__opt_context_controld,
        N_("*** Advanced Use Only ***"),
        N_("Declare an election failed if it is not decided within this much "
            "time. If you need to adjust this value, it probably indicates "
            "the presence of a bug."),
    },
    {
        PCMK_OPT_SHUTDOWN_ESCALATION, NULL, "time", NULL,
        "20min", pcmk__valid_interval_spec,
        pcmk__opt_context_controld,
        N_("*** Advanced Use Only ***"),
        N_("Exit immediately if shutdown does not complete within this much "
            "time. If you need to adjust this value, it probably indicates "
            "the presence of a bug."),
    },
    {
        PCMK_OPT_JOIN_INTEGRATION_TIMEOUT, "crmd-integration-timeout", "time",
            NULL,
        "3min", pcmk__valid_interval_spec,
        pcmk__opt_context_controld,
        N_("*** Advanced Use Only ***"),
        N_("If you need to adjust this value, it probably indicates "
            "the presence of a bug."),
    },
    {
        PCMK_OPT_JOIN_FINALIZATION_TIMEOUT, "crmd-finalization-timeout",
            "time", NULL,
        "30min", pcmk__valid_interval_spec,
        pcmk__opt_context_controld,
        N_("*** Advanced Use Only ***"),
        N_("If you need to adjust this value, it probably indicates "
            "the presence of a bug."),
    },
    {
        PCMK_OPT_TRANSITION_DELAY, "crmd-transition-delay", "time", NULL,
        "0s", pcmk__valid_interval_spec,
        pcmk__opt_context_controld,
        N_("*** Advanced Use Only *** "
            "Enabling this option will slow down cluster recovery under all "
            "conditions"),
        N_("Delay cluster recovery for this much time to allow for additional "
            "events to occur. Useful if your configuration is sensitive to "
            "the order in which ping updates arrive."),
    },
    {
        PCMK_OPT_NO_QUORUM_POLICY, NULL, "select",
            PCMK_VALUE_STOP ", " PCMK_VALUE_FREEZE ", " PCMK_VALUE_IGNORE
                ", " PCMK_VALUE_DEMOTE ", " PCMK_VALUE_FENCE_LEGACY,
        PCMK_VALUE_STOP, pcmk__valid_no_quorum_policy,
        pcmk__opt_context_schedulerd,
        N_("What to do when the cluster does not have quorum"),
        NULL,
    },
    {
        PCMK_OPT_SHUTDOWN_LOCK, NULL, "boolean", NULL,
        PCMK_VALUE_FALSE, pcmk__valid_boolean,
        pcmk__opt_context_schedulerd,
        N_("Whether to lock resources to a cleanly shut down node"),
        N_("When true, resources active on a node when it is cleanly shut down "
            "are kept \"locked\" to that node (not allowed to run elsewhere) "
            "until they start again on that node after it rejoins (or for at "
            "most shutdown-lock-limit, if set). Stonith resources and "
            "Pacemaker Remote connections are never locked. Clone and bundle "
            "instances and the promoted role of promotable clones are "
            "currently never locked, though support could be added in a future "
            "release."),
    },
    {
        PCMK_OPT_SHUTDOWN_LOCK_LIMIT, NULL, "time", NULL,
        "0", pcmk__valid_interval_spec,
        pcmk__opt_context_schedulerd,
        N_("Do not lock resources to a cleanly shut down node longer than "
           "this"),
        N_("If shutdown-lock is true and this is set to a nonzero time "
            "duration, shutdown locks will expire after this much time has "
            "passed since the shutdown was initiated, even if the node has not "
            "rejoined."),
    },
    {
        PCMK_OPT_ENABLE_ACL, NULL, "boolean", NULL,
        PCMK_VALUE_FALSE, pcmk__valid_boolean,
        pcmk__opt_context_based,
        N_("Enable Access Control Lists (ACLs) for the CIB"),
        NULL,
    },
    {
        PCMK_OPT_SYMMETRIC_CLUSTER, NULL, "boolean", NULL,
        PCMK_VALUE_TRUE, pcmk__valid_boolean,
        pcmk__opt_context_schedulerd,
        N_("Whether resources can run on any node by default"),
        NULL,
    },
    {
        PCMK_OPT_MAINTENANCE_MODE, NULL, "boolean", NULL,
        PCMK_VALUE_FALSE, pcmk__valid_boolean,
        pcmk__opt_context_schedulerd,
        N_("Whether the cluster should refrain from monitoring, starting, and "
            "stopping resources"),
        NULL,
    },
    {
        PCMK_OPT_START_FAILURE_IS_FATAL, NULL, "boolean", NULL,
        PCMK_VALUE_TRUE, pcmk__valid_boolean,
        pcmk__opt_context_schedulerd,
        N_("Whether a start failure should prevent a resource from being "
            "recovered on the same node"),
        N_("When true, the cluster will immediately ban a resource from a node "
            "if it fails to start there. When false, the cluster will instead "
            "check the resource's fail count against its migration-threshold.")
    },
    {
        PCMK_OPT_ENABLE_STARTUP_PROBES, NULL, "boolean", NULL,
        PCMK_VALUE_TRUE, pcmk__valid_boolean,
        pcmk__opt_context_schedulerd,
        N_("Whether the cluster should check for active resources during "
            "start-up"),
        NULL,
    },

    // Fencing-related options
    {
        PCMK_OPT_STONITH_ENABLED, NULL, "boolean", NULL,
        PCMK_VALUE_TRUE, pcmk__valid_boolean,
        pcmk__opt_context_schedulerd,
        N_("*** Advanced Use Only *** "
            "Whether nodes may be fenced as part of recovery"),
        N_("If false, unresponsive nodes are immediately assumed to be "
            "harmless, and resources that were active on them may be recovered "
            "elsewhere. This can result in a \"split-brain\" situation, "
            "potentially leading to data loss and/or service unavailability."),
    },
    {
        PCMK_OPT_STONITH_ACTION, NULL, "select", "reboot, off, poweroff",
        PCMK_ACTION_REBOOT, pcmk__is_fencing_action,
        pcmk__opt_context_schedulerd,
        N_("Action to send to fence device when a node needs to be fenced "
            "(\"poweroff\" is a deprecated alias for \"off\")"),
        NULL,
    },
    {
        PCMK_OPT_STONITH_TIMEOUT, NULL, "time", NULL,
        "60s", pcmk__valid_interval_spec,
        pcmk__opt_context_schedulerd,
        N_("How long to wait for on, off, and reboot fence actions to complete "
            "by default"),
        NULL,
    },
    {
        PCMK_OPT_HAVE_WATCHDOG, NULL, "boolean", NULL,
        PCMK_VALUE_FALSE, pcmk__valid_boolean,
        pcmk__opt_context_schedulerd,
        N_("Whether watchdog integration is enabled"),
        N_("This is set automatically by the cluster according to whether SBD "
            "is detected to be in use. User-configured values are ignored. "
            "The value `true` is meaningful if diskless SBD is used and "
            "`stonith-watchdog-timeout` is nonzero. In that case, if fencing "
            "is required, watchdog-based self-fencing will be performed via "
            "SBD without requiring a fencing resource explicitly configured."),
    },
    {
        /* @COMPAT Currently, unparsable values default to -1 (auto-calculate),
         * while missing values default to 0 (disable). All values are accepted
         * (unless the controller finds that the value conflicts with the
         * SBD_WATCHDOG_TIMEOUT).
         *
         * At a compatibility break: properly validate as a timeout, let
         * either negative values or a particular string like "auto" mean auto-
         * calculate, and use 0 as the single default for when the option either
         * is unset or fails to validate.
         */
        PCMK_OPT_STONITH_WATCHDOG_TIMEOUT, NULL, "time", NULL,
        "0", NULL,
        pcmk__opt_context_controld,
        N_("How long before nodes can be assumed to be safely down when "
           "watchdog-based self-fencing via SBD is in use"),
        N_("If this is set to a positive value, lost nodes are assumed to "
           "self-fence using watchdog-based SBD within this much time. This "
           "does not require a fencing resource to be explicitly configured, "
           "though a fence_watchdog resource can be configured, to limit use "
           "to specific nodes. If this is set to 0 (the default), the cluster "
           "will never assume watchdog-based self-fencing. If this is set to a "
           "negative value, the cluster will use twice the local value of the "
           "`SBD_WATCHDOG_TIMEOUT` environment variable if that is positive, "
           "or otherwise treat this as 0. WARNING: When used, this timeout "
           "must be larger than `SBD_WATCHDOG_TIMEOUT` on all nodes that use "
           "watchdog-based SBD, and Pacemaker will refuse to start on any of "
           "those nodes where this is not true for the local value or SBD is "
           "not active. When this is set to a negative value, "
           "`SBD_WATCHDOG_TIMEOUT` must be set to the same value on all nodes "
           "that use SBD, otherwise data corruption or loss could occur."),
    },
    {
        PCMK_OPT_STONITH_MAX_ATTEMPTS, NULL, "integer", NULL,
        "10", pcmk__valid_positive_int,
        pcmk__opt_context_controld,
        N_("How many times fencing can fail before it will no longer be "
            "immediately re-attempted on a target"),
        NULL,
    },
    {
        PCMK_OPT_CONCURRENT_FENCING, NULL, "boolean", NULL,
        PCMK__CONCURRENT_FENCING_DEFAULT, pcmk__valid_boolean,
        pcmk__opt_context_schedulerd,
        N_("Allow performing fencing operations in parallel"),
        NULL,
    },
    {
        PCMK_OPT_STARTUP_FENCING, NULL, "boolean", NULL,
        PCMK_VALUE_TRUE, pcmk__valid_boolean,
        pcmk__opt_context_schedulerd,
        N_("*** Advanced Use Only *** "
            "Whether to fence unseen nodes at start-up"),
        N_("Setting this to false may lead to a \"split-brain\" situation, "
            "potentially leading to data loss and/or service unavailability."),
    },
    {
        PCMK_OPT_PRIORITY_FENCING_DELAY, NULL, "time", NULL,
        "0", pcmk__valid_interval_spec,
        pcmk__opt_context_schedulerd,
        N_("Apply fencing delay targeting the lost nodes with the highest "
            "total resource priority"),
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
            "fencing delay is disabled."),
    },
    {
        PCMK_OPT_NODE_PENDING_TIMEOUT, NULL, "time", NULL,
        "0", pcmk__valid_interval_spec,
        pcmk__opt_context_schedulerd,
        N_("How long to wait for a node that has joined the cluster to join "
           "the controller process group"),
        N_("Fence nodes that do not join the controller process group within "
           "this much time after joining the cluster, to allow the cluster "
           "to continue managing resources. A value of 0 means never fence "
           "pending nodes. Setting the value to 2h means fence nodes after "
           "2 hours."),
    },
    {
        PCMK_OPT_CLUSTER_DELAY, NULL, "time", NULL,
        "60s", pcmk__valid_interval_spec,
        pcmk__opt_context_schedulerd,
        N_("Maximum time for node-to-node communication"),
        N_("The node elected Designated Controller (DC) will consider an action "
            "failed if it does not get a response from the node executing the "
            "action within this time (after considering the action's own "
            "timeout). The \"correct\" value will depend on the speed and "
            "load of your network and cluster nodes.")
    },

    // Limits
    {
        PCMK_OPT_LOAD_THRESHOLD, NULL, "percentage", NULL,
        "80%", pcmk__valid_percentage,
        pcmk__opt_context_controld,
        N_("Maximum amount of system load that should be used by cluster "
            "nodes"),
        N_("The cluster will slow down its recovery process when the amount of "
            "system resources used (currently CPU) approaches this limit"),
    },
    {
        PCMK_OPT_NODE_ACTION_LIMIT, NULL, "integer", NULL,
        "0", pcmk__valid_int,
        pcmk__opt_context_controld,
        N_("Maximum number of jobs that can be scheduled per node (defaults to "
            "2x cores)"),
        NULL,
    },
    {
        PCMK_OPT_BATCH_LIMIT, NULL, "integer", NULL,
        "0", pcmk__valid_int,
        pcmk__opt_context_schedulerd,
        N_("Maximum number of jobs that the cluster may execute in parallel "
            "across all nodes"),
        N_("The \"correct\" value will depend on the speed and load of your "
            "network and cluster nodes. If set to 0, the cluster will "
            "impose a dynamically calculated limit when any node has a "
            "high load."),
    },
    {
        PCMK_OPT_MIGRATION_LIMIT, NULL, "integer", NULL,
        "-1", pcmk__valid_int,
        pcmk__opt_context_schedulerd,
        N_("The number of live migration actions that the cluster is allowed "
            "to execute in parallel on a node (-1 means no limit)"),
        NULL,
    },
    {
        PCMK_OPT_CLUSTER_IPC_LIMIT, NULL, "integer", NULL,
        "500", pcmk__valid_positive_int,
        pcmk__opt_context_based,
        N_("Maximum IPC message backlog before disconnecting a cluster daemon"),
        N_("Raise this if log has \"Evicting client\" messages for cluster "
            "daemon PIDs (a good value is the number of resources in the "
            "cluster multiplied by the number of nodes)."),
    },

    // Orphans and stopping
    {
        PCMK_OPT_STOP_ALL_RESOURCES, NULL, "boolean", NULL,
        PCMK_VALUE_FALSE, pcmk__valid_boolean,
        pcmk__opt_context_schedulerd,
        N_("Whether the cluster should stop all active resources"),
        NULL,
    },
    {
        PCMK_OPT_STOP_ORPHAN_RESOURCES, NULL, "boolean", NULL,
        PCMK_VALUE_TRUE, pcmk__valid_boolean,
        pcmk__opt_context_schedulerd,
        N_("Whether to stop resources that were removed from the "
            "configuration"),
        NULL,
    },
    {
        PCMK_OPT_STOP_ORPHAN_ACTIONS, NULL, "boolean", NULL,
        PCMK_VALUE_TRUE, pcmk__valid_boolean,
        pcmk__opt_context_schedulerd,
        N_("Whether to cancel recurring actions removed from the "
            "configuration"),
        NULL,
    },
    {
        PCMK__OPT_REMOVE_AFTER_STOP, NULL, "boolean", NULL,
        PCMK_VALUE_FALSE, pcmk__valid_boolean,
        pcmk__opt_context_schedulerd,
        N_("*** Deprecated *** "
            "Whether to remove stopped resources from the executor"),
        N_("Values other than default are poorly tested and potentially "
            "dangerous. This option will be removed in a future release."),
    },

    // Storing inputs
    {
        PCMK_OPT_PE_ERROR_SERIES_MAX, NULL, "integer", NULL,
        "-1", pcmk__valid_int,
        pcmk__opt_context_schedulerd,
        N_("The number of scheduler inputs resulting in errors to save"),
        N_("Zero to disable, -1 to store unlimited."),
    },
    {
        PCMK_OPT_PE_WARN_SERIES_MAX, NULL, "integer", NULL,
        "5000", pcmk__valid_int,
        pcmk__opt_context_schedulerd,
        N_("The number of scheduler inputs resulting in warnings to save"),
        N_("Zero to disable, -1 to store unlimited."),
    },
    {
        PCMK_OPT_PE_INPUT_SERIES_MAX, NULL, "integer", NULL,
        "4000", pcmk__valid_int,
        pcmk__opt_context_schedulerd,
        N_("The number of scheduler inputs without errors or warnings to save"),
        N_("Zero to disable, -1 to store unlimited."),
    },

    // Node health
    {
        PCMK_OPT_NODE_HEALTH_STRATEGY, NULL, "select",
            PCMK__VALUE_NONE ", " PCMK__VALUE_MIGRATE_ON_RED ", "
                PCMK__VALUE_ONLY_GREEN ", " PCMK__VALUE_PROGRESSIVE ", "
                PCMK__VALUE_CUSTOM,
        PCMK__VALUE_NONE, pcmk__validate_health_strategy,
        pcmk__opt_context_schedulerd,
        N_("How cluster should react to node health attributes"),
        N_("Requires external entities to create node attributes (named with "
            "the prefix \"#health\") with values \"red\", \"yellow\", or "
            "\"green\".")
    },
    {
        PCMK_OPT_NODE_HEALTH_BASE, NULL, "integer", NULL,
        "0", pcmk__valid_int,
        pcmk__opt_context_schedulerd,
        N_("Base health score assigned to a node"),
        N_("Only used when \"node-health-strategy\" is set to "
            "\"progressive\"."),
    },
    {
        PCMK_OPT_NODE_HEALTH_GREEN, NULL, "integer", NULL,
        "0", pcmk__valid_int,
        pcmk__opt_context_schedulerd,
        N_("The score to use for a node health attribute whose value is "
            "\"green\""),
        N_("Only used when \"node-health-strategy\" is set to \"custom\" or "
            "\"progressive\"."),
    },
    {
        PCMK_OPT_NODE_HEALTH_YELLOW, NULL, "integer", NULL,
        "0", pcmk__valid_int,
        pcmk__opt_context_schedulerd,
        N_("The score to use for a node health attribute whose value is "
            "\"yellow\""),
        N_("Only used when \"node-health-strategy\" is set to \"custom\" or "
            "\"progressive\"."),
    },
    {
        PCMK_OPT_NODE_HEALTH_RED, NULL, "integer", NULL,
        "-INFINITY", pcmk__valid_int,
        pcmk__opt_context_schedulerd,
        N_("The score to use for a node health attribute whose value is "
            "\"red\""),
        N_("Only used when \"node-health-strategy\" is set to \"custom\" or "
            "\"progressive\".")
    },

    // Placement strategy
    {
        PCMK_OPT_PLACEMENT_STRATEGY, NULL, "select",
            PCMK_VALUE_DEFAULT ", utilization, minimal, balanced",
        PCMK_VALUE_DEFAULT, pcmk__valid_placement_strategy,
        pcmk__opt_context_schedulerd,
        N_("How the cluster should allocate resources to nodes"),
        NULL,
    },
};


/*
 * Environment variable option handling
 */

/*!
 * \internal
 * \brief Get the value of a Pacemaker environment variable option
 *
 * If an environment variable option is set, with either a PCMK_ or (for
 * backward compatibility) HA_ prefix, log and return the value.
 *
 * \param[in] option  Environment variable name (without prefix)
 *
 * \return Value of environment variable option, or NULL in case of
 *         option name too long or value not found
 */
const char *
pcmk__env_option(const char *option)
{
    const char *const prefixes[] = {"PCMK_", "HA_"};
    char env_name[NAME_MAX];
    const char *value = NULL;

    CRM_CHECK(!pcmk__str_empty(option), return NULL);

    for (int i = 0; i < PCMK__NELEM(prefixes); i++) {
        int rv = snprintf(env_name, NAME_MAX, "%s%s", prefixes[i], option);

        if (rv < 0) {
            crm_err("Failed to write %s%s to buffer: %s", prefixes[i], option,
                    strerror(errno));
            return NULL;
        }

        if (rv >= sizeof(env_name)) {
            crm_trace("\"%s%s\" is too long", prefixes[i], option);
            continue;
        }

        value = getenv(env_name);
        if (value != NULL) {
            crm_trace("Found %s = %s", env_name, value);
            return value;
        }
    }

    crm_trace("Nothing found for %s", option);
    return NULL;
}

/*!
 * \brief Set or unset a Pacemaker environment variable option
 *
 * Set an environment variable option with a \c "PCMK_" prefix and optionally
 * an \c "HA_" prefix for backward compatibility.
 *
 * \param[in] option  Environment variable name (without prefix)
 * \param[in] value   New value (or NULL to unset)
 * \param[in] compat  If false and \p value is not \c NULL, set only
 *                    \c "PCMK_<option>"; otherwise, set (or unset) both
 *                    \c "PCMK_<option>" and \c "HA_<option>"
 *
 * \note \p compat is ignored when \p value is \c NULL. A \c NULL \p value
 *       means we're unsetting \p option. \c pcmk__get_env_option() checks for
 *       both prefixes, so we want to clear them both.
 */
void
pcmk__set_env_option(const char *option, const char *value, bool compat)
{
    // @COMPAT Drop support for "HA_" options eventually
    const char *const prefixes[] = {"PCMK_", "HA_"};
    char env_name[NAME_MAX];

    CRM_CHECK(!pcmk__str_empty(option) && (strchr(option, '=') == NULL),
              return);

    for (int i = 0; i < PCMK__NELEM(prefixes); i++) {
        int rv = snprintf(env_name, NAME_MAX, "%s%s", prefixes[i], option);

        if (rv < 0) {
            crm_err("Failed to write %s%s to buffer: %s", prefixes[i], option,
                    strerror(errno));
            return;
        }

        if (rv >= sizeof(env_name)) {
            crm_trace("\"%s%s\" is too long", prefixes[i], option);
            continue;
        }

        if (value != NULL) {
            crm_trace("Setting %s to %s", env_name, value);
            rv = setenv(env_name, value, 1);
        } else {
            crm_trace("Unsetting %s", env_name);
            rv = unsetenv(env_name);
        }

        if (rv < 0) {
            crm_err("Failed to %sset %s: %s", (value != NULL)? "" : "un",
                    env_name, strerror(errno));
        }

        if (!compat && (value != NULL)) {
            // For set, don't proceed to HA_<option> unless compat is enabled
            break;
        }
    }
}

/*!
 * \internal
 * \brief Check whether Pacemaker environment variable option is enabled
 *
 * Given a Pacemaker environment variable option that can either be boolean
 * or a list of daemon names, return true if the option is enabled for a given
 * daemon.
 *
 * \param[in] daemon   Daemon name (can be NULL)
 * \param[in] option   Pacemaker environment variable name
 *
 * \return true if variable is enabled for daemon, otherwise false
 */
bool
pcmk__env_option_enabled(const char *daemon, const char *option)
{
    const char *value = pcmk__env_option(option);

    return (value != NULL)
        && (crm_is_true(value)
            || ((daemon != NULL) && (strstr(value, daemon) != NULL)));
}


/*
 * Cluster option handling
 */

/*!
 * \internal
 * \brief Check whether a string represents a valid interval specification
 *
 * \param[in] value  String to validate
 *
 * \return \c true if \p value is a valid interval specification, or \c false
 *         otherwise
 */
bool
pcmk__valid_interval_spec(const char *value)
{
    return pcmk_parse_interval_spec(value, NULL) == pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Check whether a string represents a valid boolean value
 *
 * \param[in] value  String to validate
 *
 * \return \c true if \p value is a valid boolean value, or \c false otherwise
 */
bool
pcmk__valid_boolean(const char *value)
{
    return crm_str_to_boolean(value, NULL) == 1;
}

/*!
 * \internal
 * \brief Check whether a string represents a valid integer
 *
 * Valid values include \c INFINITY, \c -INFINITY, and all 64-bit integers.
 *
 * \param[in] value  String to validate
 *
 * \return \c true if \p value is a valid integer, or \c false otherwise
 */
bool
pcmk__valid_int(const char *value)
{
    return (value != NULL)
           && (pcmk_str_is_infinity(value)
               || pcmk_str_is_minus_infinity(value)
               || (pcmk__scan_ll(value, NULL, 0LL) == pcmk_rc_ok));
}

/*!
 * \internal
 * \brief Check whether a string represents a valid positive integer
 *
 * Valid values include \c INFINITY and all 64-bit positive integers.
 *
 * \param[in] value  String to validate
 *
 * \return \c true if \p value is a valid positive integer, or \c false
 *         otherwise
 */
bool
pcmk__valid_positive_int(const char *value)
{
    long long num = 0LL;

    return pcmk_str_is_infinity(value)
           || ((pcmk__scan_ll(value, &num, 0LL) == pcmk_rc_ok)
               && (num > 0));
}

/*!
 * \internal
 * \brief Check whether a string represents a valid
 *        \c PCMK__OPT_NO_QUORUM_POLICY value
 *
 * \param[in] value  String to validate
 *
 * \return \c true if \p value is a valid \c PCMK__OPT_NO_QUORUM_POLICY value,
 *         or \c false otherwise
 */
bool
pcmk__valid_no_quorum_policy(const char *value)
{
    return pcmk__strcase_any_of(value,
                                PCMK_VALUE_STOP, PCMK_VALUE_FREEZE,
                                PCMK_VALUE_IGNORE, PCMK_VALUE_DEMOTE,
                                PCMK_VALUE_FENCE_LEGACY, NULL);
}

/*!
 * \internal
 * \brief Check whether a string represents a valid percentage
 *
 * Valid values include long integers, with an optional trailing string
 * beginning with '%'.
 *
 * \param[in] value  String to validate
 *
 * \return \c true if \p value is a valid percentage value, or \c false
 *         otherwise
 */
bool
pcmk__valid_percentage(const char *value)
{
    char *end = NULL;
    float number = strtof(value, &end);

    return ((end == NULL) || (end[0] == '%')) && (number >= 0);
}

/*!
 * \internal
 * \brief Check whether a string represents a valid script
 *
 * Valid values include \c /dev/null and paths of executable regular files
 *
 * \param[in] value  String to validate
 *
 * \return \c true if \p value is a valid script, or \c false otherwise
 */
bool
pcmk__valid_script(const char *value)
{
    struct stat st;

    if (pcmk__str_eq(value, "/dev/null", pcmk__str_none)) {
        return true;
    }

    if (stat(value, &st) != 0) {
        crm_err("Script %s does not exist", value);
        return false;
    }

    if (S_ISREG(st.st_mode) == 0) {
        crm_err("Script %s is not a regular file", value);
        return false;
    }

    if ((st.st_mode & (S_IXUSR | S_IXGRP)) == 0) {
        crm_err("Script %s is not executable", value);
        return false;
    }

    return true;
}

/*!
 * \internal
 * \brief Check whether a string represents a valid placement strategy
 *
 * \param[in] value  String to validate
 *
 * \return \c true if \p value is a valid placement strategy, or \c false
 *         otherwise
 */
bool
pcmk__valid_placement_strategy(const char *value)
{
    return pcmk__strcase_any_of(value,
                                PCMK_VALUE_DEFAULT, "utilization", "minimal",
                                "balanced", NULL);
}

/*!
 * \internal
 * \brief Check a table of configured options for a particular option
 *
 * \param[in,out] options    Name/value pairs for configured options
 * \param[in]     validate   If not NULL, validator function for option value
 * \param[in]     name       Option name to look for
 * \param[in]     old_name   Alternative option name to look for
 * \param[in]     def_value  Default to use if option not configured
 *
 * \return Option value (from supplied options table or default value)
 */
static const char *
cluster_option_value(GHashTable *options, bool (*validate)(const char *),
                     const char *name, const char *old_name,
                     const char *def_value)
{
    const char *value = NULL;
    char *new_value = NULL;

    CRM_ASSERT(name != NULL);

    if (options) {
        value = g_hash_table_lookup(options, name);

        if ((value == NULL) && old_name) {
            value = g_hash_table_lookup(options, old_name);
            if (value != NULL) {
                pcmk__config_warn("Support for legacy name '%s' for cluster "
                                  "option '%s' is deprecated and will be "
                                  "removed in a future release",
                                  old_name, name);

                // Inserting copy with current name ensures we only warn once
                new_value = strdup(value);
                g_hash_table_insert(options, strdup(name), new_value);
                value = new_value;
            }
        }

        if (value && validate && (validate(value) == FALSE)) {
            pcmk__config_err("Using default value for cluster option '%s' "
                             "because '%s' is invalid", name, value);
            value = NULL;
        }

        if (value) {
            return value;
        }
    }

    // No value found, use default
    value = def_value;

    if (value == NULL) {
        crm_trace("No value or default provided for cluster option '%s'",
                  name);
        return NULL;
    }

    if (validate) {
        CRM_CHECK(validate(value) != FALSE,
                  crm_err("Bug: default value for cluster option '%s' is invalid", name);
                  return NULL);
    }

    crm_trace("Using default value '%s' for cluster option '%s'",
              value, name);
    if (options) {
        new_value = strdup(value);
        g_hash_table_insert(options, strdup(name), new_value);
        value = new_value;
    }
    return value;
}

/*!
 * \internal
 * \brief Get the value of a cluster option
 *
 * \param[in,out] options  Name/value pairs for configured options
 * \param[in]     name     (Primary) option name to look for
 *
 * \return Option value
 */
const char *
pcmk__cluster_option(GHashTable *options, const char *name)
{
    for (int lpc = 0; lpc < PCMK__NELEM(cluster_options); lpc++) {
        if (pcmk__str_eq(name, cluster_options[lpc].name, pcmk__str_casei)) {
            return cluster_option_value(options,
                                        cluster_options[lpc].is_valid,
                                        cluster_options[lpc].name,
                                        cluster_options[lpc].alt_name,
                                        cluster_options[lpc].default_value);
        }
    }
    CRM_CHECK(FALSE, crm_err("Bug: looking for unknown option '%s'", name));
    return NULL;
}

/*!
 * \internal
 * \brief Add a description element to a meta-data string
 *
 * \param[in,out] s       Meta-data string to add to
 * \param[in]     tag     Name of element to add (\c PCMK_XE_LONGDESC or
 *                        \c PCMK_XE_SHORTDESC)
 * \param[in]     desc    Textual description to add
 * \param[in]     values  If not \p NULL, the allowed values for the parameter
 * \param[in]     spaces  If not \p NULL, spaces to insert at the beginning of
 *                        each line
 */
static void
add_desc(GString *s, const char *tag, const char *desc, const char *values,
         const char *spaces)
{
    char *escaped_en = crm_xml_escape(desc);

    if (spaces != NULL) {
        g_string_append(s, spaces);
    }
    pcmk__g_strcat(s,
                   "<", tag, " " PCMK_XA_LANG "=\"" PCMK__VALUE_EN "\">",
                   escaped_en, NULL);

    if (values != NULL) {
        // Append a period if desc doesn't end in "." or ".)"
        if (!pcmk__str_empty(escaped_en)
            && (s->str[s->len - 1] != '.')
            && ((s->str[s->len - 2] != '.') || (s->str[s->len - 1] != ')'))) {

            g_string_append_c(s, '.');
        }
        pcmk__g_strcat(s, " Allowed values: ", values, NULL);
        g_string_append_c(s, '.');
    }
    pcmk__g_strcat(s, "</", tag, ">\n", NULL);

#ifdef ENABLE_NLS
    {
        static const char *locale = NULL;

        char *localized = crm_xml_escape(_(desc));

        if (strcmp(escaped_en, localized) != 0) {
            if (locale == NULL) {
                locale = strtok(setlocale(LC_ALL, NULL), "_");
            }

            if (spaces != NULL) {
                g_string_append(s, spaces);
            }
            pcmk__g_strcat(s,
                           "<", tag, " " PCMK_XA_LANG "=\"", locale, "\">",
                           localized, NULL);

            if (values != NULL) {
                pcmk__g_strcat(s, _("  Allowed values: "), _(values), NULL);
            }
            pcmk__g_strcat(s, "</", tag, ">\n", NULL);
        }
        free(localized);
    }
#endif

    free(escaped_en);
}

/*!
 * \internal
 * \brief Format option metadata as an OCF-like XML string
 *
 * \param[in] name         Daemon name
 * \param[in] desc_short   Short description of the daemon
 * \param[in] desc_long    Long description of the daemon
 * \param[in] filter       If not \c pcmk__opt_context_none, include only
 *                         those options whose \c context field is equal to
 *                         \p filter
 * \param[in] option_list  Options whose metadata to format
 * \param[in] len          Number of items in \p option_list
 *
 * \return A string containing OCF-like option metadata XML
 *
 * \note The caller is responsible for freeing the return value using
 *       \c g_free().
 */
gchar *
pcmk__format_option_metadata(const char *name, const char *desc_short,
                             const char *desc_long,
                             enum pcmk__opt_context filter,
                             pcmk__cluster_option_t *option_list, int len)
{
    // Large enough to hold current cluster options with room for growth (2^15)
    GString *s = g_string_sized_new(32768);

    pcmk__g_strcat(s,
                   "<?xml " PCMK_XA_VERSION "=\"1.0\"?>\n"
                   "<" PCMK_XE_RESOURCE_AGENT " "
                       PCMK_XA_NAME "=\"", name, "\" "
                       PCMK_XA_VERSION "=\"" PACEMAKER_VERSION "\">\n"

                   "  <" PCMK_XE_VERSION ">" PCMK_OCF_VERSION
                     "</" PCMK_XE_VERSION ">\n", NULL);

    add_desc(s, PCMK_XE_LONGDESC, desc_long, NULL, "  ");
    add_desc(s, PCMK_XE_SHORTDESC, desc_short, NULL, "  ");

    g_string_append(s, "  <" PCMK_XE_PARAMETERS ">\n");

    for (int lpc = 0; lpc < len; lpc++) {
        const char *opt_name = option_list[lpc].name;
        const char *opt_type = option_list[lpc].type;
        const char *opt_values = option_list[lpc].values;
        const char *opt_default = option_list[lpc].default_value;
        const char *opt_desc_short = option_list[lpc].description_short;
        const char *opt_desc_long = option_list[lpc].description_long;

        if ((filter != pcmk__opt_context_none)
            && (filter != option_list[lpc].context)) {
            continue;
        }

        // The standard requires long and short parameter descriptions
        CRM_ASSERT((opt_desc_short != NULL) || (opt_desc_long != NULL));

        if (opt_desc_short == NULL) {
            opt_desc_short = opt_desc_long;
        } else if (opt_desc_long == NULL) {
            opt_desc_long = opt_desc_short;
        }

        // The standard requires a parameter type
        CRM_ASSERT(opt_type != NULL);

        pcmk__g_strcat(s,
                       "    <" PCMK_XE_PARAMETER " "
                               PCMK_XA_NAME "=\"", opt_name, "\">\n", NULL);

        add_desc(s, PCMK_XE_LONGDESC, opt_desc_long, opt_values, "      ");
        add_desc(s, PCMK_XE_SHORTDESC, opt_desc_short, NULL, "      ");

        pcmk__g_strcat(s, "      <" PCMK_XE_CONTENT " "
                                    PCMK_XA_TYPE "=\"", opt_type, "\"", NULL);
        if (opt_default != NULL) {
            pcmk__g_strcat(s,
                           " " PCMK_XA_DEFAULT "=\"", opt_default, "\"", NULL);
        }

        if ((opt_values != NULL) && (strcmp(opt_type, "select") == 0)) {
            char *str = strdup(opt_values);
            const char *delim = ", ";
            char *ptr = strtok(str, delim);

            g_string_append(s, ">\n");

            while (ptr != NULL) {
                pcmk__g_strcat(s,
                               "        <" PCMK_XE_OPTION " "
                                           PCMK_XA_VALUE "=\"", ptr, "\" />\n",
                               NULL);
                ptr = strtok(NULL, delim);
            }
            g_string_append(s, "      </" PCMK_XE_CONTENT ">\n");
            free(str);

        } else {
            g_string_append(s, "/>\n");
        }

        g_string_append(s, "    </" PCMK_XE_PARAMETER ">\n");
    }
    g_string_append(s,
                    "  </" PCMK_XE_PARAMETERS ">\n"
                    "</" PCMK_XE_RESOURCE_AGENT ">\n");

    return g_string_free(s, FALSE);
}

/*!
 * \internal
 * \brief Format cluster option metadata as an OCF-like XML string
 *
 * \param[in] name        Daemon name
 * \param[in] desc_short  Short description of the daemon
 * \param[in] desc_long   Long description of the daemon
 * \param[in] filter      If not \c pcmk__opt_context_none, include only
 *                        those options whose \c context field is equal to
 *                        \p filter
 *
 * \return A string containing OCF-like cluster option metadata XML
 *
 * \note The caller is responsible for freeing the return value using
 *       \c g_free().
 */
gchar *
pcmk__cluster_option_metadata(const char *name, const char *desc_short,
                              const char *desc_long,
                              enum pcmk__opt_context filter)
{
    return pcmk__format_option_metadata(name, desc_short, desc_long, filter,
                                        cluster_options,
                                        PCMK__NELEM(cluster_options));
}

void
pcmk__validate_cluster_options(GHashTable *options)
{
    for (int lpc = 0; lpc < PCMK__NELEM(cluster_options); lpc++) {
        cluster_option_value(options,
                             cluster_options[lpc].is_valid,
                             cluster_options[lpc].name,
                             cluster_options[lpc].alt_name,
                             cluster_options[lpc].default_value);
    }
}
