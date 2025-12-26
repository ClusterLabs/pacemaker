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
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <crm/crm.h>
#include <crm/common/xml.h>


/*
 * Option metadata
 */

static const pcmk__cluster_option_t cluster_options[] = {
    /* name, old name, type, allowed values,
     * default value, validator,
     * flags,
     * short description,
     * long description
     */
    {
        PCMK_OPT_DC_VERSION, NULL, PCMK_VALUE_VERSION, NULL,
        NULL, NULL,
        pcmk__opt_controld|pcmk__opt_generated,
        N_("Pacemaker version on cluster node elected Designated Controller "
            "(DC)"),
        N_("Includes a hash which identifies the exact revision the code was "
            "built from. Used for diagnostic purposes."),
    },
    {
        PCMK_OPT_CLUSTER_INFRASTRUCTURE, NULL, PCMK_VALUE_STRING, NULL,
        NULL, NULL,
        pcmk__opt_controld|pcmk__opt_generated,
        N_("The messaging layer on which Pacemaker is currently running"),
        N_("Used for informational and diagnostic purposes."),
    },
    {
        PCMK_OPT_CLUSTER_NAME, NULL, PCMK_VALUE_STRING, NULL,
        NULL, NULL,
        pcmk__opt_controld,
        N_("An arbitrary name for the cluster"),
        N_("This optional value is mostly for users' convenience as desired "
            "in administration, but may also be used in Pacemaker "
            "configuration rules via the #cluster-name node attribute, and "
            "by higher-level tools and resource agents."),
    },
    {
        PCMK_OPT_DC_DEADTIME, NULL, PCMK_VALUE_DURATION, NULL,
        "20s", pcmk__valid_interval_spec,
        pcmk__opt_controld,
        N_("How long to wait for a response from other nodes during start-up"),
        N_("The optimal value will depend on the speed and load of your "
            "network and the type of switches used."),
    },
    {
        PCMK_OPT_CLUSTER_RECHECK_INTERVAL, NULL, PCMK_VALUE_DURATION, NULL,
        "15min", pcmk__valid_interval_spec,
        pcmk__opt_controld,
        N_("Polling interval to recheck cluster state and evaluate rules "
            "with date specifications"),
        N_("Pacemaker is primarily event-driven, and looks ahead to know when "
            "to recheck cluster state for failure-timeout settings and most "
            "time-based rules. However, it will also recheck the cluster after "
            "this amount of inactivity, to evaluate rules with date "
            "specifications and serve as a fail-safe for certain types of "
            "scheduler bugs. A value of 0 disables polling. A positive value "
            "sets an interval in seconds, unless other units are specified "
            "(for example, \"5min\")."),
    },
    {
        PCMK_OPT_ELECTION_TIMEOUT, NULL, PCMK_VALUE_DURATION, NULL,
        "2min", pcmk__valid_interval_spec,
        pcmk__opt_controld|pcmk__opt_advanced,
        N_("Declare an election failed if it is not decided within this much "
            "time. If you need to adjust this value, it probably indicates "
            "the presence of a bug."),
        NULL,
    },
    {
        PCMK_OPT_SHUTDOWN_ESCALATION, NULL, PCMK_VALUE_DURATION, NULL,
        "20min", pcmk__valid_interval_spec,
        pcmk__opt_controld|pcmk__opt_advanced,
        N_("Exit immediately if shutdown does not complete within this much "
            "time. If you need to adjust this value, it probably indicates "
            "the presence of a bug."),
        NULL,
    },
    {
        PCMK_OPT_JOIN_INTEGRATION_TIMEOUT, NULL, PCMK_VALUE_DURATION, NULL,
        "3min", pcmk__valid_interval_spec,
        pcmk__opt_controld|pcmk__opt_advanced,
        N_("If you need to adjust this value, it probably indicates "
            "the presence of a bug."),
        NULL,
    },
    {
        PCMK_OPT_JOIN_FINALIZATION_TIMEOUT, NULL, PCMK_VALUE_DURATION, NULL,
        "30min", pcmk__valid_interval_spec,
        pcmk__opt_controld|pcmk__opt_advanced,
        N_("If you need to adjust this value, it probably indicates "
            "the presence of a bug."),
        NULL,
    },
    {
        PCMK_OPT_TRANSITION_DELAY, NULL, PCMK_VALUE_DURATION, NULL,
        "0s", pcmk__valid_interval_spec,
        pcmk__opt_controld|pcmk__opt_advanced,
        N_("Enabling this option will slow down cluster recovery under all "
            "conditions"),
        N_("Delay cluster recovery for this much time to allow for additional "
            "events to occur. Useful if your configuration is sensitive to "
            "the order in which ping updates arrive."),
    },
    {
        PCMK_OPT_NO_QUORUM_POLICY, NULL, PCMK_VALUE_SELECT,
            PCMK_VALUE_STOP ", " PCMK_VALUE_FREEZE ", " PCMK_VALUE_IGNORE
                ", " PCMK_VALUE_DEMOTE ", " PCMK_VALUE_FENCE ", "
                PCMK_VALUE_FENCE_LEGACY,
        PCMK_VALUE_STOP, pcmk__valid_no_quorum_policy,
        pcmk__opt_schedulerd,
        N_("What to do when the cluster does not have quorum"),
        NULL,
    },
    {
        PCMK_OPT_SHUTDOWN_LOCK, NULL, PCMK_VALUE_BOOLEAN, NULL,
        PCMK_VALUE_FALSE, pcmk__valid_boolean,
        pcmk__opt_schedulerd,
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
        PCMK_OPT_SHUTDOWN_LOCK_LIMIT, NULL, PCMK_VALUE_DURATION, NULL,
        "0", pcmk__valid_interval_spec,
        pcmk__opt_schedulerd,
        N_("Do not lock resources to a cleanly shut down node longer than "
           "this"),
        N_("If shutdown-lock is true and this is set to a nonzero time "
            "duration, shutdown locks will expire after this much time has "
            "passed since the shutdown was initiated, even if the node has not "
            "rejoined."),
    },
    {
        PCMK_OPT_ENABLE_ACL, NULL, PCMK_VALUE_BOOLEAN, NULL,
        PCMK_VALUE_FALSE, pcmk__valid_boolean,
        pcmk__opt_based,
        N_("Enable Access Control Lists (ACLs) for the CIB"),
        NULL,
    },
    {
        PCMK_OPT_SYMMETRIC_CLUSTER, NULL, PCMK_VALUE_BOOLEAN, NULL,
        PCMK_VALUE_TRUE, pcmk__valid_boolean,
        pcmk__opt_schedulerd,
        N_("Whether resources can run on any node by default"),
        NULL,
    },
    {
        PCMK_OPT_MAINTENANCE_MODE, NULL, PCMK_VALUE_BOOLEAN, NULL,
        PCMK_VALUE_FALSE, pcmk__valid_boolean,
        pcmk__opt_schedulerd,
        N_("Whether the cluster should refrain from monitoring, starting, and "
            "stopping resources"),
        NULL,
    },
    {
        PCMK_OPT_START_FAILURE_IS_FATAL, NULL, PCMK_VALUE_BOOLEAN, NULL,
        PCMK_VALUE_TRUE, pcmk__valid_boolean,
        pcmk__opt_schedulerd,
        N_("Whether a start failure should prevent a resource from being "
            "recovered on the same node"),
        N_("When true, the cluster will immediately ban a resource from a node "
            "if it fails to start there. When false, the cluster will instead "
            "check the resource's fail count against its migration-threshold.")
    },
    {
        PCMK__OPT_ENABLE_STARTUP_PROBES, NULL, PCMK_VALUE_BOOLEAN, NULL,
        PCMK_VALUE_TRUE, pcmk__valid_boolean,
        pcmk__opt_schedulerd|pcmk__opt_deprecated,
        N_("Whether the cluster should check for active resources during "
            "start-up"),
        NULL,
    },

    // Fencing-related options
    {
        PCMK_OPT_FENCE_REMOTE_WITHOUT_QUORUM, NULL, PCMK_VALUE_BOOLEAN, NULL,
        PCMK_VALUE_FALSE, pcmk__valid_boolean,
        pcmk__opt_schedulerd|pcmk__opt_advanced,
        N_("Whether remote nodes can be fenced without quorum"),
        N_("By default, an inquorate node can not fence Pacemaker Remote nodes "
           "that are part of its partition as long as the cluster thinks they "
           "can be restarted.  If true, inquorate nodes will be able to fence "
           "remote nodes regardless."),
    },
    {
        PCMK_OPT_FENCING_ENABLED, "stonith-enabled", PCMK_VALUE_BOOLEAN, NULL,
        PCMK_VALUE_TRUE, pcmk__valid_boolean,
        pcmk__opt_schedulerd|pcmk__opt_advanced,
        N_("Whether nodes may be fenced as part of recovery"),
        N_("If false, unresponsive nodes are immediately assumed to be "
            "harmless, and resources that were active on them may be recovered "
            "elsewhere. This can result in a \"split-brain\" situation, "
            "potentially leading to data loss and/or service unavailability."),
    },
    {
        PCMK_OPT_FENCING_ACTION, "stonith-action", PCMK_VALUE_SELECT,
            PCMK_ACTION_REBOOT ", " PCMK_ACTION_OFF,
        PCMK_ACTION_REBOOT, pcmk__is_fencing_action,
        pcmk__opt_schedulerd,
        N_("Action to send to fence device when a node needs to be fenced"),
        NULL,
    },
    {
        PCMK_OPT_FENCING_REACTION, "fence-reaction", PCMK_VALUE_SELECT,
            PCMK_VALUE_STOP ", " PCMK_VALUE_PANIC,
        PCMK_VALUE_STOP, NULL,
        pcmk__opt_controld,
        N_("How a cluster node should react if notified of its own fencing"),
        N_("A cluster node may receive notification of a \"succeeded\" "
            "fencing that targeted it if fencing is misconfigured, or if "
            "fabric fencing is in use that doesn't cut cluster communication. "
            "Use \"stop\" to attempt to immediately stop Pacemaker and stay "
            "stopped, or \"panic\" to attempt to immediately reboot the local "
            "node, falling back to stop on failure."),
    },
    {
        PCMK_OPT_FENCING_TIMEOUT, "stonith-timeout", PCMK_VALUE_DURATION, NULL,
        "60s", pcmk__valid_interval_spec,
        pcmk__opt_schedulerd,
        N_("How long to wait for on, off, and reboot fence actions to complete "
            "by default"),
        NULL,
    },
    {
        PCMK_OPT_HAVE_WATCHDOG, NULL, PCMK_VALUE_BOOLEAN, NULL,
        PCMK_VALUE_FALSE, pcmk__valid_boolean,
        pcmk__opt_schedulerd|pcmk__opt_generated,
        N_("Whether watchdog integration is enabled"),
        N_("This is set automatically by the cluster according to whether SBD "
            "is detected to be in use. User-configured values are ignored. "
            "The value `true` is meaningful if diskless SBD is used and "
            "`fencing-watchdog-timeout` is nonzero. In that case, if fencing "
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
        PCMK_OPT_FENCING_WATCHDOG_TIMEOUT, "stonith-watchdog-timeout",
            PCMK_VALUE_TIMEOUT, NULL,
        "0", NULL,
        pcmk__opt_controld,
        N_("How long before nodes can be assumed to be safely down when "
           "watchdog-based self-fencing via SBD is in use"),
        N_("If this is set to a positive value, lost nodes are assumed to "
           "achieve self-fencing using watchdog-based SBD within this much "
           "time. This does not require a fencing resource to be explicitly "
           "configured, though a fence_watchdog resource can be configured, to "
           "limit use to specific nodes. If this is set to 0 (the default), "
           "the cluster will never assume watchdog-based self-fencing. If this "
           "is set to a negative value, the cluster will use twice the local "
           "value of the `SBD_WATCHDOG_TIMEOUT` environment variable if that "
           "is positive, or otherwise treat this as 0. WARNING: When used, "
           "this timeout must be larger than `SBD_WATCHDOG_TIMEOUT` on all "
           "nodes that use watchdog-based SBD, and Pacemaker will refuse to "
           "start on any of those nodes where this is not true for the local "
           "value or SBD is not active. When this is set to a negative value, "
           "`SBD_WATCHDOG_TIMEOUT` must be set to the same value on all nodes "
           "that use SBD, otherwise data corruption or loss could occur."),
    },
    {
        PCMK_OPT_FENCING_MAX_ATTEMPTS, "stonith-max-attempts", PCMK_VALUE_SCORE,
            NULL,
        "10", pcmk__valid_positive_int,
        pcmk__opt_controld,
        N_("How many times fencing can fail before it will no longer be "
            "immediately re-attempted on a target"),
        NULL,
    },
    {
        PCMK__OPT_CONCURRENT_FENCING, NULL, PCMK_VALUE_BOOLEAN, NULL,
#if PCMK__CONCURRENT_FENCING_DEFAULT_TRUE
        PCMK_VALUE_TRUE,
#else
        PCMK_VALUE_FALSE,
#endif
        pcmk__valid_boolean,
        pcmk__opt_schedulerd|pcmk__opt_deprecated,
        N_("Allow performing fencing operations in parallel"),
        NULL,
    },
    {
        PCMK_OPT_STARTUP_FENCING, NULL, PCMK_VALUE_BOOLEAN, NULL,
        PCMK_VALUE_TRUE, pcmk__valid_boolean,
        pcmk__opt_schedulerd|pcmk__opt_advanced,
        N_("Whether to fence unseen nodes at start-up"),
        N_("Setting this to false may lead to a \"split-brain\" situation, "
            "potentially leading to data loss and/or service unavailability."),
    },
    {
        PCMK_OPT_PRIORITY_FENCING_DELAY, NULL, PCMK_VALUE_DURATION, NULL,
        "0", pcmk__valid_interval_spec,
        pcmk__opt_schedulerd,
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
        PCMK_OPT_NODE_PENDING_TIMEOUT, NULL, PCMK_VALUE_DURATION, NULL,
        "0", pcmk__valid_interval_spec,
        pcmk__opt_schedulerd,
        N_("How long to wait for a node that has joined the cluster to join "
           "the controller process group"),
        N_("Fence nodes that do not join the controller process group within "
           "this much time after joining the cluster, to allow the cluster "
           "to continue managing resources. A value of 0 means never fence "
           "pending nodes. Setting the value to 2h means fence nodes after "
           "2 hours."),
    },
    {
        PCMK_OPT_CLUSTER_DELAY, NULL, PCMK_VALUE_DURATION, NULL,
        "60s", pcmk__valid_interval_spec,
        pcmk__opt_schedulerd,
        N_("Maximum time for node-to-node communication"),
        N_("The node elected Designated Controller (DC) will consider an action "
            "failed if it does not get a response from the node executing the "
            "action within this time (after considering the action's own "
            "timeout). The \"correct\" value will depend on the speed and "
            "load of your network and cluster nodes.")
    },

    // Limits
    {
        PCMK_OPT_LOAD_THRESHOLD, NULL, PCMK_VALUE_PERCENTAGE, NULL,
        "80%", pcmk__valid_percentage,
        pcmk__opt_controld,
        N_("Maximum amount of system load that should be used by cluster "
            "nodes"),
        N_("The cluster will slow down its recovery process when the amount of "
            "system resources used (currently CPU) approaches this limit"),
    },
    {
        PCMK_OPT_NODE_ACTION_LIMIT, NULL, PCMK_VALUE_INTEGER, NULL,
        "0", pcmk__valid_int,
        pcmk__opt_controld,
        N_("Maximum number of jobs that can be scheduled per node (defaults to "
            "2x cores)"),
        NULL,
    },
    {
        PCMK_OPT_BATCH_LIMIT, NULL, PCMK_VALUE_INTEGER, NULL,
        "0", pcmk__valid_int,
        pcmk__opt_schedulerd,
        N_("Maximum number of jobs that the cluster may execute in parallel "
            "across all nodes"),
        N_("The \"correct\" value will depend on the speed and load of your "
            "network and cluster nodes. If set to 0, the cluster will "
            "impose a dynamically calculated limit when any node has a "
            "high load."),
    },
    {
        PCMK_OPT_MIGRATION_LIMIT, NULL, PCMK_VALUE_INTEGER, NULL,
        "-1", pcmk__valid_int,
        pcmk__opt_schedulerd,
        N_("The number of live migration actions that the cluster is allowed "
            "to execute in parallel on a node (-1 means no limit)"),
        NULL,
    },
    {
        "cluster-ipc-limit", NULL, PCMK_VALUE_NONNEGATIVE_INTEGER, NULL,
        NULL, NULL,
        pcmk__opt_based|pcmk__opt_deprecated,
        N_("Ignored"),
        NULL,
    },

    // Stopping resources and removed resources
    {
        /* This option complicates display and precedence a bit. The same effect
         * can be achieved by placing all nodes in standby, or by creating a
         * constraint rule that sets all resources' target roles to stopped.
         *
         * We decided to keep it based on user feedback that it's useful in its
         * simplicity. Also, it is analogous to the situation with
         * PCMK_OPT_MAINTENANCE_MODE (cluster-level),
         * PCMK_NODE_ATTR_MAINTENANCE (node-level), and PCMK_META_MAINTENANCE
         * (resource-level).
         */
        PCMK_OPT_STOP_ALL_RESOURCES, NULL, PCMK_VALUE_BOOLEAN, NULL,
        PCMK_VALUE_FALSE, pcmk__valid_boolean,
        pcmk__opt_schedulerd,
        N_("Whether the cluster should stop all active resources"),
        NULL,
    },
    {
        PCMK__OPT_STOP_REMOVED_RESOURCES, "stop-orphan-resources",
            PCMK_VALUE_BOOLEAN, NULL,
        PCMK_VALUE_TRUE, pcmk__valid_boolean,
        pcmk__opt_schedulerd|pcmk__opt_deprecated,
        N_("Whether to stop resources that were removed from the "
            "configuration"),
        NULL,
    },
    {
        PCMK__OPT_CANCEL_REMOVED_ACTIONS, "stop-orphan-actions",
            PCMK_VALUE_BOOLEAN, NULL,
        PCMK_VALUE_TRUE, pcmk__valid_boolean,
        pcmk__opt_schedulerd|pcmk__opt_deprecated,
        N_("Whether to cancel recurring actions removed from the "
            "configuration"),
        NULL,
    },

    // Storing inputs
    {
        PCMK_OPT_PE_ERROR_SERIES_MAX, NULL, PCMK_VALUE_INTEGER, NULL,
        "-1", pcmk__valid_int,
        pcmk__opt_schedulerd,
        N_("The number of scheduler inputs resulting in errors to save"),
        N_("Zero to disable, -1 to store unlimited."),
    },
    {
        PCMK_OPT_PE_WARN_SERIES_MAX, NULL, PCMK_VALUE_INTEGER, NULL,
        "5000", pcmk__valid_int,
        pcmk__opt_schedulerd,
        N_("The number of scheduler inputs resulting in warnings to save"),
        N_("Zero to disable, -1 to store unlimited."),
    },
    {
        PCMK_OPT_PE_INPUT_SERIES_MAX, NULL, PCMK_VALUE_INTEGER, NULL,
        "4000", pcmk__valid_int,
        pcmk__opt_schedulerd,
        N_("The number of scheduler inputs without errors or warnings to save"),
        N_("Zero to disable, -1 to store unlimited."),
    },

    // Node health
    {
        PCMK_OPT_NODE_HEALTH_STRATEGY, NULL, PCMK_VALUE_SELECT,
            PCMK_VALUE_NONE ", " PCMK_VALUE_MIGRATE_ON_RED ", "
                PCMK_VALUE_ONLY_GREEN ", " PCMK_VALUE_PROGRESSIVE ", "
                PCMK_VALUE_CUSTOM,
        PCMK_VALUE_NONE, pcmk__validate_health_strategy,
        pcmk__opt_schedulerd,
        N_("How cluster should react to node health attributes"),
        N_("Requires external entities to create node attributes (named with "
            "the prefix \"#health\") with values \"red\", \"yellow\", or "
            "\"green\".")
    },
    {
        PCMK_OPT_NODE_HEALTH_BASE, NULL, PCMK_VALUE_SCORE, NULL,
        "0", pcmk__valid_int,
        pcmk__opt_schedulerd,
        N_("Base health score assigned to a node"),
        N_("Only used when \"node-health-strategy\" is set to "
            "\"progressive\"."),
    },
    {
        PCMK_OPT_NODE_HEALTH_GREEN, NULL, PCMK_VALUE_SCORE, NULL,
        "0", pcmk__valid_int,
        pcmk__opt_schedulerd,
        N_("The score to use for a node health attribute whose value is "
            "\"green\""),
        N_("Only used when \"node-health-strategy\" is set to \"custom\" or "
            "\"progressive\"."),
    },
    {
        PCMK_OPT_NODE_HEALTH_YELLOW, NULL, PCMK_VALUE_SCORE, NULL,
        "0", pcmk__valid_int,
        pcmk__opt_schedulerd,
        N_("The score to use for a node health attribute whose value is "
            "\"yellow\""),
        N_("Only used when \"node-health-strategy\" is set to \"custom\" or "
            "\"progressive\"."),
    },
    {
        PCMK_OPT_NODE_HEALTH_RED, NULL, PCMK_VALUE_SCORE, NULL,
        "-INFINITY", pcmk__valid_int,
        pcmk__opt_schedulerd,
        N_("The score to use for a node health attribute whose value is "
            "\"red\""),
        N_("Only used when \"node-health-strategy\" is set to \"custom\" or "
            "\"progressive\".")
    },

    // Placement strategy
    {
        PCMK_OPT_PLACEMENT_STRATEGY, NULL, PCMK_VALUE_SELECT,
            PCMK_VALUE_DEFAULT ", " PCMK_VALUE_UTILIZATION ", "
                PCMK_VALUE_MINIMAL ", " PCMK_VALUE_BALANCED,
        PCMK_VALUE_DEFAULT, pcmk__valid_placement_strategy,
        pcmk__opt_schedulerd,
        N_("How the cluster should allocate resources to nodes"),
        NULL,
    },

    { NULL, },
};

static const pcmk__cluster_option_t fencing_params[] = {
    /* name, old name, type, allowed values,
     * default value, validator,
     * flags,
     * short description,
     * long description
     */
    {
        PCMK_FENCING_HOST_ARGUMENT, NULL, PCMK_VALUE_STRING, NULL,
        NULL, NULL,
        pcmk__opt_advanced,
        N_("Name of agent parameter that should be set to the fencing target"),
        N_("If the fencing agent metadata advertises support for the \"port\" "
            "or \"plug\" parameter, that will be used as the default, "
            "otherwise \"none\" will be used, which tells the cluster not to "
            "supply any additional parameters."),
    },
    {
        PCMK_FENCING_HOST_MAP, NULL, PCMK_VALUE_STRING, NULL,
        NULL, NULL,
        pcmk__opt_none,
        N_("A mapping of node names to port numbers for devices that do not "
            "support node names."),
        N_("For example, \"node1:1;node2:2,3\" would tell the cluster to use "
            "port 1 for node1 and ports 2 and 3 for node2."),
    },
    {
        PCMK_FENCING_HOST_LIST, NULL, PCMK_VALUE_STRING, NULL,
        NULL, NULL,
        pcmk__opt_none,
        N_("Nodes targeted by this device"),
        N_("Comma-separated list of nodes that can be targeted by this device "
           "(for example, \"node1,node2,node3\"). If pcmk_host_check is "
           "\"static-list\", either this or pcmk_host_map must be set."),
    },
    {
        PCMK_FENCING_HOST_CHECK, NULL, PCMK_VALUE_SELECT,
            PCMK_VALUE_DYNAMIC_LIST ", " PCMK_VALUE_STATIC_LIST ", "
            PCMK_VALUE_STATUS ", " PCMK_VALUE_NONE,
        NULL, NULL,
        pcmk__opt_none,
        N_("How to determine which nodes can be targeted by the device"),
        N_("Use \"dynamic-list\" to query the device via the 'list' command; "
            "\"static-list\" to check the pcmk_host_list attribute; "
            "\"status\" to query the device via the 'status' command; or "
            "\"none\" to assume every device can fence every node. "
            "The default value is \"static-list\" if pcmk_host_map or "
            "pcmk_host_list is set; otherwise \"dynamic-list\" if the device "
            "supports the list operation; otherwise \"status\" if the device "
            "supports the status operation; otherwise \"none\""),
    },
    {
        PCMK_FENCING_DELAY_MAX, NULL, PCMK_VALUE_DURATION, NULL,
        "0s", NULL,
        pcmk__opt_none,
        N_("Enable a delay of no more than the time specified before executing "
            "fencing actions."),
        N_("Enable a delay of no more than the time specified before executing "
            "fencing actions. Pacemaker derives the overall delay by taking "
            "the value of pcmk_delay_base and adding a random delay value such "
            "that the sum is kept below this maximum."),
    },
    {
        PCMK_FENCING_DELAY_BASE, NULL, PCMK_VALUE_STRING, NULL,
        "0s", NULL,
        pcmk__opt_none,
        N_("Enable a base delay for fencing actions and specify base delay "
            "value."),
        N_("This enables a static delay for fencing actions, which can help "
            "avoid \"death matches\" where two nodes try to fence each other "
            "at the same time. If pcmk_delay_max is also used, a random delay "
            "will be added such that the total delay is kept below that value. "
            "This can be set to a single time value to apply to any node "
            "targeted by this device (useful if a separate device is "
            "configured for each target), or to a node map (for example, "
            "\"node1:1s;node2:5\") to set a different value for each target."),
    },
    {
        PCMK_FENCING_ACTION_LIMIT, NULL, PCMK_VALUE_INTEGER, NULL,
        "1", NULL,
        pcmk__opt_none,
        N_("The maximum number of actions can be performed in parallel on this "
            "device"),
        N_("If the concurrent-fencing cluster property is \"true\", this "
            "specifies the maximum number of actions that can be performed in "
            "parallel on this device. A value of -1 means unlimited."),
    },
    {
        "pcmk_reboot_action", NULL, PCMK_VALUE_STRING, NULL,
        PCMK_ACTION_REBOOT, NULL,
        pcmk__opt_advanced,
        N_("An alternate command to run instead of 'reboot'"),
        N_("Some devices do not support the standard commands or may provide "
            "additional ones. Use this to specify an alternate, device-"
            "specific, command that implements the 'reboot' action."),
    },
    {
        "pcmk_reboot_timeout", NULL, PCMK_VALUE_TIMEOUT, NULL,
        "60s", NULL,
        pcmk__opt_advanced,
        N_("Specify an alternate timeout to use for 'reboot' actions instead "
            "of fencing-timeout"),
        N_("Some devices need much more/less time to complete than normal. "
            "Use this to specify an alternate, device-specific, timeout for "
            "'reboot' actions."),
    },
    {
        "pcmk_reboot_retries", NULL, PCMK_VALUE_INTEGER, NULL,
        "2", NULL,
        pcmk__opt_advanced,
        N_("The maximum number of times to try the 'reboot' command within the "
            "timeout period"),
        N_("Some devices do not support multiple connections. Operations may "
            "\"fail\" if the device is busy with another task. In that case, "
            "Pacemaker will automatically retry the operation if there is time "
            "remaining. Use this option to alter the number of times Pacemaker "
            "tries a 'reboot' action before giving up."),
    },
    {
        "pcmk_off_action", NULL, PCMK_VALUE_STRING, NULL,
        PCMK_ACTION_OFF, NULL,
        pcmk__opt_advanced,
        N_("An alternate command to run instead of 'off'"),
        N_("Some devices do not support the standard commands or may provide "
            "additional ones. Use this to specify an alternate, device-"
            "specific, command that implements the 'off' action."),
    },
    {
        "pcmk_off_timeout", NULL, PCMK_VALUE_TIMEOUT, NULL,
        "60s", NULL,
        pcmk__opt_advanced,
        N_("Specify an alternate timeout to use for 'off' actions instead of "
            "fencing-timeout"),
        N_("Some devices need much more/less time to complete than normal. "
            "Use this to specify an alternate, device-specific, timeout for "
            "'off' actions."),
    },
    {
        "pcmk_off_retries", NULL, PCMK_VALUE_INTEGER, NULL,
        "2", NULL,
        pcmk__opt_advanced,
        N_("The maximum number of times to try the 'off' command within the "
            "timeout period"),
        N_("Some devices do not support multiple connections. Operations may "
            "\"fail\" if the device is busy with another task. In that case, "
            "Pacemaker will automatically retry the operation if there is time "
            "remaining. Use this option to alter the number of times Pacemaker "
            "tries a 'off' action before giving up."),
    },
    {
        "pcmk_on_action", NULL, PCMK_VALUE_STRING, NULL,
        PCMK_ACTION_ON, NULL,
        pcmk__opt_advanced,
        N_("An alternate command to run instead of 'on'"),
        N_("Some devices do not support the standard commands or may provide "
            "additional ones. Use this to specify an alternate, device-"
            "specific, command that implements the 'on' action."),
    },
    {
        "pcmk_on_timeout", NULL, PCMK_VALUE_TIMEOUT, NULL,
        "60s", NULL,
        pcmk__opt_advanced,
        N_("Specify an alternate timeout to use for 'on' actions instead of "
            "fencing-timeout"),
        N_("Some devices need much more/less time to complete than normal. "
            "Use this to specify an alternate, device-specific, timeout for "
            "'on' actions."),
    },
    {
        "pcmk_on_retries", NULL, PCMK_VALUE_INTEGER, NULL,
        "2", NULL,
        pcmk__opt_advanced,
        N_("The maximum number of times to try the 'on' command within the "
            "timeout period"),
        N_("Some devices do not support multiple connections. Operations may "
            "\"fail\" if the device is busy with another task. In that case, "
            "Pacemaker will automatically retry the operation if there is time "
            "remaining. Use this option to alter the number of times Pacemaker "
            "tries a 'on' action before giving up."),
    },
    {
        "pcmk_list_action", NULL, PCMK_VALUE_STRING, NULL,
        PCMK_ACTION_LIST, NULL,
        pcmk__opt_advanced,
        N_("An alternate command to run instead of 'list'"),
        N_("Some devices do not support the standard commands or may provide "
            "additional ones. Use this to specify an alternate, device-"
            "specific, command that implements the 'list' action."),
    },
    {
        "pcmk_list_timeout", NULL, PCMK_VALUE_TIMEOUT, NULL,
        "60s", NULL,
        pcmk__opt_advanced,
        N_("Specify an alternate timeout to use for 'list' actions instead of "
            "fencing-timeout"),
        N_("Some devices need much more/less time to complete than normal. "
            "Use this to specify an alternate, device-specific, timeout for "
            "'list' actions."),
    },
    {
        "pcmk_list_retries", NULL, PCMK_VALUE_INTEGER, NULL,
        "2", NULL,
        pcmk__opt_advanced,
        N_("The maximum number of times to try the 'list' command within the "
            "timeout period"),
        N_("Some devices do not support multiple connections. Operations may "
            "\"fail\" if the device is busy with another task. In that case, "
            "Pacemaker will automatically retry the operation if there is time "
            "remaining. Use this option to alter the number of times Pacemaker "
            "tries a 'list' action before giving up."),
    },
    {
        "pcmk_monitor_action", NULL, PCMK_VALUE_STRING, NULL,
        PCMK_ACTION_MONITOR, NULL,
        pcmk__opt_advanced,
        N_("An alternate command to run instead of 'monitor'"),
        N_("Some devices do not support the standard commands or may provide "
            "additional ones. Use this to specify an alternate, device-"
            "specific, command that implements the 'monitor' action."),
    },
    {
        "pcmk_monitor_timeout", NULL, PCMK_VALUE_TIMEOUT, NULL,
        "60s", NULL,
        pcmk__opt_advanced,
        N_("Specify an alternate timeout to use for 'monitor' actions instead "
            "of fencing-timeout"),
        N_("Some devices need much more/less time to complete than normal. "
            "Use this to specify an alternate, device-specific, timeout for "
            "'monitor' actions."),
    },
    {
        "pcmk_monitor_retries", NULL, PCMK_VALUE_INTEGER, NULL,
        "2", NULL,
        pcmk__opt_advanced,
        N_("The maximum number of times to try the 'monitor' command within "
            "the timeout period"),
        N_("Some devices do not support multiple connections. Operations may "
            "\"fail\" if the device is busy with another task. In that case, "
            "Pacemaker will automatically retry the operation if there is time "
            "remaining. Use this option to alter the number of times Pacemaker "
            "tries a 'monitor' action before giving up."),
    },
    {
        "pcmk_status_action", NULL, PCMK_VALUE_STRING, NULL,
        PCMK_ACTION_STATUS, NULL,
        pcmk__opt_advanced,
        N_("An alternate command to run instead of 'status'"),
        N_("Some devices do not support the standard commands or may provide "
            "additional ones. Use this to specify an alternate, device-"
            "specific, command that implements the 'status' action."),
    },
    {
        "pcmk_status_timeout", NULL, PCMK_VALUE_TIMEOUT, NULL,
        "60s", NULL,
        pcmk__opt_advanced,
        N_("Specify an alternate timeout to use for 'status' actions instead "
            "of fencing-timeout"),
        N_("Some devices need much more/less time to complete than normal. "
            "Use this to specify an alternate, device-specific, timeout for "
            "'status' actions."),
    },
    {
        "pcmk_status_retries", NULL, PCMK_VALUE_INTEGER, NULL,
        "2", NULL,
        pcmk__opt_advanced,
        N_("The maximum number of times to try the 'status' command within "
            "the timeout period"),
        N_("Some devices do not support multiple connections. Operations may "
            "\"fail\" if the device is busy with another task. In that case, "
            "Pacemaker will automatically retry the operation if there is time "
            "remaining. Use this option to alter the number of times Pacemaker "
            "tries a 'status' action before giving up."),
    },

    { NULL, },
};

static const pcmk__cluster_option_t primitive_meta[] = {
    /* name, old name, type, allowed values,
     * default value, validator,
     * flags,
     * short description,
     * long description
     */
    {
        PCMK_META_PRIORITY, NULL, PCMK_VALUE_SCORE, NULL,
        "0", NULL,
        pcmk__opt_none,
        N_("Resource assignment priority"),
        N_("If not all resources can be active, the cluster will stop "
            "lower-priority resources in order to keep higher-priority ones "
            "active."),
    },
    {
        PCMK_META_CRITICAL, NULL, PCMK_VALUE_BOOLEAN, NULL,
        PCMK_VALUE_TRUE, NULL,
        pcmk__opt_none,
        N_("Default value for influence in colocation constraints"),
        N_("Use this value as the default for influence in all colocation "
            "constraints involving this resource, as well as in the implicit "
            "colocation constraints created if this resource is in a group."),
    },
    {
        PCMK_META_TARGET_ROLE, NULL, PCMK_VALUE_SELECT,
            PCMK_ROLE_STOPPED ", " PCMK_ROLE_STARTED ", "
            PCMK_ROLE_UNPROMOTED ", " PCMK_ROLE_PROMOTED,
        PCMK_ROLE_STARTED, NULL,
        pcmk__opt_none,
        N_("State the cluster should attempt to keep this resource in"),
        N_("\"Stopped\" forces the resource to be stopped. "
            "\"Started\" allows the resource to be started (and in the case of "
            "promotable clone resources, promoted if appropriate). "
            "\"Unpromoted\" allows the resource to be started, but only in the "
            "unpromoted role if the resource is promotable. "
            "\"Promoted\" is equivalent to \"Started\"."),
    },
    {
        PCMK_META_IS_MANAGED, NULL, PCMK_VALUE_BOOLEAN, NULL,
        PCMK_VALUE_TRUE, NULL,
        pcmk__opt_none,
        N_("Whether the cluster is allowed to actively change the resource's "
            "state"),
        N_("If false, the cluster will not start, stop, promote, or demote the "
            "resource on any node. Recurring actions for the resource are "
            "unaffected. If true, a true value for the maintenance-mode "
            "cluster option, the maintenance node attribute, or the "
            "maintenance resource meta-attribute overrides this."),
    },
    {
        PCMK_META_MAINTENANCE, NULL, PCMK_VALUE_BOOLEAN, NULL,
        PCMK_VALUE_FALSE, NULL,
        pcmk__opt_none,
        N_("If true, the cluster will not schedule any actions involving the "
            "resource"),
        N_("If true, the cluster will not start, stop, promote, or demote the "
            "resource on any node, and will pause any recurring monitors "
            "(except those specifying role as \"Stopped\"). If false, a true "
            "value for the maintenance-mode cluster option or maintenance node "
            "attribute overrides this."),
    },
    {
        PCMK_META_RESOURCE_STICKINESS, NULL, PCMK_VALUE_SCORE, NULL,
        NULL, NULL,
        pcmk__opt_none,
        N_("Score to add to the current node when a resource is already "
            "active"),
        N_("Score to add to the current node when a resource is already "
            "active. This allows running resources to stay where they are, "
            "even if they would be placed elsewhere if they were being started "
            "from a stopped state. "
            "The default is 1 for individual clone instances, and 0 for all "
            "other resources."),
    },
    {
        PCMK_META_REQUIRES, NULL, PCMK_VALUE_SELECT,
            PCMK_VALUE_NOTHING ", " PCMK_VALUE_QUORUM ", "
            PCMK_VALUE_FENCING ", " PCMK_VALUE_UNFENCING,
        NULL, NULL,
        pcmk__opt_none,
        N_("Conditions under which the resource can be started"),
        N_("Conditions under which the resource can be started. "
            "\"nothing\" means the cluster can always start this resource. "
            "\"quorum\" means the cluster can start this resource only if a "
            "majority of the configured nodes are active. "
            "\"fencing\" means the cluster can start this resource only if a "
            "majority of the configured nodes are active and any failed or "
            "unknown nodes have been fenced. "
            "\"unfencing\" means the cluster can start this resource only if "
            "a majority of the configured nodes are active and any failed or "
            "unknown nodes have been fenced, and only on nodes that have been "
            "unfenced. "
            "The default is \"quorum\" for resources with a class of stonith; "
            "otherwise, \"unfencing\" if unfencing is active in the cluster; "
            "otherwise, \"fencing\" if the fencing-enabled cluster option is "
            "true; "
            "otherwise, \"quorum\"."),
    },
    {
        PCMK_META_MIGRATION_THRESHOLD, NULL, PCMK_VALUE_SCORE, NULL,
        PCMK_VALUE_INFINITY, NULL,
        pcmk__opt_none,
        N_("Number of failures on a node before the resource becomes "
            "ineligible to run there."),
        N_("Number of failures that may occur for this resource on a node, "
            "before that node is marked ineligible to host this resource. A "
            "value of 0 indicates that this feature is disabled (the node will "
            "never be marked ineligible). By contrast, the cluster treats "
            "\"INFINITY\" (the default) as a very large but finite number. "
            "This option has an effect only if the failed operation specifies "
            "its on-fail attribute as \"restart\" (the default), and "
            "additionally for failed start operations, if the "
            "start-failure-is-fatal cluster property is set to false."),
    },
    {
        PCMK_META_FAILURE_TIMEOUT, NULL, PCMK_VALUE_DURATION, NULL,
        "0", NULL,
        pcmk__opt_none,
        N_("Number of seconds before acting as if a failure had not occurred"),
        N_("Number of seconds after a failed action for this resource before "
            "acting as if the failure had not occurred, and potentially "
            "allowing the resource back to the node on which it failed. "
            "A value of 0 indicates that this feature is disabled."),
    },
    {
        PCMK_META_MULTIPLE_ACTIVE, NULL, PCMK_VALUE_SELECT,
            PCMK_VALUE_BLOCK ", " PCMK_VALUE_STOP_ONLY ", "
            PCMK_VALUE_STOP_START ", " PCMK_VALUE_STOP_UNEXPECTED,
        PCMK_VALUE_STOP_START, NULL,
        pcmk__opt_none,
        N_("What to do if the cluster finds the resource active on more than "
            "one node"),
        N_("What to do if the cluster finds the resource active on more than "
            "one node. "
            "\"block\" means to mark the resource as unmanaged. "
            "\"stop_only\" means to stop all active instances of this resource "
            "and leave them stopped. "
            "\"stop_start\" means to stop all active instances of this "
            "resource and start the resource in one location only. "
            "\"stop_unexpected\" means to stop all active instances of this "
            "resource except where the resource should be active. (This should "
            "be used only when extra instances are not expected to disrupt "
            "existing instances, and the resource agent's monitor of an "
            "existing instance is capable of detecting any problems that could "
            "be caused. Note that any resources ordered after this one will "
            "still need to be restarted.)"),
    },
    {
        PCMK_META_ALLOW_MIGRATE, NULL, PCMK_VALUE_BOOLEAN, NULL,
        NULL, NULL,
        pcmk__opt_none,
        N_("Whether the cluster should try to \"live migrate\" this resource "
            "when it needs to be moved"),
        N_("Whether the cluster should try to \"live migrate\" this resource "
            "when it needs to be moved. "
            "The default is true for ocf:pacemaker:remote resources, and false "
            "otherwise."),
    },
    {
        PCMK_META_ALLOW_UNHEALTHY_NODES, NULL, PCMK_VALUE_BOOLEAN, NULL,
        PCMK_VALUE_FALSE, NULL,
        pcmk__opt_none,
        N_("Whether the resource should be allowed to run on a node even if "
            "the node's health score would otherwise prevent it"),
        NULL,
    },
    {
        PCMK_META_CONTAINER_ATTRIBUTE_TARGET, NULL, PCMK_VALUE_STRING, NULL,
        NULL, NULL,
        pcmk__opt_none,
        N_("Where to check user-defined node attributes"),
        N_("Whether to check user-defined node attributes on the physical host "
            "where a container is running or on the local node. This is "
            "usually set for a bundle resource and inherited by the bundle's "
            "primitive resource. "
            "A value of \"host\" means to check user-defined node attributes "
            "on the underlying physical host. Any other value means to check "
            "user-defined node attributes on the local node (for a bundled "
            "primitive resource, this is the bundle node)."),
    },
    {
        PCMK_META_REMOTE_NODE, NULL, PCMK_VALUE_STRING, NULL,
        NULL, NULL,
        pcmk__opt_none,
        N_("Name of the Pacemaker Remote guest node this resource is "
            "associated with, if any"),
        N_("Name of the Pacemaker Remote guest node this resource is "
            "associated with, if any. If specified, this both enables the "
            "resource as a guest node and defines the unique name used to "
            "identify the guest node. The guest must be configured to run the "
            "Pacemaker Remote daemon when it is started. "
            "WARNING: This value cannot overlap with any resource or node "
            "IDs."),
    },
    {
        PCMK_META_REMOTE_ADDR, NULL, PCMK_VALUE_STRING, NULL,
        NULL, NULL,
        pcmk__opt_none,
        N_("If remote-node is specified, the IP address or hostname used to "
            "connect to the guest via Pacemaker Remote"),
        N_("If remote-node is specified, the IP address or hostname used to "
            "connect to the guest via Pacemaker Remote. The Pacemaker Remote "
            "daemon on the guest must be configured to accept connections on "
            "this address. "
            "The default is the value of the remote-node meta-attribute."),
    },
    {
        PCMK_META_REMOTE_PORT, NULL, PCMK_VALUE_PORT, NULL,
        "3121", NULL,
        pcmk__opt_none,
        N_("If remote-node is specified, port on the guest used for its "
            "Pacemaker Remote connection"),
        N_("If remote-node is specified, the port on the guest used for its "
            "Pacemaker Remote connection. The Pacemaker Remote daemon on the "
            "guest must be configured to listen on this port."),
    },
    {
        PCMK_META_REMOTE_CONNECT_TIMEOUT, NULL, PCMK_VALUE_TIMEOUT, NULL,
        "60s", NULL,
        pcmk__opt_none,
        N_("If remote-node is specified, how long before a pending Pacemaker "
            "Remote guest connection times out."),
        NULL,
    },
    {
        PCMK_META_REMOTE_ALLOW_MIGRATE, NULL, PCMK_VALUE_BOOLEAN, NULL,
        PCMK_VALUE_TRUE, NULL,
        pcmk__opt_none,
        N_("If remote-node is specified, this acts as the allow-migrate "
            "meta-attribute for the implicit remote connection resource "
            "(ocf:pacemaker:remote)."),
        NULL,
    },

    { NULL, },
};

/*
 * Environment variable option handling
 */

/*!
 * \internal
 * \brief Get the value of a Pacemaker environment variable option
 *
 * If an environment variable option is set, with either a \c "PCMK_" or (for
 * backward compatibility) \c "HA_" prefix, log and return the value.
 *
 * \param[in] option  Environment variable name (without prefix)
 *
 * \return Value of environment variable, or \c NULL if not set
 */
const char *
pcmk__env_option(const char *option)
{
    // @COMPAT Drop support for "HA_" options eventually
    static const char *const prefixes[] = { "PCMK", "HA" };

    CRM_CHECK(!pcmk__str_empty(option), return NULL);

    for (int i = 0; i < PCMK__NELEM(prefixes); i++) {
        char *env_name = pcmk__assert_asprintf("%s_%s", prefixes[i], option);
        const char *value = getenv(env_name);

        if (value != NULL) {
            pcmk__trace("Found %s = %s", env_name, value);
            free(env_name);
            return value;
        }
        free(env_name);
    }

    pcmk__trace("Nothing found for %s", option);
    return NULL;
}

/*!
 * \internal
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
    static const char *const prefixes[] = { "PCMK", "HA" };

    CRM_CHECK(!pcmk__str_empty(option), return);

    for (int i = 0; i < PCMK__NELEM(prefixes); i++) {
        char *env_name = pcmk__assert_asprintf("%s_%s", prefixes[i], option);
        int rc = 0;

        if (value != NULL) {
            pcmk__trace("Setting %s to %s", env_name, value);
            rc = setenv(env_name, value, 1);
        } else {
            pcmk__trace("Unsetting %s", env_name);
            rc = unsetenv(env_name);
        }

        if (rc < 0) {
            int err = errno;

            pcmk__err("Failed to %sset %s: %s", ((value != NULL)? "" : "un"),
                      env_name, strerror(err));
        }
        free(env_name);

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
    gchar **subsystems = NULL;
    bool enabled = false;

    if (value == NULL) {
        return false;
    }

    if (pcmk__parse_bool(value, &enabled) == pcmk_rc_ok) {
        return enabled;
    }

    /* Value did not parse to a boolean, so try to parse it as a daemon list if
     * we have a daemon name to look for
     */

    if (daemon == NULL) {
        return false;
    }

    subsystems = g_strsplit(value, ",", 0);

    enabled = pcmk__g_strv_contains((const gchar *const *) subsystems, daemon);

    g_strfreev(subsystems);
    return enabled;
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
    return pcmk__parse_bool(value, NULL) == pcmk_rc_ok;
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
                                PCMK_VALUE_FENCE, PCMK_VALUE_FENCE_LEGACY,
                                NULL);
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
                                PCMK_VALUE_DEFAULT, PCMK_VALUE_UTILIZATION,
                                PCMK_VALUE_MINIMAL, PCMK_VALUE_BALANCED, NULL);
}

/*!
 * \internal
 * \brief Check a table of configured options for a particular option
 *
 * \param[in,out] table   Name/value pairs for configured options
 * \param[in]     option  Option to look up
 *
 * \return Option value (from supplied options table or default value)
 */
static const char *
cluster_option_value(GHashTable *table, const pcmk__cluster_option_t *option)
{
    const char *value = NULL;

    pcmk__assert((option != NULL) && (option->name != NULL));

    if (table != NULL) {
        value = g_hash_table_lookup(table, option->name);

        if ((value == NULL) && (option->alt_name != NULL)) {
            value = g_hash_table_lookup(table, option->alt_name);
            if (value != NULL) {
                pcmk__config_warn("Support for legacy name '%s' for cluster "
                                  "option '%s' is deprecated and will be "
                                  "removed in a future release",
                                  option->alt_name, option->name);

                // Inserting copy with current name ensures we only warn once
                pcmk__insert_dup(table, option->name, value);
            }
        }

        if ((value != NULL) && (option->is_valid != NULL)
            && !option->is_valid(value)) {

            pcmk__config_err("Using default value for cluster option '%s' "
                             "because '%s' is invalid", option->name, value);
            value = NULL;
        }

        if (value != NULL) {
            return value;
        }
    }

    // No value found, use default
    value = option->default_value;

    if (value == NULL) {
        pcmk__trace("No value or default provided for cluster option '%s'",
                    option->name);
        return NULL;
    }

    CRM_CHECK((option->is_valid == NULL) || option->is_valid(value),
              pcmk__err("Bug: default value for cluster option '%s' is invalid",
                        option->name);
              return NULL);

    pcmk__trace("Using default value '%s' for cluster option '%s'", value,
                option->name);
    if (table != NULL) {
        pcmk__insert_dup(table, option->name, value);
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
    for (const pcmk__cluster_option_t *option = cluster_options;
         option->name != NULL; option++) {

        if (pcmk__str_eq(name, option->name, pcmk__str_casei)) {
            return cluster_option_value(options, option);
        }
    }
    CRM_CHECK(FALSE, pcmk__err("Bug: looking for unknown option '%s'", name));
    return NULL;
}

/*!
 * \internal
 * \brief Output cluster option metadata as OCF-like XML
 *
 * \param[in,out] out         Output object
 * \param[in]     name        Fake resource agent name for the option list
 * \param[in]     desc_short  Short description of the option list
 * \param[in]     desc_long   Long description of the option list
 * \param[in]     filter      Group of <tt>enum pcmk__opt_flags</tt>; output an
 *                            option only if its \c flags member has all these
 *                            flags set
 * \param[in]     all         If \c true, output all options; otherwise, exclude
 *                            advanced and deprecated options unless
 *                            \c pcmk__opt_advanced and \c pcmk__opt_deprecated
 *                            flags (respectively) are set in \p filter. This is
 *                            always treated as true for XML output objects.
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__output_cluster_options(pcmk__output_t *out, const char *name,
                             const char *desc_short, const char *desc_long,
                             uint32_t filter, bool all)
{
    return out->message(out, "option-list", name, desc_short, desc_long, filter,
                        cluster_options, all);
}

/*!
 * \internal
 * \brief Output primitive resource meta-attributes as OCF-like XML
 *
 * \param[in,out] out         Output object
 * \param[in]     name        Fake resource agent name for the option list
 * \param[in]     desc_short  Short description of the option list
 * \param[in]     desc_long   Long description of the option list
 * \param[in]     all         If \c true, output all options; otherwise, exclude
 *                            advanced and deprecated options. This is always
 *                            treated as true for XML output objects.
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__output_primitive_meta(pcmk__output_t *out, const char *name,
                            const char *desc_short, const char *desc_long,
                            bool all)
{
    return out->message(out, "option-list", name, desc_short, desc_long,
                        pcmk__opt_none, primitive_meta, all);
}

/*!
 * \internal
 * \brief Output fence device common parameter metadata as OCF-like XML
 *
 * These are parameters that are available for all fencing resources, regardless
 * of type. They are processed by Pacemaker, rather than by the fence agent or
 * the fencing library.
 *
 * \param[in,out] out         Output object
 * \param[in]     name        Fake resource agent name for the option list
 * \param[in]     desc_short  Short description of the option list
 * \param[in]     desc_long   Long description of the option list
 * \param[in]     all         If \c true, output all options; otherwise, exclude
 *                            advanced and deprecated options. This is always
 *                            treated as true for XML output objects.
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__output_fencing_params(pcmk__output_t *out, const char *name,
                          const char *desc_short, const char *desc_long,
                          bool all)
{
    return out->message(out, "option-list", name, desc_short, desc_long,
                        pcmk__opt_none, fencing_params, all);
}

/*!
 * \internal
 * \brief Output a list of cluster options for a daemon
 *
 * \brief[in,out] out         Output object
 * \brief[in]     name        Daemon name
 * \brief[in]     desc_short  Short description of the option list
 * \brief[in]     desc_long   Long description of the option list
 * \brief[in]     filter      <tt>enum pcmk__opt_flags</tt> flag corresponding
 *                            to daemon
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__daemon_metadata(pcmk__output_t *out, const char *name,
                      const char *desc_short, const char *desc_long,
                      enum pcmk__opt_flags filter)
{
    // @COMPAT Drop this function when we drop daemon metadata
    pcmk__output_t *tmp_out = NULL;
    xmlNode *top = NULL;
    const xmlNode *metadata = NULL;
    GString *metadata_s = NULL;

    int rc = pcmk__output_new(&tmp_out, "xml", "/dev/null", NULL);

    if (rc != pcmk_rc_ok) {
        return rc;
    }

    pcmk__output_set_legacy_xml(tmp_out);

    if (filter == pcmk__opt_fencing) {
        pcmk__output_fencing_params(tmp_out, name, desc_short, desc_long, true);
    } else {
        pcmk__output_cluster_options(tmp_out, name, desc_short, desc_long,
                                     (uint32_t) filter, true);
    }

    tmp_out->finish(tmp_out, CRM_EX_OK, false, (void **) &top);
    metadata = pcmk__xe_first_child(top, PCMK_XE_RESOURCE_AGENT, NULL, NULL);

    metadata_s = g_string_sized_new(16384);
    pcmk__xml_string(metadata, pcmk__xml_fmt_pretty|pcmk__xml_fmt_text,
                     metadata_s, 0);

    out->output_xml(out, PCMK_XE_METADATA, metadata_s->str);

    pcmk__output_free(tmp_out);
    pcmk__xml_free(top);
    g_string_free(metadata_s, TRUE);
    return pcmk_rc_ok;
}

void
pcmk__validate_cluster_options(GHashTable *options)
{
    for (const pcmk__cluster_option_t *option = cluster_options;
         option->name != NULL; option++) {

        cluster_option_value(options, option);
    }
}
