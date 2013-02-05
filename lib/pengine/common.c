/* 
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
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

static gboolean
check_quorum(const char *value)
{
    if (safe_str_eq(value, "stop")) {
        return TRUE;

    } else if (safe_str_eq(value, "freeze")) {
        return TRUE;

    } else if (safe_str_eq(value, "ignore")) {
        return TRUE;

    } else if (safe_str_eq(value, "suicide")) {
        return TRUE;
    }
    return FALSE;
}

static gboolean
check_health(const char *value)
{
    if (safe_str_eq(value, "none")) {
        return TRUE;

    } else if (safe_str_eq(value, "custom")) {
        return TRUE;

    } else if (safe_str_eq(value, "only-green")) {
        return TRUE;

    } else if (safe_str_eq(value, "progressive")) {
        return TRUE;

    } else if (safe_str_eq(value, "migrate-on-red")) {
        return TRUE;
    }
    return FALSE;
}

static gboolean
check_stonith_action(const char *value)
{
    if (safe_str_eq(value, "reboot")) {
        return TRUE;

    } else if (safe_str_eq(value, "poweroff")) {
        return TRUE;

    } else if (safe_str_eq(value, "off")) {
        return TRUE;
    }
    return FALSE;
}

static gboolean
check_placement_strategy(const char *value)
{
    if (safe_str_eq(value, "default")) {
        return TRUE;

    } else if (safe_str_eq(value, "utilization")) {
        return TRUE;

    } else if (safe_str_eq(value, "minimal")) {
        return TRUE;

    } else if (safe_str_eq(value, "balanced")) {
        return TRUE;
    }
    return FALSE;
}

/* *INDENT-OFF* */
pe_cluster_option pe_opts[] = {
	/* name, old-name, validate, default, description */
	{ "no-quorum-policy", "no_quorum_policy", "enum", "stop, freeze, ignore, suicide", "stop", &check_quorum,
	  "What to do when the cluster does not have quorum", NULL },
	{ "symmetric-cluster", "symmetric_cluster", "boolean", NULL, "true", &check_boolean,
	  "All resources can run anywhere by default", NULL },
	{ "default-resource-stickiness", "default_resource_stickiness", "integer", NULL, "0", &check_number, "", NULL },
	{ "is-managed-default", "is_managed_default", "boolean", NULL, "true", &check_boolean,
	  "Should the cluster start/stop resources as required", NULL },
	{ "maintenance-mode", NULL, "boolean", NULL, "false", &check_boolean,
	  "Should the cluster monitor resources and start/stop them as required", NULL },
	{ "start-failure-is-fatal", NULL, "boolean", NULL, "true", &check_boolean, "Always treat start failures as fatal",
	  "This was the old default.  However when set to FALSE, the cluster will instead use the resource's failcount and value for resource-failure-stickiness" },
	{ "enable-startup-probes", NULL, "boolean", NULL, "true", &check_boolean,
	  "Should the cluster check for active resources during startup", NULL },

	/* Stonith Options */
	{ "stonith-enabled", "stonith_enabled", "boolean", NULL, "true", &check_boolean,
	  "Failed nodes are STONITH'd", NULL },
	{ "stonith-action", "stonith_action", "enum", "reboot, poweroff, off", "reboot", &check_stonith_action,
	  "Action to send to STONITH device", NULL },
	{ "stonith-timeout", NULL, "time", NULL, "60s", &check_timer,
	  "How long to wait for the STONITH action to complete", NULL },
	{ "startup-fencing", "startup_fencing", "boolean", NULL, "true", &check_boolean,
	  "STONITH unseen nodes", "Advanced Use Only!  Not using the default is very unsafe!" },

	/* Timeouts etc */
	{ "cluster-delay", "transition_idle_timeout", "time", NULL, "60s", &check_time,
	  "Round trip delay over the network (excluding action execution)",
	  "The \"correct\" value will depend on the speed and load of your network and cluster nodes." },
	{ "batch-limit", NULL, "integer", NULL, "30", &check_number,
	  "The number of jobs that the TE is allowed to execute in parallel",
	  "The \"correct\" value will depend on the speed and load of your network and cluster nodes." },
	{ "migration-limit", NULL, "integer", NULL, "-1", &check_number,
	  "The number of migration jobs that the TE is allowed to execute in parallel on a node"},
	{ "default-action-timeout", "default_action_timeout", "time", NULL, "20s", &check_time,
	  "How long to wait for actions to complete", NULL },

	/* Orphans and stopping */
	{ "stop-all-resources", NULL, "boolean", NULL, "false", &check_boolean,
	  "Should the cluster stop all active resources (except those needed for fencing)", NULL },
	{ "stop-orphan-resources", "stop_orphan_resources", "boolean", NULL, "true", &check_boolean,
	  "Should deleted resources be stopped", NULL },
	{ "stop-orphan-actions", "stop_orphan_actions", "boolean", NULL, "true", &check_boolean,
	  "Should deleted actions be cancelled", NULL },
 	{ "remove-after-stop", "remove_after_stop", "boolean", NULL, "false", &check_boolean,
	  "Remove resources from the LRM after they are stopped",
	  "Always set this to false.  Other values are, at best, poorly tested and potentially dangerous." },
/* 	{ "", "", , "0", "", NULL }, */

	/* Storing inputs */
	{ "pe-error-series-max", NULL, "integer", NULL, "-1", &check_number,
	  "The number of PE inputs resulting in ERRORs to save", "Zero to disable, -1 to store unlimited." },
	{ "pe-warn-series-max",  NULL, "integer", NULL, "5000", &check_number,
	  "The number of PE inputs resulting in WARNINGs to save", "Zero to disable, -1 to store unlimited." },
	{ "pe-input-series-max", NULL, "integer", NULL, "4000", &check_number,
	  "The number of other PE inputs to save", "Zero to disable, -1 to store unlimited." },

	/* Node health */
	{ "node-health-strategy", NULL, "enum", "none, migrate-on-red, only-green, progressive, custom", "none", &check_health,
	  "The strategy combining node attributes to determine overall node health.",
	  "Requires external entities to create node attributes (named with the prefix '#health') with values: 'red', 'yellow' or 'green'."},
	{ "node-health-green", NULL, "integer", NULL, "0", &check_number,
	  "The score 'green' translates to in rsc_location constraints",
	  "Only used when node-health-strategy is set to custom or progressive." },
	{ "node-health-yellow", NULL, "integer", NULL, "0", &check_number,
	  "The score 'yellow' translates to in rsc_location constraints",
	  "Only used when node-health-strategy is set to custom or progressive." },
	{ "node-health-red", NULL, "integer", NULL, "-INFINITY", &check_number,
	  "The score 'red' translates to in rsc_location constraints",
	  "Only used when node-health-strategy is set to custom or progressive." },

	/*Placement Strategy*/
	{ "placement-strategy", NULL, "enum", "default, utilization, minimal, balanced", "default", &check_placement_strategy,
	  "The strategy to determine resource placement", NULL},
};
/* *INDENT-ON* */

void
pe_metadata(void)
{
    config_metadata("Policy Engine", "1.0",
                    "Policy Engine Options",
                    "This is a fake resource that details the options that can be configured for the Policy Engine.",
                    pe_opts, DIMOF(pe_opts));
}

void
verify_pe_options(GHashTable * options)
{
    verify_all_options(options, pe_opts, DIMOF(pe_opts));
}

const char *
pe_pref(GHashTable * options, const char *name)
{
    return get_cluster_pref(options, pe_opts, DIMOF(pe_opts), name);
}

const char *
fail2text(enum action_fail_response fail)
{
    const char *result = "<unknown>";

    switch (fail) {
        case action_fail_ignore:
            result = "ignore";
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
    }
    return result;
}

enum action_tasks
text2task(const char *task)
{
    if (safe_str_eq(task, CRMD_ACTION_STOP)) {
        return stop_rsc;
    } else if (safe_str_eq(task, CRMD_ACTION_STOPPED)) {
        return stopped_rsc;
    } else if (safe_str_eq(task, CRMD_ACTION_START)) {
        return start_rsc;
    } else if (safe_str_eq(task, CRMD_ACTION_STARTED)) {
        return started_rsc;
    } else if (safe_str_eq(task, CRM_OP_SHUTDOWN)) {
        return shutdown_crm;
    } else if (safe_str_eq(task, CRM_OP_FENCE)) {
        return stonith_node;
    } else if (safe_str_eq(task, CRMD_ACTION_STATUS)) {
        return monitor_rsc;
    } else if (safe_str_eq(task, CRMD_ACTION_NOTIFY)) {
        return action_notify;
    } else if (safe_str_eq(task, CRMD_ACTION_NOTIFIED)) {
        return action_notified;
    } else if (safe_str_eq(task, CRMD_ACTION_PROMOTE)) {
        return action_promote;
    } else if (safe_str_eq(task, CRMD_ACTION_DEMOTE)) {
        return action_demote;
    } else if (safe_str_eq(task, CRMD_ACTION_PROMOTED)) {
        return action_promoted;
    } else if (safe_str_eq(task, CRMD_ACTION_DEMOTED)) {
        return action_demoted;
    }
#if SUPPORT_TRACING
    if (safe_str_eq(task, CRMD_ACTION_CANCEL)) {
        return no_action;
    } else if (safe_str_eq(task, CRMD_ACTION_DELETE)) {
        return no_action;
    } else if (safe_str_eq(task, CRMD_ACTION_STATUS)) {
        return no_action;
    } else if (safe_str_eq(task, CRM_OP_PROBED)) {
        return no_action;
    } else if (safe_str_eq(task, CRM_OP_LRM_REFRESH)) {
        return no_action;
    } else if (safe_str_eq(task, CRMD_ACTION_MIGRATE)) {
        return no_action;
    } else if (safe_str_eq(task, CRMD_ACTION_MIGRATED)) {
        return no_action;
    } else if (safe_str_eq(task, "fail")) {
        return no_action;
    } else if (safe_str_eq(task, "stonith_up")) {
        return no_action;
    } else if (safe_str_eq(task, "stonith_complete")) {
        return no_action;
    } else if (safe_str_eq(task, "all_stopped")) {
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
    CRM_CHECK(role >= RSC_ROLE_UNKNOWN, return RSC_ROLE_UNKNOWN_S);
    CRM_CHECK(role < RSC_ROLE_MAX, return RSC_ROLE_UNKNOWN_S);
    switch (role) {
        case RSC_ROLE_UNKNOWN:
            return RSC_ROLE_UNKNOWN_S;
        case RSC_ROLE_STOPPED:
            return RSC_ROLE_STOPPED_S;
        case RSC_ROLE_STARTED:
            return RSC_ROLE_STARTED_S;
        case RSC_ROLE_SLAVE:
            return RSC_ROLE_SLAVE_S;
        case RSC_ROLE_MASTER:
            return RSC_ROLE_MASTER_S;
    }
    return RSC_ROLE_UNKNOWN_S;
}

enum rsc_role_e
text2role(const char *role)
{
    CRM_ASSERT(role != NULL);
    if (safe_str_eq(role, RSC_ROLE_STOPPED_S)) {
        return RSC_ROLE_STOPPED;
    } else if (safe_str_eq(role, RSC_ROLE_STARTED_S)) {
        return RSC_ROLE_STARTED;
    } else if (safe_str_eq(role, RSC_ROLE_SLAVE_S)) {
        return RSC_ROLE_SLAVE;
    } else if (safe_str_eq(role, RSC_ROLE_MASTER_S)) {
        return RSC_ROLE_MASTER;
    } else if (safe_str_eq(role, RSC_ROLE_UNKNOWN_S)) {
        return RSC_ROLE_UNKNOWN;
    }
    crm_err("Unknown role: %s", role);
    return RSC_ROLE_UNKNOWN;
}

int
merge_weights(int w1, int w2)
{
    int result = w1 + w2;

    if (w1 <= -INFINITY || w2 <= -INFINITY) {
        if (w1 >= INFINITY || w2 >= INFINITY) {
            crm_trace("-INFINITY + INFINITY == -INFINITY");
        }
        return -INFINITY;

    } else if (w1 >= INFINITY || w2 >= INFINITY) {
        return INFINITY;
    }

    /* detect wrap-around */
    if (result > 0) {
        if (w1 <= 0 && w2 < 0) {
            result = -INFINITY;
        }

    } else if (w1 > 0 && w2 > 0) {
        result = INFINITY;
    }

    /* detect +/- INFINITY */
    if (result >= INFINITY) {
        result = INFINITY;

    } else if (result <= -INFINITY) {
        result = -INFINITY;
    }

    crm_trace("%d + %d = %d", w1, w2, result);
    return result;
}

void
add_hash_param(GHashTable * hash, const char *name, const char *value)
{
    CRM_CHECK(hash != NULL, return);

    crm_trace("adding: name=%s value=%s", crm_str(name), crm_str(value));
    if (name == NULL || value == NULL) {
        return;

    } else if (safe_str_eq(value, "#default")) {
        return;

    } else if (g_hash_table_lookup(hash, name) == NULL) {
        g_hash_table_insert(hash, strdup(name), strdup(value));
    }
}
