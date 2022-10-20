/*
 * Copyright 2004-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>
#include <string.h>
#include <glib.h>
#include <time.h>

#include <crm/crm.h>
#include <crm/services.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/xml_internal.h>

#include <crm/common/util.h>
#include <crm/pengine/rules.h>
#include <crm/pengine/internal.h>
#include <pe_status_private.h>

CRM_TRACE_INIT_DATA(pe_status);

/* This uses pcmk__set_flags_as()/pcmk__clear_flags_as() directly rather than
 * use pe__set_working_set_flags()/pe__clear_working_set_flags() so that the
 * flag is stringified more readably in log messages.
 */
#define set_config_flag(data_set, option, flag) do {                        \
        const char *scf_value = pe_pref((data_set)->config_hash, (option)); \
        if (scf_value != NULL) {                                            \
            if (crm_is_true(scf_value)) {                                   \
                (data_set)->flags = pcmk__set_flags_as(__func__, __LINE__,  \
                                    LOG_TRACE, "Working set",               \
                                    crm_system_name, (data_set)->flags,     \
                                    (flag), #flag);                         \
            } else {                                                        \
                (data_set)->flags = pcmk__clear_flags_as(__func__, __LINE__,\
                                    LOG_TRACE, "Working set",               \
                                    crm_system_name, (data_set)->flags,     \
                                    (flag), #flag);                         \
            }                                                               \
        }                                                                   \
    } while(0)

static void unpack_rsc_op(pe_resource_t *rsc, pe_node_t *node, xmlNode *xml_op,
                          xmlNode **last_failure,
                          enum action_fail_response *failed,
                          pe_working_set_t *data_set);
static void determine_remote_online_status(pe_working_set_t *data_set,
                                           pe_node_t *this_node);
static void add_node_attrs(xmlNode *attrs, pe_node_t *node, bool overwrite,
                           pe_working_set_t *data_set);
static void determine_online_status(xmlNode *node_state, pe_node_t *this_node,
                                    pe_working_set_t *data_set);

static void unpack_node_lrm(pe_node_t *node, xmlNode *xml,
                            pe_working_set_t *data_set);


// Bitmask for warnings we only want to print once
uint32_t pe_wo = 0;

static gboolean
is_dangling_guest_node(pe_node_t *node)
{
    /* we are looking for a remote-node that was supposed to be mapped to a
     * container resource, but all traces of that container have disappeared 
     * from both the config and the status section. */
    if (pe__is_guest_or_remote_node(node) &&
        node->details->remote_rsc &&
        node->details->remote_rsc->container == NULL &&
        pcmk_is_set(node->details->remote_rsc->flags,
                    pe_rsc_orphan_container_filler)) {
        return TRUE;
    }

    return FALSE;
}

/*!
 * \brief Schedule a fence action for a node
 *
 * \param[in,out] data_set  Current working set of cluster
 * \param[in,out] node      Node to fence
 * \param[in]     reason    Text description of why fencing is needed
 * \param[in]     priority_delay  Whether to consider `priority-fencing-delay`
 */
void
pe_fence_node(pe_working_set_t * data_set, pe_node_t * node,
              const char *reason, bool priority_delay)
{
    CRM_CHECK(node, return);

    /* A guest node is fenced by marking its container as failed */
    if (pe__is_guest_node(node)) {
        pe_resource_t *rsc = node->details->remote_rsc->container;

        if (!pcmk_is_set(rsc->flags, pe_rsc_failed)) {
            if (!pcmk_is_set(rsc->flags, pe_rsc_managed)) {
                crm_notice("Not fencing guest node %s "
                           "(otherwise would because %s): "
                           "its guest resource %s is unmanaged",
                           pe__node_name(node), reason, rsc->id);
            } else {
                crm_warn("Guest node %s will be fenced "
                         "(by recovering its guest resource %s): %s",
                         pe__node_name(node), rsc->id, reason);

                /* We don't mark the node as unclean because that would prevent the
                 * node from running resources. We want to allow it to run resources
                 * in this transition if the recovery succeeds.
                 */
                node->details->remote_requires_reset = TRUE;
                pe__set_resource_flags(rsc, pe_rsc_failed|pe_rsc_stop);
            }
        }

    } else if (is_dangling_guest_node(node)) {
        crm_info("Cleaning up dangling connection for guest node %s: "
                 "fencing was already done because %s, "
                 "and guest resource no longer exists",
                 pe__node_name(node), reason);
        pe__set_resource_flags(node->details->remote_rsc,
                               pe_rsc_failed|pe_rsc_stop);

    } else if (pe__is_remote_node(node)) {
        pe_resource_t *rsc = node->details->remote_rsc;

        if ((rsc != NULL) && !pcmk_is_set(rsc->flags, pe_rsc_managed)) {
            crm_notice("Not fencing remote node %s "
                       "(otherwise would because %s): connection is unmanaged",
                       pe__node_name(node), reason);
        } else if(node->details->remote_requires_reset == FALSE) {
            node->details->remote_requires_reset = TRUE;
            crm_warn("Remote node %s %s: %s",
                     pe__node_name(node),
                     pe_can_fence(data_set, node)? "will be fenced" : "is unclean",
                     reason);
        }
        node->details->unclean = TRUE;
        // No need to apply `priority-fencing-delay` for remote nodes
        pe_fence_op(node, NULL, TRUE, reason, FALSE, data_set);

    } else if (node->details->unclean) {
        crm_trace("Cluster node %s %s because %s",
                  pe__node_name(node),
                  pe_can_fence(data_set, node)? "would also be fenced" : "also is unclean",
                  reason);

    } else {
        crm_warn("Cluster node %s %s: %s",
                 pe__node_name(node),
                 pe_can_fence(data_set, node)? "will be fenced" : "is unclean",
                 reason);
        node->details->unclean = TRUE;
        pe_fence_op(node, NULL, TRUE, reason, priority_delay, data_set);
    }
}

// @TODO xpaths can't handle templates, rules, or id-refs

// nvpair with provides or requires set to unfencing
#define XPATH_UNFENCING_NVPAIR XML_CIB_TAG_NVPAIR                \
    "[(@" XML_NVPAIR_ATTR_NAME "='" PCMK_STONITH_PROVIDES "'"    \
    "or @" XML_NVPAIR_ATTR_NAME "='" XML_RSC_ATTR_REQUIRES "') " \
    "and @" XML_NVPAIR_ATTR_VALUE "='" PCMK__VALUE_UNFENCING "']"

// unfencing in rsc_defaults or any resource
#define XPATH_ENABLE_UNFENCING \
    "/" XML_TAG_CIB "/" XML_CIB_TAG_CONFIGURATION "/" XML_CIB_TAG_RESOURCES   \
    "//" XML_TAG_META_SETS "/" XPATH_UNFENCING_NVPAIR                                               \
    "|/" XML_TAG_CIB "/" XML_CIB_TAG_CONFIGURATION "/" XML_CIB_TAG_RSCCONFIG  \
    "/" XML_TAG_META_SETS "/" XPATH_UNFENCING_NVPAIR

static void
set_if_xpath(uint64_t flag, const char *xpath, pe_working_set_t *data_set)
{
    xmlXPathObjectPtr result = NULL;

    if (!pcmk_is_set(data_set->flags, flag)) {
        result = xpath_search(data_set->input, xpath);
        if (result && (numXpathResults(result) > 0)) {
            pe__set_working_set_flags(data_set, flag);
        }
        freeXpathObject(result);
    }
}

gboolean
unpack_config(xmlNode * config, pe_working_set_t * data_set)
{
    const char *value = NULL;
    GHashTable *config_hash = pcmk__strkey_table(free, free);

    pe_rule_eval_data_t rule_data = {
        .node_hash = NULL,
        .role = RSC_ROLE_UNKNOWN,
        .now = data_set->now,
        .match_data = NULL,
        .rsc_data = NULL,
        .op_data = NULL
    };

    data_set->config_hash = config_hash;

    pe__unpack_dataset_nvpairs(config, XML_CIB_TAG_PROPSET, &rule_data, config_hash,
                               CIB_OPTIONS_FIRST, FALSE, data_set);

    verify_pe_options(data_set->config_hash);

    set_config_flag(data_set, "enable-startup-probes", pe_flag_startup_probes);
    if (!pcmk_is_set(data_set->flags, pe_flag_startup_probes)) {
        crm_info("Startup probes: disabled (dangerous)");
    }

    value = pe_pref(data_set->config_hash, XML_ATTR_HAVE_WATCHDOG);
    if (value && crm_is_true(value)) {
        crm_info("Watchdog-based self-fencing will be performed via SBD if "
                 "fencing is required and stonith-watchdog-timeout is nonzero");
        pe__set_working_set_flags(data_set, pe_flag_have_stonith_resource);
    }

    /* Set certain flags via xpath here, so they can be used before the relevant
     * configuration sections are unpacked.
     */
    set_if_xpath(pe_flag_enable_unfencing, XPATH_ENABLE_UNFENCING, data_set);

    value = pe_pref(data_set->config_hash, "stonith-timeout");
    data_set->stonith_timeout = (int) crm_parse_interval_spec(value);
    crm_debug("STONITH timeout: %d", data_set->stonith_timeout);

    set_config_flag(data_set, "stonith-enabled", pe_flag_stonith_enabled);
    crm_debug("STONITH of failed nodes is %s",
              pcmk_is_set(data_set->flags, pe_flag_stonith_enabled)? "enabled" : "disabled");

    data_set->stonith_action = pe_pref(data_set->config_hash, "stonith-action");
    if (!strcmp(data_set->stonith_action, "poweroff")) {
        pe_warn_once(pe_wo_poweroff,
                     "Support for stonith-action of 'poweroff' is deprecated "
                     "and will be removed in a future release (use 'off' instead)");
        data_set->stonith_action = "off";
    }
    crm_trace("STONITH will %s nodes", data_set->stonith_action);

    set_config_flag(data_set, "concurrent-fencing", pe_flag_concurrent_fencing);
    crm_debug("Concurrent fencing is %s",
              pcmk_is_set(data_set->flags, pe_flag_concurrent_fencing)? "enabled" : "disabled");

    value = pe_pref(data_set->config_hash,
                    XML_CONFIG_ATTR_PRIORITY_FENCING_DELAY);
    if (value) {
        data_set->priority_fencing_delay = crm_parse_interval_spec(value) / 1000;
        crm_trace("Priority fencing delay is %ds", data_set->priority_fencing_delay);
    }

    set_config_flag(data_set, "stop-all-resources", pe_flag_stop_everything);
    crm_debug("Stop all active resources: %s",
              pcmk__btoa(pcmk_is_set(data_set->flags, pe_flag_stop_everything)));

    set_config_flag(data_set, "symmetric-cluster", pe_flag_symmetric_cluster);
    if (pcmk_is_set(data_set->flags, pe_flag_symmetric_cluster)) {
        crm_debug("Cluster is symmetric" " - resources can run anywhere by default");
    }

    value = pe_pref(data_set->config_hash, "no-quorum-policy");

    if (pcmk__str_eq(value, "ignore", pcmk__str_casei)) {
        data_set->no_quorum_policy = no_quorum_ignore;

    } else if (pcmk__str_eq(value, "freeze", pcmk__str_casei)) {
        data_set->no_quorum_policy = no_quorum_freeze;

    } else if (pcmk__str_eq(value, "demote", pcmk__str_casei)) {
        data_set->no_quorum_policy = no_quorum_demote;

    } else if (pcmk__str_eq(value, "suicide", pcmk__str_casei)) {
        if (pcmk_is_set(data_set->flags, pe_flag_stonith_enabled)) {
            int do_panic = 0;

            crm_element_value_int(data_set->input, XML_ATTR_QUORUM_PANIC,
                                  &do_panic);
            if (do_panic || pcmk_is_set(data_set->flags, pe_flag_have_quorum)) {
                data_set->no_quorum_policy = no_quorum_suicide;
            } else {
                crm_notice("Resetting no-quorum-policy to 'stop': cluster has never had quorum");
                data_set->no_quorum_policy = no_quorum_stop;
            }
        } else {
            pcmk__config_err("Resetting no-quorum-policy to 'stop' because "
                             "fencing is disabled");
            data_set->no_quorum_policy = no_quorum_stop;
        }

    } else {
        data_set->no_quorum_policy = no_quorum_stop;
    }

    switch (data_set->no_quorum_policy) {
        case no_quorum_freeze:
            crm_debug("On loss of quorum: Freeze resources");
            break;
        case no_quorum_stop:
            crm_debug("On loss of quorum: Stop ALL resources");
            break;
        case no_quorum_demote:
            crm_debug("On loss of quorum: "
                      "Demote promotable resources and stop other resources");
            break;
        case no_quorum_suicide:
            crm_notice("On loss of quorum: Fence all remaining nodes");
            break;
        case no_quorum_ignore:
            crm_notice("On loss of quorum: Ignore");
            break;
    }

    set_config_flag(data_set, "stop-orphan-resources", pe_flag_stop_rsc_orphans);
    crm_trace("Orphan resources are %s",
              pcmk_is_set(data_set->flags, pe_flag_stop_rsc_orphans)? "stopped" : "ignored");

    set_config_flag(data_set, "stop-orphan-actions", pe_flag_stop_action_orphans);
    crm_trace("Orphan resource actions are %s",
              pcmk_is_set(data_set->flags, pe_flag_stop_action_orphans)? "stopped" : "ignored");

    value = pe_pref(data_set->config_hash, "remove-after-stop");
    if (value != NULL) {
        if (crm_is_true(value)) {
            pe__set_working_set_flags(data_set, pe_flag_remove_after_stop);
#ifndef PCMK__COMPAT_2_0
            pe_warn_once(pe_wo_remove_after,
                         "Support for the remove-after-stop cluster property is"
                         " deprecated and will be removed in a future release");
#endif
        } else {
            pe__clear_working_set_flags(data_set, pe_flag_remove_after_stop);
        }
    }

    set_config_flag(data_set, "maintenance-mode", pe_flag_maintenance_mode);
    crm_trace("Maintenance mode: %s",
              pcmk__btoa(pcmk_is_set(data_set->flags, pe_flag_maintenance_mode)));

    set_config_flag(data_set, "start-failure-is-fatal", pe_flag_start_failure_fatal);
    crm_trace("Start failures are %s",
              pcmk_is_set(data_set->flags, pe_flag_start_failure_fatal)? "always fatal" : "handled by failcount");

    if (pcmk_is_set(data_set->flags, pe_flag_stonith_enabled)) {
        set_config_flag(data_set, "startup-fencing", pe_flag_startup_fencing);
    }
    if (pcmk_is_set(data_set->flags, pe_flag_startup_fencing)) {
        crm_trace("Unseen nodes will be fenced");
    } else {
        pe_warn_once(pe_wo_blind, "Blind faith: not fencing unseen nodes");
    }

    pe__unpack_node_health_scores(data_set);

    data_set->placement_strategy = pe_pref(data_set->config_hash, "placement-strategy");
    crm_trace("Placement strategy: %s", data_set->placement_strategy);

    set_config_flag(data_set, "shutdown-lock", pe_flag_shutdown_lock);
    crm_trace("Resources will%s be locked to cleanly shut down nodes",
              (pcmk_is_set(data_set->flags, pe_flag_shutdown_lock)? "" : " not"));
    if (pcmk_is_set(data_set->flags, pe_flag_shutdown_lock)) {
        value = pe_pref(data_set->config_hash,
                        XML_CONFIG_ATTR_SHUTDOWN_LOCK_LIMIT);
        data_set->shutdown_lock = crm_parse_interval_spec(value) / 1000;
        crm_trace("Shutdown locks expire after %us", data_set->shutdown_lock);
    }

    return TRUE;
}

pe_node_t *
pe_create_node(const char *id, const char *uname, const char *type,
               const char *score, pe_working_set_t * data_set)
{
    pe_node_t *new_node = NULL;

    if (pe_find_node(data_set->nodes, uname) != NULL) {
        pcmk__config_warn("More than one node entry has name '%s'", uname);
    }

    new_node = calloc(1, sizeof(pe_node_t));
    if (new_node == NULL) {
        return NULL;
    }

    new_node->weight = char2score(score);
    new_node->fixed = FALSE;
    new_node->details = calloc(1, sizeof(struct pe_node_shared_s));

    if (new_node->details == NULL) {
        free(new_node);
        return NULL;
    }

    crm_trace("Creating node for entry %s/%s", uname, id);
    new_node->details->id = id;
    new_node->details->uname = uname;
    new_node->details->online = FALSE;
    new_node->details->shutdown = FALSE;
    new_node->details->rsc_discovery_enabled = TRUE;
    new_node->details->running_rsc = NULL;
    new_node->details->data_set = data_set;

    if (pcmk__str_eq(type, "member", pcmk__str_null_matches | pcmk__str_casei)) {
        new_node->details->type = node_member;

    } else if (pcmk__str_eq(type, "remote", pcmk__str_casei)) {
        new_node->details->type = node_remote;
        pe__set_working_set_flags(data_set, pe_flag_have_remote_nodes);

    } else {
        /* @COMPAT 'ping' is the default for backward compatibility, but it
         * should be changed to 'member' at a compatibility break
         */
        if (!pcmk__str_eq(type, "ping", pcmk__str_casei)) {
            pcmk__config_warn("Node %s has unrecognized type '%s', "
                              "assuming 'ping'", pcmk__s(uname, "without name"),
                              type);
        }
        pe_warn_once(pe_wo_ping_node,
                     "Support for nodes of type 'ping' (such as %s) is "
                     "deprecated and will be removed in a future release",
                     pcmk__s(uname, "unnamed node"));
        new_node->details->type = node_ping;
    }

    new_node->details->attrs = pcmk__strkey_table(free, free);

    if (pe__is_guest_or_remote_node(new_node)) {
        g_hash_table_insert(new_node->details->attrs, strdup(CRM_ATTR_KIND),
                            strdup("remote"));
    } else {
        g_hash_table_insert(new_node->details->attrs, strdup(CRM_ATTR_KIND),
                            strdup("cluster"));
    }

    new_node->details->utilization = pcmk__strkey_table(free, free);
    new_node->details->digest_cache = pcmk__strkey_table(free,
                                                          pe__free_digests);

    data_set->nodes = g_list_insert_sorted(data_set->nodes, new_node,
                                           pe__cmp_node_name);
    return new_node;
}

static const char *
expand_remote_rsc_meta(xmlNode *xml_obj, xmlNode *parent, pe_working_set_t *data)
{
    xmlNode *attr_set = NULL;
    xmlNode *attr = NULL;

    const char *container_id = ID(xml_obj);
    const char *remote_name = NULL;
    const char *remote_server = NULL;
    const char *remote_port = NULL;
    const char *connect_timeout = "60s";
    const char *remote_allow_migrate=NULL;
    const char *is_managed = NULL;

    for (attr_set = pcmk__xe_first_child(xml_obj); attr_set != NULL;
         attr_set = pcmk__xe_next(attr_set)) {

        if (!pcmk__str_eq((const char *)attr_set->name, XML_TAG_META_SETS,
                          pcmk__str_casei)) {
            continue;
        }

        for (attr = pcmk__xe_first_child(attr_set); attr != NULL;
             attr = pcmk__xe_next(attr)) {
            const char *value = crm_element_value(attr, XML_NVPAIR_ATTR_VALUE);
            const char *name = crm_element_value(attr, XML_NVPAIR_ATTR_NAME);

            if (pcmk__str_eq(name, XML_RSC_ATTR_REMOTE_NODE, pcmk__str_casei)) {
                remote_name = value;
            } else if (pcmk__str_eq(name, "remote-addr", pcmk__str_casei)) {
                remote_server = value;
            } else if (pcmk__str_eq(name, "remote-port", pcmk__str_casei)) {
                remote_port = value;
            } else if (pcmk__str_eq(name, "remote-connect-timeout", pcmk__str_casei)) {
                connect_timeout = value;
            } else if (pcmk__str_eq(name, "remote-allow-migrate", pcmk__str_casei)) {
                remote_allow_migrate=value;
            } else if (pcmk__str_eq(name, XML_RSC_ATTR_MANAGED, pcmk__str_casei)) {
                is_managed = value;
            }
        }
    }

    if (remote_name == NULL) {
        return NULL;
    }

    if (pe_find_resource(data->resources, remote_name) != NULL) {
        return NULL;
    }

    pe_create_remote_xml(parent, remote_name, container_id,
                         remote_allow_migrate, is_managed,
                         connect_timeout, remote_server, remote_port);
    return remote_name;
}

static void
handle_startup_fencing(pe_working_set_t *data_set, pe_node_t *new_node)
{
    if ((new_node->details->type == node_remote) && (new_node->details->remote_rsc == NULL)) {
        /* Ignore fencing for remote nodes that don't have a connection resource
         * associated with them. This happens when remote node entries get left
         * in the nodes section after the connection resource is removed.
         */
        return;
    }

    if (pcmk_is_set(data_set->flags, pe_flag_startup_fencing)) {
        // All nodes are unclean until we've seen their status entry
        new_node->details->unclean = TRUE;

    } else {
        // Blind faith ...
        new_node->details->unclean = FALSE;
    }

    /* We need to be able to determine if a node's status section
     * exists or not separate from whether the node is unclean. */
    new_node->details->unseen = TRUE;
}

gboolean
unpack_nodes(xmlNode * xml_nodes, pe_working_set_t * data_set)
{
    xmlNode *xml_obj = NULL;
    pe_node_t *new_node = NULL;
    const char *id = NULL;
    const char *uname = NULL;
    const char *type = NULL;
    const char *score = NULL;

    pe_rule_eval_data_t rule_data = {
        .node_hash = NULL,
        .role = RSC_ROLE_UNKNOWN,
        .now = data_set->now,
        .match_data = NULL,
        .rsc_data = NULL,
        .op_data = NULL
    };

    for (xml_obj = pcmk__xe_first_child(xml_nodes); xml_obj != NULL;
         xml_obj = pcmk__xe_next(xml_obj)) {

        if (pcmk__str_eq((const char *)xml_obj->name, XML_CIB_TAG_NODE, pcmk__str_none)) {
            new_node = NULL;

            id = crm_element_value(xml_obj, XML_ATTR_ID);
            uname = crm_element_value(xml_obj, XML_ATTR_UNAME);
            type = crm_element_value(xml_obj, XML_ATTR_TYPE);
            score = crm_element_value(xml_obj, XML_RULE_ATTR_SCORE);
            crm_trace("Processing node %s/%s", uname, id);

            if (id == NULL) {
                pcmk__config_err("Ignoring <" XML_CIB_TAG_NODE
                                 "> entry in configuration without id");
                continue;
            }
            new_node = pe_create_node(id, uname, type, score, data_set);

            if (new_node == NULL) {
                return FALSE;
            }

            handle_startup_fencing(data_set, new_node);

            add_node_attrs(xml_obj, new_node, FALSE, data_set);
            pe__unpack_dataset_nvpairs(xml_obj, XML_TAG_UTILIZATION, &rule_data,
                                       new_node->details->utilization, NULL,
                                       FALSE, data_set);

            crm_trace("Done with node %s", crm_element_value(xml_obj, XML_ATTR_UNAME));
        }
    }

    if (data_set->localhost && pe_find_node(data_set->nodes, data_set->localhost) == NULL) {
        crm_info("Creating a fake local node");
        pe_create_node(data_set->localhost, data_set->localhost, NULL, 0,
                       data_set);
    }

    return TRUE;
}

static void
setup_container(pe_resource_t * rsc, pe_working_set_t * data_set)
{
    const char *container_id = NULL;

    if (rsc->children) {
        g_list_foreach(rsc->children, (GFunc) setup_container, data_set);
        return;
    }

    container_id = g_hash_table_lookup(rsc->meta, XML_RSC_ATTR_CONTAINER);
    if (container_id && !pcmk__str_eq(container_id, rsc->id, pcmk__str_casei)) {
        pe_resource_t *container = pe_find_resource(data_set->resources, container_id);

        if (container) {
            rsc->container = container;
            pe__set_resource_flags(container, pe_rsc_is_container);
            container->fillers = g_list_append(container->fillers, rsc);
            pe_rsc_trace(rsc, "Resource %s's container is %s", rsc->id, container_id);
        } else {
            pe_err("Resource %s: Unknown resource container (%s)", rsc->id, container_id);
        }
    }
}

gboolean
unpack_remote_nodes(xmlNode * xml_resources, pe_working_set_t * data_set)
{
    xmlNode *xml_obj = NULL;

    /* Create remote nodes and guest nodes from the resource configuration
     * before unpacking resources.
     */
    for (xml_obj = pcmk__xe_first_child(xml_resources); xml_obj != NULL;
         xml_obj = pcmk__xe_next(xml_obj)) {

        const char *new_node_id = NULL;

        /* Check for remote nodes, which are defined by ocf:pacemaker:remote
         * primitives.
         */
        if (xml_contains_remote_node(xml_obj)) {
            new_node_id = ID(xml_obj);
            /* The "pe_find_node" check is here to make sure we don't iterate over
             * an expanded node that has already been added to the node list. */
            if (new_node_id && pe_find_node(data_set->nodes, new_node_id) == NULL) {
                crm_trace("Found remote node %s defined by resource %s",
                          new_node_id, ID(xml_obj));
                pe_create_node(new_node_id, new_node_id, "remote", NULL,
                               data_set);
            }
            continue;
        }

        /* Check for guest nodes, which are defined by special meta-attributes
         * of a primitive of any type (for example, VirtualDomain or Xen).
         */
        if (pcmk__str_eq((const char *)xml_obj->name, XML_CIB_TAG_RESOURCE, pcmk__str_none)) {
            /* This will add an ocf:pacemaker:remote primitive to the
             * configuration for the guest node's connection, to be unpacked
             * later.
             */
            new_node_id = expand_remote_rsc_meta(xml_obj, xml_resources, data_set);
            if (new_node_id && pe_find_node(data_set->nodes, new_node_id) == NULL) {
                crm_trace("Found guest node %s in resource %s",
                          new_node_id, ID(xml_obj));
                pe_create_node(new_node_id, new_node_id, "remote", NULL,
                               data_set);
            }
            continue;
        }

        /* Check for guest nodes inside a group. Clones are currently not
         * supported as guest nodes.
         */
        if (pcmk__str_eq((const char *)xml_obj->name, XML_CIB_TAG_GROUP, pcmk__str_none)) {
            xmlNode *xml_obj2 = NULL;
            for (xml_obj2 = pcmk__xe_first_child(xml_obj); xml_obj2 != NULL;
                 xml_obj2 = pcmk__xe_next(xml_obj2)) {

                new_node_id = expand_remote_rsc_meta(xml_obj2, xml_resources, data_set);

                if (new_node_id && pe_find_node(data_set->nodes, new_node_id) == NULL) {
                    crm_trace("Found guest node %s in resource %s inside group %s",
                              new_node_id, ID(xml_obj2), ID(xml_obj));
                    pe_create_node(new_node_id, new_node_id, "remote", NULL,
                                   data_set);
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
link_rsc2remotenode(pe_working_set_t *data_set, pe_resource_t *new_rsc)
{
    pe_node_t *remote_node = NULL;

    if (new_rsc->is_remote_node == FALSE) {
        return;
    }

    if (pcmk_is_set(data_set->flags, pe_flag_quick_location)) {
        /* remote_nodes and remote_resources are not linked in quick location calculations */
        return;
    }

    remote_node = pe_find_node(data_set->nodes, new_rsc->id);
    CRM_CHECK(remote_node != NULL, return);

    pe_rsc_trace(new_rsc, "Linking remote connection resource %s to %s",
                 new_rsc->id, pe__node_name(remote_node));
    remote_node->details->remote_rsc = new_rsc;

    if (new_rsc->container == NULL) {
        /* Handle start-up fencing for remote nodes (as opposed to guest nodes)
         * the same as is done for cluster nodes.
         */
        handle_startup_fencing(data_set, remote_node);

    } else {
        /* pe_create_node() marks the new node as "remote" or "cluster"; now
         * that we know the node is a guest node, update it correctly.
         */
        g_hash_table_replace(remote_node->details->attrs, strdup(CRM_ATTR_KIND),
                             strdup("container"));
    }
}

static void
destroy_tag(gpointer data)
{
    pe_tag_t *tag = data;

    if (tag) {
        free(tag->id);
        g_list_free_full(tag->refs, free);
        free(tag);
    }
}

/*!
 * \internal
 * \brief Parse configuration XML for resource information
 *
 * \param[in]     xml_resources  Top of resource configuration XML
 * \param[in,out] data_set       Where to put resource information
 *
 * \return TRUE
 *
 * \note unpack_remote_nodes() MUST be called before this, so that the nodes can
 *       be used when pe__unpack_resource() calls resource_location()
 */
gboolean
unpack_resources(xmlNode * xml_resources, pe_working_set_t * data_set)
{
    xmlNode *xml_obj = NULL;
    GList *gIter = NULL;

    data_set->template_rsc_sets = pcmk__strkey_table(free, destroy_tag);

    for (xml_obj = pcmk__xe_first_child(xml_resources); xml_obj != NULL;
         xml_obj = pcmk__xe_next(xml_obj)) {

        pe_resource_t *new_rsc = NULL;
        const char *id = ID(xml_obj);

        if (pcmk__str_empty(id)) {
            pcmk__config_err("Ignoring <%s> resource without ID",
                             crm_element_name(xml_obj));
            continue;
        }

        if (pcmk__str_eq((const char *) xml_obj->name, XML_CIB_TAG_RSC_TEMPLATE,
                         pcmk__str_none)) {
            if (g_hash_table_lookup_extended(data_set->template_rsc_sets, id,
                                             NULL, NULL) == FALSE) {
                /* Record the template's ID for the knowledge of its existence anyway. */
                g_hash_table_insert(data_set->template_rsc_sets, strdup(id), NULL);
            }
            continue;
        }

        crm_trace("Unpacking <%s id='%s'>", crm_element_name(xml_obj), id);
        if (pe__unpack_resource(xml_obj, &new_rsc, NULL,
                                data_set) == pcmk_rc_ok) {
            data_set->resources = g_list_append(data_set->resources, new_rsc);
            pe_rsc_trace(new_rsc, "Added resource %s", new_rsc->id);

        } else {
            pcmk__config_err("Ignoring <%s> resource '%s' "
                             "because configuration is invalid",
                             crm_element_name(xml_obj), id);
        }
    }

    for (gIter = data_set->resources; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *rsc = (pe_resource_t *) gIter->data;

        setup_container(rsc, data_set);
        link_rsc2remotenode(data_set, rsc);
    }

    data_set->resources = g_list_sort(data_set->resources,
                                      pe__cmp_rsc_priority);
    if (pcmk_is_set(data_set->flags, pe_flag_quick_location)) {
        /* Ignore */

    } else if (pcmk_is_set(data_set->flags, pe_flag_stonith_enabled)
               && !pcmk_is_set(data_set->flags, pe_flag_have_stonith_resource)) {

        pcmk__config_err("Resource start-up disabled since no STONITH resources have been defined");
        pcmk__config_err("Either configure some or disable STONITH with the stonith-enabled option");
        pcmk__config_err("NOTE: Clusters with shared data need STONITH to ensure data integrity");
    }

    return TRUE;
}

gboolean
unpack_tags(xmlNode * xml_tags, pe_working_set_t * data_set)
{
    xmlNode *xml_tag = NULL;

    data_set->tags = pcmk__strkey_table(free, destroy_tag);

    for (xml_tag = pcmk__xe_first_child(xml_tags); xml_tag != NULL;
         xml_tag = pcmk__xe_next(xml_tag)) {

        xmlNode *xml_obj_ref = NULL;
        const char *tag_id = ID(xml_tag);

        if (!pcmk__str_eq((const char *)xml_tag->name, XML_CIB_TAG_TAG, pcmk__str_none)) {
            continue;
        }

        if (tag_id == NULL) {
            pcmk__config_err("Ignoring <%s> without " XML_ATTR_ID,
                             crm_element_name(xml_tag));
            continue;
        }

        for (xml_obj_ref = pcmk__xe_first_child(xml_tag); xml_obj_ref != NULL;
             xml_obj_ref = pcmk__xe_next(xml_obj_ref)) {

            const char *obj_ref = ID(xml_obj_ref);

            if (!pcmk__str_eq((const char *)xml_obj_ref->name, XML_CIB_TAG_OBJ_REF, pcmk__str_none)) {
                continue;
            }

            if (obj_ref == NULL) {
                pcmk__config_err("Ignoring <%s> for tag '%s' without " XML_ATTR_ID,
                                 crm_element_name(xml_obj_ref), tag_id);
                continue;
            }

            if (add_tag_ref(data_set->tags, tag_id, obj_ref) == FALSE) {
                return FALSE;
            }
        }
    }

    return TRUE;
}

/* The ticket state section:
 * "/cib/status/tickets/ticket_state" */
static gboolean
unpack_ticket_state(xmlNode * xml_ticket, pe_working_set_t * data_set)
{
    const char *ticket_id = NULL;
    const char *granted = NULL;
    const char *last_granted = NULL;
    const char *standby = NULL;
    xmlAttrPtr xIter = NULL;

    pe_ticket_t *ticket = NULL;

    ticket_id = ID(xml_ticket);
    if (pcmk__str_empty(ticket_id)) {
        return FALSE;
    }

    crm_trace("Processing ticket state for %s", ticket_id);

    ticket = g_hash_table_lookup(data_set->tickets, ticket_id);
    if (ticket == NULL) {
        ticket = ticket_new(ticket_id, data_set);
        if (ticket == NULL) {
            return FALSE;
        }
    }

    for (xIter = xml_ticket->properties; xIter; xIter = xIter->next) {
        const char *prop_name = (const char *)xIter->name;
        const char *prop_value = crm_element_value(xml_ticket, prop_name);

        if (pcmk__str_eq(prop_name, XML_ATTR_ID, pcmk__str_none)) {
            continue;
        }
        g_hash_table_replace(ticket->state, strdup(prop_name), strdup(prop_value));
    }

    granted = g_hash_table_lookup(ticket->state, "granted");
    if (granted && crm_is_true(granted)) {
        ticket->granted = TRUE;
        crm_info("We have ticket '%s'", ticket->id);
    } else {
        ticket->granted = FALSE;
        crm_info("We do not have ticket '%s'", ticket->id);
    }

    last_granted = g_hash_table_lookup(ticket->state, "last-granted");
    if (last_granted) {
        long long last_granted_ll;

        pcmk__scan_ll(last_granted, &last_granted_ll, 0LL);
        ticket->last_granted = (time_t) last_granted_ll;
    }

    standby = g_hash_table_lookup(ticket->state, "standby");
    if (standby && crm_is_true(standby)) {
        ticket->standby = TRUE;
        if (ticket->granted) {
            crm_info("Granted ticket '%s' is in standby-mode", ticket->id);
        }
    } else {
        ticket->standby = FALSE;
    }

    crm_trace("Done with ticket state for %s", ticket_id);

    return TRUE;
}

static gboolean
unpack_tickets_state(xmlNode * xml_tickets, pe_working_set_t * data_set)
{
    xmlNode *xml_obj = NULL;

    for (xml_obj = pcmk__xe_first_child(xml_tickets); xml_obj != NULL;
         xml_obj = pcmk__xe_next(xml_obj)) {

        if (!pcmk__str_eq((const char *)xml_obj->name, XML_CIB_TAG_TICKET_STATE, pcmk__str_none)) {
            continue;
        }
        unpack_ticket_state(xml_obj, data_set);
    }

    return TRUE;
}

static void
unpack_handle_remote_attrs(pe_node_t *this_node, xmlNode *state, pe_working_set_t * data_set) 
{
    const char *resource_discovery_enabled = NULL;
    xmlNode *attrs = NULL;
    pe_resource_t *rsc = NULL;

    if (!pcmk__str_eq((const char *)state->name, XML_CIB_TAG_STATE, pcmk__str_none)) {
        return;
    }

    if ((this_node == NULL) || !pe__is_guest_or_remote_node(this_node)) {
        return;
    }
    crm_trace("Processing Pacemaker Remote node %s", pe__node_name(this_node));

    pcmk__scan_min_int(crm_element_value(state, XML_NODE_IS_MAINTENANCE),
                       &(this_node->details->remote_maintenance), 0);

    rsc = this_node->details->remote_rsc;
    if (this_node->details->remote_requires_reset == FALSE) {
        this_node->details->unclean = FALSE;
        this_node->details->unseen = FALSE;
    }
    attrs = find_xml_node(state, XML_TAG_TRANSIENT_NODEATTRS, FALSE);
    add_node_attrs(attrs, this_node, TRUE, data_set);

    if (pe__shutdown_requested(this_node)) {
        crm_info("%s is shutting down", pe__node_name(this_node));
        this_node->details->shutdown = TRUE;
    }
 
    if (crm_is_true(pe_node_attribute_raw(this_node, "standby"))) {
        crm_info("%s is in standby mode", pe__node_name(this_node));
        this_node->details->standby = TRUE;
    }

    if (crm_is_true(pe_node_attribute_raw(this_node, "maintenance")) ||
        ((rsc != NULL) && !pcmk_is_set(rsc->flags, pe_rsc_managed))) {
        crm_info("%s is in maintenance mode", pe__node_name(this_node));
        this_node->details->maintenance = TRUE;
    }

    resource_discovery_enabled = pe_node_attribute_raw(this_node, XML_NODE_ATTR_RSC_DISCOVERY);
    if (resource_discovery_enabled && !crm_is_true(resource_discovery_enabled)) {
        if (pe__is_remote_node(this_node)
            && !pcmk_is_set(data_set->flags, pe_flag_stonith_enabled)) {
            crm_warn("Ignoring " XML_NODE_ATTR_RSC_DISCOVERY
                     " attribute on Pacemaker Remote node %s"
                     " because fencing is disabled",
                     pe__node_name(this_node));
        } else {
            /* This is either a remote node with fencing enabled, or a guest
             * node. We don't care whether fencing is enabled when fencing guest
             * nodes, because they are "fenced" by recovering their containing
             * resource.
             */
            crm_info("%s has resource discovery disabled",
                     pe__node_name(this_node));
            this_node->details->rsc_discovery_enabled = FALSE;
        }
    }
}

/*!
 * \internal
 * \brief Unpack a cluster node's transient attributes
 *
 * \param[in] state     CIB node state XML
 * \param[in] node      Cluster node whose attributes are being unpacked
 * \param[in] data_set  Cluster working set
 */
static void
unpack_transient_attributes(xmlNode *state, pe_node_t *node,
                            pe_working_set_t *data_set)
{
    const char *discovery = NULL;
    xmlNode *attrs = find_xml_node(state, XML_TAG_TRANSIENT_NODEATTRS, FALSE);

    add_node_attrs(attrs, node, TRUE, data_set);

    if (crm_is_true(pe_node_attribute_raw(node, "standby"))) {
        crm_info("%s is in standby mode", pe__node_name(node));
        node->details->standby = TRUE;
    }

    if (crm_is_true(pe_node_attribute_raw(node, "maintenance"))) {
        crm_info("%s is in maintenance mode", pe__node_name(node));
        node->details->maintenance = TRUE;
    }

    discovery = pe_node_attribute_raw(node, XML_NODE_ATTR_RSC_DISCOVERY);
    if ((discovery != NULL) && !crm_is_true(discovery)) {
        crm_warn("Ignoring " XML_NODE_ATTR_RSC_DISCOVERY
                 " attribute for %s because disabling resource discovery "
                 "is not allowed for cluster nodes", pe__node_name(node));
    }
}

/*!
 * \internal
 * \brief Unpack a node state entry (first pass)
 *
 * Unpack one node state entry from status. This unpacks information from the
 * node_state element itself and node attributes inside it, but not the
 * resource history inside it. Multiple passes through the status are needed to
 * fully unpack everything.
 *
 * \param[in] state     CIB node state XML
 * \param[in] data_set  Cluster working set
 */
static void
unpack_node_state(xmlNode *state, pe_working_set_t *data_set)
{
    const char *id = NULL;
    const char *uname = NULL;
    pe_node_t *this_node = NULL;

    id = crm_element_value(state, XML_ATTR_ID);
    if (id == NULL) {
        crm_warn("Ignoring malformed " XML_CIB_TAG_STATE " entry without "
                 XML_ATTR_ID);
        return;
    }

    uname = crm_element_value(state, XML_ATTR_UNAME);
    if (uname == NULL) {
        crm_warn("Ignoring malformed " XML_CIB_TAG_STATE " entry without "
                 XML_ATTR_UNAME);
        return;
    }

    this_node = pe_find_node_any(data_set->nodes, id, uname);
    if (this_node == NULL) {
        pcmk__config_warn("Ignoring recorded node state for '%s' because "
                          "it is no longer in the configuration", uname);
        return;
    }

    if (pe__is_guest_or_remote_node(this_node)) {
        /* We can't determine the online status of Pacemaker Remote nodes until
         * after all resource history has been unpacked. In this first pass, we
         * do need to mark whether the node has been fenced, as this plays a
         * role during unpacking cluster node resource state.
         */
        pcmk__scan_min_int(crm_element_value(state, XML_NODE_IS_FENCED),
                           &(this_node->details->remote_was_fenced), 0);
        return;
    }

    unpack_transient_attributes(state, this_node, data_set);

    /* Provisionally mark this cluster node as clean. We have at least seen it
     * in the current cluster's lifetime.
     */
    this_node->details->unclean = FALSE;
    this_node->details->unseen = FALSE;

    crm_trace("Determining online status of cluster node %s (id %s)",
              pe__node_name(this_node), id);
    determine_online_status(state, this_node, data_set);

    if (!pcmk_is_set(data_set->flags, pe_flag_have_quorum)
        && this_node->details->online
        && (data_set->no_quorum_policy == no_quorum_suicide)) {
        /* Everything else should flow from this automatically
         * (at least until the scheduler becomes able to migrate off
         * healthy resources)
         */
        pe_fence_node(data_set, this_node, "cluster does not have quorum",
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
 * \param[in] status    CIB XML status section
 * \param[in] fence     If true, treat any not-yet-unpacked nodes as unseen
 * \param[in] data_set  Cluster working set
 *
 * \return Standard Pacemaker return code (specifically pcmk_rc_ok if done,
 *         or EAGAIN if more unpacking remains to be done)
 */
static int
unpack_node_history(xmlNode *status, bool fence, pe_working_set_t *data_set)
{
    int rc = pcmk_rc_ok;

    // Loop through all node_state entries in CIB status
    for (xmlNode *state = first_named_child(status, XML_CIB_TAG_STATE);
         state != NULL; state = crm_next_same_xml(state)) {

        const char *id = ID(state);
        const char *uname = crm_element_value(state, XML_ATTR_UNAME);
        pe_node_t *this_node = NULL;

        if ((id == NULL) || (uname == NULL)) {
            // Warning already logged in first pass through status section
            crm_trace("Not unpacking resource history from malformed "
                      XML_CIB_TAG_STATE " without id and/or uname");
            continue;
        }

        this_node = pe_find_node_any(data_set->nodes, id, uname);
        if (this_node == NULL) {
            // Warning already logged in first pass through status section
            crm_trace("Not unpacking resource history for node %s because "
                      "no longer in configuration", id);
            continue;
        }

        if (this_node->details->unpacked) {
            crm_trace("Not unpacking resource history for node %s because "
                      "already unpacked", id);
            continue;
        }

        if (fence) {
            // We're processing all remaining nodes

        } else if (pe__is_guest_node(this_node)) {
            /* We can unpack a guest node's history only after we've unpacked
             * other resource history to the point that we know that the node's
             * connection and containing resource are both up.
             */
            pe_resource_t *rsc = this_node->details->remote_rsc;

            if ((rsc == NULL) || (rsc->role != RSC_ROLE_STARTED)
                || (rsc->container->role != RSC_ROLE_STARTED)) {
                crm_trace("Not unpacking resource history for guest node %s "
                          "because container and connection are not known to "
                          "be up", id);
                continue;
            }

        } else if (pe__is_remote_node(this_node)) {
            /* We can unpack a remote node's history only after we've unpacked
             * other resource history to the point that we know that the node's
             * connection is up, with the exception of when shutdown locks are
             * in use.
             */
            pe_resource_t *rsc = this_node->details->remote_rsc;

            if ((rsc == NULL)
                || (!pcmk_is_set(data_set->flags, pe_flag_shutdown_lock)
                    && (rsc->role != RSC_ROLE_STARTED))) {
                crm_trace("Not unpacking resource history for remote node %s "
                          "because connection is not known to be up", id);
                continue;
            }

        /* If fencing and shutdown locks are disabled and we're not processing
         * unseen nodes, then we don't want to unpack offline nodes until online
         * nodes have been unpacked. This allows us to number active clone
         * instances first.
         */
        } else if (!pcmk_any_flags_set(data_set->flags, pe_flag_stonith_enabled
                                                        |pe_flag_shutdown_lock)
                   && !this_node->details->online) {
            crm_trace("Not unpacking resource history for offline "
                      "cluster node %s", id);
            continue;
        }

        if (pe__is_guest_or_remote_node(this_node)) {
            determine_remote_online_status(data_set, this_node);
            unpack_handle_remote_attrs(this_node, state, data_set);
        }

        crm_trace("Unpacking resource history for %snode %s",
                  (fence? "unseen " : ""), id);

        this_node->details->unpacked = TRUE;
        unpack_node_lrm(this_node, state, data_set);

        rc = EAGAIN; // Other node histories might depend on this one
    }
    return rc;
}

/* remove nodes that are down, stopping */
/* create positive rsc_to_node constraints between resources and the nodes they are running on */
/* anything else? */
gboolean
unpack_status(xmlNode * status, pe_working_set_t * data_set)
{
    xmlNode *state = NULL;

    crm_trace("Beginning unpack");

    if (data_set->tickets == NULL) {
        data_set->tickets = pcmk__strkey_table(free, destroy_ticket);
    }

    for (state = pcmk__xe_first_child(status); state != NULL;
         state = pcmk__xe_next(state)) {

        if (pcmk__str_eq((const char *)state->name, XML_CIB_TAG_TICKETS, pcmk__str_none)) {
            unpack_tickets_state((xmlNode *) state, data_set);

        } else if (pcmk__str_eq((const char *)state->name, XML_CIB_TAG_STATE, pcmk__str_none)) {
            unpack_node_state(state, data_set);
        }
    }

    while (unpack_node_history(status, FALSE, data_set) == EAGAIN) {
        crm_trace("Another pass through node resource histories is needed");
    }

    // Now catch any nodes we didn't see
    unpack_node_history(status,
                        pcmk_is_set(data_set->flags, pe_flag_stonith_enabled),
                        data_set);

    /* Now that we know where resources are, we can schedule stops of containers
     * with failed bundle connections
     */
    if (data_set->stop_needed != NULL) {
        for (GList *item = data_set->stop_needed; item; item = item->next) {
            pe_resource_t *container = item->data;
            pe_node_t *node = pe__current_node(container);

            if (node) {
                stop_action(container, node, FALSE);
            }
        }
        g_list_free(data_set->stop_needed);
        data_set->stop_needed = NULL;
    }

    /* Now that we know status of all Pacemaker Remote connections and nodes,
     * we can stop connections for node shutdowns, and check the online status
     * of remote/guest nodes that didn't have any node history to unpack.
     */
    for (GList *gIter = data_set->nodes; gIter != NULL; gIter = gIter->next) {
        pe_node_t *this_node = gIter->data;

        if (!pe__is_guest_or_remote_node(this_node)) {
            continue;
        }
        if (this_node->details->shutdown
            && (this_node->details->remote_rsc != NULL)) {
            pe__set_next_role(this_node->details->remote_rsc, RSC_ROLE_STOPPED,
                              "remote shutdown");
        }
        if (!this_node->details->unpacked) {
            determine_remote_online_status(data_set, this_node);
        }
    }

    return TRUE;
}

static gboolean
determine_online_status_no_fencing(pe_working_set_t * data_set, xmlNode * node_state,
                                   pe_node_t * this_node)
{
    gboolean online = FALSE;
    const char *join = crm_element_value(node_state, XML_NODE_JOIN_STATE);
    const char *is_peer = crm_element_value(node_state, XML_NODE_IS_PEER);
    const char *in_cluster = crm_element_value(node_state, XML_NODE_IN_CLUSTER);
    const char *exp_state = crm_element_value(node_state, XML_NODE_EXPECTED);

    if (!crm_is_true(in_cluster)) {
        crm_trace("Node is down: in_cluster=%s",
                  pcmk__s(in_cluster, "<null>"));

    } else if (pcmk__str_eq(is_peer, ONLINESTATUS, pcmk__str_casei)) {
        if (pcmk__str_eq(join, CRMD_JOINSTATE_MEMBER, pcmk__str_casei)) {
            online = TRUE;
        } else {
            crm_debug("Node is not ready to run resources: %s", join);
        }

    } else if (this_node->details->expected_up == FALSE) {
        crm_trace("Controller is down: "
                  "in_cluster=%s is_peer=%s join=%s expected=%s",
                  pcmk__s(in_cluster, "<null>"), pcmk__s(is_peer, "<null>"),
                  pcmk__s(join, "<null>"), pcmk__s(exp_state, "<null>"));

    } else {
        /* mark it unclean */
        pe_fence_node(data_set, this_node, "peer is unexpectedly down", FALSE);
        crm_info("in_cluster=%s is_peer=%s join=%s expected=%s",
                 pcmk__s(in_cluster, "<null>"), pcmk__s(is_peer, "<null>"),
                 pcmk__s(join, "<null>"), pcmk__s(exp_state, "<null>"));
    }
    return online;
}

static gboolean
determine_online_status_fencing(pe_working_set_t * data_set, xmlNode * node_state,
                                pe_node_t * this_node)
{
    gboolean online = FALSE;
    gboolean do_terminate = FALSE;
    bool crmd_online = FALSE;
    const char *join = crm_element_value(node_state, XML_NODE_JOIN_STATE);
    const char *is_peer = crm_element_value(node_state, XML_NODE_IS_PEER);
    const char *in_cluster = crm_element_value(node_state, XML_NODE_IN_CLUSTER);
    const char *exp_state = crm_element_value(node_state, XML_NODE_EXPECTED);
    const char *terminate = pe_node_attribute_raw(this_node, "terminate");

/*
  - XML_NODE_IN_CLUSTER    ::= true|false
  - XML_NODE_IS_PEER       ::= online|offline
  - XML_NODE_JOIN_STATE    ::= member|down|pending|banned
  - XML_NODE_EXPECTED      ::= member|down
*/

    if (crm_is_true(terminate)) {
        do_terminate = TRUE;

    } else if (terminate != NULL && strlen(terminate) > 0) {
        /* could be a time() value */
        char t = terminate[0];

        if (t != '0' && isdigit(t)) {
            do_terminate = TRUE;
        }
    }

    crm_trace("%s: in_cluster=%s is_peer=%s join=%s expected=%s term=%d",
              pe__node_name(this_node), pcmk__s(in_cluster, "<null>"),
              pcmk__s(is_peer, "<null>"), pcmk__s(join, "<null>"),
              pcmk__s(exp_state, "<null>"), do_terminate);

    online = crm_is_true(in_cluster);
    crmd_online = pcmk__str_eq(is_peer, ONLINESTATUS, pcmk__str_casei);
    if (exp_state == NULL) {
        exp_state = CRMD_JOINSTATE_DOWN;
    }

    if (this_node->details->shutdown) {
        crm_debug("%s is shutting down", pe__node_name(this_node));

        /* Slightly different criteria since we can't shut down a dead peer */
        online = crmd_online;

    } else if (in_cluster == NULL) {
        pe_fence_node(data_set, this_node, "peer has not been seen by the cluster", FALSE);

    } else if (pcmk__str_eq(join, CRMD_JOINSTATE_NACK, pcmk__str_casei)) {
        pe_fence_node(data_set, this_node,
                      "peer failed Pacemaker membership criteria", FALSE);

    } else if (do_terminate == FALSE && pcmk__str_eq(exp_state, CRMD_JOINSTATE_DOWN, pcmk__str_casei)) {

        if (crm_is_true(in_cluster) || crmd_online) {
            crm_info("- %s is not ready to run resources",
                     pe__node_name(this_node));
            this_node->details->standby = TRUE;
            this_node->details->pending = TRUE;

        } else {
            crm_trace("%s is down or still coming up",
                      pe__node_name(this_node));
        }

    } else if (do_terminate && pcmk__str_eq(join, CRMD_JOINSTATE_DOWN, pcmk__str_casei)
               && crm_is_true(in_cluster) == FALSE && !crmd_online) {
        crm_info("%s was just shot", pe__node_name(this_node));
        online = FALSE;

    } else if (crm_is_true(in_cluster) == FALSE) {
        // Consider `priority-fencing-delay` for lost nodes
        pe_fence_node(data_set, this_node, "peer is no longer part of the cluster", TRUE);

    } else if (!crmd_online) {
        pe_fence_node(data_set, this_node, "peer process is no longer available", FALSE);

        /* Everything is running at this point, now check join state */
    } else if (do_terminate) {
        pe_fence_node(data_set, this_node, "termination was requested", FALSE);

    } else if (pcmk__str_eq(join, CRMD_JOINSTATE_MEMBER, pcmk__str_casei)) {
        crm_info("%s is active", pe__node_name(this_node));

    } else if (pcmk__strcase_any_of(join, CRMD_JOINSTATE_PENDING, CRMD_JOINSTATE_DOWN, NULL)) {
        crm_info("%s is not ready to run resources", pe__node_name(this_node));
        this_node->details->standby = TRUE;
        this_node->details->pending = TRUE;

    } else {
        pe_fence_node(data_set, this_node, "peer was in an unknown state", FALSE);
        crm_warn("%s: in-cluster=%s is-peer=%s join=%s expected=%s term=%d shutdown=%d",
                 pe__node_name(this_node), pcmk__s(in_cluster, "<null>"),
                 pcmk__s(is_peer, "<null>"), pcmk__s(join, "<null>"),
                 pcmk__s(exp_state, "<null>"), do_terminate,
                 this_node->details->shutdown);
    }

    return online;
}

static void
determine_remote_online_status(pe_working_set_t * data_set, pe_node_t * this_node)
{
    pe_resource_t *rsc = this_node->details->remote_rsc;
    pe_resource_t *container = NULL;
    pe_node_t *host = NULL;

    /* If there is a node state entry for a (former) Pacemaker Remote node
     * but no resource creating that node, the node's connection resource will
     * be NULL. Consider it an offline remote node in that case.
     */
    if (rsc == NULL) {
        this_node->details->online = FALSE;
        goto remote_online_done;
    }

    container = rsc->container;

    if (container && pcmk__list_of_1(rsc->running_on)) {
        host = rsc->running_on->data;
    }

    /* If the resource is currently started, mark it online. */
    if (rsc->role == RSC_ROLE_STARTED) {
        crm_trace("%s node %s presumed ONLINE because connection resource is started",
                  (container? "Guest" : "Remote"), this_node->details->id);
        this_node->details->online = TRUE;
    }

    /* consider this node shutting down if transitioning start->stop */
    if (rsc->role == RSC_ROLE_STARTED && rsc->next_role == RSC_ROLE_STOPPED) {
        crm_trace("%s node %s shutting down because connection resource is stopping",
                  (container? "Guest" : "Remote"), this_node->details->id);
        this_node->details->shutdown = TRUE;
    }

    /* Now check all the failure conditions. */
    if(container && pcmk_is_set(container->flags, pe_rsc_failed)) {
        crm_trace("Guest node %s UNCLEAN because guest resource failed",
                  this_node->details->id);
        this_node->details->online = FALSE;
        this_node->details->remote_requires_reset = TRUE;

    } else if (pcmk_is_set(rsc->flags, pe_rsc_failed)) {
        crm_trace("%s node %s OFFLINE because connection resource failed",
                  (container? "Guest" : "Remote"), this_node->details->id);
        this_node->details->online = FALSE;

    } else if (rsc->role == RSC_ROLE_STOPPED
        || (container && container->role == RSC_ROLE_STOPPED)) {

        crm_trace("%s node %s OFFLINE because its resource is stopped",
                  (container? "Guest" : "Remote"), this_node->details->id);
        this_node->details->online = FALSE;
        this_node->details->remote_requires_reset = FALSE;

    } else if (host && (host->details->online == FALSE)
               && host->details->unclean) {
        crm_trace("Guest node %s UNCLEAN because host is unclean",
                  this_node->details->id);
        this_node->details->online = FALSE;
        this_node->details->remote_requires_reset = TRUE;
    }

remote_online_done:
    crm_trace("Remote node %s online=%s",
        this_node->details->id, this_node->details->online ? "TRUE" : "FALSE");
}

static void
determine_online_status(xmlNode * node_state, pe_node_t * this_node, pe_working_set_t * data_set)
{
    gboolean online = FALSE;
    const char *exp_state = crm_element_value(node_state, XML_NODE_EXPECTED);

    CRM_CHECK(this_node != NULL, return);

    this_node->details->shutdown = FALSE;
    this_node->details->expected_up = FALSE;

    if (pe__shutdown_requested(this_node)) {
        this_node->details->shutdown = TRUE;

    } else if (pcmk__str_eq(exp_state, CRMD_JOINSTATE_MEMBER, pcmk__str_casei)) {
        this_node->details->expected_up = TRUE;
    }

    if (this_node->details->type == node_ping) {
        this_node->details->unclean = FALSE;
        online = FALSE;         /* As far as resource management is concerned,
                                 * the node is safely offline.
                                 * Anyone caught abusing this logic will be shot
                                 */

    } else if (!pcmk_is_set(data_set->flags, pe_flag_stonith_enabled)) {
        online = determine_online_status_no_fencing(data_set, node_state, this_node);

    } else {
        online = determine_online_status_fencing(data_set, node_state, this_node);
    }

    if (online) {
        this_node->details->online = TRUE;

    } else {
        /* remove node from contention */
        this_node->fixed = TRUE;
        this_node->weight = -INFINITY;
    }

    if (online && this_node->details->shutdown) {
        /* don't run resources here */
        this_node->fixed = TRUE;
        this_node->weight = -INFINITY;
    }

    if (this_node->details->type == node_ping) {
        crm_info("%s is not a Pacemaker node", pe__node_name(this_node));

    } else if (this_node->details->unclean) {
        pe_proc_warn("%s is unclean", pe__node_name(this_node));

    } else if (this_node->details->online) {
        crm_info("%s is %s", pe__node_name(this_node),
                 this_node->details->shutdown ? "shutting down" :
                 this_node->details->pending ? "pending" :
                 this_node->details->standby ? "standby" :
                 this_node->details->maintenance ? "maintenance" : "online");

    } else {
        crm_trace("%s is offline", pe__node_name(this_node));
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

    CRM_ASSERT(end);
    basename = strndup(last_rsc_id, end - last_rsc_id + 1);
    CRM_ASSERT(basename);
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

    CRM_ASSERT(end);
    zero = calloc(base_name_len + 3, sizeof(char));
    CRM_ASSERT(zero);
    memcpy(zero, last_rsc_id, base_name_len);
    zero[base_name_len] = ':';
    zero[base_name_len + 1] = '0';
    return zero;
}

static pe_resource_t *
create_fake_resource(const char *rsc_id, xmlNode * rsc_entry, pe_working_set_t * data_set)
{
    pe_resource_t *rsc = NULL;
    xmlNode *xml_rsc = create_xml_node(NULL, XML_CIB_TAG_RESOURCE);

    copy_in_properties(xml_rsc, rsc_entry);
    crm_xml_add(xml_rsc, XML_ATTR_ID, rsc_id);
    crm_log_xml_debug(xml_rsc, "Orphan resource");

    if (pe__unpack_resource(xml_rsc, &rsc, NULL, data_set) != pcmk_rc_ok) {
        return NULL;
    }

    if (xml_contains_remote_node(xml_rsc)) {
        pe_node_t *node;

        crm_debug("Detected orphaned remote node %s", rsc_id);
        node = pe_find_node(data_set->nodes, rsc_id);
        if (node == NULL) {
	        node = pe_create_node(rsc_id, rsc_id, "remote", NULL, data_set);
        }
        link_rsc2remotenode(data_set, rsc);

        if (node) {
            crm_trace("Setting node %s as shutting down due to orphaned connection resource", rsc_id);
            node->details->shutdown = TRUE;
        }
    }

    if (crm_element_value(rsc_entry, XML_RSC_ATTR_CONTAINER)) {
        /* This orphaned rsc needs to be mapped to a container. */
        crm_trace("Detected orphaned container filler %s", rsc_id);
        pe__set_resource_flags(rsc, pe_rsc_orphan_container_filler);
    }
    pe__set_resource_flags(rsc, pe_rsc_orphan);
    data_set->resources = g_list_append(data_set->resources, rsc);
    return rsc;
}

/*!
 * \internal
 * \brief Create orphan instance for anonymous clone resource history
 */
static pe_resource_t *
create_anonymous_orphan(pe_resource_t *parent, const char *rsc_id,
                        pe_node_t *node, pe_working_set_t *data_set)
{
    pe_resource_t *top = pe__create_clone_child(parent, data_set);

    // find_rsc() because we might be a cloned group
    pe_resource_t *orphan = top->fns->find_rsc(top, rsc_id, NULL, pe_find_clone);

    pe_rsc_debug(parent, "Created orphan %s for %s: %s on %s",
                 top->id, parent->id, rsc_id, pe__node_name(node));
    return orphan;
}

/*!
 * \internal
 * \brief Check a node for an instance of an anonymous clone
 *
 * Return a child instance of the specified anonymous clone, in order of
 * preference: (1) the instance running on the specified node, if any;
 * (2) an inactive instance (i.e. within the total of clone-max instances);
 * (3) a newly created orphan (i.e. clone-max instances are already active).
 *
 * \param[in] data_set  Cluster information
 * \param[in] node      Node on which to check for instance
 * \param[in] parent    Clone to check
 * \param[in] rsc_id    Name of cloned resource in history (without instance)
 */
static pe_resource_t *
find_anonymous_clone(pe_working_set_t * data_set, pe_node_t * node, pe_resource_t * parent,
                     const char *rsc_id)
{
    GList *rIter = NULL;
    pe_resource_t *rsc = NULL;
    pe_resource_t *inactive_instance = NULL;
    gboolean skip_inactive = FALSE;

    CRM_ASSERT(parent != NULL);
    CRM_ASSERT(pe_rsc_is_clone(parent));
    CRM_ASSERT(!pcmk_is_set(parent->flags, pe_rsc_unique));

    // Check for active (or partially active, for cloned groups) instance
    pe_rsc_trace(parent, "Looking for %s on %s in %s",
                 rsc_id, pe__node_name(node), parent->id);
    for (rIter = parent->children; rsc == NULL && rIter; rIter = rIter->next) {
        GList *locations = NULL;
        pe_resource_t *child = rIter->data;

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
         *     instance on the same node (which can happen if globally-unique
         *     was flipped from true to false); and
         * (3) when we re-run calculations on the same data set as part of a
         *     simulation.
         */
        child->fns->location(child, &locations, 2);
        if (locations) {
            /* We should never associate the same numbered anonymous clone
             * instance with multiple nodes, and clone instances can't migrate,
             * so there must be only one location, regardless of history.
             */
            CRM_LOG_ASSERT(locations->next == NULL);

            if (((pe_node_t *)locations->data)->details == node->details) {
                /* This child instance is active on the requested node, so check
                 * for a corresponding configured resource. We use find_rsc()
                 * instead of child because child may be a cloned group, and we
                 * need the particular member corresponding to rsc_id.
                 *
                 * If the history entry is orphaned, rsc will be NULL.
                 */
                rsc = parent->fns->find_rsc(child, rsc_id, NULL, pe_find_clone);
                if (rsc) {
                    /* If there are multiple instance history entries for an
                     * anonymous clone in a single node's history (which can
                     * happen if globally-unique is switched from true to
                     * false), we want to consider the instances beyond the
                     * first as orphans, even if there are inactive instance
                     * numbers available.
                     */
                    if (rsc->running_on) {
                        crm_notice("Active (now-)anonymous clone %s has "
                                   "multiple (orphan) instance histories on %s",
                                   parent->id, pe__node_name(node));
                        skip_inactive = TRUE;
                        rsc = NULL;
                    } else {
                        pe_rsc_trace(parent, "Resource %s, active", rsc->id);
                    }
                }
            }
            g_list_free(locations);

        } else {
            pe_rsc_trace(parent, "Resource %s, skip inactive", child->id);
            if (!skip_inactive && !inactive_instance
                && !pcmk_is_set(child->flags, pe_rsc_block)) {
                // Remember one inactive instance in case we don't find active
                inactive_instance = parent->fns->find_rsc(child, rsc_id, NULL,
                                                          pe_find_clone);

                /* ... but don't use it if it was already associated with a
                 * pending action on another node
                 */
                if (inactive_instance && inactive_instance->pending_node
                    && (inactive_instance->pending_node->details != node->details)) {
                    inactive_instance = NULL;
                }
            }
        }
    }

    if ((rsc == NULL) && !skip_inactive && (inactive_instance != NULL)) {
        pe_rsc_trace(parent, "Resource %s, empty slot", inactive_instance->id);
        rsc = inactive_instance;
    }

    /* If the resource has "requires" set to "quorum" or "nothing", and we don't
     * have a clone instance for every node, we don't want to consume a valid
     * instance number for unclean nodes. Such instances may appear to be active
     * according to the history, but should be considered inactive, so we can
     * start an instance elsewhere. Treat such instances as orphans.
     *
     * An exception is instances running on guest nodes -- since guest node
     * "fencing" is actually just a resource stop, requires shouldn't apply.
     *
     * @TODO Ideally, we'd use an inactive instance number if it is not needed
     * for any clean instances. However, we don't know that at this point.
     */
    if ((rsc != NULL) && !pcmk_is_set(rsc->flags, pe_rsc_needs_fencing)
        && (!node->details->online || node->details->unclean)
        && !pe__is_guest_node(node)
        && !pe__is_universal_clone(parent, data_set)) {

        rsc = NULL;
    }

    if (rsc == NULL) {
        rsc = create_anonymous_orphan(parent, rsc_id, node, data_set);
        pe_rsc_trace(parent, "Resource %s, orphan", rsc->id);
    }
    return rsc;
}

static pe_resource_t *
unpack_find_resource(pe_working_set_t * data_set, pe_node_t * node, const char *rsc_id,
                     xmlNode * rsc_entry)
{
    pe_resource_t *rsc = NULL;
    pe_resource_t *parent = NULL;

    crm_trace("looking for %s", rsc_id);
    rsc = pe_find_resource(data_set->resources, rsc_id);

    if (rsc == NULL) {
        /* If we didn't find the resource by its name in the operation history,
         * check it again as a clone instance. Even when clone-max=0, we create
         * a single :0 orphan to match against here.
         */
        char *clone0_id = clone_zero(rsc_id);
        pe_resource_t *clone0 = pe_find_resource(data_set->resources, clone0_id);

        if (clone0 && !pcmk_is_set(clone0->flags, pe_rsc_unique)) {
            rsc = clone0;
            parent = uber_parent(clone0);
            crm_trace("%s found as %s (%s)", rsc_id, clone0_id, parent->id);
        } else {
            crm_trace("%s is not known as %s either (orphan)",
                      rsc_id, clone0_id);
        }
        free(clone0_id);

    } else if (rsc->variant > pe_native) {
        crm_trace("Resource history for %s is orphaned because it is no longer primitive",
                  rsc_id);
        return NULL;

    } else {
        parent = uber_parent(rsc);
    }

    if (pe_rsc_is_anon_clone(parent)) {

        if (pe_rsc_is_bundled(parent)) {
            rsc = pe__find_bundle_replica(parent->parent, node);
        } else {
            char *base = clone_strip(rsc_id);

            rsc = find_anonymous_clone(data_set, node, parent, base);
            free(base);
            CRM_ASSERT(rsc != NULL);
        }
    }

    if (rsc && !pcmk__str_eq(rsc_id, rsc->id, pcmk__str_casei)
        && !pcmk__str_eq(rsc_id, rsc->clone_name, pcmk__str_casei)) {

        pcmk__str_update(&rsc->clone_name, rsc_id);
        pe_rsc_debug(rsc, "Internally renamed %s on %s to %s%s",
                     rsc_id, pe__node_name(node), rsc->id,
                     (pcmk_is_set(rsc->flags, pe_rsc_orphan)? " (ORPHAN)" : ""));
    }
    return rsc;
}

static pe_resource_t *
process_orphan_resource(xmlNode * rsc_entry, pe_node_t * node, pe_working_set_t * data_set)
{
    pe_resource_t *rsc = NULL;
    const char *rsc_id = crm_element_value(rsc_entry, XML_ATTR_ID);

    crm_debug("Detected orphan resource %s on %s", rsc_id, pe__node_name(node));
    rsc = create_fake_resource(rsc_id, rsc_entry, data_set);
    if (rsc == NULL) {
        return NULL;
    }

    if (!pcmk_is_set(data_set->flags, pe_flag_stop_rsc_orphans)) {
        pe__clear_resource_flags(rsc, pe_rsc_managed);

    } else {
        CRM_CHECK(rsc != NULL, return NULL);
        pe_rsc_trace(rsc, "Added orphan %s", rsc->id);
        resource_location(rsc, NULL, -INFINITY, "__orphan_do_not_run__", data_set);
    }
    return rsc;
}

static void
process_rsc_state(pe_resource_t * rsc, pe_node_t * node,
                  enum action_fail_response on_fail,
                  xmlNode * migrate_op, pe_working_set_t * data_set)
{
    pe_node_t *tmpnode = NULL;
    char *reason = NULL;
    enum action_fail_response save_on_fail = action_fail_ignore;

    CRM_ASSERT(rsc);
    pe_rsc_trace(rsc, "Resource %s is %s on %s: on_fail=%s",
                 rsc->id, role2text(rsc->role), pe__node_name(node),
                 fail2text(on_fail));

    /* process current state */
    if (rsc->role != RSC_ROLE_UNKNOWN) {
        pe_resource_t *iter = rsc;

        while (iter) {
            if (g_hash_table_lookup(iter->known_on, node->details->id) == NULL) {
                pe_node_t *n = pe__copy_node(node);

                pe_rsc_trace(rsc, "%s%s%s known on %s",
                             rsc->id,
                             ((rsc->clone_name == NULL)? "" : " also known as "),
                             ((rsc->clone_name == NULL)? "" : rsc->clone_name),
                             pe__node_name(n));
                g_hash_table_insert(iter->known_on, (gpointer) n->details->id, n);
            }
            if (pcmk_is_set(iter->flags, pe_rsc_unique)) {
                break;
            }
            iter = iter->parent;
        }
    }

    /* If a managed resource is believed to be running, but node is down ... */
    if (rsc->role > RSC_ROLE_STOPPED
        && node->details->online == FALSE
        && node->details->maintenance == FALSE
        && pcmk_is_set(rsc->flags, pe_rsc_managed)) {

        gboolean should_fence = FALSE;

        /* If this is a guest node, fence it (regardless of whether fencing is
         * enabled, because guest node fencing is done by recovery of the
         * container resource rather than by the fencer). Mark the resource
         * we're processing as failed. When the guest comes back up, its
         * operation history in the CIB will be cleared, freeing the affected
         * resource to run again once we are sure we know its state.
         */
        if (pe__is_guest_node(node)) {
            pe__set_resource_flags(rsc, pe_rsc_failed|pe_rsc_stop);
            should_fence = TRUE;

        } else if (pcmk_is_set(data_set->flags, pe_flag_stonith_enabled)) {
            if (pe__is_remote_node(node) && node->details->remote_rsc
                && !pcmk_is_set(node->details->remote_rsc->flags, pe_rsc_failed)) {

                /* Setting unseen means that fencing of the remote node will
                 * occur only if the connection resource is not going to start
                 * somewhere. This allows connection resources on a failed
                 * cluster node to move to another node without requiring the
                 * remote nodes to be fenced as well.
                 */
                node->details->unseen = TRUE;
                reason = crm_strdup_printf("%s is active there (fencing will be"
                                           " revoked if remote connection can "
                                           "be re-established elsewhere)",
                                           rsc->id);
            }
            should_fence = TRUE;
        }

        if (should_fence) {
            if (reason == NULL) {
               reason = crm_strdup_printf("%s is thought to be active there", rsc->id);
            }
            pe_fence_node(data_set, node, reason, FALSE);
        }
        free(reason);
    }

    /* In order to calculate priority_fencing_delay correctly, save the failure information and pass it to native_add_running(). */
    save_on_fail = on_fail;

    if (node->details->unclean) {
        /* No extra processing needed
         * Also allows resources to be started again after a node is shot
         */
        on_fail = action_fail_ignore;
    }

    switch (on_fail) {
        case action_fail_ignore:
            /* nothing to do */
            break;

        case action_fail_demote:
            pe__set_resource_flags(rsc, pe_rsc_failed);
            demote_action(rsc, node, FALSE);
            break;

        case action_fail_fence:
            /* treat it as if it is still running
             * but also mark the node as unclean
             */
            reason = crm_strdup_printf("%s failed there", rsc->id);
            pe_fence_node(data_set, node, reason, FALSE);
            free(reason);
            break;

        case action_fail_standby:
            node->details->standby = TRUE;
            node->details->standby_onfail = TRUE;
            break;

        case action_fail_block:
            /* is_managed == FALSE will prevent any
             * actions being sent for the resource
             */
            pe__clear_resource_flags(rsc, pe_rsc_managed);
            pe__set_resource_flags(rsc, pe_rsc_block);
            break;

        case action_fail_migrate:
            /* make sure it comes up somewhere else
             * or not at all
             */
            resource_location(rsc, node, -INFINITY, "__action_migration_auto__", data_set);
            break;

        case action_fail_stop:
            pe__set_next_role(rsc, RSC_ROLE_STOPPED, "on-fail=stop");
            break;

        case action_fail_recover:
            if (rsc->role != RSC_ROLE_STOPPED && rsc->role != RSC_ROLE_UNKNOWN) {
                pe__set_resource_flags(rsc, pe_rsc_failed|pe_rsc_stop);
                stop_action(rsc, node, FALSE);
            }
            break;

        case action_fail_restart_container:
            pe__set_resource_flags(rsc, pe_rsc_failed|pe_rsc_stop);
            if (rsc->container && pe_rsc_is_bundled(rsc)) {
                /* A bundle's remote connection can run on a different node than
                 * the bundle's container. We don't necessarily know where the
                 * container is running yet, so remember it and add a stop
                 * action for it later.
                 */
                data_set->stop_needed = g_list_prepend(data_set->stop_needed,
                                                       rsc->container);
            } else if (rsc->container) {
                stop_action(rsc->container, node, FALSE);
            } else if (rsc->role != RSC_ROLE_STOPPED && rsc->role != RSC_ROLE_UNKNOWN) {
                stop_action(rsc, node, FALSE);
            }
            break;

        case action_fail_reset_remote:
            pe__set_resource_flags(rsc, pe_rsc_failed|pe_rsc_stop);
            if (pcmk_is_set(data_set->flags, pe_flag_stonith_enabled)) {
                tmpnode = NULL;
                if (rsc->is_remote_node) {
                    tmpnode = pe_find_node(data_set->nodes, rsc->id);
                }
                if (tmpnode &&
                    pe__is_remote_node(tmpnode) &&
                    tmpnode->details->remote_was_fenced == 0) {

                    /* The remote connection resource failed in a way that
                     * should result in fencing the remote node.
                     */
                    pe_fence_node(data_set, tmpnode,
                                  "remote connection is unrecoverable", FALSE);
                }
            }

            /* require the stop action regardless if fencing is occurring or not. */
            if (rsc->role > RSC_ROLE_STOPPED) {
                stop_action(rsc, node, FALSE);
            }

            /* if reconnect delay is in use, prevent the connection from exiting the
             * "STOPPED" role until the failure is cleared by the delay timeout. */
            if (rsc->remote_reconnect_ms) {
                pe__set_next_role(rsc, RSC_ROLE_STOPPED, "remote reset");
            }
            break;
    }

    /* ensure a remote-node connection failure forces an unclean remote-node
     * to be fenced. By setting unseen = FALSE, the remote-node failure will
     * result in a fencing operation regardless if we're going to attempt to 
     * reconnect to the remote-node in this transition or not. */
    if (pcmk_is_set(rsc->flags, pe_rsc_failed) && rsc->is_remote_node) {
        tmpnode = pe_find_node(data_set->nodes, rsc->id);
        if (tmpnode && tmpnode->details->unclean) {
            tmpnode->details->unseen = FALSE;
        }
    }

    if (rsc->role != RSC_ROLE_STOPPED && rsc->role != RSC_ROLE_UNKNOWN) {
        if (pcmk_is_set(rsc->flags, pe_rsc_orphan)) {
            if (pcmk_is_set(rsc->flags, pe_rsc_managed)) {
                pcmk__config_warn("Detected active orphan %s running on %s",
                                  rsc->id, pe__node_name(node));
            } else {
                pcmk__config_warn("Resource '%s' must be stopped manually on "
                                  "%s because cluster is configured not to "
                                  "stop active orphans",
                                  rsc->id, pe__node_name(node));
            }
        }

        native_add_running(rsc, node, data_set, (save_on_fail != action_fail_ignore));
        switch (on_fail) {
            case action_fail_ignore:
                break;
            case action_fail_demote:
            case action_fail_block:
                pe__set_resource_flags(rsc, pe_rsc_failed);
                break;
            default:
                pe__set_resource_flags(rsc, pe_rsc_failed|pe_rsc_stop);
                break;
        }

    } else if (rsc->clone_name && strchr(rsc->clone_name, ':') != NULL) {
        /* Only do this for older status sections that included instance numbers
         * Otherwise stopped instances will appear as orphans
         */
        pe_rsc_trace(rsc, "Resetting clone_name %s for %s (stopped)", rsc->clone_name, rsc->id);
        free(rsc->clone_name);
        rsc->clone_name = NULL;

    } else {
        GList *possible_matches = pe__resource_actions(rsc, node, RSC_STOP,
                                                       FALSE);
        GList *gIter = possible_matches;

        for (; gIter != NULL; gIter = gIter->next) {
            pe_action_t *stop = (pe_action_t *) gIter->data;

            pe__set_action_flags(stop, pe_action_optional);
        }

        g_list_free(possible_matches);
    }

    /* A successful stop after migrate_to on the migration source doesn't make
     * the partially migrated resource stopped on the migration target.
     */
    if (rsc->role == RSC_ROLE_STOPPED
        && rsc->partial_migration_source
        && rsc->partial_migration_source->details == node->details
        && rsc->partial_migration_target
        && rsc->running_on) {

        rsc->role = RSC_ROLE_STARTED;
    }
}

/* create active recurring operations as optional */
static void
process_recurring(pe_node_t * node, pe_resource_t * rsc,
                  int start_index, int stop_index,
                  GList *sorted_op_list, pe_working_set_t * data_set)
{
    int counter = -1;
    const char *task = NULL;
    const char *status = NULL;
    GList *gIter = sorted_op_list;

    CRM_ASSERT(rsc);
    pe_rsc_trace(rsc, "%s: Start index %d, stop index = %d", rsc->id, start_index, stop_index);

    for (; gIter != NULL; gIter = gIter->next) {
        xmlNode *rsc_op = (xmlNode *) gIter->data;

        guint interval_ms = 0;
        char *key = NULL;
        const char *id = ID(rsc_op);

        counter++;

        if (node->details->online == FALSE) {
            pe_rsc_trace(rsc, "Skipping %s on %s: node is offline",
                         rsc->id, pe__node_name(node));
            break;

            /* Need to check if there's a monitor for role="Stopped" */
        } else if (start_index < stop_index && counter <= stop_index) {
            pe_rsc_trace(rsc, "Skipping %s on %s: resource is not active",
                         id, pe__node_name(node));
            continue;

        } else if (counter < start_index) {
            pe_rsc_trace(rsc, "Skipping %s on %s: old %d",
                         id, pe__node_name(node), counter);
            continue;
        }

        crm_element_value_ms(rsc_op, XML_LRM_ATTR_INTERVAL_MS, &interval_ms);
        if (interval_ms == 0) {
            pe_rsc_trace(rsc, "Skipping %s on %s: non-recurring",
                         id, pe__node_name(node));
            continue;
        }

        status = crm_element_value(rsc_op, XML_LRM_ATTR_OPSTATUS);
        if (pcmk__str_eq(status, "-1", pcmk__str_casei)) {
            pe_rsc_trace(rsc, "Skipping %s on %s: status",
                         id, pe__node_name(node));
            continue;
        }
        task = crm_element_value(rsc_op, XML_LRM_ATTR_TASK);
        /* create the action */
        key = pcmk__op_key(rsc->id, task, interval_ms);
        pe_rsc_trace(rsc, "Creating %s on %s", key, pe__node_name(node));
        custom_action(rsc, key, task, node, TRUE, TRUE, data_set);
    }
}

void
calculate_active_ops(GList *sorted_op_list, int *start_index, int *stop_index)
{
    int counter = -1;
    int implied_monitor_start = -1;
    int implied_clone_start = -1;
    const char *task = NULL;
    const char *status = NULL;
    GList *gIter = sorted_op_list;

    *stop_index = -1;
    *start_index = -1;

    for (; gIter != NULL; gIter = gIter->next) {
        xmlNode *rsc_op = (xmlNode *) gIter->data;

        counter++;

        task = crm_element_value(rsc_op, XML_LRM_ATTR_TASK);
        status = crm_element_value(rsc_op, XML_LRM_ATTR_OPSTATUS);

        if (pcmk__str_eq(task, CRMD_ACTION_STOP, pcmk__str_casei)
            && pcmk__str_eq(status, "0", pcmk__str_casei)) {
            *stop_index = counter;

        } else if (pcmk__strcase_any_of(task, CRMD_ACTION_START, CRMD_ACTION_MIGRATED, NULL)) {
            *start_index = counter;

        } else if ((implied_monitor_start <= *stop_index) && pcmk__str_eq(task, CRMD_ACTION_STATUS, pcmk__str_casei)) {
            const char *rc = crm_element_value(rsc_op, XML_LRM_ATTR_RC);

            if (pcmk__strcase_any_of(rc, "0", "8", NULL)) {
                implied_monitor_start = counter;
            }
        } else if (pcmk__strcase_any_of(task, CRMD_ACTION_PROMOTE, CRMD_ACTION_DEMOTE, NULL)) {
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
unpack_shutdown_lock(xmlNode *rsc_entry, pe_resource_t *rsc, pe_node_t *node,
                     pe_working_set_t *data_set)
{
    time_t lock_time = 0;   // When lock started (i.e. node shutdown time)

    if ((crm_element_value_epoch(rsc_entry, XML_CONFIG_ATTR_SHUTDOWN_LOCK,
                                 &lock_time) == pcmk_ok) && (lock_time != 0)) {

        if ((data_set->shutdown_lock > 0)
            && (get_effective_time(data_set)
                > (lock_time + data_set->shutdown_lock))) {
            pe_rsc_info(rsc, "Shutdown lock for %s on %s expired",
                        rsc->id, pe__node_name(node));
            pe__clear_resource_history(rsc, node, data_set);
        } else {
            rsc->lock_node = node;
            rsc->lock_time = lock_time;
        }
    }
}

/*!
 * \internal
 * \brief Unpack one lrm_resource entry from a node's CIB status
 *
 * \param[in] node       Node whose status is being unpacked
 * \param[in] rsc_entry  lrm_resource XML being unpacked
 * \param[in] data_set   Cluster working set
 *
 * \return Resource corresponding to the entry, or NULL if no operation history
 */
static pe_resource_t *
unpack_lrm_resource(pe_node_t *node, xmlNode *lrm_resource,
                    pe_working_set_t *data_set)
{
    GList *gIter = NULL;
    int stop_index = -1;
    int start_index = -1;
    enum rsc_role_e req_role = RSC_ROLE_UNKNOWN;

    const char *task = NULL;
    const char *rsc_id = ID(lrm_resource);

    pe_resource_t *rsc = NULL;
    GList *op_list = NULL;
    GList *sorted_op_list = NULL;

    xmlNode *migrate_op = NULL;
    xmlNode *rsc_op = NULL;
    xmlNode *last_failure = NULL;

    enum action_fail_response on_fail = action_fail_ignore;
    enum rsc_role_e saved_role = RSC_ROLE_UNKNOWN;

    if (rsc_id == NULL) {
        crm_warn("Ignoring malformed " XML_LRM_TAG_RESOURCE
                 " entry without id");
        return NULL;
    }
    crm_trace("Unpacking " XML_LRM_TAG_RESOURCE " for %s on %s",
              rsc_id, pe__node_name(node));

    // Build a list of individual lrm_rsc_op entries, so we can sort them
    for (rsc_op = first_named_child(lrm_resource, XML_LRM_TAG_RSC_OP);
         rsc_op != NULL; rsc_op = crm_next_same_xml(rsc_op)) {

        op_list = g_list_prepend(op_list, rsc_op);
    }

    if (!pcmk_is_set(data_set->flags, pe_flag_shutdown_lock)) {
        if (op_list == NULL) {
            // If there are no operations, there is nothing to do
            return NULL;
        }
    }

    /* find the resource */
    rsc = unpack_find_resource(data_set, node, rsc_id, lrm_resource);
    if (rsc == NULL) {
        if (op_list == NULL) {
            // If there are no operations, there is nothing to do
            return NULL;
        } else {
            rsc = process_orphan_resource(lrm_resource, node, data_set);
        }
    }
    CRM_ASSERT(rsc != NULL);

    // Check whether the resource is "shutdown-locked" to this node
    if (pcmk_is_set(data_set->flags, pe_flag_shutdown_lock)) {
        unpack_shutdown_lock(lrm_resource, rsc, node, data_set);
    }

    /* process operations */
    saved_role = rsc->role;
    rsc->role = RSC_ROLE_UNKNOWN;
    sorted_op_list = g_list_sort(op_list, sort_op_by_callid);

    for (gIter = sorted_op_list; gIter != NULL; gIter = gIter->next) {
        xmlNode *rsc_op = (xmlNode *) gIter->data;

        task = crm_element_value(rsc_op, XML_LRM_ATTR_TASK);
        if (pcmk__str_eq(task, CRMD_ACTION_MIGRATED, pcmk__str_casei)) {
            migrate_op = rsc_op;
        }

        unpack_rsc_op(rsc, node, rsc_op, &last_failure, &on_fail, data_set);
    }

    /* create active recurring operations as optional */
    calculate_active_ops(sorted_op_list, &start_index, &stop_index);
    process_recurring(node, rsc, start_index, stop_index, sorted_op_list, data_set);

    /* no need to free the contents */
    g_list_free(sorted_op_list);

    process_rsc_state(rsc, node, on_fail, migrate_op, data_set);

    if (get_target_role(rsc, &req_role)) {
        if (rsc->next_role == RSC_ROLE_UNKNOWN || req_role < rsc->next_role) {
            pe__set_next_role(rsc, req_role, XML_RSC_ATTR_TARGET_ROLE);

        } else if (req_role > rsc->next_role) {
            pe_rsc_info(rsc, "%s: Not overwriting calculated next role %s"
                        " with requested next role %s",
                        rsc->id, role2text(rsc->next_role), role2text(req_role));
        }
    }

    if (saved_role > rsc->role) {
        rsc->role = saved_role;
    }

    return rsc;
}

static void
handle_orphaned_container_fillers(xmlNode * lrm_rsc_list, pe_working_set_t * data_set)
{
    xmlNode *rsc_entry = NULL;
    for (rsc_entry = pcmk__xe_first_child(lrm_rsc_list); rsc_entry != NULL;
         rsc_entry = pcmk__xe_next(rsc_entry)) {

        pe_resource_t *rsc;
        pe_resource_t *container;
        const char *rsc_id;
        const char *container_id;

        if (!pcmk__str_eq((const char *)rsc_entry->name, XML_LRM_TAG_RESOURCE, pcmk__str_casei)) {
            continue;
        }

        container_id = crm_element_value(rsc_entry, XML_RSC_ATTR_CONTAINER);
        rsc_id = crm_element_value(rsc_entry, XML_ATTR_ID);
        if (container_id == NULL || rsc_id == NULL) {
            continue;
        }

        container = pe_find_resource(data_set->resources, container_id);
        if (container == NULL) {
            continue;
        }

        rsc = pe_find_resource(data_set->resources, rsc_id);
        if (rsc == NULL ||
            !pcmk_is_set(rsc->flags, pe_rsc_orphan_container_filler) ||
            rsc->container != NULL) {
            continue;
        }

        pe_rsc_trace(rsc, "Mapped container of orphaned resource %s to %s",
                     rsc->id, container_id);
        rsc->container = container;
        container->fillers = g_list_append(container->fillers, rsc);
    }
}

/*!
 * \internal
 * \brief Unpack one node's lrm status section
 *
 * \param[in] node      Node whose status is being unpacked
 * \param[in] xml       CIB node state XML
 * \param[in] data_set  Cluster working set
 */
static void
unpack_node_lrm(pe_node_t *node, xmlNode *xml, pe_working_set_t *data_set)
{
    bool found_orphaned_container_filler = false;

    // Drill down to lrm_resources section
    xml = find_xml_node(xml, XML_CIB_TAG_LRM, FALSE);
    if (xml == NULL) {
        return;
    }
    xml = find_xml_node(xml, XML_LRM_TAG_RESOURCES, FALSE);
    if (xml == NULL) {
        return;
    }

    // Unpack each lrm_resource entry
    for (xmlNode *rsc_entry = first_named_child(xml, XML_LRM_TAG_RESOURCE);
         rsc_entry != NULL; rsc_entry = crm_next_same_xml(rsc_entry)) {

        pe_resource_t *rsc = unpack_lrm_resource(node, rsc_entry, data_set);

        if ((rsc != NULL)
            && pcmk_is_set(rsc->flags, pe_rsc_orphan_container_filler)) {
            found_orphaned_container_filler = true;
        }
    }

    /* Now that all resource state has been unpacked for this node, map any
     * orphaned container fillers to their container resource.
     */
    if (found_orphaned_container_filler) {
        handle_orphaned_container_fillers(xml, data_set);
    }
}

static void
set_active(pe_resource_t * rsc)
{
    pe_resource_t *top = uber_parent(rsc);

    if (top && pcmk_is_set(top->flags, pe_rsc_promotable)) {
        rsc->role = RSC_ROLE_UNPROMOTED;
    } else {
        rsc->role = RSC_ROLE_STARTED;
    }
}

static void
set_node_score(gpointer key, gpointer value, gpointer user_data)
{
    pe_node_t *node = value;
    int *score = user_data;

    node->weight = *score;
}

static xmlNode *
find_lrm_op(const char *resource, const char *op, const char *node, const char *source,
            int target_rc, pe_working_set_t *data_set)
{
    GString *xpath = NULL;
    xmlNode *xml = NULL;

    CRM_CHECK((resource != NULL) && (op != NULL) && (node != NULL),
              return NULL);

    xpath = g_string_sized_new(256);
    pcmk__g_strcat(xpath,
                   "//" XML_CIB_TAG_STATE "[@" XML_ATTR_UNAME "='", node, "']"
                   "//" XML_LRM_TAG_RESOURCE
                   "[@" XML_ATTR_ID "='", resource, "']"
                   "/" XML_LRM_TAG_RSC_OP "[@" XML_LRM_ATTR_TASK "='", op, "'",
                   NULL);

    /* Need to check against transition_magic too? */
    if ((source != NULL) && (strcmp(op, CRMD_ACTION_MIGRATE) == 0)) {
        pcmk__g_strcat(xpath,
                       " and @" XML_LRM_ATTR_MIGRATE_TARGET "='", source, "']",
                       NULL);

    } else if ((source != NULL) && (strcmp(op, CRMD_ACTION_MIGRATED) == 0)) {
        pcmk__g_strcat(xpath,
                       " and @" XML_LRM_ATTR_MIGRATE_SOURCE "='", source, "']",
                       NULL);
    } else {
        g_string_append_c(xpath, ']');
    }

    xml = get_xpath_object((const char *) xpath->str, data_set->input,
                           LOG_DEBUG);
    g_string_free(xpath, TRUE);

    if (xml && target_rc >= 0) {
        int rc = PCMK_OCF_UNKNOWN_ERROR;
        int status = PCMK_EXEC_ERROR;

        crm_element_value_int(xml, XML_LRM_ATTR_RC, &rc);
        crm_element_value_int(xml, XML_LRM_ATTR_OPSTATUS, &status);
        if ((rc != target_rc) || (status != PCMK_EXEC_DONE)) {
            return NULL;
        }
    }
    return xml;
}

static xmlNode *
find_lrm_resource(const char *rsc_id, const char *node_name,
                  pe_working_set_t *data_set)
{
    GString *xpath = NULL;
    xmlNode *xml = NULL;

    CRM_CHECK((rsc_id != NULL) && (node_name != NULL), return NULL);

    xpath = g_string_sized_new(256);
    pcmk__g_strcat(xpath,
                   "//" XML_CIB_TAG_STATE
                   "[@" XML_ATTR_UNAME "='", node_name, "']"
                   "//" XML_LRM_TAG_RESOURCE
                   "[@" XML_ATTR_ID "='", rsc_id, "']",
                   NULL);

    xml = get_xpath_object((const char *) xpath->str, data_set->input,
                           LOG_DEBUG);

    g_string_free(xpath, TRUE);
    return xml;
}

static bool
unknown_on_node(const char *rsc_id, const char *node_name,
                pe_working_set_t *data_set)
{
    xmlNode *lrm_resource = NULL;

    lrm_resource = find_lrm_resource(rsc_id, node_name, data_set);

    /* If the resource has no lrm_rsc_op history on the node, that means its
     * state is unknown there.
     */
    return (lrm_resource == NULL
            || first_named_child(lrm_resource, XML_LRM_TAG_RSC_OP) == NULL);
}

/*!
 * \brief Check whether a probe/monitor indicating the resource was not running
 * on a node happened after some event
 *
 * \param[in] rsc_id    Resource being checked
 * \param[in] node_name Node being checked
 * \param[in] xml_op    Event that monitor is being compared to
 * \param[in] data_set  Cluster working set
 *
 * \return true if such a monitor happened after event, false otherwise
 */
static bool
monitor_not_running_after(const char *rsc_id, const char *node_name,
                          xmlNode *xml_op, bool same_node,
                          pe_working_set_t *data_set)
{
    /* Any probe/monitor operation on the node indicating it was not running
     * there
     */
    xmlNode *monitor = find_lrm_op(rsc_id, CRMD_ACTION_STATUS, node_name,
                                   NULL, PCMK_OCF_NOT_RUNNING, data_set);

    return (monitor && pe__is_newer_op(monitor, xml_op, same_node) > 0);
}

/*!
 * \brief Check whether any non-monitor operation on a node happened after some
 * event
 *
 * \param[in] rsc_id    Resource being checked
 * \param[in] node_name Node being checked
 * \param[in] xml_op    Event that non-monitor is being compared to
 * \param[in] same_node Whether the operations are on the same node
 * \param[in] data_set  Cluster working set
 *
 * \return true if such a operation happened after event, false otherwise
 */
static bool
non_monitor_after(const char *rsc_id, const char *node_name, xmlNode *xml_op,
                  bool same_node, pe_working_set_t *data_set)
{
    xmlNode *lrm_resource = NULL;

    lrm_resource = find_lrm_resource(rsc_id, node_name, data_set);
    if (lrm_resource == NULL) {
        return false;
    }

    for (xmlNode *op = first_named_child(lrm_resource, XML_LRM_TAG_RSC_OP);
         op != NULL; op = crm_next_same_xml(op)) {
        const char * task = NULL;

        if (op == xml_op) {
            continue;
        }

        task = crm_element_value(op, XML_LRM_ATTR_TASK);

        if (pcmk__str_any_of(task, CRMD_ACTION_START, CRMD_ACTION_STOP,
                             CRMD_ACTION_MIGRATE, CRMD_ACTION_MIGRATED, NULL)
            && pe__is_newer_op(op, xml_op, same_node) > 0) {
            return true;
        }
    }

    return false;
}

/*!
 * \brief Check whether the resource has newer state on a node after a migration
 * attempt
 *
 * \param[in] rsc_id       Resource being checked
 * \param[in] node_name    Node being checked
 * \param[in] migrate_to   Any migrate_to event that is being compared to
 * \param[in] migrate_from Any migrate_from event that is being compared to
 * \param[in] data_set     Cluster working set
 *
 * \return true if such a operation happened after event, false otherwise
 */
static bool
newer_state_after_migrate(const char *rsc_id, const char *node_name,
                          xmlNode *migrate_to, xmlNode *migrate_from,
                          pe_working_set_t *data_set)
{
    xmlNode *xml_op = migrate_to;
    const char *source = NULL;
    const char *target = NULL;
    bool same_node = false;

    if (migrate_from) {
        xml_op = migrate_from;
    }

    source = crm_element_value(xml_op, XML_LRM_ATTR_MIGRATE_SOURCE);
    target = crm_element_value(xml_op, XML_LRM_ATTR_MIGRATE_TARGET);

    /* It's preferred to compare to the migrate event on the same node if
     * existing, since call ids are more reliable.
     */
    if (pcmk__str_eq(node_name, target, pcmk__str_casei)) {
        if (migrate_from) {
           xml_op = migrate_from;
           same_node = true;

        } else {
           xml_op = migrate_to;
        }

    } else if (pcmk__str_eq(node_name, source, pcmk__str_casei)) {
        if (migrate_to) {
           xml_op = migrate_to;
           same_node = true;

        } else {
           xml_op = migrate_from;
        }
    }

    /* If there's any newer non-monitor operation on the node, or any newer
     * probe/monitor operation on the node indicating it was not running there,
     * the migration events potentially no longer matter for the node.
     */
    return non_monitor_after(rsc_id, node_name, xml_op, same_node, data_set)
           || monitor_not_running_after(rsc_id, node_name, xml_op, same_node,
                                        data_set);
}

static void
unpack_migrate_to_success(pe_resource_t *rsc, pe_node_t *node, xmlNode *xml_op,
                          pe_working_set_t *data_set)
{
    /* A successful migration sequence is:
     *    migrate_to on source node
     *    migrate_from on target node
     *    stop on source node
     *
     * But there could be scenarios like (It's easier to produce with cluster
     * property batch-limit=1):
     *
     * - rscA is live-migrating from node1 to node2.
     *
     * - Before migrate_to on node1 returns, put node2 into standby.
     *
     * - Transition aborts upon return of successful migrate_to on node1. New
     *   transition is going to stop the rscA on both nodes and start it on
     *   node1.
     *
     * - While it is stopping on node1, run something that is going to make
     *   the transition abort again like:
     *   crm_resource  --resource rscA --ban --node node2
     *
     * - Transition aborts upon return of stop on node1.
     *
     * Now although there's a stop on node1, it's still a partial migration and
     * rscA is still potentially active on node2.
     *
     * So even if a migrate_to is followed by a stop, we still need to check
     * whether there's a corresponding migrate_from or any newer operation on
     * the target.
     *
     * If no migrate_from has happened, the migration is considered to be
     * "partial". If the migrate_from failed, make sure the resource gets
     * stopped on both source and target (if up).
     *
     * If the migrate_to and migrate_from both succeeded (which also implies the
     * resource is no longer running on the source), but there is no stop, the
     * migration is considered to be "dangling". Schedule a stop on the source
     * in this case.
     */
    int from_rc = 0;
    int from_status = 0;
    pe_node_t *target_node = NULL;
    pe_node_t *source_node = NULL;
    xmlNode *migrate_from = NULL;
    const char *source = crm_element_value(xml_op, XML_LRM_ATTR_MIGRATE_SOURCE);
    const char *target = crm_element_value(xml_op, XML_LRM_ATTR_MIGRATE_TARGET);
    bool source_newer_op = false;
    bool target_newer_state = false;

    // Sanity check
    CRM_CHECK(source && target && !strcmp(source, node->details->uname), return);

    /* If there's any newer non-monitor operation on the source, this migrate_to
     * potentially no longer matters for the source.
     */
    source_newer_op = non_monitor_after(rsc->id, source, xml_op, true,
                                        data_set);

    // Check whether there was a migrate_from action on the target
    migrate_from = find_lrm_op(rsc->id, CRMD_ACTION_MIGRATED, target,
                               source, -1, data_set);

    /* Even if there's a newer non-monitor operation on the source, we still
     * need to check how this migrate_to might matter for the target.
     */
    if (source_newer_op && migrate_from) {
        return;
    }

    /* If the resource has newer state on the target after the migration
     * events, this migrate_to no longer matters for the target.
     */
    target_newer_state = newer_state_after_migrate(rsc->id, target, xml_op,
                                                   migrate_from, data_set);

    if (source_newer_op && target_newer_state) {
        return;
    }

    // Clones are not allowed to migrate, so role can't be promoted
    rsc->role = RSC_ROLE_STARTED;

    target_node = pe_find_node(data_set->nodes, target);
    source_node = pe_find_node(data_set->nodes, source);

    if (migrate_from) {
        crm_element_value_int(migrate_from, XML_LRM_ATTR_RC, &from_rc);
        crm_element_value_int(migrate_from, XML_LRM_ATTR_OPSTATUS, &from_status);
        pe_rsc_trace(rsc, "%s op on %s exited with status=%d, rc=%d",
                     ID(migrate_from), target, from_status, from_rc);
    }

    if (migrate_from && from_rc == PCMK_OCF_OK
        && (from_status == PCMK_EXEC_DONE)) {
        /* The migrate_to and migrate_from both succeeded, so mark the migration
         * as "dangling". This will be used to schedule a stop action on the
         * source without affecting the target.
         */
        pe_rsc_trace(rsc, "Detected dangling migration op: %s on %s", ID(xml_op),
                     source);
        rsc->role = RSC_ROLE_STOPPED;
        rsc->dangling_migrations = g_list_prepend(rsc->dangling_migrations, node);

    } else if (migrate_from && (from_status != PCMK_EXEC_PENDING)) { // Failed
        /* If the resource has newer state on the target, this migrate_to no
         * longer matters for the target.
         */
        if (!target_newer_state
            && target_node && target_node->details->online) {
            pe_rsc_trace(rsc, "Marking active on %s %p %d", target, target_node,
                         target_node->details->online);
            native_add_running(rsc, target_node, data_set, TRUE);

        } else {
            /* With the earlier bail logic, migrate_from != NULL here implies
             * source_newer_op is false, meaning this migrate_to still matters
             * for the source.
             * Consider it failed here - forces a restart, prevents migration
             */
            pe__set_resource_flags(rsc, pe_rsc_failed|pe_rsc_stop);
            pe__clear_resource_flags(rsc, pe_rsc_allow_migrate);
        }

    } else { // Pending, or complete but erased
        /* If the resource has newer state on the target, this migrate_to no
         * longer matters for the target.
         */
        if (!target_newer_state
            && target_node && target_node->details->online) {
            pe_rsc_trace(rsc, "Marking active on %s %p %d", target, target_node,
                         target_node->details->online);

            native_add_running(rsc, target_node, data_set, FALSE);
            if (source_node && source_node->details->online) {
                /* This is a partial migration: the migrate_to completed
                 * successfully on the source, but the migrate_from has not
                 * completed. Remember the source and target; if the newly
                 * chosen target remains the same when we schedule actions
                 * later, we may continue with the migration.
                 */
                rsc->partial_migration_target = target_node;
                rsc->partial_migration_source = source_node;
            }
        } else if (!source_newer_op) {
            /* This migrate_to matters for the source only if it's the last
             * non-monitor operation here.
             * Consider it failed here - forces a restart, prevents migration
             */
            pe__set_resource_flags(rsc, pe_rsc_failed|pe_rsc_stop);
            pe__clear_resource_flags(rsc, pe_rsc_allow_migrate);
        }
    }
}

static void
unpack_migrate_to_failure(pe_resource_t *rsc, pe_node_t *node, xmlNode *xml_op,
                          pe_working_set_t *data_set)
{
    xmlNode *target_migrate_from = NULL;
    const char *source = crm_element_value(xml_op, XML_LRM_ATTR_MIGRATE_SOURCE);
    const char *target = crm_element_value(xml_op, XML_LRM_ATTR_MIGRATE_TARGET);

    // Sanity check
    CRM_CHECK(source && target && !strcmp(source, node->details->uname), return);

    /* If a migration failed, we have to assume the resource is active. Clones
     * are not allowed to migrate, so role can't be promoted.
     */
    rsc->role = RSC_ROLE_STARTED;

    // Check for migrate_from on the target
    target_migrate_from = find_lrm_op(rsc->id, CRMD_ACTION_MIGRATED, target,
                                      source, PCMK_OCF_OK, data_set);

    if (/* If the resource state is unknown on the target, it will likely be
         * probed there.
         * Don't just consider it running there. We will get back here anyway in
         * case the probe detects it's running there.
         */
        !unknown_on_node(rsc->id, target, data_set)
        /* If the resource has newer state on the target after the migration
         * events, this migrate_to no longer matters for the target.
         */
        && !newer_state_after_migrate(rsc->id, target, xml_op, target_migrate_from,
                                      data_set)) {
        /* The resource has no newer state on the target, so assume it's still
         * active there.
         * (if it is up).
         */
        pe_node_t *target_node = pe_find_node(data_set->nodes, target);

        if (target_node && target_node->details->online) {
            native_add_running(rsc, target_node, data_set, FALSE);
        }

    } else if (!non_monitor_after(rsc->id, source, xml_op, true, data_set)) {
        /* We know the resource has newer state on the target, but this
         * migrate_to still matters for the source as long as there's no newer
         * non-monitor operation there.
         */

        // Mark node as having dangling migration so we can force a stop later
        rsc->dangling_migrations = g_list_prepend(rsc->dangling_migrations, node);
    }
}

static void
unpack_migrate_from_failure(pe_resource_t *rsc, pe_node_t *node,
                            xmlNode *xml_op, pe_working_set_t *data_set)
{
    xmlNode *source_migrate_to = NULL;
    const char *source = crm_element_value(xml_op, XML_LRM_ATTR_MIGRATE_SOURCE);
    const char *target = crm_element_value(xml_op, XML_LRM_ATTR_MIGRATE_TARGET);

    // Sanity check
    CRM_CHECK(source && target && !strcmp(target, node->details->uname), return);

    /* If a migration failed, we have to assume the resource is active. Clones
     * are not allowed to migrate, so role can't be promoted.
     */
    rsc->role = RSC_ROLE_STARTED;

    // Check for a migrate_to on the source
    source_migrate_to = find_lrm_op(rsc->id, CRMD_ACTION_MIGRATE,
                                    source, target, PCMK_OCF_OK, data_set);

    if (/* If the resource state is unknown on the source, it will likely be
         * probed there.
         * Don't just consider it running there. We will get back here anyway in
         * case the probe detects it's running there.
         */
        !unknown_on_node(rsc->id, source, data_set)
        /* If the resource has newer state on the source after the migration
         * events, this migrate_from no longer matters for the source.
         */
        && !newer_state_after_migrate(rsc->id, source, source_migrate_to, xml_op,
                                      data_set)) {
        /* The resource has no newer state on the source, so assume it's still
         * active there (if it is up).
         */
        pe_node_t *source_node = pe_find_node(data_set->nodes, source);

        if (source_node && source_node->details->online) {
            native_add_running(rsc, source_node, data_set, TRUE);
        }
    }
}

static void
record_failed_op(xmlNode *op, const pe_node_t *node,
                 const pe_resource_t *rsc, pe_working_set_t *data_set)
{
    xmlNode *xIter = NULL;
    const char *op_key = crm_element_value(op, XML_LRM_ATTR_TASK_KEY);

    if (node->details->online == FALSE) {
        return;
    }

    for (xIter = data_set->failed->children; xIter; xIter = xIter->next) {
        const char *key = crm_element_value(xIter, XML_LRM_ATTR_TASK_KEY);
        const char *uname = crm_element_value(xIter, XML_ATTR_UNAME);

        if(pcmk__str_eq(op_key, key, pcmk__str_casei) && pcmk__str_eq(uname, node->details->uname, pcmk__str_casei)) {
            crm_trace("Skipping duplicate entry %s on %s",
                      op_key, pe__node_name(node));
            return;
        }
    }

    crm_trace("Adding entry %s on %s", op_key, pe__node_name(node));
    crm_xml_add(op, XML_ATTR_UNAME, node->details->uname);
    crm_xml_add(op, XML_LRM_ATTR_RSCID, rsc->id);
    add_node_copy(data_set->failed, op);
}

static const char *get_op_key(xmlNode *xml_op)
{
    const char *key = crm_element_value(xml_op, XML_LRM_ATTR_TASK_KEY);
    if(key == NULL) {
        key = ID(xml_op);
    }
    return key;
}

static const char *
last_change_str(const xmlNode *xml_op)
{
    time_t when;
    const char *when_s = NULL;

    if (crm_element_value_epoch(xml_op, XML_RSC_OP_LAST_CHANGE,
                                &when) == pcmk_ok) {
        when_s = pcmk__epoch2str(&when);
        if (when_s) {
            // Skip day of week to make message shorter
            when_s = strchr(when_s, ' ');
            if (when_s) {
                ++when_s;
            }
        }
    }
    return ((when_s && *when_s)? when_s : "unknown time");
}

/*!
 * \internal
 * \brief Compare two on-fail values
 *
 * \param[in] first   One on-fail value to compare
 * \param[in] second  The other on-fail value to compare
 *
 * \return A negative number if second is more severe than first, zero if they
 *         are equal, or a positive number if first is more severe than second.
 * \note This is only needed until the action_fail_response values can be
 *       renumbered at the next API compatibility break.
 */
static int
cmp_on_fail(enum action_fail_response first, enum action_fail_response second)
{
    switch (first) {
        case action_fail_demote:
            switch (second) {
                case action_fail_ignore:
                    return 1;
                case action_fail_demote:
                    return 0;
                default:
                    return -1;
            }
            break;

        case action_fail_reset_remote:
            switch (second) {
                case action_fail_ignore:
                case action_fail_demote:
                case action_fail_recover:
                    return 1;
                case action_fail_reset_remote:
                    return 0;
                default:
                    return -1;
            }
            break;

        case action_fail_restart_container:
            switch (second) {
                case action_fail_ignore:
                case action_fail_demote:
                case action_fail_recover:
                case action_fail_reset_remote:
                    return 1;
                case action_fail_restart_container:
                    return 0;
                default:
                    return -1;
            }
            break;

        default:
            break;
    }
    switch (second) {
        case action_fail_demote:
            return (first == action_fail_ignore)? -1 : 1;

        case action_fail_reset_remote:
            switch (first) {
                case action_fail_ignore:
                case action_fail_demote:
                case action_fail_recover:
                    return -1;
                default:
                    return 1;
            }
            break;

        case action_fail_restart_container:
            switch (first) {
                case action_fail_ignore:
                case action_fail_demote:
                case action_fail_recover:
                case action_fail_reset_remote:
                    return -1;
                default:
                    return 1;
            }
            break;

        default:
            break;
    }
    return first - second;
}

static void
unpack_rsc_op_failure(pe_resource_t * rsc, pe_node_t * node, int rc, xmlNode * xml_op, xmlNode ** last_failure,
                      enum action_fail_response * on_fail, pe_working_set_t * data_set)
{
    bool is_probe = false;
    pe_action_t *action = NULL;

    const char *key = get_op_key(xml_op);
    const char *task = crm_element_value(xml_op, XML_LRM_ATTR_TASK);
    const char *exit_reason = crm_element_value(xml_op,
                                                XML_LRM_ATTR_EXIT_REASON);

    CRM_ASSERT(rsc);
    CRM_CHECK(task != NULL, return);

    *last_failure = xml_op;

    is_probe = pcmk_xe_is_probe(xml_op);

    if (exit_reason == NULL) {
        exit_reason = "";
    }

    if (!pcmk_is_set(data_set->flags, pe_flag_symmetric_cluster)
        && (rc == PCMK_OCF_NOT_INSTALLED)) {
        crm_trace("Unexpected result (%s%s%s) was recorded for "
                  "%s of %s on %s at %s " CRM_XS " rc=%d id=%s",
                  services_ocf_exitcode_str(rc),
                  (*exit_reason? ": " : ""), exit_reason,
                  (is_probe? "probe" : task), rsc->id, pe__node_name(node),
                  last_change_str(xml_op), rc, ID(xml_op));
    } else {
        crm_warn("Unexpected result (%s%s%s) was recorded for "
                  "%s of %s on %s at %s " CRM_XS " rc=%d id=%s",
                 services_ocf_exitcode_str(rc),
                 (*exit_reason? ": " : ""), exit_reason,
                 (is_probe? "probe" : task), rsc->id, pe__node_name(node),
                 last_change_str(xml_op), rc, ID(xml_op));

        if (is_probe && (rc != PCMK_OCF_OK)
            && (rc != PCMK_OCF_NOT_RUNNING)
            && (rc != PCMK_OCF_RUNNING_PROMOTED)) {

            /* A failed (not just unexpected) probe result could mean the user
             * didn't know resources will be probed even where they can't run.
             */
            crm_notice("If it is not possible for %s to run on %s, see "
                       "the resource-discovery option for location constraints",
                       rsc->id, pe__node_name(node));
        }

        record_failed_op(xml_op, node, rsc, data_set);
    }

    action = custom_action(rsc, strdup(key), task, NULL, TRUE, FALSE, data_set);
    if (cmp_on_fail(*on_fail, action->on_fail) < 0) {
        pe_rsc_trace(rsc, "on-fail %s -> %s for %s (%s)", fail2text(*on_fail),
                     fail2text(action->on_fail), action->uuid, key);
        *on_fail = action->on_fail;
    }

    if (!strcmp(task, CRMD_ACTION_STOP)) {
        resource_location(rsc, node, -INFINITY, "__stop_fail__", data_set);

    } else if (!strcmp(task, CRMD_ACTION_MIGRATE)) {
        unpack_migrate_to_failure(rsc, node, xml_op, data_set);

    } else if (!strcmp(task, CRMD_ACTION_MIGRATED)) {
        unpack_migrate_from_failure(rsc, node, xml_op, data_set);

    } else if (!strcmp(task, CRMD_ACTION_PROMOTE)) {
        rsc->role = RSC_ROLE_PROMOTED;

    } else if (!strcmp(task, CRMD_ACTION_DEMOTE)) {
        if (action->on_fail == action_fail_block) {
            rsc->role = RSC_ROLE_PROMOTED;
            pe__set_next_role(rsc, RSC_ROLE_STOPPED,
                              "demote with on-fail=block");

        } else if(rc == PCMK_OCF_NOT_RUNNING) {
            rsc->role = RSC_ROLE_STOPPED;

        } else {
            /* Staying in the promoted role would put the scheduler and
             * controller into a loop. Setting the role to unpromoted is not
             * dangerous because the resource will be stopped as part of
             * recovery, and any promotion will be ordered after that stop.
             */
            rsc->role = RSC_ROLE_UNPROMOTED;
        }
    }

    if(is_probe && rc == PCMK_OCF_NOT_INSTALLED) {
        /* leave stopped */
        pe_rsc_trace(rsc, "Leaving %s stopped", rsc->id);
        rsc->role = RSC_ROLE_STOPPED;

    } else if (rsc->role < RSC_ROLE_STARTED) {
        pe_rsc_trace(rsc, "Setting %s active", rsc->id);
        set_active(rsc);
    }

    pe_rsc_trace(rsc, "Resource %s: role=%s, unclean=%s, on_fail=%s, fail_role=%s",
                 rsc->id, role2text(rsc->role),
                 pcmk__btoa(node->details->unclean),
                 fail2text(action->on_fail), role2text(action->fail_role));

    if (action->fail_role != RSC_ROLE_STARTED && rsc->next_role < action->fail_role) {
        pe__set_next_role(rsc, action->fail_role, "failure");
    }

    if (action->fail_role == RSC_ROLE_STOPPED) {
        int score = -INFINITY;

        pe_resource_t *fail_rsc = rsc;

        if (fail_rsc->parent) {
            pe_resource_t *parent = uber_parent(fail_rsc);

            if (pe_rsc_is_clone(parent)
                && !pcmk_is_set(parent->flags, pe_rsc_unique)) {
                /* For clone resources, if a child fails on an operation
                 * with on-fail = stop, all the resources fail.  Do this by preventing
                 * the parent from coming up again. */
                fail_rsc = parent;
            }
        }
        crm_notice("%s will not be started under current conditions",
                   fail_rsc->id);
        /* make sure it doesn't come up again */
        if (fail_rsc->allowed_nodes != NULL) {
            g_hash_table_destroy(fail_rsc->allowed_nodes);
        }
        fail_rsc->allowed_nodes = pe__node_list2table(data_set->nodes);
        g_hash_table_foreach(fail_rsc->allowed_nodes, set_node_score, &score);
    }

    pe_free_action(action);
}

/*!
 * \internal
 * \brief Check whether a resource with a failed action can be recovered
 *
 * If resource action is a failed stop and fencing is not possible, mark the
 * resource as unmanaged and blocked, since recovery cannot be done.
 *
 * \param[in,out] rsc          Resource with failed action
 * \param[in]     node         Node where action failed
 * \param[in]     task         Name of action that failed
 * \param[in]     exit_status  Exit status of failed action (for logging only)
 * \param[in]     xml_op       XML of failed action result (for logging only)
 */
static void
check_recoverable(pe_resource_t *rsc, pe_node_t *node, const char *task,
                  int exit_status, const xmlNode *xml_op)
{
    const char *exit_reason = NULL;

    if (strcmp(task, CRMD_ACTION_STOP) != 0) {
        return; // All actions besides stop are always recoverable
    }
    if (pe_can_fence(node->details->data_set, node)) {
        return; // Failed stops are recoverable via fencing
    }

    exit_reason = crm_element_value(xml_op, XML_LRM_ATTR_EXIT_REASON);
    pe_proc_err("No further recovery can be attempted for %s "
                "because %s on %s failed (%s%s%s) at %s "
                CRM_XS " rc=%d id=%s", rsc->id, task, pe__node_name(node),
                services_ocf_exitcode_str(exit_status),
                ((exit_reason == NULL)? "" : ": "), pcmk__s(exit_reason, ""),
                last_change_str(xml_op), exit_status, ID(xml_op));

    pe__clear_resource_flags(rsc, pe_rsc_managed);
    pe__set_resource_flags(rsc, pe_rsc_block);
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
 * \param[in]     xml_op     Operation history entry XML from CIB status
 * \param[in,out] rsc        Resource that operation history entry is for
 * \param[in]     node       Node where operation was executed
 * \param[in]     data_set   Current cluster working set
 * \param[in,out] on_fail    What should be done about the result
 * \param[in]     target_rc  Expected return code of operation
 * \param[in,out] rc         Actual return code of operation
 * \param[in,out] status     Operation execution status
 *
 * \note If the result is remapped and the node is not shutting down or failed,
 *       the operation will be recorded in the data set's list of failed operations
 *       to highlight it for the user.
 *
 * \note This may update the resource's current and next role.
 */
static void
remap_operation(xmlNode *xml_op, pe_resource_t *rsc, pe_node_t *node,
                pe_working_set_t *data_set, enum action_fail_response *on_fail,
                int target_rc, int *rc, int *status) {
    bool is_probe = false;
    const char *task = crm_element_value(xml_op, XML_LRM_ATTR_TASK);
    const char *key = get_op_key(xml_op);
    const char *exit_reason = crm_element_value(xml_op,
                                                XML_LRM_ATTR_EXIT_REASON);

    if (pcmk__str_eq(task, CRMD_ACTION_STATUS, pcmk__str_none)) {
        int remapped_rc = pcmk__effective_rc(*rc);

        if (*rc != remapped_rc) {
            crm_trace("Remapping monitor result %d to %d", *rc, remapped_rc);
            if (!node->details->shutdown || node->details->online) {
                record_failed_op(xml_op, node, rsc, data_set);
            }

            *rc = remapped_rc;
        }
    }

    if (!pe_rsc_is_bundled(rsc) && pcmk_xe_mask_probe_failure(xml_op)) {
        *status = PCMK_EXEC_DONE;
        *rc = PCMK_OCF_NOT_RUNNING;
    }

    /* If the executor reported an operation status of anything but done or
     * error, consider that final. But for done or error, we know better whether
     * it should be treated as a failure or not, because we know the expected
     * result.
     */
    if (*status != PCMK_EXEC_DONE && *status != PCMK_EXEC_ERROR) {
        return;
    }

    CRM_ASSERT(rsc);
    CRM_CHECK(task != NULL,
              *status = PCMK_EXEC_ERROR; return);

    *status = PCMK_EXEC_DONE;

    if (exit_reason == NULL) {
        exit_reason = "";
    }

    is_probe = pcmk_xe_is_probe(xml_op);

    if (is_probe) {
        task = "probe";
    }

    if (target_rc < 0) {
        /* Pre-1.0 Pacemaker versions, and Pacemaker 1.1.6 or earlier with
         * Heartbeat 2.0.7 or earlier as the cluster layer, did not include the
         * target_rc in the transition key, which (along with the similar case
         * of a corrupted transition key in the CIB) will be reported to this
         * function as -1. Pacemaker 2.0+ does not support rolling upgrades from
         * those versions or processing of saved CIB files from those versions,
         * so we do not need to care much about this case.
         */
        *status = PCMK_EXEC_ERROR;
        crm_warn("Expected result not found for %s on %s (corrupt or obsolete CIB?)",
                 key, pe__node_name(node));

    } else if (target_rc != *rc) {
        *status = PCMK_EXEC_ERROR;
        pe_rsc_debug(rsc, "%s on %s: expected %d (%s), got %d (%s%s%s)",
                     key, pe__node_name(node),
                     target_rc, services_ocf_exitcode_str(target_rc),
                     *rc, services_ocf_exitcode_str(*rc),
                     (*exit_reason? ": " : ""), exit_reason);
    }

    switch (*rc) {
        case PCMK_OCF_OK:
            if (is_probe && (target_rc == PCMK_OCF_NOT_RUNNING)) {
                *status = PCMK_EXEC_DONE;
                pe_rsc_info(rsc, "Probe found %s active on %s at %s",
                            rsc->id, pe__node_name(node),
                            last_change_str(xml_op));
            }
            break;

        case PCMK_OCF_NOT_RUNNING:
            if (is_probe || (target_rc == *rc)
                || !pcmk_is_set(rsc->flags, pe_rsc_managed)) {

                *status = PCMK_EXEC_DONE;
                rsc->role = RSC_ROLE_STOPPED;

                /* clear any previous failure actions */
                *on_fail = action_fail_ignore;
                pe__set_next_role(rsc, RSC_ROLE_UNKNOWN, "not running");
            }
            break;

        case PCMK_OCF_RUNNING_PROMOTED:
            if (is_probe && (*rc != target_rc)) {
                *status = PCMK_EXEC_DONE;
                pe_rsc_info(rsc,
                            "Probe found %s active and promoted on %s at %s",
                            rsc->id, pe__node_name(node),
                            last_change_str(xml_op));
            }
            rsc->role = RSC_ROLE_PROMOTED;
            break;

        case PCMK_OCF_DEGRADED_PROMOTED:
        case PCMK_OCF_FAILED_PROMOTED:
            rsc->role = RSC_ROLE_PROMOTED;
            *status = PCMK_EXEC_ERROR;
            break;

        case PCMK_OCF_NOT_CONFIGURED:
            *status = PCMK_EXEC_ERROR_FATAL;
            break;

        case PCMK_OCF_UNIMPLEMENT_FEATURE:
            {
                guint interval_ms = 0;
                crm_element_value_ms(xml_op, XML_LRM_ATTR_INTERVAL_MS,
                                     &interval_ms);

                if (interval_ms == 0) {
                    check_recoverable(rsc, node, task, *rc, xml_op);
                    *status = PCMK_EXEC_ERROR_HARD;
                } else {
                    *status = PCMK_EXEC_NOT_SUPPORTED;
                }
            }
            break;

        case PCMK_OCF_NOT_INSTALLED:
        case PCMK_OCF_INVALID_PARAM:
        case PCMK_OCF_INSUFFICIENT_PRIV:
            check_recoverable(rsc, node, task, *rc, xml_op);
            *status = PCMK_EXEC_ERROR_HARD;
            break;

        default:
            if (*status == PCMK_EXEC_DONE) {
                crm_info("Treating unknown exit status %d from %s of %s "
                         "on %s at %s as failure",
                         *rc, task, rsc->id, pe__node_name(node),
                         last_change_str(xml_op));
                *status = PCMK_EXEC_ERROR;
            }
            break;
    }

    pe_rsc_trace(rsc, "Remapped %s status to '%s'",
                 key, pcmk_exec_status_str(*status));
}

// return TRUE if start or monitor last failure but parameters changed
static bool
should_clear_for_param_change(xmlNode *xml_op, const char *task,
                              pe_resource_t *rsc, pe_node_t *node,
                              pe_working_set_t *data_set)
{
    if (!strcmp(task, "start") || !strcmp(task, "monitor")) {

        if (pe__bundle_needs_remote_name(rsc, data_set)) {
            /* We haven't allocated resources yet, so we can't reliably
             * substitute addr parameters for the REMOTE_CONTAINER_HACK.
             * When that's needed, defer the check until later.
             */
            pe__add_param_check(xml_op, rsc, node, pe_check_last_failure,
                                data_set);

        } else {
            op_digest_cache_t *digest_data = NULL;

            digest_data = rsc_action_digest_cmp(rsc, xml_op, node, data_set);
            switch (digest_data->rc) {
                case RSC_DIGEST_UNKNOWN:
                    crm_trace("Resource %s history entry %s on %s"
                              " has no digest to compare",
                              rsc->id, get_op_key(xml_op), node->details->id);
                    break;
                case RSC_DIGEST_MATCH:
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
order_after_remote_fencing(pe_action_t *action, pe_resource_t *remote_conn,
                           pe_working_set_t *data_set)
{
    pe_node_t *remote_node = pe_find_node(data_set->nodes, remote_conn->id);

    if (remote_node) {
        pe_action_t *fence = pe_fence_op(remote_node, NULL, TRUE, NULL,
                                         FALSE, data_set);

        order_actions(fence, action, pe_order_implies_then);
    }
}

static bool
should_ignore_failure_timeout(pe_resource_t *rsc, xmlNode *xml_op,
                              const char *task, guint interval_ms,
                              bool is_last_failure, pe_working_set_t *data_set)
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
    if (rsc->remote_reconnect_ms
        && pcmk_is_set(data_set->flags, pe_flag_stonith_enabled)
        && (interval_ms != 0) && pcmk__str_eq(task, CRMD_ACTION_STATUS, pcmk__str_casei)) {

        pe_node_t *remote_node = pe_find_node(data_set->nodes, rsc->id);

        if (remote_node && !remote_node->details->remote_was_fenced) {
            if (is_last_failure) {
                crm_info("Waiting to clear monitor failure for remote node %s"
                         " until fencing has occurred", rsc->id);
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
 * \param[in] rsc       Resource that operation happened to
 * \param[in] node      Node that operation happened on
 * \param[in] rc        Actual result of operation
 * \param[in] xml_op    Operation history entry XML
 * \param[in] data_set  Current working set
 *
 * \return TRUE if operation history entry is expired, FALSE otherwise
 */
static bool
check_operation_expiry(pe_resource_t *rsc, pe_node_t *node, int rc,
                       xmlNode *xml_op, pe_working_set_t *data_set)
{
    bool expired = FALSE;
    bool is_last_failure = pcmk__ends_with(ID(xml_op), "_last_failure_0");
    time_t last_run = 0;
    guint interval_ms = 0;
    int unexpired_fail_count = 0;
    const char *task = crm_element_value(xml_op, XML_LRM_ATTR_TASK);
    const char *clear_reason = NULL;

    crm_element_value_ms(xml_op, XML_LRM_ATTR_INTERVAL_MS, &interval_ms);

    if ((rsc->failure_timeout > 0)
        && (crm_element_value_epoch(xml_op, XML_RSC_OP_LAST_CHANGE,
                                    &last_run) == 0)) {

        // Resource has a failure-timeout, and history entry has a timestamp

        time_t now = get_effective_time(data_set);
        time_t last_failure = 0;

        // Is this particular operation history older than the failure timeout?
        if ((now >= (last_run + rsc->failure_timeout))
            && !should_ignore_failure_timeout(rsc, xml_op, task, interval_ms,
                                              is_last_failure, data_set)) {
            expired = TRUE;
        }

        // Does the resource as a whole have an unexpired fail count?
        unexpired_fail_count = pe_get_failcount(node, rsc, &last_failure,
                                                pe_fc_effective, xml_op,
                                                data_set);

        // Update scheduler recheck time according to *last* failure
        crm_trace("%s@%lld is %sexpired @%lld with unexpired_failures=%d timeout=%ds"
                  " last-failure@%lld",
                  ID(xml_op), (long long) last_run, (expired? "" : "not "),
                  (long long) now, unexpired_fail_count, rsc->failure_timeout,
                  (long long) last_failure);
        last_failure += rsc->failure_timeout + 1;
        if (unexpired_fail_count && (now < last_failure)) {
            pe__update_recheck_time(last_failure, data_set);
        }
    }

    if (expired) {
        if (pe_get_failcount(node, rsc, NULL, pe_fc_default, xml_op, data_set)) {

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
                expired = FALSE;
            }

        } else if (is_last_failure && rsc->remote_reconnect_ms) {
            /* Clear any expired last failure when reconnect interval is set,
             * even if there is no fail count.
             */
            clear_reason = "reconnect interval is set";
        }
    }

    if (!expired && is_last_failure
        && should_clear_for_param_change(xml_op, task, rsc, node, data_set)) {
        clear_reason = "resource parameters have changed";
    }

    if (clear_reason != NULL) {
        // Schedule clearing of the fail count
        pe_action_t *clear_op = pe__clear_failcount(rsc, node, clear_reason,
                                                    data_set);

        if (pcmk_is_set(data_set->flags, pe_flag_stonith_enabled)
            && rsc->remote_reconnect_ms) {
            /* If we're clearing a remote connection due to a reconnect
             * interval, we want to wait until any scheduled fencing
             * completes.
             *
             * We could limit this to remote_node->details->unclean, but at
             * this point, that's always true (it won't be reliable until
             * after unpack_node_history() is done).
             */
            crm_info("Clearing %s failure will wait until any scheduled "
                     "fencing of %s completes", task, rsc->id);
            order_after_remote_fencing(clear_op, rsc, data_set);
        }
    }

    if (expired && (interval_ms == 0) && pcmk__str_eq(task, CRMD_ACTION_STATUS, pcmk__str_casei)) {
        switch(rc) {
            case PCMK_OCF_OK:
            case PCMK_OCF_NOT_RUNNING:
            case PCMK_OCF_RUNNING_PROMOTED:
            case PCMK_OCF_DEGRADED:
            case PCMK_OCF_DEGRADED_PROMOTED:
                // Don't expire probes that return these values
                expired = FALSE;
                break;
        }
    }

    return expired;
}

int pe__target_rc_from_xml(xmlNode *xml_op)
{
    int target_rc = 0;
    const char *key = crm_element_value(xml_op, XML_ATTR_TRANSITION_KEY);

    if (key == NULL) {
        return -1;
    }
    decode_transition_key(key, NULL, NULL, NULL, &target_rc);
    return target_rc;
}

static enum action_fail_response
get_action_on_fail(pe_resource_t *rsc, const char *key, const char *task, pe_working_set_t * data_set) 
{
    enum action_fail_response result = action_fail_recover;
    pe_action_t *action = custom_action(rsc, strdup(key), task, NULL, TRUE, FALSE, data_set);

    result = action->on_fail;
    pe_free_action(action);

    return result;
}

static void
update_resource_state(pe_resource_t * rsc, pe_node_t * node, xmlNode * xml_op, const char * task, int rc,
                      xmlNode * last_failure, enum action_fail_response * on_fail, pe_working_set_t * data_set)
{
    gboolean clear_past_failure = FALSE;

    CRM_ASSERT(rsc);
    CRM_ASSERT(xml_op);

    if (rc == PCMK_OCF_NOT_INSTALLED || (!pe_rsc_is_bundled(rsc) && pcmk_xe_mask_probe_failure(xml_op))) {
        rsc->role = RSC_ROLE_STOPPED;

    } else if (rc == PCMK_OCF_NOT_RUNNING) {
        clear_past_failure = TRUE;

    } else if (pcmk__str_eq(task, CRMD_ACTION_STATUS, pcmk__str_casei)) {
        if (last_failure) {
            const char *op_key = get_op_key(xml_op);
            const char *last_failure_key = get_op_key(last_failure);

            if (pcmk__str_eq(op_key, last_failure_key, pcmk__str_casei)) {
                clear_past_failure = TRUE;
            }
        }

        if (rsc->role < RSC_ROLE_STARTED) {
            set_active(rsc);
        }

    } else if (pcmk__str_eq(task, CRMD_ACTION_START, pcmk__str_casei)) {
        rsc->role = RSC_ROLE_STARTED;
        clear_past_failure = TRUE;

    } else if (pcmk__str_eq(task, CRMD_ACTION_STOP, pcmk__str_casei)) {
        rsc->role = RSC_ROLE_STOPPED;
        clear_past_failure = TRUE;

    } else if (pcmk__str_eq(task, CRMD_ACTION_PROMOTE, pcmk__str_casei)) {
        rsc->role = RSC_ROLE_PROMOTED;
        clear_past_failure = TRUE;

    } else if (pcmk__str_eq(task, CRMD_ACTION_DEMOTE, pcmk__str_casei)) {

        if (*on_fail == action_fail_demote) {
            // Demote clears an error only if on-fail=demote
            clear_past_failure = TRUE;
        }
        rsc->role = RSC_ROLE_UNPROMOTED;

    } else if (pcmk__str_eq(task, CRMD_ACTION_MIGRATED, pcmk__str_casei)) {
        rsc->role = RSC_ROLE_STARTED;
        clear_past_failure = TRUE;

    } else if (pcmk__str_eq(task, CRMD_ACTION_MIGRATE, pcmk__str_casei)) {
        unpack_migrate_to_success(rsc, node, xml_op, data_set);

    } else if (rsc->role < RSC_ROLE_STARTED) {
        pe_rsc_trace(rsc, "%s active on %s", rsc->id, pe__node_name(node));
        set_active(rsc);
    }

    /* clear any previous failure actions */
    if (clear_past_failure) {
        switch (*on_fail) {
            case action_fail_stop:
            case action_fail_fence:
            case action_fail_migrate:
            case action_fail_standby:
                pe_rsc_trace(rsc, "%s.%s is not cleared by a completed stop",
                             rsc->id, fail2text(*on_fail));
                break;

            case action_fail_block:
            case action_fail_ignore:
            case action_fail_demote:
            case action_fail_recover:
            case action_fail_restart_container:
                *on_fail = action_fail_ignore;
                pe__set_next_role(rsc, RSC_ROLE_UNKNOWN, "clear past failures");
                break;
            case action_fail_reset_remote:
                if (rsc->remote_reconnect_ms == 0) {
                    /* With no reconnect interval, the connection is allowed to
                     * start again after the remote node is fenced and
                     * completely stopped. (With a reconnect interval, we wait
                     * for the failure to be cleared entirely before attempting
                     * to reconnect.)
                     */
                    *on_fail = action_fail_ignore;
                    pe__set_next_role(rsc, RSC_ROLE_UNKNOWN,
                                      "clear past failures and reset remote");
                }
                break;
        }
    }
}

static void
unpack_rsc_op(pe_resource_t *rsc, pe_node_t *node, xmlNode *xml_op,
              xmlNode **last_failure, enum action_fail_response *on_fail,
              pe_working_set_t *data_set)
{
    int rc = 0;
    int old_rc = 0;
    int task_id = 0;
    int target_rc = 0;
    int old_target_rc = 0;
    int status = PCMK_EXEC_UNKNOWN;
    guint interval_ms = 0;
    const char *task = NULL;
    const char *task_key = NULL;
    const char *exit_reason = NULL;
    bool expired = false;
    pe_resource_t *parent = rsc;
    enum action_fail_response failure_strategy = action_fail_recover;
    bool maskable_probe_failure = false;

    CRM_CHECK(rsc && node && xml_op, return);

    target_rc = pe__target_rc_from_xml(xml_op);
    task_key = get_op_key(xml_op);
    task = crm_element_value(xml_op, XML_LRM_ATTR_TASK);
    exit_reason = crm_element_value(xml_op, XML_LRM_ATTR_EXIT_REASON);
    if (exit_reason == NULL) {
        exit_reason = "";
    }

    crm_element_value_int(xml_op, XML_LRM_ATTR_RC, &rc);
    crm_element_value_int(xml_op, XML_LRM_ATTR_CALLID, &task_id);
    crm_element_value_int(xml_op, XML_LRM_ATTR_OPSTATUS, &status);
    crm_element_value_ms(xml_op, XML_LRM_ATTR_INTERVAL_MS, &interval_ms);

    CRM_CHECK(task != NULL, return);
    CRM_CHECK((status >= PCMK_EXEC_PENDING) && (status <= PCMK_EXEC_MAX),
              return);

    if (!strcmp(task, CRMD_ACTION_NOTIFY) ||
        !strcmp(task, CRMD_ACTION_METADATA)) {
        /* safe to ignore these */
        return;
    }

    if (!pcmk_is_set(rsc->flags, pe_rsc_unique)) {
        parent = uber_parent(rsc);
    }

    pe_rsc_trace(rsc, "Unpacking task %s/%s (call_id=%d, status=%d, rc=%d) on %s (role=%s)",
                 task_key, task, task_id, status, rc, pe__node_name(node),
                 role2text(rsc->role));

    if (node->details->unclean) {
        pe_rsc_trace(rsc,
                     "%s is running on %s, which is unclean (further action "
                     "depends on value of stop's on-fail attribute)",
                     rsc->id, pe__node_name(node));
    }

    /* It should be possible to call remap_operation() first then call
     * check_operation_expiry() only if rc != target_rc, because there should
     * never be a fail count without at least one unexpected result in the
     * resource history. That would be more efficient by avoiding having to call
     * check_operation_expiry() for expected results.
     *
     * However, we do have such configurations in the scheduler regression
     * tests, even if it shouldn't be possible with the current code. It's
     * probably a good idea anyway, but that would require updating the test
     * inputs to something currently possible.
     */

    if ((status != PCMK_EXEC_NOT_INSTALLED)
        && check_operation_expiry(rsc, node, rc, xml_op, data_set)) {
        expired = true;
    }

    old_rc = rc;
    old_target_rc = target_rc;

    remap_operation(xml_op, rsc, node, data_set, on_fail, target_rc,
                    &rc, &status);

    maskable_probe_failure = !pe_rsc_is_bundled(rsc) && pcmk_xe_mask_probe_failure(xml_op);

    if (expired && maskable_probe_failure && old_rc != old_target_rc) {
        if (rsc->role <= RSC_ROLE_STOPPED) {
            rsc->role = RSC_ROLE_UNKNOWN;
        }

        goto done;

    } else if (expired && (rc != target_rc)) {
        const char *magic = crm_element_value(xml_op, XML_ATTR_TRANSITION_MAGIC);

        if (interval_ms == 0) {
            crm_notice("Ignoring expired %s failure on %s "
                       CRM_XS " actual=%d expected=%d magic=%s",
                       task_key, pe__node_name(node), rc, target_rc, magic);
            goto done;

        } else if(node->details->online && node->details->unclean == FALSE) {
            /* Reschedule the recurring monitor. schedule_cancel() won't work at
             * this stage, so as a hacky workaround, forcibly change the restart
             * digest so pcmk__check_action_config() does what we want later.
             *
             * @TODO We should skip this if there is a newer successful monitor.
             *       Also, this causes rescheduling only if the history entry
             *       has an op-digest (which the expire-non-blocked-failure
             *       scheduler regression test doesn't, but that may not be a
             *       realistic scenario in production).
             */
            crm_notice("Rescheduling %s after failure expired on %s "
                       CRM_XS " actual=%d expected=%d magic=%s",
                       task_key, pe__node_name(node), rc, target_rc, magic);
            crm_xml_add(xml_op, XML_LRM_ATTR_RESTART_DIGEST, "calculated-failure-timeout");
            goto done;
        }
    }

    if (maskable_probe_failure) {
        crm_notice("Treating probe result '%s' for %s on %s as 'not running'",
                   services_ocf_exitcode_str(old_rc), rsc->id,
                   pe__node_name(node));
        update_resource_state(rsc, node, xml_op, task, target_rc, *last_failure,
                              on_fail, data_set);
        crm_xml_add(xml_op, XML_ATTR_UNAME, node->details->uname);

        record_failed_op(xml_op, node, rsc, data_set);
        resource_location(parent, node, -INFINITY, "masked-probe-failure", data_set);
        goto done;
    }

    switch (status) {
        case PCMK_EXEC_CANCELLED:
            // Should never happen
            pe_err("Resource history contains cancellation '%s' "
                   "(%s of %s on %s at %s)",
                   ID(xml_op), task, rsc->id, pe__node_name(node),
                   last_change_str(xml_op));
            goto done;

        case PCMK_EXEC_PENDING:
            if (!strcmp(task, CRMD_ACTION_START)) {
                pe__set_resource_flags(rsc, pe_rsc_start_pending);
                set_active(rsc);

            } else if (!strcmp(task, CRMD_ACTION_PROMOTE)) {
                rsc->role = RSC_ROLE_PROMOTED;

            } else if (!strcmp(task, CRMD_ACTION_MIGRATE) && node->details->unclean) {
                /* If a pending migrate_to action is out on a unclean node,
                 * we have to force the stop action on the target. */
                const char *migrate_target = crm_element_value(xml_op, XML_LRM_ATTR_MIGRATE_TARGET);
                pe_node_t *target = pe_find_node(data_set->nodes, migrate_target);
                if (target) {
                    stop_action(rsc, target, FALSE);
                }
            }

            if (rsc->pending_task == NULL) {
                if ((interval_ms != 0) || strcmp(task, CRMD_ACTION_STATUS)) {
                    rsc->pending_task = strdup(task);
                    rsc->pending_node = node;
                } else {
                    /* Pending probes are not printed, even if pending
                     * operations are requested. If someone ever requests that
                     * behavior, enable the below and the corresponding part of
                     * native.c:native_pending_task().
                     */
#if 0
                    rsc->pending_task = strdup("probe");
                    rsc->pending_node = node;
#endif
                }
            }
            goto done;

        case PCMK_EXEC_DONE:
            pe_rsc_trace(rsc, "%s of %s on %s completed at %s " CRM_XS " id=%s",
                         task, rsc->id, pe__node_name(node),
                         last_change_str(xml_op), ID(xml_op));
            update_resource_state(rsc, node, xml_op, task, rc, *last_failure, on_fail, data_set);
            goto done;

        case PCMK_EXEC_NOT_INSTALLED:
            failure_strategy = get_action_on_fail(rsc, task_key, task, data_set);
            if (failure_strategy == action_fail_ignore) {
                crm_warn("Cannot ignore failed %s of %s on %s: "
                         "Resource agent doesn't exist "
                         CRM_XS " status=%d rc=%d id=%s",
                         task, rsc->id, pe__node_name(node), status, rc,
                         ID(xml_op));
                /* Also for printing it as "FAILED" by marking it as pe_rsc_failed later */
                *on_fail = action_fail_migrate;
            }
            resource_location(parent, node, -INFINITY, "hard-error", data_set);
            unpack_rsc_op_failure(rsc, node, rc, xml_op, last_failure, on_fail, data_set);
            goto done;

        case PCMK_EXEC_NOT_CONNECTED:
            if (pe__is_guest_or_remote_node(node)
                && pcmk_is_set(node->details->remote_rsc->flags, pe_rsc_managed)) {
                /* We should never get into a situation where a managed remote
                 * connection resource is considered OK but a resource action
                 * behind the connection gets a "not connected" status. But as a
                 * fail-safe in case a bug or unusual circumstances do lead to
                 * that, ensure the remote connection is considered failed.
                 */
                pe__set_resource_flags(node->details->remote_rsc,
                                       pe_rsc_failed|pe_rsc_stop);
            }
            break; // Not done, do error handling

        case PCMK_EXEC_ERROR:
        case PCMK_EXEC_ERROR_HARD:
        case PCMK_EXEC_ERROR_FATAL:
        case PCMK_EXEC_TIMEOUT:
        case PCMK_EXEC_NOT_SUPPORTED:
        case PCMK_EXEC_INVALID:
            break; // Not done, do error handling

        case PCMK_EXEC_NO_FENCE_DEVICE:
        case PCMK_EXEC_NO_SECRETS:
            status = PCMK_EXEC_ERROR_HARD;
            break; // Not done, do error handling
    }

    failure_strategy = get_action_on_fail(rsc, task_key, task, data_set);
    if ((failure_strategy == action_fail_ignore)
        || (failure_strategy == action_fail_restart_container
            && !strcmp(task, CRMD_ACTION_STOP))) {

        crm_warn("Pretending failed %s (%s%s%s) of %s on %s at %s "
                 "succeeded " CRM_XS " rc=%d id=%s",
                 task, services_ocf_exitcode_str(rc),
                 (*exit_reason? ": " : ""), exit_reason, rsc->id,
                 pe__node_name(node), last_change_str(xml_op), rc,
                 ID(xml_op));

        update_resource_state(rsc, node, xml_op, task, target_rc, *last_failure,
                              on_fail, data_set);
        crm_xml_add(xml_op, XML_ATTR_UNAME, node->details->uname);
        pe__set_resource_flags(rsc, pe_rsc_failure_ignored);

        record_failed_op(xml_op, node, rsc, data_set);

        if ((failure_strategy == action_fail_restart_container)
            && cmp_on_fail(*on_fail, action_fail_recover) <= 0) {
            *on_fail = failure_strategy;
        }

    } else {
        unpack_rsc_op_failure(rsc, node, rc, xml_op, last_failure, on_fail,
                              data_set);

        if (status == PCMK_EXEC_ERROR_HARD) {
            do_crm_log(rc != PCMK_OCF_NOT_INSTALLED?LOG_ERR:LOG_NOTICE,
                       "Preventing %s from restarting on %s because "
                       "of hard failure (%s%s%s)" CRM_XS " rc=%d id=%s",
                       parent->id, pe__node_name(node),
                       services_ocf_exitcode_str(rc),
                       (*exit_reason? ": " : ""), exit_reason,
                       rc, ID(xml_op));
            resource_location(parent, node, -INFINITY, "hard-error", data_set);

        } else if (status == PCMK_EXEC_ERROR_FATAL) {
            crm_err("Preventing %s from restarting anywhere because "
                    "of fatal failure (%s%s%s) " CRM_XS " rc=%d id=%s",
                    parent->id, services_ocf_exitcode_str(rc),
                    (*exit_reason? ": " : ""), exit_reason,
                    rc, ID(xml_op));
            resource_location(parent, NULL, -INFINITY, "fatal-error", data_set);
        }
    }

done:
    pe_rsc_trace(rsc, "Resource %s after %s: role=%s, next=%s",
                 rsc->id, task, role2text(rsc->role),
                 role2text(rsc->next_role));
}

static void
add_node_attrs(xmlNode *xml_obj, pe_node_t *node, bool overwrite,
               pe_working_set_t *data_set)
{
    const char *cluster_name = NULL;

    pe_rule_eval_data_t rule_data = {
        .node_hash = NULL,
        .role = RSC_ROLE_UNKNOWN,
        .now = data_set->now,
        .match_data = NULL,
        .rsc_data = NULL,
        .op_data = NULL
    };

    g_hash_table_insert(node->details->attrs,
                        strdup(CRM_ATTR_UNAME), strdup(node->details->uname));

    g_hash_table_insert(node->details->attrs, strdup(CRM_ATTR_ID),
                        strdup(node->details->id));
    if (pcmk__str_eq(node->details->id, data_set->dc_uuid, pcmk__str_casei)) {
        data_set->dc_node = node;
        node->details->is_dc = TRUE;
        g_hash_table_insert(node->details->attrs,
                            strdup(CRM_ATTR_IS_DC), strdup(XML_BOOLEAN_TRUE));
    } else {
        g_hash_table_insert(node->details->attrs,
                            strdup(CRM_ATTR_IS_DC), strdup(XML_BOOLEAN_FALSE));
    }

    cluster_name = g_hash_table_lookup(data_set->config_hash, "cluster-name");
    if (cluster_name) {
        g_hash_table_insert(node->details->attrs, strdup(CRM_ATTR_CLUSTER_NAME),
                            strdup(cluster_name));
    }

    pe__unpack_dataset_nvpairs(xml_obj, XML_TAG_ATTR_SETS, &rule_data,
                               node->details->attrs, NULL, overwrite, data_set);

    if (pe_node_attribute_raw(node, CRM_ATTR_SITE_NAME) == NULL) {
        const char *site_name = pe_node_attribute_raw(node, "site-name");

        if (site_name) {
            g_hash_table_insert(node->details->attrs,
                                strdup(CRM_ATTR_SITE_NAME),
                                strdup(site_name));

        } else if (cluster_name) {
            /* Default to cluster-name if unset */
            g_hash_table_insert(node->details->attrs,
                                strdup(CRM_ATTR_SITE_NAME),
                                strdup(cluster_name));
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

    for (rsc_op = pcmk__xe_first_child(rsc_entry);
         rsc_op != NULL; rsc_op = pcmk__xe_next(rsc_op)) {

        if (pcmk__str_eq((const char *)rsc_op->name, XML_LRM_TAG_RSC_OP,
                         pcmk__str_none)) {
            crm_xml_add(rsc_op, "resource", rsc);
            crm_xml_add(rsc_op, XML_ATTR_UNAME, node);
            op_list = g_list_prepend(op_list, rsc_op);
        }
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
            crm_trace("Skipping %s: not active", ID(rsc_entry));
            break;

        } else if (counter < start_index) {
            crm_trace("Skipping %s: old", ID(rsc_op));
            continue;
        }
        op_list = g_list_append(op_list, rsc_op);
    }

    g_list_free(sorted_op_list);
    return op_list;
}

GList *
find_operations(const char *rsc, const char *node, gboolean active_filter,
                pe_working_set_t * data_set)
{
    GList *output = NULL;
    GList *intermediate = NULL;

    xmlNode *tmp = NULL;
    xmlNode *status = find_xml_node(data_set->input, XML_CIB_TAG_STATUS, TRUE);

    pe_node_t *this_node = NULL;

    xmlNode *node_state = NULL;

    for (node_state = pcmk__xe_first_child(status); node_state != NULL;
         node_state = pcmk__xe_next(node_state)) {

        if (pcmk__str_eq((const char *)node_state->name, XML_CIB_TAG_STATE, pcmk__str_none)) {
            const char *uname = crm_element_value(node_state, XML_ATTR_UNAME);

            if (node != NULL && !pcmk__str_eq(uname, node, pcmk__str_casei)) {
                continue;
            }

            this_node = pe_find_node(data_set->nodes, uname);
            if(this_node == NULL) {
                CRM_LOG_ASSERT(this_node != NULL);
                continue;

            } else if (pe__is_guest_or_remote_node(this_node)) {
                determine_remote_online_status(data_set, this_node);

            } else {
                determine_online_status(node_state, this_node, data_set);
            }

            if (this_node->details->online
                || pcmk_is_set(data_set->flags, pe_flag_stonith_enabled)) {
                /* offline nodes run no resources...
                 * unless stonith is enabled in which case we need to
                 *   make sure rsc start events happen after the stonith
                 */
                xmlNode *lrm_rsc = NULL;

                tmp = find_xml_node(node_state, XML_CIB_TAG_LRM, FALSE);
                tmp = find_xml_node(tmp, XML_LRM_TAG_RESOURCES, FALSE);

                for (lrm_rsc = pcmk__xe_first_child(tmp); lrm_rsc != NULL;
                     lrm_rsc = pcmk__xe_next(lrm_rsc)) {

                    if (pcmk__str_eq((const char *)lrm_rsc->name,
                                     XML_LRM_TAG_RESOURCE, pcmk__str_none)) {

                        const char *rsc_id = crm_element_value(lrm_rsc, XML_ATTR_ID);

                        if (rsc != NULL && !pcmk__str_eq(rsc_id, rsc, pcmk__str_casei)) {
                            continue;
                        }

                        intermediate = extract_operations(uname, rsc_id, lrm_rsc, active_filter);
                        output = g_list_concat(output, intermediate);
                    }
                }
            }
        }
    }

    return output;
}
