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

#include <glib.h>

#include <crm/crm.h>
#include <crm/services.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>

#include <crm/common/util.h>
#include <crm/pengine/rules.h>
#include <crm/pengine/internal.h>
#include <unpack.h>

CRM_TRACE_INIT_DATA(pe_status);

#define set_config_flag(data_set, option, flag) do {			\
	const char *tmp = pe_pref(data_set->config_hash, option);	\
	if(tmp) {							\
	    if(crm_is_true(tmp)) {					\
		set_bit(data_set->flags, flag);			\
	    } else {							\
		clear_bit(data_set->flags, flag);		\
	    }								\
	}								\
    } while(0)

gboolean unpack_rsc_op(resource_t * rsc, node_t * node, xmlNode * xml_op,
                       enum action_fail_response *failed, pe_working_set_t * data_set);
static gboolean determine_remote_online_status(node_t * this_node);

static void
pe_fence_node(pe_working_set_t * data_set, node_t * node, const char *reason)
{
    CRM_CHECK(node, return);

    /* fence remote nodes living in a container by marking
     * the container as failed. */
    if (node->details->remote_rsc && node->details->remote_rsc->container) {
        resource_t *rsc = node->details->remote_rsc->container;
        if (is_set(rsc->flags, pe_rsc_failed) == FALSE) {
            crm_warn("Remote node %s will be fenced by recovering container resource %s",
                node->details->uname, rsc->id, reason);
            set_bit(rsc->flags, pe_rsc_failed);
        }
    } else if (node->details->unclean == FALSE) {
        if (is_set(data_set->flags, pe_flag_stonith_enabled)) {
            crm_warn("Node %s will be fenced %s", node->details->uname, reason);
        } else {
            crm_warn("Node %s is unclean %s", node->details->uname, reason);
        }
        node->details->unclean = TRUE;
    }
}

gboolean
unpack_config(xmlNode * config, pe_working_set_t * data_set)
{
    const char *value = NULL;
    GHashTable *config_hash =
        g_hash_table_new_full(crm_str_hash, g_str_equal, g_hash_destroy_str, g_hash_destroy_str);

    data_set->config_hash = config_hash;

    unpack_instance_attributes(data_set->input, config, XML_CIB_TAG_PROPSET, NULL, config_hash,
                               CIB_OPTIONS_FIRST, FALSE, data_set->now);

    verify_pe_options(data_set->config_hash);

    set_config_flag(data_set, "enable-startup-probes", pe_flag_startup_probes);
    crm_info("Startup probes: %s",
             is_set(data_set->flags, pe_flag_startup_probes) ? "enabled" : "disabled (dangerous)");

    value = pe_pref(data_set->config_hash, "stonith-timeout");
    data_set->stonith_timeout = crm_get_msec(value);
    crm_debug("STONITH timeout: %d", data_set->stonith_timeout);

    set_config_flag(data_set, "stonith-enabled", pe_flag_stonith_enabled);
    crm_debug("STONITH of failed nodes is %s",
              is_set(data_set->flags, pe_flag_stonith_enabled) ? "enabled" : "disabled");

    data_set->stonith_action = pe_pref(data_set->config_hash, "stonith-action");
    crm_trace("STONITH will %s nodes", data_set->stonith_action);

    set_config_flag(data_set, "stop-all-resources", pe_flag_stop_everything);
    crm_debug("Stop all active resources: %s",
              is_set(data_set->flags, pe_flag_stop_everything) ? "true" : "false");

    set_config_flag(data_set, "symmetric-cluster", pe_flag_symmetric_cluster);
    if (is_set(data_set->flags, pe_flag_symmetric_cluster)) {
        crm_debug("Cluster is symmetric" " - resources can run anywhere by default");
    }

    value = pe_pref(data_set->config_hash, "default-resource-stickiness");
    data_set->default_resource_stickiness = char2score(value);
    crm_debug("Default stickiness: %d", data_set->default_resource_stickiness);

    value = pe_pref(data_set->config_hash, "no-quorum-policy");

    if (safe_str_eq(value, "ignore")) {
        data_set->no_quorum_policy = no_quorum_ignore;

    } else if (safe_str_eq(value, "freeze")) {
        data_set->no_quorum_policy = no_quorum_freeze;

    } else if (safe_str_eq(value, "suicide")) {
        gboolean do_panic = FALSE;

        crm_element_value_int(data_set->input, XML_ATTR_QUORUM_PANIC, &do_panic);

        if (is_set(data_set->flags, pe_flag_stonith_enabled) == FALSE) {
            crm_config_err
                ("Setting no-quorum-policy=suicide makes no sense if stonith-enabled=false");
        }

        if (do_panic && is_set(data_set->flags, pe_flag_stonith_enabled)) {
            data_set->no_quorum_policy = no_quorum_suicide;

        } else if (is_set(data_set->flags, pe_flag_have_quorum) == FALSE && do_panic == FALSE) {
            crm_notice("Resetting no-quorum-policy to 'stop': The cluster has never had quorum");
            data_set->no_quorum_policy = no_quorum_stop;
        }

    } else {
        data_set->no_quorum_policy = no_quorum_stop;
    }

    switch (data_set->no_quorum_policy) {
        case no_quorum_freeze:
            crm_debug("On loss of CCM Quorum: Freeze resources");
            break;
        case no_quorum_stop:
            crm_debug("On loss of CCM Quorum: Stop ALL resources");
            break;
        case no_quorum_suicide:
            crm_notice("On loss of CCM Quorum: Fence all remaining nodes");
            break;
        case no_quorum_ignore:
            crm_notice("On loss of CCM Quorum: Ignore");
            break;
    }

    set_config_flag(data_set, "stop-orphan-resources", pe_flag_stop_rsc_orphans);
    crm_trace("Orphan resources are %s",
              is_set(data_set->flags, pe_flag_stop_rsc_orphans) ? "stopped" : "ignored");

    set_config_flag(data_set, "stop-orphan-actions", pe_flag_stop_action_orphans);
    crm_trace("Orphan resource actions are %s",
              is_set(data_set->flags, pe_flag_stop_action_orphans) ? "stopped" : "ignored");

    set_config_flag(data_set, "remove-after-stop", pe_flag_remove_after_stop);
    crm_trace("Stopped resources are removed from the status section: %s",
              is_set(data_set->flags, pe_flag_remove_after_stop) ? "true" : "false");

    set_config_flag(data_set, "maintenance-mode", pe_flag_maintenance_mode);
    crm_trace("Maintenance mode: %s",
              is_set(data_set->flags, pe_flag_maintenance_mode) ? "true" : "false");

    if (is_set(data_set->flags, pe_flag_maintenance_mode)) {
        clear_bit(data_set->flags, pe_flag_is_managed_default);
    } else {
        set_config_flag(data_set, "is-managed-default", pe_flag_is_managed_default);
    }
    crm_trace("By default resources are %smanaged",
              is_set(data_set->flags, pe_flag_is_managed_default) ? "" : "not ");

    set_config_flag(data_set, "start-failure-is-fatal", pe_flag_start_failure_fatal);
    crm_trace("Start failures are %s",
              is_set(data_set->flags,
                     pe_flag_start_failure_fatal) ? "always fatal" : "handled by failcount");

    node_score_red = char2score(pe_pref(data_set->config_hash, "node-health-red"));
    node_score_green = char2score(pe_pref(data_set->config_hash, "node-health-green"));
    node_score_yellow = char2score(pe_pref(data_set->config_hash, "node-health-yellow"));

    crm_info("Node scores: 'red' = %s, 'yellow' = %s, 'green' = %s",
             pe_pref(data_set->config_hash, "node-health-red"),
             pe_pref(data_set->config_hash, "node-health-yellow"),
             pe_pref(data_set->config_hash, "node-health-green"));

    data_set->placement_strategy = pe_pref(data_set->config_hash, "placement-strategy");
    crm_trace("Placement strategy: %s", data_set->placement_strategy);

    return TRUE;
}

static void
destroy_digest_cache(gpointer ptr)
{
    op_digest_cache_t *data = ptr;

    free_xml(data->params_all);
    free_xml(data->params_restart);
    free(data->digest_all_calc);
    free(data->digest_restart_calc);
    free(data);
}

static node_t *
create_node(const char *id, const char *uname, const char *type, const char *score, pe_working_set_t * data_set)
{
    node_t *new_node = NULL;

    if (pe_find_node(data_set->nodes, uname) != NULL) {
        crm_config_warn("Detected multiple node entries with uname=%s"
                        " - this is rarely intended", uname);
    }

    new_node = calloc(1, sizeof(node_t));
    if (new_node == NULL) {
        return NULL;
    }

    new_node->weight = char2score(score);
    new_node->fixed = FALSE;
    new_node->details = calloc(1, sizeof(struct node_shared_s));

    if (new_node->details == NULL) {
        free(new_node);
        return NULL;
    }

    crm_trace("Creating node for entry %s/%s", uname, id);
    new_node->details->id = id;
    new_node->details->uname = uname;
    new_node->details->online = FALSE;
    new_node->details->shutdown = FALSE;
    new_node->details->running_rsc = NULL;
    new_node->details->type = node_ping;

    if (safe_str_eq(type, "remote")) {
        new_node->details->type = node_remote;
    } else if (type == NULL || safe_str_eq(type, "member")
        || safe_str_eq(type, NORMALNODE)) {
        new_node->details->type = node_member;
    }

    new_node->details->attrs = g_hash_table_new_full(crm_str_hash, g_str_equal,
                                                     g_hash_destroy_str,
                                                     g_hash_destroy_str);
    new_node->details->utilization =
        g_hash_table_new_full(crm_str_hash, g_str_equal, g_hash_destroy_str,
                              g_hash_destroy_str);

    new_node->details->digest_cache =
        g_hash_table_new_full(crm_str_hash, g_str_equal, g_hash_destroy_str,
                              destroy_digest_cache);

    data_set->nodes = g_list_insert_sorted(data_set->nodes, new_node, sort_node_uname);
    return new_node;
}

static gboolean
is_remote_node(xmlNode *xml)
{
    const char *class = crm_element_value(xml, XML_AGENT_ATTR_CLASS);
    const char *provider = crm_element_value(xml, XML_AGENT_ATTR_PROVIDER);
    const char *agent = crm_element_value(xml, XML_ATTR_TYPE);

    if (safe_str_eq(agent, "remote") && safe_str_eq(provider, "pacemaker") && safe_str_eq(class, "ocf")) {
        return TRUE;
    }
    return FALSE;
}

static const char *
expand_remote_rsc_meta(xmlNode *xml_obj, xmlNode *parent, GHashTable **rsc_name_check)
{
    xmlNode *xml_rsc = NULL;
    xmlNode *xml_tmp = NULL;
    xmlNode *attr_set = NULL;
    xmlNode *attr = NULL;

    const char *container_id = ID(xml_obj);
    const char *remote_name = NULL;
    const char *remote_server = NULL;
    const char *remote_port = NULL;
    char *tmp_id = NULL;

    for (attr_set = __xml_first_child(xml_obj); attr_set != NULL; attr_set = __xml_next(attr_set)) {
        if (safe_str_neq((const char *)attr_set->name, XML_TAG_META_SETS)) {
            continue;
        }

        for (attr = __xml_first_child(attr_set); attr != NULL; attr = __xml_next(attr)) {
            const char *value = crm_element_value(attr, XML_NVPAIR_ATTR_VALUE);
            const char *name = crm_element_value(attr, XML_NVPAIR_ATTR_NAME);

            if (safe_str_eq(name, "remote-node")) {
                remote_name = value;
            } else if (safe_str_eq(name, "remote-addr")) {
                remote_server = value;
            } else if (safe_str_eq(name, "remote-port")) {
                remote_port = value;
            }
        }
    }

    if (remote_name == NULL) {
        return NULL;
    }

    if (*rsc_name_check == NULL) {
        *rsc_name_check = g_hash_table_new(crm_str_hash, g_str_equal);
        for (xml_rsc = __xml_first_child(parent); xml_rsc != NULL; xml_rsc = __xml_next(xml_rsc)) {
            const char *id = ID(xml_rsc);

            /* avoiding heap allocation here because we know the duration of this hashtable allows us to */
            g_hash_table_insert(*rsc_name_check, (char *) id, (char *) id);
        }
    }

    if (g_hash_table_lookup(*rsc_name_check, remote_name)) {

        crm_err("Naming conflict with remote-node=%s.  remote-nodes can not have the same name as a resource.",
                remote_name);
        return NULL;
    }

    xml_rsc = create_xml_node(parent, XML_CIB_TAG_RESOURCE);

    crm_xml_add(xml_rsc, XML_ATTR_ID, remote_name);
    crm_xml_add(xml_rsc, XML_AGENT_ATTR_CLASS, "ocf");
    crm_xml_add(xml_rsc, XML_AGENT_ATTR_PROVIDER, "pacemaker");
    crm_xml_add(xml_rsc, XML_ATTR_TYPE, "remote");

    xml_tmp = create_xml_node(xml_rsc, XML_TAG_META_SETS);
    tmp_id = crm_concat(remote_name, XML_TAG_META_SETS, '_');
    crm_xml_add(xml_tmp, XML_ATTR_ID, tmp_id);
    free(tmp_id);

    attr = create_xml_node(xml_tmp, XML_CIB_TAG_NVPAIR);
    tmp_id = crm_concat(remote_name, "meta-attributes-container", '_');
    crm_xml_add(attr, XML_ATTR_ID, tmp_id);
    crm_xml_add(attr, XML_NVPAIR_ATTR_NAME, XML_RSC_ATTR_CONTAINER);
    crm_xml_add(attr, XML_NVPAIR_ATTR_VALUE, container_id);
    free(tmp_id);

    attr = create_xml_node(xml_tmp, XML_CIB_TAG_NVPAIR);
    tmp_id = crm_concat(remote_name, "meta-attributes-internal", '_');
    crm_xml_add(attr, XML_ATTR_ID, tmp_id);
    crm_xml_add(attr, XML_NVPAIR_ATTR_NAME, XML_RSC_ATTR_INTERNAL_RSC);
    crm_xml_add(attr, XML_NVPAIR_ATTR_VALUE, "true");
    free(tmp_id);

    xml_tmp = create_xml_node(xml_rsc, "operations");
    attr = create_xml_node(xml_tmp, XML_ATTR_OP);
    tmp_id = crm_concat(remote_name, "monitor-interval-30s", '_');
    crm_xml_add(attr, XML_ATTR_ID, tmp_id);
    crm_xml_add(attr, XML_ATTR_TIMEOUT, "30s");
    crm_xml_add(attr, XML_LRM_ATTR_INTERVAL, "30s");
    crm_xml_add(attr, XML_NVPAIR_ATTR_NAME, "monitor");
    free(tmp_id);

    if (remote_port || remote_server) {
        xml_tmp = create_xml_node(xml_rsc, XML_TAG_ATTR_SETS);
        tmp_id = crm_concat(remote_name, XML_TAG_ATTR_SETS, '_');
        crm_xml_add(xml_tmp, XML_ATTR_ID, tmp_id);
        free(tmp_id);

        if (remote_server) {
            attr = create_xml_node(xml_tmp, XML_CIB_TAG_NVPAIR);
            tmp_id = crm_concat(remote_name, "instance-attributes-addr", '_');
            crm_xml_add(attr, XML_ATTR_ID, tmp_id);
            crm_xml_add(attr, XML_NVPAIR_ATTR_NAME, "addr");
            crm_xml_add(attr, XML_NVPAIR_ATTR_VALUE, remote_server);
            free(tmp_id);
        }
        if (remote_port) {
            attr = create_xml_node(xml_tmp, XML_CIB_TAG_NVPAIR);
            tmp_id = crm_concat(remote_name, "instance-attributes-port", '_');
            crm_xml_add(attr, XML_ATTR_ID, tmp_id);
            crm_xml_add(attr, XML_NVPAIR_ATTR_NAME, "port");
            crm_xml_add(attr, XML_NVPAIR_ATTR_VALUE, remote_port);
            free(tmp_id);
        }
    }

    return remote_name;
}

gboolean
unpack_nodes(xmlNode * xml_nodes, pe_working_set_t * data_set)
{
    xmlNode *xml_obj = NULL;
    node_t *new_node = NULL;
    const char *id = NULL;
    const char *uname = NULL;
    const char *type = NULL;
    const char *score = NULL;
    gboolean unseen_are_unclean = TRUE;
    const char *blind_faith = pe_pref(data_set->config_hash, "startup-fencing");

    if (crm_is_true(blind_faith) == FALSE) {
        unseen_are_unclean = FALSE;
        crm_warn("Blind faith: not fencing unseen nodes");
    }

    for (xml_obj = __xml_first_child(xml_nodes); xml_obj != NULL; xml_obj = __xml_next(xml_obj)) {
        if (crm_str_eq((const char *)xml_obj->name, XML_CIB_TAG_NODE, TRUE)) {
            new_node = NULL;

            id = crm_element_value(xml_obj, XML_ATTR_ID);
            uname = crm_element_value(xml_obj, XML_ATTR_UNAME);
            type = crm_element_value(xml_obj, XML_ATTR_TYPE);
            score = crm_element_value(xml_obj, XML_RULE_ATTR_SCORE);
            crm_trace("Processing node %s/%s", uname, id);

            if (id == NULL) {
                crm_config_err("Must specify id tag in <node>");
                continue;
            }
            new_node = create_node(id, uname, type, score, data_set);

            if (new_node == NULL) {
                return FALSE;
            }

/* 		if(data_set->have_quorum == FALSE */
/* 		   && data_set->no_quorum_policy == no_quorum_stop) { */
/* 			/\* start shutting resources down *\/ */
/* 			new_node->weight = -INFINITY; */
/* 		} */

            if (is_set(data_set->flags, pe_flag_stonith_enabled) == FALSE
                || unseen_are_unclean == FALSE) {
                /* blind faith... */
                new_node->details->unclean = FALSE;

            } else {
                /* all nodes are unclean until we've seen their
                 * status entry
                 */
                new_node->details->unclean = TRUE;
            }

            add_node_attrs(xml_obj, new_node, FALSE, data_set);
            unpack_instance_attributes(data_set->input, xml_obj, XML_TAG_UTILIZATION, NULL,
                                       new_node->details->utilization, NULL, FALSE, data_set->now);

            crm_trace("Done with node %s", crm_element_value(xml_obj, XML_ATTR_UNAME));
        }
    }

    return TRUE;
}

static void
g_hash_destroy_node_list(gpointer data)
{
    GListPtr domain = data;

    g_list_free_full(domain, free);
}

gboolean
unpack_domains(xmlNode * xml_domains, pe_working_set_t * data_set)
{
    const char *id = NULL;
    GListPtr domain = NULL;
    xmlNode *xml_node = NULL;
    xmlNode *xml_domain = NULL;

    crm_info("Unpacking domains");
    data_set->domains =
        g_hash_table_new_full(crm_str_hash, g_str_equal, g_hash_destroy_str,
                              g_hash_destroy_node_list);

    for (xml_domain = __xml_first_child(xml_domains); xml_domain != NULL;
         xml_domain = __xml_next(xml_domain)) {
        if (crm_str_eq((const char *)xml_domain->name, XML_CIB_TAG_DOMAIN, TRUE)) {
            domain = NULL;
            id = crm_element_value(xml_domain, XML_ATTR_ID);

            for (xml_node = __xml_first_child(xml_domain); xml_node != NULL;
                 xml_node = __xml_next(xml_node)) {
                if (crm_str_eq((const char *)xml_node->name, XML_CIB_TAG_NODE, TRUE)) {
                    node_t *copy = NULL;
                    node_t *node = NULL;
                    const char *uname = crm_element_value(xml_node, "name");
                    const char *score = crm_element_value(xml_node, XML_RULE_ATTR_SCORE);

                    if (uname == NULL) {
                        crm_config_err("Invalid domain %s: Must specify id tag in <node>", id);
                        continue;
                    }

                    node = pe_find_node(data_set->nodes, uname);
                    if (node == NULL) {
                        node = pe_find_node_id(data_set->nodes, uname);
                    }
                    if (node == NULL) {
                        crm_config_warn("Invalid domain %s: Node %s does not exist", id, uname);
                        continue;
                    }

                    copy = node_copy(node);
                    copy->weight = char2score(score);
                    crm_debug("Adding %s to domain %s with score %s", node->details->uname, id,
                              score);

                    domain = g_list_prepend(domain, copy);
                }
            }

            if (domain) {
                crm_debug("Created domain %s with %d members", id, g_list_length(domain));
                g_hash_table_replace(data_set->domains, strdup(id), domain);
            }
        }
    }

    return TRUE;
}

static void
destroy_template_rsc_set(gpointer data)
{
    xmlNode *rsc_set = data;

    free_xml(rsc_set);
}

static void
setup_container(resource_t * rsc, pe_working_set_t * data_set)
{
    const char *container_id = NULL;

    if (rsc->children) {
        GListPtr gIter = rsc->children;

        for (; gIter != NULL; gIter = gIter->next) {
            resource_t *child_rsc = (resource_t *) gIter->data;

            setup_container(child_rsc, data_set);
        }
        return;
    }

    container_id = g_hash_table_lookup(rsc->meta, XML_RSC_ATTR_CONTAINER);
    if (container_id && safe_str_neq(container_id, rsc->id)) {
        resource_t *container = pe_find_resource(data_set->resources, container_id);

        if (container) {
            rsc->container = container;
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
    GHashTable *rsc_name_check = NULL;

    /* generate remote nodes from resource config before unpacking resources */
    for (xml_obj = __xml_first_child(xml_resources); xml_obj != NULL; xml_obj = __xml_next(xml_obj)) {
        const char *new_node_id = NULL;

        /* remote rsc can be defined as primitive, or exist within the metadata of another rsc */
        if (is_remote_node(xml_obj)) {
            new_node_id = ID(xml_obj);
            /* This check is here to make sure we don't iterate over
             * an expanded node that has already been added to the node list. */
            if (new_node_id && pe_find_node(data_set->nodes, new_node_id) != NULL) {
                continue;
            }
        } else {
            /* expands a metadata defined remote resource into the xml config
             * as an actual rsc primitive to be unpacked later. */
            new_node_id = expand_remote_rsc_meta(xml_obj, xml_resources, &rsc_name_check);
        }

        if (new_node_id) {
            set_bit(data_set->flags, pe_flag_have_remote_nodes);
            crm_trace("detected remote node %s", new_node_id);
            create_node(new_node_id, new_node_id, "remote", NULL, data_set);
        }
    }
    if (rsc_name_check) {
        g_hash_table_destroy(rsc_name_check);
    }

    return TRUE;
}

gboolean
unpack_resources(xmlNode * xml_resources, pe_working_set_t * data_set)
{
    xmlNode *xml_obj = NULL;
    GListPtr gIter = NULL;

    data_set->template_rsc_sets =
        g_hash_table_new_full(crm_str_hash, g_str_equal, g_hash_destroy_str,
                              destroy_template_rsc_set);

    for (xml_obj = __xml_first_child(xml_resources); xml_obj != NULL; xml_obj = __xml_next(xml_obj)) {
        resource_t *new_rsc = NULL;

        if (crm_str_eq((const char *)xml_obj->name, XML_CIB_TAG_RSC_TEMPLATE, TRUE)) {
            const char *template_id = ID(xml_obj);

            if (template_id && g_hash_table_lookup_extended(data_set->template_rsc_sets,
                                                            template_id, NULL, NULL) == FALSE) {
                /* Record the template's ID for the knowledge of its existence anyway. */
                g_hash_table_insert(data_set->template_rsc_sets, strdup(template_id), NULL);
            }
            continue;
        }

        crm_trace("Beginning unpack... <%s id=%s... >", crm_element_name(xml_obj), ID(xml_obj));
        if (common_unpack(xml_obj, &new_rsc, NULL, data_set)) {
            data_set->resources = g_list_append(data_set->resources, new_rsc);

            if (is_remote_node(xml_obj)) {
                node_t *remote = pe_find_node(data_set->nodes, new_rsc->id);
                if (remote) {
                    remote->details->remote_rsc = new_rsc;
                    new_rsc->is_remote_node = TRUE;
                }
            }
            print_resource(LOG_DEBUG_3, "Added ", new_rsc, FALSE);

        } else {
            crm_config_err("Failed unpacking %s %s",
                           crm_element_name(xml_obj), crm_element_value(xml_obj, XML_ATTR_ID));
            if (new_rsc != NULL && new_rsc->fns != NULL) {
                new_rsc->fns->free(new_rsc);
            }
        }
    }

    for (gIter = data_set->resources; gIter != NULL; gIter = gIter->next) {
        resource_t *rsc = (resource_t *) gIter->data;

        setup_container(rsc, data_set);
    }

    data_set->resources = g_list_sort(data_set->resources, sort_rsc_priority);

    if (is_set(data_set->flags, pe_flag_stonith_enabled)
        && is_set(data_set->flags, pe_flag_have_stonith_resource) == FALSE) {
        crm_config_err("Resource start-up disabled since no STONITH resources have been defined");
        crm_config_err("Either configure some or disable STONITH with the stonith-enabled option");
        crm_config_err("NOTE: Clusters with shared data need STONITH to ensure data integrity");
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

    ticket_t *ticket = NULL;

    ticket_id = ID(xml_ticket);
    if (ticket_id == NULL || strlen(ticket_id) == 0) {
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

        if (crm_str_eq(prop_name, XML_ATTR_ID, TRUE)) {
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
        ticket->last_granted = crm_parse_int(last_granted, 0);
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

    for (xml_obj = __xml_first_child(xml_tickets); xml_obj != NULL; xml_obj = __xml_next(xml_obj)) {
        if (crm_str_eq((const char *)xml_obj->name, XML_CIB_TAG_TICKET_STATE, TRUE) == FALSE) {
            continue;
        }
        unpack_ticket_state(xml_obj, data_set);
    }

    return TRUE;
}

/* Compatibility with the deprecated ticket state section:
 * "/cib/status/tickets/instance_attributes" */
static void
get_ticket_state_legacy(gpointer key, gpointer value, gpointer user_data)
{
    const char *long_key = key;
    char *state_key = NULL;

    const char *granted_prefix = "granted-ticket-";
    const char *last_granted_prefix = "last-granted-";
    static int granted_prefix_strlen = 0;
    static int last_granted_prefix_strlen = 0;

    const char *ticket_id = NULL;
    const char *is_granted = NULL;
    const char *last_granted = NULL;
    const char *sep = NULL;

    ticket_t *ticket = NULL;
    pe_working_set_t *data_set = user_data;

    if (granted_prefix_strlen == 0) {
        granted_prefix_strlen = strlen(granted_prefix);
    }

    if (last_granted_prefix_strlen == 0) {
        last_granted_prefix_strlen = strlen(last_granted_prefix);
    }

    if (strstr(long_key, granted_prefix) == long_key) {
        ticket_id = long_key + granted_prefix_strlen;
        if (strlen(ticket_id)) {
            state_key = strdup("granted");
            is_granted = value;
        }
    } else if (strstr(long_key, last_granted_prefix) == long_key) {
        ticket_id = long_key + last_granted_prefix_strlen;
        if (strlen(ticket_id)) {
            state_key = strdup("last-granted");
            last_granted = value;
        }
    } else if ((sep = strrchr(long_key, '-'))) {
        ticket_id = sep + 1;
        state_key = strndup(long_key, strlen(long_key) - strlen(sep));
    }

    if (ticket_id == NULL || strlen(ticket_id) == 0) {
        free(state_key);
        return;
    }

    if (state_key == NULL || strlen(state_key) == 0) {
        free(state_key);
        return;
    }

    ticket = g_hash_table_lookup(data_set->tickets, ticket_id);
    if (ticket == NULL) {
        ticket = ticket_new(ticket_id, data_set);
        if (ticket == NULL) {
            free(state_key);
            return;
        }
    }

    g_hash_table_replace(ticket->state, state_key, strdup(value));

    if (is_granted) {
        if (crm_is_true(is_granted)) {
            ticket->granted = TRUE;
            crm_info("We have ticket '%s'", ticket->id);
        } else {
            ticket->granted = FALSE;
            crm_info("We do not have ticket '%s'", ticket->id);
        }

    } else if (last_granted) {
        ticket->last_granted = crm_parse_int(last_granted, 0);
    }
}

/* remove nodes that are down, stopping */
/* create +ve rsc_to_node constraints between resources and the nodes they are running on */
/* anything else? */
gboolean
unpack_status(xmlNode * status, pe_working_set_t * data_set)
{
    const char *id = NULL;
    const char *uname = NULL;

    xmlNode *state = NULL;
    xmlNode *lrm_rsc = NULL;
    node_t *this_node = NULL;

    crm_trace("Beginning unpack");

    if (data_set->tickets == NULL) {
        data_set->tickets =
            g_hash_table_new_full(crm_str_hash, g_str_equal, g_hash_destroy_str, destroy_ticket);
    }

    for (state = __xml_first_child(status); state != NULL; state = __xml_next(state)) {
        if (crm_str_eq((const char *)state->name, XML_CIB_TAG_TICKETS, TRUE)) {
            xmlNode *xml_tickets = state;
            GHashTable *state_hash = NULL;

            /* Compatibility with the deprecated ticket state section:
             * Unpack the attributes in the deprecated "/cib/status/tickets/instance_attributes" if it exists. */
            state_hash =
                g_hash_table_new_full(crm_str_hash, g_str_equal, g_hash_destroy_str,
                                      g_hash_destroy_str);

            unpack_instance_attributes(data_set->input, xml_tickets, XML_TAG_ATTR_SETS, NULL,
                                       state_hash, NULL, TRUE, data_set->now);

            g_hash_table_foreach(state_hash, get_ticket_state_legacy, data_set);

            if (state_hash) {
                g_hash_table_destroy(state_hash);
            }

            /* Unpack the new "/cib/status/tickets/ticket_state"s */
            unpack_tickets_state(xml_tickets, data_set);
        }

        if (crm_str_eq((const char *)state->name, XML_CIB_TAG_STATE, TRUE)) {
            xmlNode *attrs = NULL;

            id = crm_element_value(state, XML_ATTR_ID);
            uname = crm_element_value(state, XML_ATTR_UNAME);
            this_node = pe_find_node_any(data_set->nodes, id, uname);

            if (uname == NULL) {
                /* error */
                continue;

            } else if (this_node == NULL) {
                crm_config_warn("Node %s in status section no longer exists", uname);
                continue;

            } else if (this_node->details->remote_rsc) {
                /* online state for remote nodes is determined by the rsc state
                 * after all the unpacking is done. */
                continue;
            }

            crm_trace("Processing node id=%s, uname=%s", id, uname);

            /* Mark the node as provisionally clean
             * - at least we have seen it in the current cluster's lifetime
             */
            this_node->details->unclean = FALSE;
            attrs = find_xml_node(state, XML_TAG_TRANSIENT_NODEATTRS, FALSE);
            add_node_attrs(attrs, this_node, TRUE, data_set);

            if (crm_is_true(g_hash_table_lookup(this_node->details->attrs, "standby"))) {
                crm_info("Node %s is in standby-mode", this_node->details->uname);
                this_node->details->standby = TRUE;
            }

            crm_trace("determining node state");
            determine_online_status(state, this_node, data_set);

            if (this_node->details->online && data_set->no_quorum_policy == no_quorum_suicide) {
                /* Everything else should flow from this automatically
                 * At least until the PE becomes able to migrate off healthy resources
                 */
                pe_fence_node(data_set, this_node, "because the cluster does not have quorum");
            }
        }
    }

    /* Now that we know all node states, we can safely handle migration ops */
    for (state = __xml_first_child(status); state != NULL; state = __xml_next(state)) {
        if (crm_str_eq((const char *)state->name, XML_CIB_TAG_STATE, TRUE) == FALSE) {
            continue;
        }

        id = crm_element_value(state, XML_ATTR_ID);
        uname = crm_element_value(state, XML_ATTR_UNAME);
        this_node = pe_find_node_any(data_set->nodes, id, uname);

        if (this_node == NULL) {
            crm_info("Node %s is unknown", id);
            continue;

        } else if (this_node->details->remote_rsc) {

            /* online status of remote node can not be determined until all other
             * resource status is unpacked. */
            continue;
        } else if (this_node->details->online || is_set(data_set->flags, pe_flag_stonith_enabled)) {
            crm_trace("Processing lrm resource entries on healthy node: %s",
                      this_node->details->uname);
            lrm_rsc = find_xml_node(state, XML_CIB_TAG_LRM, FALSE);
            lrm_rsc = find_xml_node(lrm_rsc, XML_LRM_TAG_RESOURCES, FALSE);
            unpack_lrm_resources(this_node, lrm_rsc, data_set);
        }
    }

    /* now that the rest of the cluster's status is determined
     * calculate remote-nodes */
    unpack_remote_status(status, data_set);

    return TRUE;
}

gboolean
unpack_remote_status(xmlNode * status, pe_working_set_t * data_set)
{
    const char *id = NULL;
    const char *uname = NULL;
    GListPtr gIter = NULL;

    xmlNode *state = NULL;
    xmlNode *lrm_rsc = NULL;
    node_t *this_node = NULL;

    if (is_set(data_set->flags, pe_flag_have_remote_nodes) == FALSE) {
        crm_trace("no remote nodes to unpack");
        return TRUE;
    }

    /* get online status */
    for (gIter = data_set->nodes; gIter != NULL; gIter = gIter->next) {
        this_node = gIter->data;

        if ((this_node == NULL) || (this_node->details->remote_rsc == NULL)) {
            continue;
        }
        determine_remote_online_status(this_node);
    }

    /* process attributes */
    for (state = __xml_first_child(status); state != NULL; state = __xml_next(state)) {
        xmlNode *attrs = NULL;
        if (crm_str_eq((const char *)state->name, XML_CIB_TAG_STATE, TRUE) == FALSE) {
            continue;
        }

        id = crm_element_value(state, XML_ATTR_ID);
        uname = crm_element_value(state, XML_ATTR_UNAME);
        this_node = pe_find_node_any(data_set->nodes, id, uname);

        if ((this_node == NULL) || (this_node->details->remote_rsc == NULL)) {
            continue;
        }
        crm_trace("Processing remote node id=%s, uname=%s", id, uname);

        this_node->details->unclean = FALSE;
        attrs = find_xml_node(state, XML_TAG_TRANSIENT_NODEATTRS, FALSE);
        add_node_attrs(attrs, this_node, TRUE, data_set);

        if (crm_is_true(g_hash_table_lookup(this_node->details->attrs, "standby"))) {
            crm_info("Node %s is in standby-mode", this_node->details->uname);
            this_node->details->standby = TRUE;
        }
    }

    /* process node rsc status */
    for (state = __xml_first_child(status); state != NULL; state = __xml_next(state)) {
        if (crm_str_eq((const char *)state->name, XML_CIB_TAG_STATE, TRUE) == FALSE) {
            continue;
        }

        id = crm_element_value(state, XML_ATTR_ID);
        uname = crm_element_value(state, XML_ATTR_UNAME);
        this_node = pe_find_node_any(data_set->nodes, id, uname);

        if ((this_node == NULL) || (this_node->details->remote_rsc == NULL)) {
            continue;
        }
        crm_trace("Processing lrm resource entries on healthy remote node: %s",
                  this_node->details->uname);
        lrm_rsc = find_xml_node(state, XML_CIB_TAG_LRM, FALSE);
        lrm_rsc = find_xml_node(lrm_rsc, XML_LRM_TAG_RESOURCES, FALSE);
        unpack_lrm_resources(this_node, lrm_rsc, data_set);
    }

    return TRUE;
}

static gboolean
determine_online_status_no_fencing(pe_working_set_t * data_set, xmlNode * node_state,
                                   node_t * this_node)
{
    gboolean online = FALSE;
    const char *join = crm_element_value(node_state, XML_NODE_JOIN_STATE);
    const char *is_peer = crm_element_value(node_state, XML_NODE_IS_PEER);
    const char *in_cluster = crm_element_value(node_state, XML_NODE_IN_CLUSTER);
    const char *exp_state = crm_element_value(node_state, XML_NODE_EXPECTED);

    if (!crm_is_true(in_cluster)) {
        crm_trace("Node is down: in_cluster=%s", crm_str(in_cluster));

    } else if (safe_str_eq(is_peer, ONLINESTATUS)) {
        if (safe_str_eq(join, CRMD_JOINSTATE_MEMBER)) {
            online = TRUE;
        } else {
            crm_debug("Node is not ready to run resources: %s", join);
        }

    } else if (this_node->details->expected_up == FALSE) {
        crm_trace("CRMd is down: in_cluster=%s", crm_str(in_cluster));
        crm_trace("\tis_peer=%s, join=%s, expected=%s",
                  crm_str(is_peer), crm_str(join), crm_str(exp_state));

    } else {
        /* mark it unclean */
        pe_fence_node(data_set, this_node, "because it is partially and/or un-expectedly down");
        crm_info("\tin_cluster=%s, is_peer=%s, join=%s, expected=%s",
                 crm_str(in_cluster), crm_str(is_peer), crm_str(join), crm_str(exp_state));
    }
    return online;
}

static gboolean
determine_online_status_fencing(pe_working_set_t * data_set, xmlNode * node_state,
                                node_t * this_node)
{
    gboolean online = FALSE;
    gboolean do_terminate = FALSE;
    const char *join = crm_element_value(node_state, XML_NODE_JOIN_STATE);
    const char *is_peer = crm_element_value(node_state, XML_NODE_IS_PEER);
    const char *in_cluster = crm_element_value(node_state, XML_NODE_IN_CLUSTER);
    const char *exp_state = crm_element_value(node_state, XML_NODE_EXPECTED);
    const char *terminate = g_hash_table_lookup(this_node->details->attrs, "terminate");

/*
  - XML_NODE_IN_CLUSTER    ::= true|false
  - XML_NODE_IS_PEER       ::= true|false|online|offline
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

    crm_trace("%s: in_cluster=%s, is_peer=%s, join=%s, expected=%s, term=%d",
              this_node->details->uname, crm_str(in_cluster), crm_str(is_peer),
              crm_str(join), crm_str(exp_state), do_terminate);

    online = crm_is_true(in_cluster);
    if (safe_str_eq(is_peer, ONLINESTATUS)) {
        is_peer = XML_BOOLEAN_YES;
    }
    if (exp_state == NULL) {
        exp_state = CRMD_JOINSTATE_DOWN;
    }

    if (this_node->details->shutdown) {
        crm_debug("%s is shutting down", this_node->details->uname);
        online = crm_is_true(is_peer);  /* Slightly different criteria since we cant shut down a dead peer */

    } else if (in_cluster == NULL) {
        pe_fence_node(data_set, this_node, "because the peer has not been seen by the cluster");

    } else if (safe_str_eq(join, CRMD_JOINSTATE_NACK)) {
        pe_fence_node(data_set, this_node, "because it failed the pacemaker membership criteria");

    } else if (do_terminate == FALSE && safe_str_eq(exp_state, CRMD_JOINSTATE_DOWN)) {

        if (crm_is_true(in_cluster) || crm_is_true(is_peer)) {
            crm_info("- Node %s is not ready to run resources", this_node->details->uname);
            this_node->details->standby = TRUE;
            this_node->details->pending = TRUE;

        } else {
            crm_trace("%s is down or still coming up", this_node->details->uname);
        }

    } else if (do_terminate && safe_str_eq(join, CRMD_JOINSTATE_DOWN)
               && crm_is_true(in_cluster) == FALSE && crm_is_true(is_peer) == FALSE) {
        crm_info("Node %s was just shot", this_node->details->uname);
        online = FALSE;

    } else if (crm_is_true(in_cluster) == FALSE) {
        pe_fence_node(data_set, this_node, "because the node is no longer part of the cluster");

    } else if (crm_is_true(is_peer) == FALSE) {
        pe_fence_node(data_set, this_node, "because our peer process is no longer available");

        /* Everything is running at this point, now check join state */
    } else if (do_terminate) {
        pe_fence_node(data_set, this_node, "because termination was requested");

    } else if (safe_str_eq(join, CRMD_JOINSTATE_MEMBER)) {
        crm_info("Node %s is active", this_node->details->uname);

    } else if (safe_str_eq(join, CRMD_JOINSTATE_PENDING)
               || safe_str_eq(join, CRMD_JOINSTATE_DOWN)) {
        crm_info("Node %s is not ready to run resources", this_node->details->uname);
        this_node->details->standby = TRUE;
        this_node->details->pending = TRUE;

    } else {
        pe_fence_node(data_set, this_node, "because the peer was in an unknown state");
        crm_warn("%s: in-cluster=%s, is-peer=%s, join=%s, expected=%s, term=%d, shutdown=%d",
                 this_node->details->uname, crm_str(in_cluster), crm_str(is_peer),
                 crm_str(join), crm_str(exp_state), do_terminate, this_node->details->shutdown);
    }

    return online;
}

static gboolean
determine_remote_online_status(node_t * this_node)
{
    resource_t *rsc = this_node->details->remote_rsc;
    resource_t *container = rsc->container;

    CRM_ASSERT(rsc != NULL);

    /* If the resource is currently started, mark it online. */
    if (rsc->role == RSC_ROLE_STARTED) {
        crm_trace("Remote node %s is set to ONLINE. role == started", this_node->details->id);
        this_node->details->online = TRUE;
    }

    /* consider this node shutting down if transitioning start->stop */
    if (rsc->role == RSC_ROLE_STARTED && rsc->next_role == RSC_ROLE_STOPPED) {
        crm_trace("Remote node %s shutdown. transition from start to stop role", this_node->details->id);
        this_node->details->shutdown = TRUE;
    }

    /* Now check all the failure conditions. */
    if (is_set(rsc->flags, pe_rsc_failed) ||
        (rsc->role == RSC_ROLE_STOPPED) ||
        (container && is_set(container->flags, pe_rsc_failed)) ||
        (container && container->role == RSC_ROLE_STOPPED)) {

        crm_trace("Remote node %s is set to OFFLINE. node is stopped or rsc failed.", this_node->details->id);
        this_node->details->online = FALSE;
    }

    crm_trace("Remote node %s online=%s",
        this_node->details->id, this_node->details->online ? "TRUE" : "FALSE");
    return this_node->details->online;
}

gboolean
determine_online_status(xmlNode * node_state, node_t * this_node, pe_working_set_t * data_set)
{
    gboolean online = FALSE;
    const char *shutdown = NULL;
    const char *exp_state = crm_element_value(node_state, XML_NODE_EXPECTED);

    if (this_node == NULL) {
        crm_config_err("No node to check");
        return online;
    }

    this_node->details->shutdown = FALSE;
    this_node->details->expected_up = FALSE;
    shutdown = g_hash_table_lookup(this_node->details->attrs, XML_CIB_ATTR_SHUTDOWN);

    if (shutdown != NULL && safe_str_neq("0", shutdown)) {
        this_node->details->shutdown = TRUE;

    } else if (safe_str_eq(exp_state, CRMD_JOINSTATE_MEMBER)) {
        this_node->details->expected_up = TRUE;
    }

    if (this_node->details->type == node_ping) {
        this_node->details->unclean = FALSE;
        online = FALSE;         /* As far as resource management is concerned,
                                 * the node is safely offline.
                                 * Anyone caught abusing this logic will be shot
                                 */

    } else if (is_set(data_set->flags, pe_flag_stonith_enabled) == FALSE) {
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
        /* dont run resources here */
        this_node->fixed = TRUE;
        this_node->weight = -INFINITY;
    }

    if (this_node->details->type == node_ping) {
        crm_info("Node %s is not a pacemaker node", this_node->details->uname);

    } else if (this_node->details->unclean) {
        pe_proc_warn("Node %s is unclean", this_node->details->uname);

    } else if (this_node->details->online) {
        crm_info("Node %s is %s", this_node->details->uname,
                 this_node->details->shutdown ? "shutting down" :
                 this_node->details->pending ? "pending" :
                 this_node->details->standby ? "standby" : "online");

    } else {
        crm_trace("Node %s is offline", this_node->details->uname);
    }

    return online;
}

char *
clone_strip(const char *last_rsc_id)
{
    int lpc = 0;
    char *zero = NULL;

    CRM_CHECK(last_rsc_id != NULL, return NULL);
    lpc = strlen(last_rsc_id);
    while (--lpc > 0) {
        switch (last_rsc_id[lpc]) {
            case 0:
                crm_err("Empty string: %s", last_rsc_id);
                return NULL;
                break;
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
                zero = calloc(1, lpc + 1);
                memcpy(zero, last_rsc_id, lpc);
                zero[lpc] = 0;
                return zero;
            default:
                goto done;
        }
    }
  done:
    zero = strdup(last_rsc_id);
    return zero;
}

char *
clone_zero(const char *last_rsc_id)
{
    int lpc = 0;
    char *zero = NULL;

    CRM_CHECK(last_rsc_id != NULL, return NULL);
    if (last_rsc_id != NULL) {
        lpc = strlen(last_rsc_id);
    }

    while (--lpc > 0) {
        switch (last_rsc_id[lpc]) {
            case 0:
                return NULL;
                break;
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
                zero = calloc(1, lpc + 3);
                memcpy(zero, last_rsc_id, lpc);
                zero[lpc] = ':';
                zero[lpc + 1] = '0';
                zero[lpc + 2] = 0;
                return zero;
            default:
                goto done;
        }
    }
  done:
    lpc = strlen(last_rsc_id);
    zero = calloc(1, lpc + 3);
    memcpy(zero, last_rsc_id, lpc);
    zero[lpc] = ':';
    zero[lpc + 1] = '0';
    zero[lpc + 2] = 0;
    crm_trace("%s -> %s", last_rsc_id, zero);
    return zero;
}

static resource_t *
create_fake_resource(const char *rsc_id, xmlNode * rsc_entry, pe_working_set_t * data_set)
{
    resource_t *rsc = NULL;
    xmlNode *xml_rsc = create_xml_node(NULL, XML_CIB_TAG_RESOURCE);

    copy_in_properties(xml_rsc, rsc_entry);
    crm_xml_add(xml_rsc, XML_ATTR_ID, rsc_id);
    crm_log_xml_debug(xml_rsc, "Orphan resource");

    if (!common_unpack(xml_rsc, &rsc, NULL, data_set)) {
        return NULL;
    }

    set_bit(rsc->flags, pe_rsc_orphan);
    data_set->resources = g_list_append(data_set->resources, rsc);
    return rsc;
}

extern resource_t *create_child_clone(resource_t * rsc, int sub_id, pe_working_set_t * data_set);

static resource_t *
find_anonymous_clone(pe_working_set_t * data_set, node_t * node, resource_t * parent,
                     const char *rsc_id)
{
    GListPtr rIter = NULL;
    resource_t *rsc = NULL;
    gboolean skip_inactive = FALSE;

    CRM_ASSERT(parent != NULL);
    CRM_ASSERT(parent->variant == pe_clone || parent->variant == pe_master);
    CRM_ASSERT(is_not_set(parent->flags, pe_rsc_unique));

    /* Find an instance active (or partially active for grouped clones) on the specified node */
    pe_rsc_trace(parent, "Looking for %s on %s in %s", rsc_id, node->details->uname, parent->id);
    for (rIter = parent->children; rsc == NULL && rIter; rIter = rIter->next) {
        GListPtr nIter = NULL;
        GListPtr locations = NULL;
        resource_t *child = rIter->data;

        child->fns->location(child, &locations, TRUE);
        if (locations == NULL) {
            pe_rsc_trace(child, "Resource %s, skip inactive", child->id);
            continue;
        }

        for (nIter = locations; nIter && rsc == NULL; nIter = nIter->next) {
            node_t *childnode = nIter->data;

            if (childnode->details == node->details) {
                /* ->find_rsc() because we might be a cloned group */
                rsc = parent->fns->find_rsc(child, rsc_id, NULL, pe_find_clone);
                pe_rsc_trace(rsc, "Resource %s, active", rsc->id);
            }

            /* Keep this block, it means we'll do the right thing if
             * anyone toggles the unique flag to 'off'
             */
            if (rsc && rsc->running_on) {
                crm_notice("/Anonymous/ clone %s is already running on %s",
                           parent->id, node->details->uname);
                skip_inactive = TRUE;
                rsc = NULL;
            }
        }

        g_list_free(locations);
    }

    /* Find an inactive instance */
    if (skip_inactive == FALSE) {
        pe_rsc_trace(parent, "Looking for %s anywhere", rsc_id);
        for (rIter = parent->children; rsc == NULL && rIter; rIter = rIter->next) {
            GListPtr locations = NULL;
            resource_t *child = rIter->data;

            child->fns->location(child, &locations, TRUE);
            if (locations == NULL) {
                /* ->find_rsc() because we might be a cloned group */
                rsc = parent->fns->find_rsc(child, rsc_id, NULL, pe_find_clone);
                pe_rsc_trace(parent, "Resource %s, empty slot", rsc->id);
            }
            g_list_free(locations);
        }
    }

    if (rsc == NULL) {
        /* Create an extra orphan */
        resource_t *top = create_child_clone(parent, -1, data_set);

        /* ->find_rsc() because we might be a cloned group */
        rsc = top->fns->find_rsc(top, rsc_id, NULL, pe_find_clone);
        CRM_ASSERT(rsc != NULL);

        pe_rsc_debug(parent, "Created orphan %s for %s: %s on %s", top->id, parent->id, rsc_id,
                     node->details->uname);
    }

    if (safe_str_neq(rsc_id, rsc->id)) {
        pe_rsc_info(rsc, "Internally renamed %s on %s to %s%s",
                    rsc_id, node->details->uname, rsc->id,
                    is_set(rsc->flags, pe_rsc_orphan) ? " (ORPHAN)" : "");
    }

    return rsc;
}

static resource_t *
unpack_find_resource(pe_working_set_t * data_set, node_t * node, const char *rsc_id,
                     xmlNode * rsc_entry)
{
    resource_t *rsc = NULL;
    resource_t *parent = NULL;

    crm_trace("looking for %s", rsc_id);
    rsc = pe_find_resource(data_set->resources, rsc_id);

    /* no match */
    if (rsc == NULL) {
        /* Even when clone-max=0, we still create a single :0 orphan to match against */
        char *tmp = clone_zero(rsc_id);
        resource_t *clone0 = pe_find_resource(data_set->resources, tmp);

        if (clone0 && is_not_set(clone0->flags, pe_rsc_unique)) {
            rsc = clone0;
        } else {
            crm_trace("%s is not known as %s either", rsc_id, tmp);
        }

        parent = uber_parent(clone0);
        free(tmp);

        crm_trace("%s not found: %s", rsc_id, parent ? parent->id : "orphan");

    } else if (rsc->variant > pe_native) {
        crm_trace("%s is no longer a primitve resource, the lrm_resource entry is obsolete",
                  rsc_id);
        return NULL;

    } else {
        parent = uber_parent(rsc);
    }

    if (parent && parent->variant > pe_group) {
        if (is_not_set(parent->flags, pe_rsc_unique)) {
            char *base = clone_strip(rsc_id);

            rsc = find_anonymous_clone(data_set, node, parent, base);
            CRM_ASSERT(rsc != NULL);
            free(base);
        }

        if (rsc && safe_str_neq(rsc_id, rsc->id)) {
            free(rsc->clone_name);
            rsc->clone_name = strdup(rsc_id);
        }
    }

    return rsc;
}

static resource_t *
process_orphan_resource(xmlNode * rsc_entry, node_t * node, pe_working_set_t * data_set)
{
    resource_t *rsc = NULL;
    const char *rsc_id = crm_element_value(rsc_entry, XML_ATTR_ID);

    crm_debug("Detected orphan resource %s on %s", rsc_id, node->details->uname);
    rsc = create_fake_resource(rsc_id, rsc_entry, data_set);

    if (is_set(data_set->flags, pe_flag_stop_rsc_orphans) == FALSE) {
        clear_bit(rsc->flags, pe_rsc_managed);

    } else {
        GListPtr gIter = NULL;

        print_resource(LOG_DEBUG_3, "Added orphan", rsc, FALSE);

        CRM_CHECK(rsc != NULL, return NULL);
        resource_location(rsc, NULL, -INFINITY, "__orphan_dont_run__", data_set);

        for (gIter = data_set->nodes; gIter != NULL; gIter = gIter->next) {
            node_t *node = (node_t *) gIter->data;

            if (node->details->online && get_failcount(node, rsc, NULL, data_set)) {
                action_t *clear_op = NULL;
                action_t *ready = NULL;

                if (node->details->remote_rsc) {
                    char *pseudo_op_name = crm_concat(CRM_OP_PROBED, node->details->id, '_');
                    ready = get_pseudo_op(pseudo_op_name, data_set);
                    free(pseudo_op_name);
                } else {
                    ready = get_pseudo_op(CRM_OP_PROBED, data_set);
                }

                clear_op = custom_action(rsc, crm_concat(rsc->id, CRM_OP_CLEAR_FAILCOUNT, '_'),
                                         CRM_OP_CLEAR_FAILCOUNT, node, FALSE, TRUE, data_set);

                add_hash_param(clear_op->meta, XML_ATTR_TE_NOWAIT, XML_BOOLEAN_TRUE);
                pe_rsc_info(rsc, "Clearing failcount (%d) for orphaned resource %s on %s (%s)",
                            get_failcount(node, rsc, NULL, data_set), rsc->id, node->details->uname,
                            clear_op->uuid);

                order_actions(clear_op, ready, pe_order_optional);
            }
        }
    }
    return rsc;
}

static void
process_rsc_state(resource_t * rsc, node_t * node,
                  enum action_fail_response on_fail,
                  xmlNode * migrate_op, pe_working_set_t * data_set)
{
    pe_rsc_trace(rsc, "Resource %s is %s on %s: on_fail=%s",
                 rsc->id, role2text(rsc->role), node->details->uname, fail2text(on_fail));

    /* process current state */
    if (rsc->role != RSC_ROLE_UNKNOWN) {
        resource_t *iter = rsc;

        while (iter) {
            if (g_hash_table_lookup(iter->known_on, node->details->id) == NULL) {
                node_t *n = node_copy(node);

                pe_rsc_trace(rsc, "%s (aka. %s) known on %s", rsc->id, rsc->clone_name,
                             n->details->uname);
                g_hash_table_insert(iter->known_on, (gpointer) n->details->id, n);
            }
            if (is_set(iter->flags, pe_rsc_unique)) {
                break;
            }
            iter = iter->parent;
        }
    }

    if (rsc->role > RSC_ROLE_STOPPED
        && node->details->online == FALSE && is_set(rsc->flags, pe_rsc_managed)) {

        gboolean should_fence = FALSE;

        /* if this is a remote_node living in a container, fence the container
         * by recovering it. Mark the resource as unmanaged. Once the container
         * and remote connenction are re-established, the status section will
         * get reset in the crmd freeing up this resource to run again once we
         * are sure we know the resources state. */
        if (node->details->remote_rsc && node->details->remote_rsc->container) {
            set_bit(rsc->flags, pe_rsc_failed);

            should_fence = TRUE;
        } else if (is_set(data_set->flags, pe_flag_stonith_enabled)) {
            should_fence = TRUE;
        }

        if (should_fence) {
            char *reason = g_strdup_printf("because %s is thought to be active there", rsc->id);
            pe_fence_node(data_set, node, reason);
            g_free(reason);
        }
    }

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

        case action_fail_fence:
            /* treat it as if it is still running
             * but also mark the node as unclean
             */
            pe_fence_node(data_set, node, "to recover from resource failure(s)");
            break;

        case action_fail_standby:
            node->details->standby = TRUE;
            node->details->standby_onfail = TRUE;
            break;

        case action_fail_block:
            /* is_managed == FALSE will prevent any
             * actions being sent for the resource
             */
            clear_bit(rsc->flags, pe_rsc_managed);
            set_bit(rsc->flags, pe_rsc_block);
            break;

        case action_fail_migrate:
            /* make sure it comes up somewhere else
             * or not at all
             */
            resource_location(rsc, node, -INFINITY, "__action_migration_auto__", data_set);
            break;

        case action_fail_stop:
            rsc->next_role = RSC_ROLE_STOPPED;
            break;

        case action_fail_recover:
            if (rsc->role != RSC_ROLE_STOPPED && rsc->role != RSC_ROLE_UNKNOWN) {
                set_bit(rsc->flags, pe_rsc_failed);
                stop_action(rsc, node, FALSE);
            }
            break;

        case action_fail_restart_container:
            set_bit(rsc->flags, pe_rsc_failed);

            if (rsc->container) {
                stop_action(rsc->container, node, FALSE);

            } else if (rsc->role != RSC_ROLE_STOPPED && rsc->role != RSC_ROLE_UNKNOWN) {
                stop_action(rsc, node, FALSE);
            }
            break;
    }

    if (rsc->role != RSC_ROLE_STOPPED && rsc->role != RSC_ROLE_UNKNOWN) {
        if (is_set(rsc->flags, pe_rsc_orphan)) {
            if (is_set(rsc->flags, pe_rsc_managed)) {
                crm_config_warn("Detected active orphan %s running on %s",
                                rsc->id, node->details->uname);
            } else {
                crm_config_warn("Cluster configured not to stop active orphans."
                                " %s must be stopped manually on %s",
                                rsc->id, node->details->uname);
            }
        }

        native_add_running(rsc, node, data_set);
        if (on_fail != action_fail_ignore) {
            set_bit(rsc->flags, pe_rsc_failed);
        }

    } else if (rsc->clone_name && strchr(rsc->clone_name, ':') != NULL) {
        /* Only do this for older status sections that included instance numbers
         * Otherwise stopped instances will appear as orphans
         */
        pe_rsc_trace(rsc, "Resetting clone_name %s for %s (stopped)", rsc->clone_name, rsc->id);
        free(rsc->clone_name);
        rsc->clone_name = NULL;

    } else {
        char *key = stop_key(rsc);
        GListPtr possible_matches = find_actions(rsc->actions, key, node);
        GListPtr gIter = possible_matches;

        for (; gIter != NULL; gIter = gIter->next) {
            action_t *stop = (action_t *) gIter->data;

            stop->flags |= pe_action_optional;
        }

        free(key);
    }
}

/* create active recurring operations as optional */
static void
process_recurring(node_t * node, resource_t * rsc,
                  int start_index, int stop_index,
                  GListPtr sorted_op_list, pe_working_set_t * data_set)
{
    int counter = -1;
    const char *task = NULL;
    const char *status = NULL;
    GListPtr gIter = sorted_op_list;

    pe_rsc_trace(rsc, "%s: Start index %d, stop index = %d", rsc->id, start_index, stop_index);

    for (; gIter != NULL; gIter = gIter->next) {
        xmlNode *rsc_op = (xmlNode *) gIter->data;

        int interval = 0;
        char *key = NULL;
        const char *id = ID(rsc_op);
        const char *interval_s = NULL;

        counter++;

        if (node->details->online == FALSE) {
            pe_rsc_trace(rsc, "Skipping %s/%s: node is offline", rsc->id, node->details->uname);
            break;

            /* Need to check if there's a monitor for role="Stopped" */
        } else if (start_index < stop_index && counter <= stop_index) {
            pe_rsc_trace(rsc, "Skipping %s/%s: resource is not active", id, node->details->uname);
            continue;

        } else if (counter < start_index) {
            pe_rsc_trace(rsc, "Skipping %s/%s: old %d", id, node->details->uname, counter);
            continue;
        }

        interval_s = crm_element_value(rsc_op, XML_LRM_ATTR_INTERVAL);
        interval = crm_parse_int(interval_s, "0");
        if (interval == 0) {
            pe_rsc_trace(rsc, "Skipping %s/%s: non-recurring", id, node->details->uname);
            continue;
        }

        status = crm_element_value(rsc_op, XML_LRM_ATTR_OPSTATUS);
        if (safe_str_eq(status, "-1")) {
            pe_rsc_trace(rsc, "Skipping %s/%s: status", id, node->details->uname);
            continue;
        }
        task = crm_element_value(rsc_op, XML_LRM_ATTR_TASK);
        /* create the action */
        key = generate_op_key(rsc->id, task, interval);
        pe_rsc_trace(rsc, "Creating %s/%s", key, node->details->uname);
        custom_action(rsc, key, task, node, TRUE, TRUE, data_set);
    }
}

void
calculate_active_ops(GListPtr sorted_op_list, int *start_index, int *stop_index)
{
    int counter = -1;
    int implied_monitor_start = -1;
    int implied_master_start = -1;
    const char *task = NULL;
    const char *status = NULL;
    GListPtr gIter = sorted_op_list;

    *stop_index = -1;
    *start_index = -1;

    for (; gIter != NULL; gIter = gIter->next) {
        xmlNode *rsc_op = (xmlNode *) gIter->data;

        counter++;

        task = crm_element_value(rsc_op, XML_LRM_ATTR_TASK);
        status = crm_element_value(rsc_op, XML_LRM_ATTR_OPSTATUS);

        if (safe_str_eq(task, CRMD_ACTION_STOP)
            && safe_str_eq(status, "0")) {
            *stop_index = counter;

        } else if (safe_str_eq(task, CRMD_ACTION_START) || safe_str_eq(task, CRMD_ACTION_MIGRATED)) {
            *start_index = counter;

        } else if ((implied_monitor_start <= *stop_index) && safe_str_eq(task, CRMD_ACTION_STATUS)) {
            const char *rc = crm_element_value(rsc_op, XML_LRM_ATTR_RC);

            if (safe_str_eq(rc, "0") || safe_str_eq(rc, "8")) {
                implied_monitor_start = counter;
            }
        } else if (safe_str_eq(task, CRMD_ACTION_PROMOTE) || safe_str_eq(task, CRMD_ACTION_DEMOTE)) {
            implied_master_start = counter;
        }
    }

    if (*start_index == -1) {
        if (implied_master_start != -1) {
            *start_index = implied_master_start;
        } else if (implied_monitor_start != -1) {
            *start_index = implied_monitor_start;
        }
    }
}

static void
unpack_lrm_rsc_state(node_t * node, xmlNode * rsc_entry, pe_working_set_t * data_set)
{
    GListPtr gIter = NULL;
    int stop_index = -1;
    int start_index = -1;
    enum rsc_role_e req_role = RSC_ROLE_UNKNOWN;

    const char *task = NULL;
    const char *rsc_id = crm_element_value(rsc_entry, XML_ATTR_ID);

    resource_t *rsc = NULL;
    GListPtr op_list = NULL;
    GListPtr sorted_op_list = NULL;

    xmlNode *migrate_op = NULL;
    xmlNode *rsc_op = NULL;

    enum action_fail_response on_fail = FALSE;
    enum rsc_role_e saved_role = RSC_ROLE_UNKNOWN;

    crm_trace("[%s] Processing %s on %s",
              crm_element_name(rsc_entry), rsc_id, node->details->uname);

    /* extract operations */
    op_list = NULL;
    sorted_op_list = NULL;

    for (rsc_op = __xml_first_child(rsc_entry); rsc_op != NULL; rsc_op = __xml_next(rsc_op)) {
        if (crm_str_eq((const char *)rsc_op->name, XML_LRM_TAG_RSC_OP, TRUE)) {
            op_list = g_list_prepend(op_list, rsc_op);
        }
    }

    if (op_list == NULL) {
        /* if there are no operations, there is nothing to do */
        return;
    }

    /* find the resource */
    rsc = unpack_find_resource(data_set, node, rsc_id, rsc_entry);
    if (rsc == NULL) {
        rsc = process_orphan_resource(rsc_entry, node, data_set);
    }
    CRM_ASSERT(rsc != NULL);

    /* process operations */
    saved_role = rsc->role;
    on_fail = action_fail_ignore;
    rsc->role = RSC_ROLE_UNKNOWN;
    sorted_op_list = g_list_sort(op_list, sort_op_by_callid);

    for (gIter = sorted_op_list; gIter != NULL; gIter = gIter->next) {
        xmlNode *rsc_op = (xmlNode *) gIter->data;

        task = crm_element_value(rsc_op, XML_LRM_ATTR_TASK);
        if (safe_str_eq(task, CRMD_ACTION_MIGRATED)) {
            migrate_op = rsc_op;
        }

        unpack_rsc_op(rsc, node, rsc_op, &on_fail, data_set);
    }

    /* create active recurring operations as optional */
    calculate_active_ops(sorted_op_list, &start_index, &stop_index);
    process_recurring(node, rsc, start_index, stop_index, sorted_op_list, data_set);

    /* no need to free the contents */
    g_list_free(sorted_op_list);

    process_rsc_state(rsc, node, on_fail, migrate_op, data_set);

    if (get_target_role(rsc, &req_role)) {
        if (rsc->next_role == RSC_ROLE_UNKNOWN || req_role < rsc->next_role) {
            pe_rsc_debug(rsc, "%s: Overwriting calculated next role %s"
                         " with requested next role %s",
                         rsc->id, role2text(rsc->next_role), role2text(req_role));
            rsc->next_role = req_role;

        } else if (req_role > rsc->next_role) {
            pe_rsc_info(rsc, "%s: Not overwriting calculated next role %s"
                        " with requested next role %s",
                        rsc->id, role2text(rsc->next_role), role2text(req_role));
        }
    }

    if (saved_role > rsc->role) {
        rsc->role = saved_role;
    }
}

gboolean
unpack_lrm_resources(node_t * node, xmlNode * lrm_rsc_list, pe_working_set_t * data_set)
{
    xmlNode *rsc_entry = NULL;

    CRM_CHECK(node != NULL, return FALSE);

    crm_trace("Unpacking resources on %s", node->details->uname);

    for (rsc_entry = __xml_first_child(lrm_rsc_list); rsc_entry != NULL;
         rsc_entry = __xml_next(rsc_entry)) {
        if (crm_str_eq((const char *)rsc_entry->name, XML_LRM_TAG_RESOURCE, TRUE)) {
            unpack_lrm_rsc_state(node, rsc_entry, data_set);
        }
    }

    return TRUE;
}

static void
set_active(resource_t * rsc)
{
    resource_t *top = uber_parent(rsc);

    if (top && top->variant == pe_master) {
        rsc->role = RSC_ROLE_SLAVE;
    } else {
        rsc->role = RSC_ROLE_STARTED;
    }
}

static void
set_node_score(gpointer key, gpointer value, gpointer user_data)
{
    node_t *node = value;
    int *score = user_data;

    node->weight = *score;
}

#define STATUS_PATH_MAX 1024
static xmlNode *
find_lrm_op(const char *resource, const char *op, const char *node, const char *source,
            pe_working_set_t * data_set)
{
    int offset = 0;
    char xpath[STATUS_PATH_MAX];

    offset += snprintf(xpath + offset, STATUS_PATH_MAX - offset, "//node_state[@uname='%s']", node);
    offset +=
        snprintf(xpath + offset, STATUS_PATH_MAX - offset, "//" XML_LRM_TAG_RESOURCE "[@id='%s']",
                 resource);

    /* Need to check against transition_magic too? */
    if (source && safe_str_eq(op, CRMD_ACTION_MIGRATE)) {
        offset +=
            snprintf(xpath + offset, STATUS_PATH_MAX - offset,
                     "/" XML_LRM_TAG_RSC_OP "[@operation='%s' and @migrate_target='%s']", op,
                     source);
    } else if (source && safe_str_eq(op, CRMD_ACTION_MIGRATED)) {
        offset +=
            snprintf(xpath + offset, STATUS_PATH_MAX - offset,
                     "/" XML_LRM_TAG_RSC_OP "[@operation='%s' and @migrate_source='%s']", op,
                     source);
    } else {
        offset +=
            snprintf(xpath + offset, STATUS_PATH_MAX - offset,
                     "/" XML_LRM_TAG_RSC_OP "[@operation='%s']", op);
    }

    return get_xpath_object(xpath, data_set->input, LOG_DEBUG);
}

gboolean
unpack_rsc_op(resource_t * rsc, node_t * node, xmlNode * xml_op,
              enum action_fail_response * on_fail, pe_working_set_t * data_set)
{
    int task_id = 0;

    const char *id = NULL;
    const char *key = NULL;
    const char *task = NULL;
    const char *task_key = NULL;
    const char *magic = NULL;
    const char *actual_rc = NULL;

/* 	const char *target_rc   = NULL;	 */
    const char *task_status = NULL;
    const char *interval_s = NULL;
    const char *op_version = NULL;

    int interval = 0;
    int task_status_i = -2;
    int actual_rc_i = 0;
    int target_rc = -1;
    int last_failure = 0;
    int clear_failcount = 0;

    action_t *action = NULL;
    node_t *effective_node = NULL;
    resource_t *failed = NULL;

    gboolean expired = FALSE;
    gboolean is_probe = FALSE;
    gboolean clear_past_failure = FALSE;
    gboolean stop_failure_ignored = FALSE;

    CRM_CHECK(rsc != NULL, return FALSE);
    CRM_CHECK(node != NULL, return FALSE);
    CRM_CHECK(xml_op != NULL, return FALSE);

    id = ID(xml_op);
    task = crm_element_value(xml_op, XML_LRM_ATTR_TASK);
    task_key = crm_element_value(xml_op, XML_LRM_ATTR_TASK_KEY);
    task_status = crm_element_value(xml_op, XML_LRM_ATTR_OPSTATUS);
    op_version = crm_element_value(xml_op, XML_ATTR_CRM_VERSION);
    magic = crm_element_value(xml_op, XML_ATTR_TRANSITION_MAGIC);
    key = crm_element_value(xml_op, XML_ATTR_TRANSITION_KEY);

    crm_element_value_int(xml_op, XML_LRM_ATTR_CALLID, &task_id);

    CRM_CHECK(id != NULL, return FALSE);
    CRM_CHECK(task != NULL, return FALSE);
    CRM_CHECK(task_status != NULL, return FALSE);

    task_status_i = crm_parse_int(task_status, NULL);

    CRM_CHECK(task_status_i <= PCMK_LRM_OP_ERROR, return FALSE);
    CRM_CHECK(task_status_i >= PCMK_LRM_OP_PENDING, return FALSE);

    if (safe_str_eq(task, CRMD_ACTION_NOTIFY)) {
        /* safe to ignore these */
        return TRUE;
    }

    if (rsc->failure_timeout > 0) {
        int last_run = 0;

        if (crm_element_value_int(xml_op, "last-rc-change", &last_run) == 0) {
            time_t now = get_timet_now(data_set);

            if (now > (last_run + rsc->failure_timeout)) {
                expired = TRUE;
            }
        }
    }

    pe_rsc_trace(rsc, "Unpacking task %s/%s (call_id=%d, status=%s) on %s (role=%s)",
                 id, task, task_id, task_status, node->details->uname, role2text(rsc->role));

    interval_s = crm_element_value(xml_op, XML_LRM_ATTR_INTERVAL);
    interval = crm_parse_int(interval_s, "0");

    if (interval == 0 && safe_str_eq(task, CRMD_ACTION_STATUS)) {
        is_probe = TRUE;
    }

    if (node->details->unclean) {
        pe_rsc_trace(rsc, "Node %s (where %s is running) is unclean."
                     " Further action depends on the value of the stop's on-fail attribue",
                     node->details->uname, rsc->id);
    }

    actual_rc = crm_element_value(xml_op, XML_LRM_ATTR_RC);
    CRM_CHECK(actual_rc != NULL, return FALSE);
    actual_rc_i = crm_parse_int(actual_rc, NULL);

    if (key) {
        int dummy = 0;
        char *dummy_string = NULL;

        decode_transition_key(key, &dummy_string, &dummy, &dummy, &target_rc);
        free(dummy_string);
    }

    if (task_status_i == PCMK_LRM_OP_DONE && target_rc >= 0) {
        if (target_rc == actual_rc_i) {
            task_status_i = PCMK_LRM_OP_DONE;

        } else {
            task_status_i = PCMK_LRM_OP_ERROR;
            pe_rsc_debug(rsc, "%s on %s returned %d (%s) instead of the expected value: %d (%s)",
                         id, node->details->uname,
                         actual_rc_i, lrmd_event_rc2str(actual_rc_i),
                         target_rc, lrmd_event_rc2str(target_rc));
        }

    } else if (task_status_i == PCMK_LRM_OP_ERROR) {
        /* let us decide that */
        task_status_i = PCMK_LRM_OP_DONE;
    }

    if (task_status_i == PCMK_LRM_OP_NOTSUPPORTED) {
        actual_rc_i = PCMK_EXECRA_UNIMPLEMENT_FEATURE;
    }

    if (expired) {
        int fc = get_failcount(node, rsc, &last_failure, data_set);

        if (rsc->failure_timeout > 0 && last_failure > 0 && fc == 0) {

            clear_failcount = 1;
            crm_notice("Clearing expired failcount for %s on %s", rsc->id, node->details->uname);
        }
    } else if (strstr(id, "last_failure") &&
               ((strcmp(task, "start") == 0) || (strcmp(task, "monitor") == 0))) {

        op_digest_cache_t *digest_data = NULL;

        digest_data = rsc_action_digest_cmp(rsc, xml_op, node, data_set);

        if (digest_data->rc == RSC_DIGEST_UNKNOWN) {
            crm_trace("rsc op %s on node %s does not have a op digest to compare against", rsc->id,
                      id, node->details->id);
        } else if (digest_data->rc != RSC_DIGEST_MATCH) {
            clear_failcount = 1;
            crm_info
                ("Clearing failcount for %s on %s, %s failed and now resource parameters have changed.",
                 task, rsc->id, node->details->uname);
        }
    }

    if (clear_failcount) {
        action_t *clear_op = NULL;

        clear_op = custom_action(rsc, crm_concat(rsc->id, CRM_OP_CLEAR_FAILCOUNT, '_'),
                                 CRM_OP_CLEAR_FAILCOUNT, node, FALSE, TRUE, data_set);
        add_hash_param(clear_op->meta, XML_ATTR_TE_NOWAIT, XML_BOOLEAN_TRUE);
    }

    if (expired
        && actual_rc_i != PCMK_EXECRA_NOT_RUNNING
        && actual_rc_i != PCMK_EXECRA_RUNNING_MASTER && actual_rc_i != PCMK_EXECRA_OK) {
        crm_notice("Ignoring expired failure %s (rc=%d, magic=%s) on %s",
                   id, actual_rc_i, magic, node->details->uname);
        goto done;
    }

    /* we could clean this up significantly except for old LRMs and CRMs that
     * didnt include target_rc and liked to remap status
     */
    switch (actual_rc_i) {
        case PCMK_EXECRA_NOT_RUNNING:
            if (is_probe || target_rc == actual_rc_i) {
                task_status_i = PCMK_LRM_OP_DONE;
                rsc->role = RSC_ROLE_STOPPED;

                /* clear any previous failure actions */
                *on_fail = action_fail_ignore;
                rsc->next_role = RSC_ROLE_UNKNOWN;

            } else if (safe_str_neq(task, CRMD_ACTION_STOP)) {
                task_status_i = PCMK_LRM_OP_ERROR;
            }
            break;

        case PCMK_EXECRA_RUNNING_MASTER:
            if (is_probe) {
                task_status_i = PCMK_LRM_OP_DONE;
                crm_notice("Operation %s found resource %s active in master mode on %s",
                           task, rsc->id, node->details->uname);

            } else if (target_rc == actual_rc_i) {
                /* nothing to do */

            } else if (target_rc >= 0) {
                task_status_i = PCMK_LRM_OP_ERROR;

                /* legacy code for pre-0.6.5 operations */
            } else if (safe_str_neq(task, CRMD_ACTION_STATUS)
                       || rsc->role != RSC_ROLE_MASTER) {
                task_status_i = PCMK_LRM_OP_ERROR;
                if (rsc->role != RSC_ROLE_MASTER) {
                    crm_err("%s reported %s in master mode on %s",
                            id, rsc->id, node->details->uname);
                }
            }
            rsc->role = RSC_ROLE_MASTER;
            break;

        case PCMK_EXECRA_FAILED_MASTER:
            rsc->role = RSC_ROLE_MASTER;
            task_status_i = PCMK_LRM_OP_ERROR;
            break;

        case PCMK_EXECRA_UNIMPLEMENT_FEATURE:
            if (interval > 0) {
                task_status_i = PCMK_LRM_OP_NOTSUPPORTED;
                break;
            }
            /* else: fall through */
        case PCMK_EXECRA_INSUFFICIENT_PRIV:
        case PCMK_EXECRA_NOT_INSTALLED:
        case PCMK_EXECRA_INVALID_PARAM:
            effective_node = node;
            /* fall through */
        case PCMK_EXECRA_NOT_CONFIGURED:
            failed = rsc;
            if (is_not_set(rsc->flags, pe_rsc_unique)) {
                failed = uber_parent(failed);
            }

            do_crm_log(actual_rc_i == PCMK_EXECRA_NOT_INSTALLED ? LOG_NOTICE : LOG_ERR,
                       "Preventing %s from re-starting %s %s: operation %s failed '%s' (rc=%d)",
                       failed->id,
                       effective_node ? "on" : "anywhere in the cluster",
                       effective_node ? effective_node->details->uname : "",
                       task, lrmd_event_rc2str(actual_rc_i), actual_rc_i);

            resource_location(failed, effective_node, -INFINITY, "hard-error", data_set);
            if (is_probe) {
                /* treat these like stops */
                task = CRMD_ACTION_STOP;
                task_status_i = PCMK_LRM_OP_DONE;
                crm_xml_add(xml_op, XML_ATTR_UNAME, node->details->uname);
                if (actual_rc_i != PCMK_EXECRA_NOT_INSTALLED
                    || is_set(data_set->flags, pe_flag_symmetric_cluster)) {
                    if ((node->details->shutdown == FALSE) || (node->details->online == TRUE)) {
                        add_node_copy(data_set->failed, xml_op);
                    }
                }
            }
            break;

        case PCMK_EXECRA_OK:
            if (is_probe && target_rc == 7) {
                task_status_i = PCMK_LRM_OP_DONE;
                pe_rsc_info(rsc, "Operation %s found resource %s active on %s",
                            task, rsc->id, node->details->uname);

                /* legacy code for pre-0.6.5 operations */
            } else if (target_rc < 0 && interval > 0 && rsc->role == RSC_ROLE_MASTER) {
                /* catch status ops that return 0 instead of 8 while they
                 *   are supposed to be in master mode
                 */
                task_status_i = PCMK_LRM_OP_ERROR;
            }

            break;

        default:
            if (task_status_i == PCMK_LRM_OP_DONE) {
                crm_info("Remapping %s (rc=%d) on %s to an ERROR",
                         id, actual_rc_i, node->details->uname);
                task_status_i = PCMK_LRM_OP_ERROR;
            }
    }

    if (task_status_i == PCMK_LRM_OP_ERROR
        || task_status_i == PCMK_LRM_OP_TIMEOUT || task_status_i == PCMK_LRM_OP_NOTSUPPORTED) {
        const char *action_key = task_key ? task_key : id;

        action = custom_action(rsc, strdup(action_key), task, NULL, TRUE, FALSE, data_set);
        if (expired) {
            crm_notice("Ignoring expired failure (calculated) %s (rc=%d, magic=%s) on %s",
                       id, actual_rc_i, magic, node->details->uname);
            goto done;

        } else if ((action->on_fail == action_fail_ignore) ||
                   (action->on_fail == action_fail_restart_container &&
                    safe_str_eq(task, CRMD_ACTION_STOP))) {
            crm_warn("Remapping %s (rc=%d) on %s to DONE: ignore",
                     id, actual_rc_i, node->details->uname);
            task_status_i = PCMK_LRM_OP_DONE;
            set_bit(rsc->flags, pe_rsc_failure_ignored);

            crm_xml_add(xml_op, XML_ATTR_UNAME, node->details->uname);
            if ((node->details->shutdown == FALSE) || (node->details->online == TRUE)) {
                add_node_copy(data_set->failed, xml_op);
            }

            if (action->on_fail == action_fail_restart_container && *on_fail <= action_fail_recover) {
                *on_fail = action->on_fail;
            }

            if (safe_str_eq(task, CRMD_ACTION_STOP)) {
                stop_failure_ignored = TRUE;
            }
        }
    }

    switch (task_status_i) {
        case PCMK_LRM_OP_PENDING:
            if (safe_str_eq(task, CRMD_ACTION_START)) {
                set_bit(rsc->flags, pe_rsc_start_pending);
                set_active(rsc);

            } else if (safe_str_eq(task, CRMD_ACTION_PROMOTE)) {
                rsc->role = RSC_ROLE_MASTER;
            }
            /*
             * Intentionally ignoring pending migrate ops here;
             * haven't decided if we need to do anything special
             * with them yet...
             */
            break;

        case PCMK_LRM_OP_DONE:
            pe_rsc_trace(rsc, "%s/%s completed on %s", rsc->id, task, node->details->uname);

            if (actual_rc_i == PCMK_EXECRA_NOT_RUNNING) {
                clear_past_failure = TRUE;

            } else if (safe_str_eq(task, CRMD_ACTION_START)) {
                rsc->role = RSC_ROLE_STARTED;
                clear_past_failure = TRUE;

            } else if (safe_str_eq(task, CRMD_ACTION_STOP)) {
                rsc->role = RSC_ROLE_STOPPED;
                clear_past_failure = TRUE;

            } else if (safe_str_eq(task, CRMD_ACTION_PROMOTE)) {
                rsc->role = RSC_ROLE_MASTER;
                clear_past_failure = TRUE;

            } else if (safe_str_eq(task, CRMD_ACTION_DEMOTE)) {
                /* Demote from Master does not clear an error */
                rsc->role = RSC_ROLE_SLAVE;

            } else if (safe_str_eq(task, CRMD_ACTION_MIGRATED)) {
                rsc->role = RSC_ROLE_STARTED;
                clear_past_failure = TRUE;

            } else if (safe_str_eq(task, CRMD_ACTION_MIGRATE)) {
                /*
                 * The normal sequence is (now): migrate_to(Src) -> migrate_from(Tgt) -> stop(Src)
                 *
                 * So if a migrate_to is followed by a stop, then we dont need to care what
                 * happended on the target node
                 *
                 * Without the stop, we need to look for a successful migrate_from.
                 * This would also imply we're no longer running on the source
                 *
                 * Without the stop, and without a migrate_from op we make sure the resource
                 * gets stopped on both source and target (assuming the target is up)
                 *
                 */
                int stop_id = 0;
                xmlNode *stop_op =
                    find_lrm_op(rsc->id, CRMD_ACTION_STOP, node->details->id, NULL, data_set);

                if (stop_op) {
                    crm_element_value_int(stop_op, XML_LRM_ATTR_CALLID, &stop_id);
                }

                if (stop_op == NULL || stop_id < task_id) {
                    int from_rc = 0, from_status = 0;
                    const char *migrate_source =
                        crm_element_value(xml_op, XML_LRM_ATTR_MIGRATE_SOURCE);
                    const char *migrate_target =
                        crm_element_value(xml_op, XML_LRM_ATTR_MIGRATE_TARGET);

                    node_t *target = pe_find_node(data_set->nodes, migrate_target);
                    node_t *source = pe_find_node(data_set->nodes, migrate_source);
                    xmlNode *migrate_from =
                        find_lrm_op(rsc->id, CRMD_ACTION_MIGRATED, migrate_target, migrate_source,
                                    data_set);

                    rsc->role = RSC_ROLE_STARTED;       /* can be master? */
                    if (migrate_from) {
                        crm_element_value_int(migrate_from, XML_LRM_ATTR_RC, &from_rc);
                        crm_element_value_int(migrate_from, XML_LRM_ATTR_OPSTATUS, &from_status);
                        pe_rsc_trace(rsc, "%s op on %s exited with status=%d, rc=%d",
                                     ID(migrate_from), migrate_target, from_status, from_rc);
                    }

                    if (migrate_from && from_rc == PCMK_EXECRA_OK
                        && from_status == PCMK_LRM_OP_DONE) {
                        pe_rsc_trace(rsc, "Detected dangling migration op: %s on %s", ID(xml_op),
                                     migrate_source);

                        /* all good
                         * just need to arrange for the stop action to get sent
                         * but _without_ affecting the target somehow
                         */
                        rsc->role = RSC_ROLE_STOPPED;
                        rsc->dangling_migrations = g_list_prepend(rsc->dangling_migrations, node);

                    } else if (migrate_from) {  /* Failed */
                        if (target && target->details->online) {
                            pe_rsc_trace(rsc, "Marking active on %s %p %d", migrate_target, target,
                                         target->details->online);
                            native_add_running(rsc, target, data_set);
                        }

                    } else {    /* Pending or complete but erased */
                        node_t *target = pe_find_node_id(data_set->nodes, migrate_target);

                        if (target && target->details->online) {
                            pe_rsc_trace(rsc, "Marking active on %s %p %d", migrate_target, target,
                                         target->details->online);

                            native_add_running(rsc, target, data_set);
                            if (source && source->details->online) {
                                /* If we make it here we have a partial migration.  The migrate_to
                                 * has completed but the migrate_from on the target has not. Hold on
                                 * to the target and source on the resource. Later on if we detect that
                                 * the resource is still going to run on that target, we may continue
                                 * the migration */
                                rsc->partial_migration_target = target;
                                rsc->partial_migration_source = source;
                            }
                        } else {
                            /* Consider it failed here - forces a restart, prevents migration */
                            set_bit(rsc->flags, pe_rsc_failed);
                        }
                    }
                }

            } else if (rsc->role < RSC_ROLE_STARTED) {
                /* start, migrate_to and migrate_from will land here */
                pe_rsc_trace(rsc, "%s active on %s", rsc->id, node->details->uname);
                set_active(rsc);
            }

            /* clear any previous failure actions */
            if (clear_past_failure) {
                switch (*on_fail) {
                    case action_fail_block:
                    case action_fail_stop:
                    case action_fail_fence:
                    case action_fail_migrate:
                    case action_fail_standby:
                        pe_rsc_trace(rsc, "%s.%s is not cleared by a completed stop",
                                     rsc->id, fail2text(*on_fail));
                        break;

                    case action_fail_ignore:
                    case action_fail_recover:
                        *on_fail = action_fail_ignore;
                        rsc->next_role = RSC_ROLE_UNKNOWN;
                        break;

                    case action_fail_restart_container:
                        if (stop_failure_ignored) {
                            pe_rsc_trace(rsc, "%s.%s is not cleared by an ignored failed stop",
                                         rsc->id, fail2text(*on_fail));

                        } else {
                            *on_fail = action_fail_ignore;
                            rsc->next_role = RSC_ROLE_UNKNOWN;
                        }
                }
            }
            break;

        case PCMK_LRM_OP_ERROR:
        case PCMK_LRM_OP_TIMEOUT:
        case PCMK_LRM_OP_NOTSUPPORTED:
            crm_warn("Processing failed op %s for %s on %s: %s (%d)",
                     task, rsc->id, node->details->uname, lrmd_event_rc2str(actual_rc_i),
                     actual_rc_i);
            crm_xml_add(xml_op, XML_ATTR_UNAME, node->details->uname);
            if ((node->details->shutdown == FALSE) || (node->details->online == TRUE)) {
                add_node_copy(data_set->failed, xml_op);
            }

            if ((action->on_fail <= action_fail_fence && *on_fail < action->on_fail) ||
                (action->on_fail == action_fail_restart_container
                 && *on_fail <= action_fail_recover) || (*on_fail == action_fail_restart_container
                                                         && action->on_fail >=
                                                         action_fail_migrate)) {
                pe_rsc_trace(rsc, "on-fail %s -> %s for %s (%s)", fail2text(*on_fail),
                             fail2text(action->on_fail), action->uuid, task_key ? task_key : id);
                *on_fail = action->on_fail;
            }

            if (safe_str_eq(task, CRMD_ACTION_STOP)) {
                resource_location(rsc, node, -INFINITY, "__stop_fail__", data_set);

            } else if (safe_str_eq(task, CRMD_ACTION_MIGRATED)) {
                int stop_id = 0;
                int migrate_id = 0;
                const char *migrate_source = crm_element_value(xml_op, XML_LRM_ATTR_MIGRATE_SOURCE);
                const char *migrate_target = crm_element_value(xml_op, XML_LRM_ATTR_MIGRATE_TARGET);

                xmlNode *stop_op =
                    find_lrm_op(rsc->id, CRMD_ACTION_STOP, migrate_source, NULL, data_set);
                xmlNode *migrate_op =
                    find_lrm_op(rsc->id, CRMD_ACTION_MIGRATE, migrate_source, migrate_target,
                                data_set);

                if (stop_op) {
                    crm_element_value_int(stop_op, XML_LRM_ATTR_CALLID, &stop_id);
                }
                if (migrate_op) {
                    crm_element_value_int(migrate_op, XML_LRM_ATTR_CALLID, &migrate_id);
                }

                /* Get our state right */
                rsc->role = RSC_ROLE_STARTED;   /* can be master? */

                if (stop_op == NULL || stop_id < migrate_id) {
                    node_t *source = pe_find_node(data_set->nodes, migrate_source);

                    if (source && source->details->online) {
                        native_add_running(rsc, source, data_set);
                    }
                }

            } else if (safe_str_eq(task, CRMD_ACTION_MIGRATE)) {
                int stop_id = 0;
                int migrate_id = 0;
                const char *migrate_source = crm_element_value(xml_op, XML_LRM_ATTR_MIGRATE_SOURCE);
                const char *migrate_target = crm_element_value(xml_op, XML_LRM_ATTR_MIGRATE_TARGET);

                xmlNode *stop_op =
                    find_lrm_op(rsc->id, CRMD_ACTION_STOP, migrate_target, NULL, data_set);
                xmlNode *migrate_op =
                    find_lrm_op(rsc->id, CRMD_ACTION_MIGRATED, migrate_target, migrate_source,
                                data_set);

                if (stop_op) {
                    crm_element_value_int(stop_op, XML_LRM_ATTR_CALLID, &stop_id);
                }
                if (migrate_op) {
                    crm_element_value_int(migrate_op, XML_LRM_ATTR_CALLID, &migrate_id);
                }

                /* Get our state right */
                rsc->role = RSC_ROLE_STARTED;   /* can be master? */

                if (stop_op == NULL || stop_id < migrate_id) {
                    node_t *target = pe_find_node(data_set->nodes, migrate_target);

                    pe_rsc_trace(rsc, "Stop: %p %d, Migrated: %p %d", stop_op, stop_id, migrate_op,
                                 migrate_id);
                    if (target && target->details->online) {
                        native_add_running(rsc, target, data_set);
                    }

                } else if (migrate_op == NULL) {
                    /* Make sure it gets cleaned up, the stop may pre-date the migrate_from */
                    rsc->dangling_migrations = g_list_prepend(rsc->dangling_migrations, node);
                }

            } else if (safe_str_eq(task, CRMD_ACTION_PROMOTE)) {
                rsc->role = RSC_ROLE_MASTER;

            } else if (safe_str_eq(task, CRMD_ACTION_DEMOTE)) {
                /*
                 * staying in role=master ends up putting the PE/TE into a loop
                 * setting role=slave is not dangerous because no master will be
                 * promoted until the failed resource has been fully stopped
                 */
                crm_warn("Forcing %s to stop after a failed demote action", rsc->id);
                rsc->next_role = RSC_ROLE_STOPPED;
                rsc->role = RSC_ROLE_SLAVE;

            } else if (compare_version("2.0", op_version) > 0
                       && safe_str_eq(task, CRMD_ACTION_START)) {
                crm_warn("Compatibility handling for failed op %s on %s", id, node->details->uname);
                resource_location(rsc, node, -INFINITY, "__legacy_start__", data_set);
            }

            if (rsc->role < RSC_ROLE_STARTED) {
                set_active(rsc);
            }

            pe_rsc_trace(rsc, "Resource %s: role=%s, unclean=%s, on_fail=%s, fail_role=%s",
                         rsc->id, role2text(rsc->role),
                         node->details->unclean ? "true" : "false",
                         fail2text(action->on_fail), role2text(action->fail_role));

            if (action->fail_role != RSC_ROLE_STARTED && rsc->next_role < action->fail_role) {
                rsc->next_role = action->fail_role;
            }

            if (action->fail_role == RSC_ROLE_STOPPED) {
                int score = -INFINITY;

                resource_t *fail_rsc = rsc;

                if (fail_rsc->parent) {
                    resource_t *parent = uber_parent(fail_rsc);

                    if ((parent->variant == pe_clone || parent->variant == pe_master)
                        && is_not_set(parent->flags, pe_rsc_unique)) {
                        /* for clone and master resources, if a child fails on an operation
                         * with on-fail = stop, all the resources fail.  Do this by preventing
                         * the parent from coming up again. */
                        fail_rsc = parent;
                    }
                }
                crm_warn("Making sure %s doesn't come up again", fail_rsc->id);
                /* make sure it doesnt come up again */
                g_hash_table_destroy(fail_rsc->allowed_nodes);
                fail_rsc->allowed_nodes = node_hash_from_list(data_set->nodes);
                g_hash_table_foreach(fail_rsc->allowed_nodes, set_node_score, &score);
            }

            pe_free_action(action);
            action = NULL;
            break;
        case PCMK_LRM_OP_CANCELLED:
            /* do nothing?? */
            pe_err("Dont know what to do for cancelled ops yet");
            break;
    }

  done:
    pe_rsc_trace(rsc, "Resource %s after %s: role=%s", rsc->id, task, role2text(rsc->role));

    pe_free_action(action);

    return TRUE;
}

gboolean
add_node_attrs(xmlNode * xml_obj, node_t * node, gboolean overwrite, pe_working_set_t * data_set)
{
    g_hash_table_insert(node->details->attrs,
                        strdup("#" XML_ATTR_UNAME), strdup(node->details->uname));
    g_hash_table_insert(node->details->attrs, strdup("#" XML_ATTR_ID), strdup(node->details->id));
    if (safe_str_eq(node->details->id, data_set->dc_uuid)) {
        data_set->dc_node = node;
        node->details->is_dc = TRUE;
        g_hash_table_insert(node->details->attrs,
                            strdup("#" XML_ATTR_DC), strdup(XML_BOOLEAN_TRUE));
    } else {
        g_hash_table_insert(node->details->attrs,
                            strdup("#" XML_ATTR_DC), strdup(XML_BOOLEAN_FALSE));
    }

    unpack_instance_attributes(data_set->input, xml_obj, XML_TAG_ATTR_SETS, NULL,
                               node->details->attrs, NULL, overwrite, data_set->now);

    return TRUE;
}

static GListPtr
extract_operations(const char *node, const char *rsc, xmlNode * rsc_entry, gboolean active_filter)
{
    int counter = -1;
    int stop_index = -1;
    int start_index = -1;

    xmlNode *rsc_op = NULL;

    GListPtr gIter = NULL;
    GListPtr op_list = NULL;
    GListPtr sorted_op_list = NULL;

    /* extract operations */
    op_list = NULL;
    sorted_op_list = NULL;

    for (rsc_op = __xml_first_child(rsc_entry); rsc_op != NULL; rsc_op = __xml_next(rsc_op)) {
        if (crm_str_eq((const char *)rsc_op->name, XML_LRM_TAG_RSC_OP, TRUE)) {
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

GListPtr
find_operations(const char *rsc, const char *node, gboolean active_filter,
                pe_working_set_t * data_set)
{
    GListPtr output = NULL;
    GListPtr intermediate = NULL;

    xmlNode *tmp = NULL;
    xmlNode *status = find_xml_node(data_set->input, XML_CIB_TAG_STATUS, TRUE);

    node_t *this_node = NULL;

    xmlNode *node_state = NULL;

    for (node_state = __xml_first_child(status); node_state != NULL;
         node_state = __xml_next(node_state)) {

        if (crm_str_eq((const char *)node_state->name, XML_CIB_TAG_STATE, TRUE)) {
            const char *uname = crm_element_value(node_state, XML_ATTR_UNAME);

            if (node != NULL && safe_str_neq(uname, node)) {
                continue;
            }

            this_node = pe_find_node(data_set->nodes, uname);
            CRM_CHECK(this_node != NULL, continue);

            if (this_node->details->remote_rsc) {
                determine_remote_online_status(this_node);
            } else {
                determine_online_status(node_state, this_node, data_set);
            }

            if (this_node->details->online || is_set(data_set->flags, pe_flag_stonith_enabled)) {
                /* offline nodes run no resources...
                 * unless stonith is enabled in which case we need to
                 *   make sure rsc start events happen after the stonith
                 */
                xmlNode *lrm_rsc = NULL;

                tmp = find_xml_node(node_state, XML_CIB_TAG_LRM, FALSE);
                tmp = find_xml_node(tmp, XML_LRM_TAG_RESOURCES, FALSE);

                for (lrm_rsc = __xml_first_child(tmp); lrm_rsc != NULL;
                     lrm_rsc = __xml_next(lrm_rsc)) {
                    if (crm_str_eq((const char *)lrm_rsc->name, XML_LRM_TAG_RESOURCE, TRUE)) {

                        const char *rsc_id = crm_element_value(lrm_rsc, XML_ATTR_ID);

                        if (rsc != NULL && safe_str_neq(rsc_id, rsc)) {
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
