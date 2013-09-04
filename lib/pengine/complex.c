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

#include <crm/pengine/rules.h>
#include <crm/pengine/internal.h>
#include <crm/msg_xml.h>

void populate_hash(xmlNode * nvpair_list, GHashTable * hash, const char **attrs, int attrs_length);

resource_object_functions_t resource_class_functions[] = {
    {
     native_unpack,
     native_find_rsc,
     native_parameter,
     native_print,
     native_active,
     native_resource_state,
     native_location,
     native_free},
    {
     group_unpack,
     native_find_rsc,
     native_parameter,
     group_print,
     group_active,
     group_resource_state,
     native_location,
     group_free},
    {
     clone_unpack,
     native_find_rsc,
     native_parameter,
     clone_print,
     clone_active,
     clone_resource_state,
     native_location,
     clone_free},
    {
     master_unpack,
     native_find_rsc,
     native_parameter,
     clone_print,
     clone_active,
     clone_resource_state,
     native_location,
     clone_free}
};

enum pe_obj_types
get_resource_type(const char *name)
{
    if (safe_str_eq(name, XML_CIB_TAG_RESOURCE)) {
        return pe_native;

    } else if (safe_str_eq(name, XML_CIB_TAG_GROUP)) {
        return pe_group;

    } else if (safe_str_eq(name, XML_CIB_TAG_INCARNATION)) {
        return pe_clone;

    } else if (safe_str_eq(name, XML_CIB_TAG_MASTER)) {
        return pe_master;
    }

    return pe_unknown;
}

const char *
get_resource_typename(enum pe_obj_types type)
{
    switch (type) {
        case pe_native:
            return XML_CIB_TAG_RESOURCE;
        case pe_group:
            return XML_CIB_TAG_GROUP;
        case pe_clone:
            return XML_CIB_TAG_INCARNATION;
        case pe_master:
            return XML_CIB_TAG_MASTER;
        case pe_unknown:
            return "unknown";
    }
    return "<unknown>";
}

static void
dup_attr(gpointer key, gpointer value, gpointer user_data)
{
    add_hash_param(user_data, key, value);
}

void
get_meta_attributes(GHashTable * meta_hash, resource_t * rsc,
                    node_t * node, pe_working_set_t * data_set)
{
    GHashTable *node_hash = NULL;

    if (node) {
        node_hash = node->details->attrs;
    }

    if (rsc->xml) {
        xmlAttrPtr xIter = NULL;

        for (xIter = rsc->xml->properties; xIter; xIter = xIter->next) {
            const char *prop_name = (const char *)xIter->name;
            const char *prop_value = crm_element_value(rsc->xml, prop_name);

            add_hash_param(meta_hash, prop_name, prop_value);
        }
    }

    unpack_instance_attributes(data_set->input, rsc->xml, XML_TAG_META_SETS, node_hash,
                               meta_hash, NULL, FALSE, data_set->now);

    /* populate from the regular attributes until the GUI can create
     * meta attributes
     */
    unpack_instance_attributes(data_set->input, rsc->xml, XML_TAG_ATTR_SETS, node_hash,
                               meta_hash, NULL, FALSE, data_set->now);

    /* set anything else based on the parent */
    if (rsc->parent != NULL) {
        g_hash_table_foreach(rsc->parent->meta, dup_attr, meta_hash);
    }

    /* and finally check the defaults */
    unpack_instance_attributes(data_set->input, data_set->rsc_defaults, XML_TAG_META_SETS,
                               node_hash, meta_hash, NULL, FALSE, data_set->now);
}

void
get_rsc_attributes(GHashTable * meta_hash, resource_t * rsc,
                   node_t * node, pe_working_set_t * data_set)
{
    GHashTable *node_hash = NULL;

    if (node) {
        node_hash = node->details->attrs;
    }

    unpack_instance_attributes(data_set->input, rsc->xml, XML_TAG_ATTR_SETS, node_hash,
                               meta_hash, NULL, FALSE, data_set->now);

    /* set anything else based on the parent */
    if (rsc->parent != NULL) {
        get_rsc_attributes(meta_hash, rsc->parent, node, data_set);

    } else {
        /* and finally check the defaults */
        unpack_instance_attributes(data_set->input, data_set->rsc_defaults, XML_TAG_ATTR_SETS,
                                   node_hash, meta_hash, NULL, FALSE, data_set->now);
    }
}

static char *
template_op_key(xmlNode * op)
{
    const char *name = crm_element_value(op, "name");
    const char *role = crm_element_value(op, "role");
    char *key = NULL;

    if (role == NULL || crm_str_eq(role, RSC_ROLE_STARTED_S, TRUE)
        || crm_str_eq(role, RSC_ROLE_SLAVE_S, TRUE)) {
        role = RSC_ROLE_UNKNOWN_S;
    }

    key = crm_concat(name, role, '-');
    return key;
}

static gboolean
unpack_template(xmlNode * xml_obj, xmlNode ** expanded_xml, pe_working_set_t * data_set)
{
    xmlNode *cib_resources = NULL;
    xmlNode *template = NULL;
    xmlNode *new_xml = NULL;
    xmlNode *child_xml = NULL;
    xmlNode *rsc_ops = NULL;
    xmlNode *template_ops = NULL;
    const char *template_ref = NULL;
    const char *id = NULL;

    if (xml_obj == NULL) {
        pe_err("No resource object for template unpacking");
        return FALSE;
    }

    template_ref = crm_element_value(xml_obj, XML_CIB_TAG_RSC_TEMPLATE);
    if (template_ref == NULL) {
        return TRUE;
    }

    id = ID(xml_obj);
    if (id == NULL) {
        pe_err("'%s' object must have a id", crm_element_name(xml_obj));
        return FALSE;
    }

    if (crm_str_eq(template_ref, id, TRUE)) {
        pe_err("The resource object '%s' should not reference itself", id);
        return FALSE;
    }

    cib_resources = get_xpath_object("//"XML_CIB_TAG_RESOURCES, data_set->input, LOG_TRACE);
    if (cib_resources == NULL) {
        pe_err("No resources configured");
        return FALSE;
    }

    template = find_entity(cib_resources, XML_CIB_TAG_RSC_TEMPLATE, template_ref);
    if (template == NULL) {
        pe_err("No template named '%s'", template_ref);
        return FALSE;
    }

    new_xml = copy_xml(template);
    xmlNodeSetName(new_xml, xml_obj->name);
    crm_xml_replace(new_xml, XML_ATTR_ID, id);
    template_ops = find_xml_node(new_xml, "operations", FALSE);

    for (child_xml = __xml_first_child(xml_obj); child_xml != NULL;
         child_xml = __xml_next(child_xml)) {
        xmlNode *new_child = NULL;

        new_child = add_node_copy(new_xml, child_xml);

        if (crm_str_eq((const char *)new_child->name, "operations", TRUE)) {
            rsc_ops = new_child;
        }
    }

    if (template_ops && rsc_ops) {
        xmlNode *op = NULL;
        GHashTable *rsc_ops_hash =
            g_hash_table_new_full(crm_str_hash, g_str_equal, g_hash_destroy_str, NULL);

        for (op = __xml_first_child(rsc_ops); op != NULL; op = __xml_next(op)) {
            char *key = template_op_key(op);

            g_hash_table_insert(rsc_ops_hash, key, op);
        }

        for (op = __xml_first_child(template_ops); op != NULL; op = __xml_next(op)) {
            char *key = template_op_key(op);

            if (g_hash_table_lookup(rsc_ops_hash, key) == NULL) {
                add_node_copy(rsc_ops, op);
            }

            free(key);
        }

        if (rsc_ops_hash) {
            g_hash_table_destroy(rsc_ops_hash);
        }

        free_xml(template_ops);
    }

    /*free_xml(*expanded_xml); */
    *expanded_xml = new_xml;

    /* Disable multi-level templates for now */
    /*if(unpack_template(new_xml, expanded_xml, data_set) == FALSE) {
       free_xml(*expanded_xml);
       *expanded_xml = NULL;

       return FALSE;
       } */

    return TRUE;
}

static gboolean
add_template_rsc(xmlNode * xml_obj, pe_working_set_t * data_set)
{
    const char *template_ref = NULL;
    const char *id = NULL;
    xmlNode *rsc_set = NULL;
    xmlNode *rsc_ref = NULL;

    if (xml_obj == NULL) {
        pe_err("No resource object for processing resource list of template");
        return FALSE;
    }

    template_ref = crm_element_value(xml_obj, XML_CIB_TAG_RSC_TEMPLATE);
    if (template_ref == NULL) {
        return TRUE;
    }

    id = ID(xml_obj);
    if (id == NULL) {
        pe_err("'%s' object must have a id", crm_element_name(xml_obj));
        return FALSE;
    }

    if (crm_str_eq(template_ref, id, TRUE)) {
        pe_err("The resource object '%s' should not reference itself", id);
        return FALSE;
    }

    rsc_set = g_hash_table_lookup(data_set->template_rsc_sets, template_ref);
    if (rsc_set == NULL) {
        rsc_set = create_xml_node(NULL, XML_CONS_TAG_RSC_SET);
        crm_xml_add(rsc_set, XML_ATTR_ID, template_ref);

        g_hash_table_insert(data_set->template_rsc_sets, strdup(template_ref), rsc_set);
    }

    rsc_ref = create_xml_node(rsc_set, XML_TAG_RESOURCE_REF);
    crm_xml_add(rsc_ref, XML_ATTR_ID, id);

    return TRUE;
}

gboolean
common_unpack(xmlNode * xml_obj, resource_t ** rsc,
              resource_t * parent, pe_working_set_t * data_set)
{
    xmlNode *expanded_xml = NULL;
    xmlNode *ops = NULL;
    resource_t *top = NULL;
    const char *value = NULL;
    const char *id = crm_element_value(xml_obj, XML_ATTR_ID);
    const char *class = crm_element_value(xml_obj, XML_AGENT_ATTR_CLASS);

    crm_log_xml_trace(xml_obj, "Processing resource input...");

    if (id == NULL) {
        pe_err("Must specify id tag in <resource>");
        return FALSE;

    } else if (rsc == NULL) {
        pe_err("Nowhere to unpack resource into");
        return FALSE;

    }

    if (unpack_template(xml_obj, &expanded_xml, data_set) == FALSE) {
        return FALSE;
    }

    *rsc = calloc(1, sizeof(resource_t));

    if (expanded_xml) {
        crm_log_xml_trace(expanded_xml, "Expanded resource...");
        (*rsc)->xml = expanded_xml;
        (*rsc)->orig_xml = xml_obj;

    } else {
        (*rsc)->xml = xml_obj;
        (*rsc)->orig_xml = NULL;
    }

    (*rsc)->parent = parent;

    ops = find_xml_node((*rsc)->xml, "operations", FALSE);
    (*rsc)->ops_xml = expand_idref(ops, data_set->input);

    (*rsc)->variant = get_resource_type(crm_element_name(xml_obj));
    if ((*rsc)->variant == pe_unknown) {
        pe_err("Unknown resource type: %s", crm_element_name(xml_obj));
        free(*rsc);
        return FALSE;
    }

    (*rsc)->parameters =
        g_hash_table_new_full(crm_str_hash, g_str_equal, g_hash_destroy_str, g_hash_destroy_str);

    (*rsc)->meta =
        g_hash_table_new_full(crm_str_hash, g_str_equal, g_hash_destroy_str, g_hash_destroy_str);

    (*rsc)->allowed_nodes =
        g_hash_table_new_full(crm_str_hash, g_str_equal, NULL, g_hash_destroy_str);

    (*rsc)->known_on = g_hash_table_new_full(crm_str_hash, g_str_equal, NULL, g_hash_destroy_str);

    value = crm_element_value(xml_obj, XML_RSC_ATTR_INCARNATION);
    if (value) {
        (*rsc)->id = crm_concat(id, value, ':');
        add_hash_param((*rsc)->meta, XML_RSC_ATTR_INCARNATION, value);

    } else {
        (*rsc)->id = strdup(id);
    }

    (*rsc)->fns = &resource_class_functions[(*rsc)->variant];
    pe_rsc_trace((*rsc), "Unpacking resource...");

    get_meta_attributes((*rsc)->meta, *rsc, NULL, data_set);

    (*rsc)->flags = 0;
    set_bit((*rsc)->flags, pe_rsc_runnable);
    set_bit((*rsc)->flags, pe_rsc_provisional);

    if (is_set(data_set->flags, pe_flag_is_managed_default)) {
        set_bit((*rsc)->flags, pe_rsc_managed);
    }

    (*rsc)->rsc_cons = NULL;
    (*rsc)->rsc_tickets = NULL;
    (*rsc)->actions = NULL;
    (*rsc)->role = RSC_ROLE_STOPPED;
    (*rsc)->next_role = RSC_ROLE_UNKNOWN;

    (*rsc)->recovery_type = recovery_stop_start;
    (*rsc)->stickiness = data_set->default_resource_stickiness;
    (*rsc)->migration_threshold = INFINITY;
    (*rsc)->failure_timeout = 0;

    value = g_hash_table_lookup((*rsc)->meta, XML_CIB_ATTR_PRIORITY);
    (*rsc)->priority = crm_parse_int(value, "0");
    (*rsc)->effective_priority = (*rsc)->priority;

    value = g_hash_table_lookup((*rsc)->meta, XML_RSC_ATTR_NOTIFY);
    if (crm_is_true(value)) {
        set_bit((*rsc)->flags, pe_rsc_notify);
    }

    value = g_hash_table_lookup((*rsc)->meta, XML_RSC_ATTR_MANAGED);
    if (value != NULL && safe_str_neq("default", value)) {
        gboolean bool_value = TRUE;

        crm_str_to_boolean(value, &bool_value);
        if (bool_value == FALSE) {
            clear_bit((*rsc)->flags, pe_rsc_managed);
        } else {
            set_bit((*rsc)->flags, pe_rsc_managed);
        }
    }

    if (is_set(data_set->flags, pe_flag_maintenance_mode)) {
        clear_bit((*rsc)->flags, pe_rsc_managed);
    }

    pe_rsc_trace((*rsc), "Options for %s", (*rsc)->id);
    value = g_hash_table_lookup((*rsc)->meta, XML_RSC_ATTR_UNIQUE);

    top = uber_parent(*rsc);
    if (crm_is_true(value) || top->variant < pe_clone) {
        set_bit((*rsc)->flags, pe_rsc_unique);
    }

    value = g_hash_table_lookup((*rsc)->meta, XML_RSC_ATTR_RESTART);
    if (safe_str_eq(value, "restart")) {
        (*rsc)->restart_type = pe_restart_restart;
        pe_rsc_trace((*rsc), "\tDependency restart handling: restart");

    } else {
        (*rsc)->restart_type = pe_restart_ignore;
        pe_rsc_trace((*rsc), "\tDependency restart handling: ignore");
    }

    value = g_hash_table_lookup((*rsc)->meta, XML_RSC_ATTR_MULTIPLE);
    if (safe_str_eq(value, "stop_only")) {
        (*rsc)->recovery_type = recovery_stop_only;
        pe_rsc_trace((*rsc), "\tMultiple running resource recovery: stop only");

    } else if (safe_str_eq(value, "block")) {
        (*rsc)->recovery_type = recovery_block;
        pe_rsc_trace((*rsc), "\tMultiple running resource recovery: block");

    } else {
        (*rsc)->recovery_type = recovery_stop_start;
        pe_rsc_trace((*rsc), "\tMultiple running resource recovery: stop/start");
    }

    value = g_hash_table_lookup((*rsc)->meta, XML_RSC_ATTR_STICKINESS);
    if (value != NULL && safe_str_neq("default", value)) {
        (*rsc)->stickiness = char2score(value);
    }

    value = g_hash_table_lookup((*rsc)->meta, XML_RSC_ATTR_FAIL_STICKINESS);
    if (value != NULL && safe_str_neq("default", value)) {
        (*rsc)->migration_threshold = char2score(value);

    } else if (value == NULL) {
        /* Make a best-effort guess at a migration threshold for people with 0.6 configs
         * try with underscores and hyphens, from both the resource and global defaults section
         */

        value = g_hash_table_lookup((*rsc)->meta, "resource-failure-stickiness");
        if (value == NULL) {
            value = g_hash_table_lookup((*rsc)->meta, "resource_failure_stickiness");
        }
        if (value == NULL) {
            value =
                g_hash_table_lookup(data_set->config_hash, "default-resource-failure-stickiness");
        }
        if (value == NULL) {
            value =
                g_hash_table_lookup(data_set->config_hash, "default_resource_failure_stickiness");
        }

        if (value) {
            int fail_sticky = char2score(value);

            if (fail_sticky == -INFINITY) {
                (*rsc)->migration_threshold = 1;
                pe_rsc_info((*rsc),
                            "Set a migration threshold of %d for %s based on a failure-stickiness of %s",
                            (*rsc)->migration_threshold, (*rsc)->id, value);

            } else if ((*rsc)->stickiness != 0 && fail_sticky != 0) {
                (*rsc)->migration_threshold = (*rsc)->stickiness / fail_sticky;
                if ((*rsc)->migration_threshold < 0) {
                    /* Make sure it's positive */
                    (*rsc)->migration_threshold = 0 - (*rsc)->migration_threshold;
                }
                (*rsc)->migration_threshold += 1;
                pe_rsc_info((*rsc),
                            "Calculated a migration threshold for %s of %d based on a stickiness of %d/%s",
                            (*rsc)->id, (*rsc)->migration_threshold, (*rsc)->stickiness, value);
            }
        }
    }

    value = g_hash_table_lookup((*rsc)->meta, XML_RSC_ATTR_REQUIRES);
    if (safe_str_eq(value, "nothing")) {

    } else if (safe_str_eq(value, "quorum")) {
        set_bit((*rsc)->flags, pe_rsc_needs_quorum);

    } else if (safe_str_eq(value, "unfencing")) {
        set_bit((*rsc)->flags, pe_rsc_needs_fencing);
        set_bit((*rsc)->flags, pe_rsc_needs_unfencing);
        if (is_set(data_set->flags, pe_flag_stonith_enabled)) {
            crm_notice("%s requires (un)fencing but fencing is disabled", (*rsc)->id);
        }

    } else if (safe_str_eq(value, "fencing")) {
        set_bit((*rsc)->flags, pe_rsc_needs_fencing);
        if (is_set(data_set->flags, pe_flag_stonith_enabled)) {
            crm_notice("%s requires fencing but fencing is disabled", (*rsc)->id);
        }

    } else {
        if (value) {
            crm_config_err("Invalid value for %s->requires: %s%s",
                           (*rsc)->id, value,
                           is_set(data_set->flags,
                                  pe_flag_stonith_enabled) ? "" : " (stonith-enabled=false)");
        }

        if (is_set(data_set->flags, pe_flag_stonith_enabled)) {
            set_bit((*rsc)->flags, pe_rsc_needs_fencing);
            value = "fencing (default)";

        } else if (data_set->no_quorum_policy == no_quorum_ignore) {
            value = "nothing (default)";

        } else {
            set_bit((*rsc)->flags, pe_rsc_needs_quorum);
            value = "quorum (default)";
        }
    }

    pe_rsc_trace((*rsc), "\tRequired to start: %s", value);

    value = g_hash_table_lookup((*rsc)->meta, XML_RSC_ATTR_FAIL_TIMEOUT);
    if (value != NULL) {
        /* call crm_get_msec() and convert back to seconds */
        (*rsc)->failure_timeout = (crm_get_msec(value) / 1000);
    }

    get_target_role(*rsc, &((*rsc)->next_role));
    pe_rsc_trace((*rsc), "\tDesired next state: %s",
                 (*rsc)->next_role != RSC_ROLE_UNKNOWN ? role2text((*rsc)->next_role) : "default");

    if ((*rsc)->fns->unpack(*rsc, data_set) == FALSE) {
        return FALSE;
    }

    if (is_set(data_set->flags, pe_flag_symmetric_cluster)) {
        resource_location(*rsc, NULL, 0, "symmetric_default", data_set);
    } else if (xml_contains_remote_node(xml_obj) && g_hash_table_lookup((*rsc)->meta, XML_RSC_ATTR_CONTAINER)) {
        /* remote resources tied to a container resource must always be allowed
         * to opt-in to the cluster. Whether the connection resource is actually
         * allowed to be placed on a node is dependent on the container resource */
        resource_location(*rsc, NULL, 0, "remote_connection_default", data_set);
    }

    pe_rsc_trace((*rsc), "\tAction notification: %s",
                 is_set((*rsc)->flags, pe_rsc_notify) ? "required" : "not required");

    if (safe_str_eq(class, "stonith")) {
        set_bit(data_set->flags, pe_flag_have_stonith_resource);
    }

    (*rsc)->utilization =
        g_hash_table_new_full(crm_str_hash, g_str_equal, g_hash_destroy_str, g_hash_destroy_str);

    unpack_instance_attributes(data_set->input, (*rsc)->xml, XML_TAG_UTILIZATION, NULL,
                               (*rsc)->utilization, NULL, FALSE, data_set->now);

/* 	data_set->resources = g_list_append(data_set->resources, (*rsc)); */

    if (expanded_xml) {
        if (add_template_rsc(xml_obj, data_set) == FALSE) {
            return FALSE;
        }
    }
    return TRUE;
}

void
common_update_score(resource_t * rsc, const char *id, int score)
{
    node_t *node = NULL;

    node = pe_hash_table_lookup(rsc->allowed_nodes, id);
    if (node != NULL) {
        pe_rsc_trace(rsc, "Updating score for %s on %s: %d + %d", rsc->id, id, node->weight, score);
        node->weight = merge_weights(node->weight, score);
    }

    if (rsc->children) {
        GListPtr gIter = rsc->children;

        for (; gIter != NULL; gIter = gIter->next) {
            resource_t *child_rsc = (resource_t *) gIter->data;

            common_update_score(child_rsc, id, score);
        }
    }
}

resource_t *
uber_parent(resource_t * rsc)
{
    resource_t *parent = rsc;

    if (parent == NULL) {
        return NULL;
    }
    while (parent->parent != NULL) {
        parent = parent->parent;
    }
    return parent;
}

void
common_free(resource_t * rsc)
{
    if (rsc == NULL) {
        return;
    }

    pe_rsc_trace(rsc, "Freeing %s %d", rsc->id, rsc->variant);

    g_list_free(rsc->rsc_cons);
    g_list_free(rsc->rsc_cons_lhs);
    g_list_free(rsc->rsc_tickets);
    g_list_free(rsc->dangling_migrations);

    if (rsc->parameters != NULL) {
        g_hash_table_destroy(rsc->parameters);
    }
    if (rsc->meta != NULL) {
        g_hash_table_destroy(rsc->meta);
    }
    if (rsc->utilization != NULL) {
        g_hash_table_destroy(rsc->utilization);
    }

    if (rsc->parent == NULL && is_set(rsc->flags, pe_rsc_orphan)) {
        free_xml(rsc->xml);
        rsc->xml = NULL;
        free_xml(rsc->orig_xml);
        rsc->orig_xml = NULL;

        /* if rsc->orig_xml, then rsc->xml is an expanded xml from a template */
    } else if (rsc->orig_xml) {
        free_xml(rsc->xml);
        rsc->xml = NULL;
    }
    if (rsc->running_on) {
        g_list_free(rsc->running_on);
        rsc->running_on = NULL;
    }
    if (rsc->known_on) {
        g_hash_table_destroy(rsc->known_on);
        rsc->known_on = NULL;
    }
    if (rsc->actions) {
        g_list_free(rsc->actions);
        rsc->actions = NULL;
    }
    if (rsc->allowed_nodes) {
        g_hash_table_destroy(rsc->allowed_nodes);
        rsc->allowed_nodes = NULL;
    }
    g_list_free(rsc->fillers);
    g_list_free(rsc->rsc_location);
    pe_rsc_trace(rsc, "Resource freed");
    free(rsc->id);
    free(rsc->clone_name);
    free(rsc->allocated_to);
    free(rsc->variant_opaque);
    free(rsc);
}
