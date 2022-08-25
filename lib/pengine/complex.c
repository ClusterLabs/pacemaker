/*
 * Copyright 2004-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/pengine/rules.h>
#include <crm/pengine/internal.h>
#include <crm/msg_xml.h>
#include <crm/common/xml_internal.h>

#include "pe_status_private.h"

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
         native_free,
         pe__count_common,
         pe__native_is_filtered,
    },
    {
         group_unpack,
         native_find_rsc,
         native_parameter,
         group_print,
         group_active,
         group_resource_state,
         native_location,
         group_free,
         pe__count_common,
         pe__group_is_filtered,
    },
    {
         clone_unpack,
         native_find_rsc,
         native_parameter,
         clone_print,
         clone_active,
         clone_resource_state,
         native_location,
         clone_free,
         pe__count_common,
         pe__clone_is_filtered,
    },
    {
         pe__unpack_bundle,
         native_find_rsc,
         native_parameter,
         pe__print_bundle,
         pe__bundle_active,
         pe__bundle_resource_state,
         native_location,
         pe__free_bundle,
         pe__count_bundle,
         pe__bundle_is_filtered,
    }
};

static enum pe_obj_types
get_resource_type(const char *name)
{
    if (pcmk__str_eq(name, XML_CIB_TAG_RESOURCE, pcmk__str_casei)) {
        return pe_native;

    } else if (pcmk__str_eq(name, XML_CIB_TAG_GROUP, pcmk__str_casei)) {
        return pe_group;

    } else if (pcmk__str_eq(name, XML_CIB_TAG_INCARNATION, pcmk__str_casei)) {
        return pe_clone;

    } else if (pcmk__str_eq(name, PCMK_XE_PROMOTABLE_LEGACY, pcmk__str_casei)) {
        // @COMPAT deprecated since 2.0.0
        return pe_clone;

    } else if (pcmk__str_eq(name, XML_CIB_TAG_CONTAINER, pcmk__str_casei)) {
        return pe_container;
    }

    return pe_unknown;
}

static void
dup_attr(gpointer key, gpointer value, gpointer user_data)
{
    add_hash_param(user_data, key, value);
}

static void
expand_parents_fixed_nvpairs(pe_resource_t * rsc, pe_rule_eval_data_t * rule_data, GHashTable * meta_hash, pe_working_set_t * data_set)
{
    GHashTable *parent_orig_meta = pcmk__strkey_table(free, free);
    pe_resource_t *p = rsc->parent;

    if (p == NULL) {
        return ;
    }

    /* Search all parent resources, get the fixed value of "meta_attributes" set only in the original xml, and stack it in the hash table. */
    /* The fixed value of the lower parent resource takes precedence and is not overwritten. */
    while(p != NULL) {
        /* A hash table for comparison is generated, including the id-ref. */
        pe__unpack_dataset_nvpairs(p->xml, XML_TAG_META_SETS,
                               rule_data, parent_orig_meta, NULL, FALSE, data_set);
        p = p->parent; 
    }

    /* If there is a fixed value of "meta_attributes" of the parent resource, it will be processed. */
    if (parent_orig_meta != NULL) {
        GHashTableIter iter;
        char *key = NULL;
        char *value = NULL;

        g_hash_table_iter_init(&iter, parent_orig_meta);
        while (g_hash_table_iter_next(&iter, (gpointer *) &key, (gpointer *) &value)) {
            /* Parameters set in the original xml of the parent resource will also try to overwrite the child resource. */
            /* Attributes that already exist in the child lease are not updated. */
            dup_attr(key, value, meta_hash);
        }
    }

    if (parent_orig_meta != NULL) {
        g_hash_table_destroy(parent_orig_meta);
    }
    
    return ;

}
void
get_meta_attributes(GHashTable * meta_hash, pe_resource_t * rsc,
                    pe_node_t * node, pe_working_set_t * data_set)
{
    pe_rsc_eval_data_t rsc_rule_data = {
        .standard = crm_element_value(rsc->xml, XML_AGENT_ATTR_CLASS),
        .provider = crm_element_value(rsc->xml, XML_AGENT_ATTR_PROVIDER),
        .agent = crm_element_value(rsc->xml, XML_EXPR_ATTR_TYPE)
    };

    pe_rule_eval_data_t rule_data = {
        .node_hash = NULL,
        .role = RSC_ROLE_UNKNOWN,
        .now = data_set->now,
        .match_data = NULL,
        .rsc_data = &rsc_rule_data,
        .op_data = NULL
    };

    if (node) {
        rule_data.node_hash = node->details->attrs;
    }

    for (xmlAttrPtr a = pcmk__xe_first_attr(rsc->xml); a != NULL; a = a->next) {
        const char *prop_name = (const char *) a->name;
        const char *prop_value = crm_element_value(rsc->xml, prop_name);

        add_hash_param(meta_hash, prop_name, prop_value);
    }

    pe__unpack_dataset_nvpairs(rsc->xml, XML_TAG_META_SETS, &rule_data,
                               meta_hash, NULL, FALSE, data_set);

    /* Set the "meta_attributes" explicitly set in the parent resource to the hash table of the child resource. */
    /* If it is already explicitly set as a child, it will not be overwritten. */
    if (rsc->parent != NULL) {
        expand_parents_fixed_nvpairs(rsc, &rule_data, meta_hash, data_set);
    }

    /* check the defaults */
    pe__unpack_dataset_nvpairs(data_set->rsc_defaults, XML_TAG_META_SETS,
                               &rule_data, meta_hash, NULL, FALSE, data_set);

    /* If there is "meta_attributes" that the parent resource has not explicitly set, set a value that is not set from rsc_default either. */
    /* The values already set up to this point will not be overwritten. */
    if (rsc->parent) {
        g_hash_table_foreach(rsc->parent->meta, dup_attr, meta_hash);
    }
}

void
get_rsc_attributes(GHashTable *meta_hash, const pe_resource_t *rsc,
                   const pe_node_t *node, pe_working_set_t *data_set)
{
    pe_rule_eval_data_t rule_data = {
        .node_hash = NULL,
        .role = RSC_ROLE_UNKNOWN,
        .now = data_set->now,
        .match_data = NULL,
        .rsc_data = NULL,
        .op_data = NULL
    };

    if (node) {
        rule_data.node_hash = node->details->attrs;
    }

    pe__unpack_dataset_nvpairs(rsc->xml, XML_TAG_ATTR_SETS, &rule_data,
                               meta_hash, NULL, FALSE, data_set);

    /* set anything else based on the parent */
    if (rsc->parent != NULL) {
        get_rsc_attributes(meta_hash, rsc->parent, node, data_set);

    } else {
        /* and finally check the defaults */
        pe__unpack_dataset_nvpairs(data_set->rsc_defaults, XML_TAG_ATTR_SETS,
                                   &rule_data, meta_hash, NULL, FALSE, data_set);
    }
}

#if ENABLE_VERSIONED_ATTRS
void
pe_get_versioned_attributes(xmlNode * meta_hash, pe_resource_t * rsc,
                            pe_node_t * node, pe_working_set_t * data_set)
{
    pe_rule_eval_data_t rule_data = {
        .node_hash = (node == NULL)? NULL : node->details->attrs,
        .role = RSC_ROLE_UNKNOWN,
        .now = data_set->now,
        .match_data = NULL,
        .rsc_data = NULL,
        .op_data = NULL
    };

    pe_eval_versioned_attributes(data_set->input, rsc->xml, XML_TAG_ATTR_SETS,
                                 &rule_data, meta_hash, NULL);

    /* set anything else based on the parent */
    if (rsc->parent != NULL) {
        pe_get_versioned_attributes(meta_hash, rsc->parent, node, data_set);

    } else {
        /* and finally check the defaults */
        pe_eval_versioned_attributes(data_set->input, data_set->rsc_defaults,
                                     XML_TAG_ATTR_SETS, &rule_data, meta_hash,
                                     NULL);
    }
}
#endif

static char *
template_op_key(xmlNode * op)
{
    const char *name = crm_element_value(op, "name");
    const char *role = crm_element_value(op, "role");
    char *key = NULL;

    if ((role == NULL)
        || pcmk__strcase_any_of(role, RSC_ROLE_STARTED_S, RSC_ROLE_UNPROMOTED_S,
                                RSC_ROLE_UNPROMOTED_LEGACY_S, NULL)) {
        role = RSC_ROLE_UNKNOWN_S;
    }

    key = crm_strdup_printf("%s-%s", name, role);
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
    const char *clone = NULL;
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

    if (pcmk__str_eq(template_ref, id, pcmk__str_none)) {
        pe_err("The resource object '%s' should not reference itself", id);
        return FALSE;
    }

    cib_resources = get_xpath_object("//"XML_CIB_TAG_RESOURCES, data_set->input, LOG_TRACE);
    if (cib_resources == NULL) {
        pe_err("No resources configured");
        return FALSE;
    }

    template = pcmk__xe_match(cib_resources, XML_CIB_TAG_RSC_TEMPLATE,
                              XML_ATTR_ID, template_ref);
    if (template == NULL) {
        pe_err("No template named '%s'", template_ref);
        return FALSE;
    }

    new_xml = copy_xml(template);
    xmlNodeSetName(new_xml, xml_obj->name);
    crm_xml_replace(new_xml, XML_ATTR_ID, id);

    clone = crm_element_value(xml_obj, XML_RSC_ATTR_INCARNATION);
    if(clone) {
        crm_xml_add(new_xml, XML_RSC_ATTR_INCARNATION, clone);
    }

    template_ops = find_xml_node(new_xml, "operations", FALSE);

    for (child_xml = pcmk__xe_first_child(xml_obj); child_xml != NULL;
         child_xml = pcmk__xe_next(child_xml)) {
        xmlNode *new_child = NULL;

        new_child = add_node_copy(new_xml, child_xml);

        if (pcmk__str_eq((const char *)new_child->name, "operations", pcmk__str_none)) {
            rsc_ops = new_child;
        }
    }

    if (template_ops && rsc_ops) {
        xmlNode *op = NULL;
        GHashTable *rsc_ops_hash = pcmk__strkey_table(free, NULL);

        for (op = pcmk__xe_first_child(rsc_ops); op != NULL;
             op = pcmk__xe_next(op)) {

            char *key = template_op_key(op);

            g_hash_table_insert(rsc_ops_hash, key, op);
        }

        for (op = pcmk__xe_first_child(template_ops); op != NULL;
             op = pcmk__xe_next(op)) {

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

    if (pcmk__str_eq(template_ref, id, pcmk__str_none)) {
        pe_err("The resource object '%s' should not reference itself", id);
        return FALSE;
    }

    if (add_tag_ref(data_set->template_rsc_sets, template_ref, id) == FALSE) {
        return FALSE;
    }

    return TRUE;
}

static bool
detect_promotable(pe_resource_t *rsc)
{
    const char *promotable = g_hash_table_lookup(rsc->meta,
                                                 XML_RSC_ATTR_PROMOTABLE);

    if (crm_is_true(promotable)) {
        return TRUE;
    }

    // @COMPAT deprecated since 2.0.0
    if (pcmk__str_eq(crm_element_name(rsc->xml), PCMK_XE_PROMOTABLE_LEGACY,
                     pcmk__str_casei)) {
        /* @TODO in some future version, pe_warn_once() here,
         *       then drop support in even later version
         */
        g_hash_table_insert(rsc->meta, strdup(XML_RSC_ATTR_PROMOTABLE),
                            strdup(XML_BOOLEAN_TRUE));
        return TRUE;
    }
    return FALSE;
}

static void
free_params_table(gpointer data)
{
    g_hash_table_destroy((GHashTable *) data);
}

/*!
 * \brief Get a table of resource parameters
 *
 * \param[in,out] rsc       Resource to query
 * \param[in]     node      Node for evaluating rules (NULL for defaults)
 * \param[in]     data_set  Cluster working set
 *
 * \return Hash table containing resource parameter names and values
 *         (or NULL if \p rsc or \p data_set is NULL)
 * \note The returned table will be destroyed when the resource is freed, so
 *       callers should not destroy it.
 */
GHashTable *
pe_rsc_params(pe_resource_t *rsc, const pe_node_t *node,
              pe_working_set_t *data_set)
{
    GHashTable *params_on_node = NULL;

    /* A NULL node is used to request the resource's default parameters
     * (not evaluated for node), but we always want something non-NULL
     * as a hash table key.
     */
    const char *node_name = "";

    // Sanity check
    if ((rsc == NULL) || (data_set == NULL)) {
        return NULL;
    }
    if ((node != NULL) && (node->details->uname != NULL)) {
        node_name = node->details->uname;
    }

    // Find the parameter table for given node
    if (rsc->parameter_cache == NULL) {
        rsc->parameter_cache = pcmk__strikey_table(free, free_params_table);
    } else {
        params_on_node = g_hash_table_lookup(rsc->parameter_cache, node_name);
    }

    // If none exists yet, create one with parameters evaluated for node
    if (params_on_node == NULL) {
        params_on_node = pcmk__strkey_table(free, free);
        get_rsc_attributes(params_on_node, rsc, node, data_set);
        g_hash_table_insert(rsc->parameter_cache, strdup(node_name),
                            params_on_node);
    }
    return params_on_node;
}

/*!
 * \internal
 * \brief Unpack a resource's "requires" meta-attribute
 *
 * \param[in] rsc         Resource being unpacked
 * \param[in] value       Value of "requires" meta-attribute
 * \param[in] is_default  Whether \p value was selected by default
 */
static void
unpack_requires(pe_resource_t *rsc, const char *value, bool is_default)
{
    if (pcmk__str_eq(value, PCMK__VALUE_NOTHING, pcmk__str_casei)) {

    } else if (pcmk__str_eq(value, PCMK__VALUE_QUORUM, pcmk__str_casei)) {
        pe__set_resource_flags(rsc, pe_rsc_needs_quorum);

    } else if (pcmk__str_eq(value, PCMK__VALUE_FENCING, pcmk__str_casei)) {
        pe__set_resource_flags(rsc, pe_rsc_needs_fencing);
        if (!pcmk_is_set(rsc->cluster->flags, pe_flag_stonith_enabled)) {
            pcmk__config_warn("%s requires fencing but fencing is disabled",
                              rsc->id);
        }

    } else if (pcmk__str_eq(value, PCMK__VALUE_UNFENCING, pcmk__str_casei)) {
        if (pcmk_is_set(rsc->flags, pe_rsc_fence_device)) {
            pcmk__config_warn("Resetting \"" XML_RSC_ATTR_REQUIRES "\" for %s "
                              "to \"" PCMK__VALUE_QUORUM "\" because fencing "
                              "devices cannot require unfencing", rsc->id);
            unpack_requires(rsc, PCMK__VALUE_QUORUM, true);
            return;

        } else if (!pcmk_is_set(rsc->cluster->flags, pe_flag_stonith_enabled)) {
            pcmk__config_warn("Resetting \"" XML_RSC_ATTR_REQUIRES "\" for %s "
                              "to \"" PCMK__VALUE_QUORUM "\" because fencing "
                              "is disabled", rsc->id);
            unpack_requires(rsc, PCMK__VALUE_QUORUM, true);
            return;

        } else {
            pe__set_resource_flags(rsc,
                                   pe_rsc_needs_fencing|pe_rsc_needs_unfencing);
        }

    } else {
        const char *orig_value = value;

        if (pcmk_is_set(rsc->flags, pe_rsc_fence_device)) {
            value = PCMK__VALUE_QUORUM;

        } else if ((rsc->variant == pe_native)
                   && xml_contains_remote_node(rsc->xml)) {
            value = PCMK__VALUE_QUORUM;

        } else if (pcmk_is_set(rsc->cluster->flags, pe_flag_enable_unfencing)) {
            value = PCMK__VALUE_UNFENCING;

        } else if (pcmk_is_set(rsc->cluster->flags, pe_flag_stonith_enabled)) {
            value = PCMK__VALUE_FENCING;

        } else if (rsc->cluster->no_quorum_policy == no_quorum_ignore) {
            value = PCMK__VALUE_NOTHING;

        } else {
            value = PCMK__VALUE_QUORUM;
        }

        if (orig_value != NULL) {
            pcmk__config_err("Resetting '" XML_RSC_ATTR_REQUIRES "' for %s "
                             "to '%s' because '%s' is not valid",
                              rsc->id, value, orig_value);
        }
        unpack_requires(rsc, value, true);
        return;
    }

    pe_rsc_trace(rsc, "\tRequired to start: %s%s", value,
                 (is_default? " (default)" : ""));
}

/*!
 * \internal
 * \brief Unpack configuration XML for a given resource
 *
 * Unpack the XML object containing a resource's configuration into a new
 * \c pe_resource_t object.
 *
 * \param[in]     xml_obj   XML node containing the resource's configuration
 * \param[out]    rsc       Where to store the unpacked resource information
 * \param[in]     parent    Resource's parent, if any
 * \param[in,out] data_set  Cluster working set
 *
 * \return Standard Pacemaker return code
 */
int
pe__unpack_resource(xmlNode *xml_obj, pe_resource_t **rsc,
                    pe_resource_t *parent, pe_working_set_t *data_set)
{
    xmlNode *expanded_xml = NULL;
    xmlNode *ops = NULL;
    const char *value = NULL;
    const char *rclass = NULL; /* Look for this after any templates have been expanded */
    const char *id = crm_element_value(xml_obj, XML_ATTR_ID);
    bool guest_node = false;
    bool remote_node = false;
    bool has_versioned_params = false;

    pe_rule_eval_data_t rule_data = {
        .node_hash = NULL,
        .role = RSC_ROLE_UNKNOWN,
        .now = data_set->now,
        .match_data = NULL,
        .rsc_data = NULL,
        .op_data = NULL
    };

    crm_log_xml_trace(xml_obj, "Processing resource input...");

    CRM_CHECK(rsc != NULL, return EINVAL);

    if (id == NULL) {
        pe_err("Must specify id tag in <resource>");
        return pcmk_rc_unpack_error;
    }

    if (unpack_template(xml_obj, &expanded_xml, data_set) == FALSE) {
        return pcmk_rc_unpack_error;
    }

    *rsc = calloc(1, sizeof(pe_resource_t));
    (*rsc)->cluster = data_set;

    if (expanded_xml) {
        crm_log_xml_trace(expanded_xml, "Expanded resource...");
        (*rsc)->xml = expanded_xml;
        (*rsc)->orig_xml = xml_obj;

    } else {
        (*rsc)->xml = xml_obj;
        (*rsc)->orig_xml = NULL;
    }

    /* Do not use xml_obj from here on, use (*rsc)->xml in case templates are involved */
    rclass = crm_element_value((*rsc)->xml, XML_AGENT_ATTR_CLASS);
    (*rsc)->parent = parent;

    ops = find_xml_node((*rsc)->xml, "operations", FALSE);
    (*rsc)->ops_xml = expand_idref(ops, data_set->input);

    (*rsc)->variant = get_resource_type(crm_element_name((*rsc)->xml));
    if ((*rsc)->variant == pe_unknown) {
        pe_err("Unknown resource type: %s", crm_element_name((*rsc)->xml));
        free(*rsc);
        return pcmk_rc_unpack_error;
    }

#if ENABLE_VERSIONED_ATTRS
    (*rsc)->versioned_parameters = create_xml_node(NULL, XML_TAG_RSC_VER_ATTRS);
#endif

    (*rsc)->meta = pcmk__strkey_table(free, free);
    (*rsc)->allowed_nodes = pcmk__strkey_table(NULL, free);
    (*rsc)->known_on = pcmk__strkey_table(NULL, free);

    value = crm_element_value((*rsc)->xml, XML_RSC_ATTR_INCARNATION);
    if (value) {
        (*rsc)->id = crm_strdup_printf("%s:%s", id, value);
        add_hash_param((*rsc)->meta, XML_RSC_ATTR_INCARNATION, value);

    } else {
        (*rsc)->id = strdup(id);
    }

    (*rsc)->fns = &resource_class_functions[(*rsc)->variant];
    pe_rsc_trace((*rsc), "Unpacking resource...");

    get_meta_attributes((*rsc)->meta, *rsc, NULL, data_set);
    (*rsc)->parameters = pe_rsc_params(*rsc, NULL, data_set); // \deprecated
#if ENABLE_VERSIONED_ATTRS
    pe_get_versioned_attributes((*rsc)->versioned_parameters, *rsc, NULL, data_set);
#endif

    (*rsc)->flags = 0;
    pe__set_resource_flags(*rsc, pe_rsc_runnable|pe_rsc_provisional);

    if (!pcmk_is_set(data_set->flags, pe_flag_maintenance_mode)) {
        pe__set_resource_flags(*rsc, pe_rsc_managed);
    }

    (*rsc)->rsc_cons = NULL;
    (*rsc)->rsc_tickets = NULL;
    (*rsc)->actions = NULL;
    (*rsc)->role = RSC_ROLE_STOPPED;
    (*rsc)->next_role = RSC_ROLE_UNKNOWN;

    (*rsc)->recovery_type = recovery_stop_start;
    (*rsc)->stickiness = 0;
    (*rsc)->migration_threshold = INFINITY;
    (*rsc)->failure_timeout = 0;

    value = g_hash_table_lookup((*rsc)->meta, XML_CIB_ATTR_PRIORITY);
    (*rsc)->priority = char2score(value);

    value = g_hash_table_lookup((*rsc)->meta, XML_RSC_ATTR_CRITICAL);
    if ((value == NULL) || crm_is_true(value)) {
        pe__set_resource_flags(*rsc, pe_rsc_critical);
    }

    value = g_hash_table_lookup((*rsc)->meta, XML_RSC_ATTR_NOTIFY);
    if (crm_is_true(value)) {
        pe__set_resource_flags(*rsc, pe_rsc_notify);
    }

    if (xml_contains_remote_node((*rsc)->xml)) {
        (*rsc)->is_remote_node = TRUE;
        if (g_hash_table_lookup((*rsc)->meta, XML_RSC_ATTR_CONTAINER)) {
            guest_node = true;
        } else {
            remote_node = true;
        }
    }

    value = g_hash_table_lookup((*rsc)->meta, XML_OP_ATTR_ALLOW_MIGRATE);
#if ENABLE_VERSIONED_ATTRS
    has_versioned_params = xml_has_children((*rsc)->versioned_parameters);
#endif
    if (crm_is_true(value) && has_versioned_params) {
        pe_rsc_trace((*rsc), "Migration is disabled for resources with versioned parameters");
    } else if (crm_is_true(value)) {
        pe__set_resource_flags(*rsc, pe_rsc_allow_migrate);
    } else if ((value == NULL) && remote_node && !has_versioned_params) {
        /* By default, we want remote nodes to be able
         * to float around the cluster without having to stop all the
         * resources within the remote-node before moving. Allowing
         * migration support enables this feature. If this ever causes
         * problems, migration support can be explicitly turned off with
         * allow-migrate=false.
         * We don't support migration for versioned resources, though. */
        pe__set_resource_flags(*rsc, pe_rsc_allow_migrate);
    }

    value = g_hash_table_lookup((*rsc)->meta, XML_RSC_ATTR_MANAGED);
    if (value != NULL && !pcmk__str_eq("default", value, pcmk__str_casei)) {
        if (crm_is_true(value)) {
            pe__set_resource_flags(*rsc, pe_rsc_managed);
        } else {
            pe__clear_resource_flags(*rsc, pe_rsc_managed);
        }
    }

    value = g_hash_table_lookup((*rsc)->meta, XML_RSC_ATTR_MAINTENANCE);
    if (crm_is_true(value)) {
        pe__clear_resource_flags(*rsc, pe_rsc_managed);
        pe__set_resource_flags(*rsc, pe_rsc_maintenance);
    }
    if (pcmk_is_set(data_set->flags, pe_flag_maintenance_mode)) {
        pe__clear_resource_flags(*rsc, pe_rsc_managed);
        pe__set_resource_flags(*rsc, pe_rsc_maintenance);
    }

    if (pe_rsc_is_clone(uber_parent(*rsc))) {
        value = g_hash_table_lookup((*rsc)->meta, XML_RSC_ATTR_UNIQUE);
        if (crm_is_true(value)) {
            pe__set_resource_flags(*rsc, pe_rsc_unique);
        }
        if (detect_promotable(*rsc)) {
            pe__set_resource_flags(*rsc, pe_rsc_promotable);
        }
    } else {
        pe__set_resource_flags(*rsc, pe_rsc_unique);
    }

    pe_rsc_trace((*rsc), "Options for %s", (*rsc)->id);

    value = g_hash_table_lookup((*rsc)->meta, XML_RSC_ATTR_RESTART);
    if (pcmk__str_eq(value, "restart", pcmk__str_casei)) {
        (*rsc)->restart_type = pe_restart_restart;
        pe_rsc_trace((*rsc), "\tDependency restart handling: restart");
        pe_warn_once(pe_wo_restart_type,
                     "Support for restart-type is deprecated and will be removed in a future release");

    } else {
        (*rsc)->restart_type = pe_restart_ignore;
        pe_rsc_trace((*rsc), "\tDependency restart handling: ignore");
    }

    value = g_hash_table_lookup((*rsc)->meta, XML_RSC_ATTR_MULTIPLE);
    if (pcmk__str_eq(value, "stop_only", pcmk__str_casei)) {
        (*rsc)->recovery_type = recovery_stop_only;
        pe_rsc_trace((*rsc), "\tMultiple running resource recovery: stop only");

    } else if (pcmk__str_eq(value, "block", pcmk__str_casei)) {
        (*rsc)->recovery_type = recovery_block;
        pe_rsc_trace((*rsc), "\tMultiple running resource recovery: block");

    } else if (pcmk__str_eq(value, "stop_unexpected", pcmk__str_casei)) {
        (*rsc)->recovery_type = recovery_stop_unexpected;
        pe_rsc_trace((*rsc), "\tMultiple running resource recovery: "
                             "stop unexpected instances");

    } else { // "stop_start"
        if (!pcmk__str_eq(value, "stop_start",
                          pcmk__str_casei|pcmk__str_null_matches)) {
            pe_warn("%s is not a valid value for " XML_RSC_ATTR_MULTIPLE
                    ", using default of \"stop_start\"", value);
        }
        (*rsc)->recovery_type = recovery_stop_start;
        pe_rsc_trace((*rsc), "\tMultiple running resource recovery: stop/start");
    }

    value = g_hash_table_lookup((*rsc)->meta, XML_RSC_ATTR_STICKINESS);
    if (value != NULL && !pcmk__str_eq("default", value, pcmk__str_casei)) {
        (*rsc)->stickiness = char2score(value);
    }

    value = g_hash_table_lookup((*rsc)->meta, XML_RSC_ATTR_FAIL_STICKINESS);
    if (value != NULL && !pcmk__str_eq("default", value, pcmk__str_casei)) {
        (*rsc)->migration_threshold = char2score(value);
        if ((*rsc)->migration_threshold < 0) {
            /* @TODO We use 1 here to preserve previous behavior, but this
             * should probably use the default (INFINITY) or 0 (to disable)
             * instead.
             */
            pe_warn_once(pe_wo_neg_threshold,
                         XML_RSC_ATTR_FAIL_STICKINESS
                         " must be non-negative, using 1 instead");
            (*rsc)->migration_threshold = 1;
        }
    }

    if (pcmk__str_eq(rclass, PCMK_RESOURCE_CLASS_STONITH, pcmk__str_casei)) {
        pe__set_working_set_flags(data_set, pe_flag_have_stonith_resource);
        pe__set_resource_flags(*rsc, pe_rsc_fence_device);
    }

    value = g_hash_table_lookup((*rsc)->meta, XML_RSC_ATTR_REQUIRES);
    unpack_requires(*rsc, value, false);

    value = g_hash_table_lookup((*rsc)->meta, XML_RSC_ATTR_FAIL_TIMEOUT);
    if (value != NULL) {
        // Stored as seconds
        (*rsc)->failure_timeout = (int) (crm_parse_interval_spec(value) / 1000);
    }

    if (remote_node) {
        GHashTable *params = pe_rsc_params(*rsc, NULL, data_set);

        /* Grabbing the value now means that any rules based on node attributes
         * will evaluate to false, so such rules should not be used with
         * reconnect_interval.
         *
         * @TODO Evaluate per node before using
         */
        value = g_hash_table_lookup(params, XML_REMOTE_ATTR_RECONNECT_INTERVAL);
        if (value) {
            /* reconnect delay works by setting failure_timeout and preventing the
             * connection from starting until the failure is cleared. */
            (*rsc)->remote_reconnect_ms = crm_parse_interval_spec(value);
            /* we want to override any default failure_timeout in use when remote
             * reconnect_interval is in use. */ 
            (*rsc)->failure_timeout = (*rsc)->remote_reconnect_ms / 1000;
        }
    }

    get_target_role(*rsc, &((*rsc)->next_role));
    pe_rsc_trace((*rsc), "\tDesired next state: %s",
                 (*rsc)->next_role != RSC_ROLE_UNKNOWN ? role2text((*rsc)->next_role) : "default");

    if ((*rsc)->fns->unpack(*rsc, data_set) == FALSE) {
        return pcmk_rc_unpack_error;
    }

    if (pcmk_is_set(data_set->flags, pe_flag_symmetric_cluster)) {
        // This tag must stay exactly the same because it is tested elsewhere
        resource_location(*rsc, NULL, 0, "symmetric_default", data_set);
    } else if (guest_node) {
        /* remote resources tied to a container resource must always be allowed
         * to opt-in to the cluster. Whether the connection resource is actually
         * allowed to be placed on a node is dependent on the container resource */
        resource_location(*rsc, NULL, 0, "remote_connection_default", data_set);
    }

    pe_rsc_trace((*rsc), "\tAction notification: %s",
                 pcmk_is_set((*rsc)->flags, pe_rsc_notify)? "required" : "not required");

    (*rsc)->utilization = pcmk__strkey_table(free, free);

    pe__unpack_dataset_nvpairs((*rsc)->xml, XML_TAG_UTILIZATION, &rule_data,
                               (*rsc)->utilization, NULL, FALSE, data_set);

/* 	data_set->resources = g_list_append(data_set->resources, (*rsc)); */

    if (expanded_xml) {
        if (add_template_rsc(xml_obj, data_set) == FALSE) {
            return pcmk_rc_unpack_error;
        }
    }
    return pcmk_rc_ok;
}

void
common_update_score(pe_resource_t * rsc, const char *id, int score)
{
    pe_node_t *node = NULL;

    node = pe_hash_table_lookup(rsc->allowed_nodes, id);
    if (node != NULL) {
        pe_rsc_trace(rsc, "Updating score for %s on %s: %d + %d", rsc->id, id, node->weight, score);
        node->weight = pcmk__add_scores(node->weight, score);
    }

    if (rsc->children) {
        GList *gIter = rsc->children;

        for (; gIter != NULL; gIter = gIter->next) {
            pe_resource_t *child_rsc = (pe_resource_t *) gIter->data;

            common_update_score(child_rsc, id, score);
        }
    }
}

gboolean
is_parent(pe_resource_t *child, pe_resource_t *rsc)
{
    pe_resource_t *parent = child;

    if (parent == NULL || rsc == NULL) {
        return FALSE;
    }
    while (parent->parent != NULL) {
        if (parent->parent == rsc) {
            return TRUE;
        }
        parent = parent->parent;
    }
    return FALSE;
}

pe_resource_t *
uber_parent(pe_resource_t * rsc)
{
    pe_resource_t *parent = rsc;

    if (parent == NULL) {
        return NULL;
    }
    while (parent->parent != NULL && parent->parent->variant != pe_container) {
        parent = parent->parent;
    }
    return parent;
}

void
common_free(pe_resource_t * rsc)
{
    if (rsc == NULL) {
        return;
    }

    pe_rsc_trace(rsc, "Freeing %s %d", rsc->id, rsc->variant);

    g_list_free(rsc->rsc_cons);
    g_list_free(rsc->rsc_cons_lhs);
    g_list_free(rsc->rsc_tickets);
    g_list_free(rsc->dangling_migrations);

    if (rsc->parameter_cache != NULL) {
        g_hash_table_destroy(rsc->parameter_cache);
    }
#if ENABLE_VERSIONED_ATTRS
    if (rsc->versioned_parameters != NULL) {
        free_xml(rsc->versioned_parameters);
    }
#endif
    if (rsc->meta != NULL) {
        g_hash_table_destroy(rsc->meta);
    }
    if (rsc->utilization != NULL) {
        g_hash_table_destroy(rsc->utilization);
    }

    if ((rsc->parent == NULL) && pcmk_is_set(rsc->flags, pe_rsc_orphan)) {
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
    free(rsc->pending_task);
    free(rsc);
}

/*!
 * \brief
 * \internal Find a node (and optionally count all) where resource is active
 *
 * \param[in]  rsc          Resource to check
 * \param[out] count_all    If not NULL, will be set to count of active nodes
 * \param[out] count_clean  If not NULL, will be set to count of clean nodes
 *
 * \return An active node (or NULL if resource is not active anywhere)
 *
 * \note The order of preference is: an active node that is the resource's
 *       partial migration source; if the resource's "requires" is "quorum" or
 *       "nothing", the first active node in the list that is clean and online;
 *       the first active node in the list.
 */
pe_node_t *
pe__find_active_on(const pe_resource_t *rsc, unsigned int *count_all,
                   unsigned int *count_clean)
{
    pe_node_t *active = NULL;
    pe_node_t *node = NULL;
    bool keep_looking = FALSE;
    bool is_happy = FALSE;

    if (count_all) {
        *count_all = 0;
    }
    if (count_clean) {
        *count_clean = 0;
    }
    if (rsc == NULL) {
        return NULL;
    }

    for (GList *node_iter = rsc->running_on; node_iter != NULL;
         node_iter = node_iter->next) {

        node = node_iter->data;
        keep_looking = FALSE;

        is_happy = node->details->online && !node->details->unclean;

        if (count_all) {
            ++*count_all;
        }
        if (count_clean && is_happy) {
            ++*count_clean;
        }
        if (count_all || count_clean) {
            // If we're counting, we need to go through entire list
            keep_looking = TRUE;
        }

        if (rsc->partial_migration_source != NULL) {
            if (node->details == rsc->partial_migration_source->details) {
                // This is the migration source
                active = node;
            } else {
                keep_looking = TRUE;
            }
        } else if (!pcmk_is_set(rsc->flags, pe_rsc_needs_fencing)) {
            if (is_happy && (!active || !active->details->online
                             || active->details->unclean)) {
                // This is the first clean node
                active = node;
            } else {
                keep_looking = TRUE;
            }
        }
        if (active == NULL) {
            // This is first node in list
            active = node;
        }

        if (keep_looking == FALSE) {
            // Don't waste time iterating if we don't have to
            break;
        }
    }
    return active;
}

/*!
 * \brief
 * \internal Find and count active nodes according to "requires"
 *
 * \param[in]  rsc    Resource to check
 * \param[out] count  If not NULL, will be set to count of active nodes
 *
 * \return An active node (or NULL if resource is not active anywhere)
 *
 * \note This is a convenience wrapper for pe__find_active_on() where the count
 *       of all active nodes or only clean active nodes is desired according to
 *       the "requires" meta-attribute.
 */
pe_node_t *
pe__find_active_requires(const pe_resource_t *rsc, unsigned int *count)
{
    if (rsc && !pcmk_is_set(rsc->flags, pe_rsc_needs_fencing)) {
        return pe__find_active_on(rsc, NULL, count);
    }
    return pe__find_active_on(rsc, count, NULL);
}

void
pe__count_common(pe_resource_t *rsc)
{
    if (rsc->children != NULL) {
        for (GList *item = rsc->children; item != NULL; item = item->next) {
            ((pe_resource_t *) item->data)->fns->count(item->data);
        }

    } else if (!pcmk_is_set(rsc->flags, pe_rsc_orphan)
               || (rsc->role > RSC_ROLE_STOPPED)) {
        rsc->cluster->ninstances++;
        if (pe__resource_is_disabled(rsc)) {
            rsc->cluster->disabled_resources++;
        }
        if (pcmk_is_set(rsc->flags, pe_rsc_block)) {
            rsc->cluster->blocked_resources++;
        }
    }
}

/*!
 * \internal
 * \brief Update a resource's next role
 *
 * \param[in,out] rsc   Resource to be updated
 * \param[in]     role  Resource's new next role
 * \param[in]     why   Human-friendly reason why role is changing (for logs)
 */
void
pe__set_next_role(pe_resource_t *rsc, enum rsc_role_e role, const char *why)
{
    CRM_ASSERT((rsc != NULL) && (why != NULL));
    if (rsc->next_role != role) {
        pe_rsc_trace(rsc, "Resetting next role for %s from %s to %s (%s)",
                     rsc->id, role2text(rsc->next_role), role2text(role), why);
        rsc->next_role = role;
    }
}
