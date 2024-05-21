/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/pengine/rules.h>
#include <crm/pengine/internal.h>
#include <crm/common/xml.h>
#include <crm/common/xml_internal.h>
#include <crm/common/scheduler_internal.h>

#include "pe_status_private.h"

void populate_hash(xmlNode * nvpair_list, GHashTable * hash, const char **attrs, int attrs_length);

static pcmk_node_t *active_node(const pcmk_resource_t *rsc,
                                unsigned int *count_all,
                                unsigned int *count_clean);

static pcmk__rsc_methods_t resource_class_functions[] = {
    {
         native_unpack,
         native_find_rsc,
         native_parameter,
         native_active,
         native_resource_state,
         native_location,
         native_free,
         pe__count_common,
         pe__native_is_filtered,
         active_node,
         pe__primitive_max_per_node,
    },
    {
         group_unpack,
         native_find_rsc,
         native_parameter,
         group_active,
         group_resource_state,
         native_location,
         group_free,
         pe__count_common,
         pe__group_is_filtered,
         active_node,
         pe__group_max_per_node,
    },
    {
         clone_unpack,
         native_find_rsc,
         native_parameter,
         clone_active,
         clone_resource_state,
         native_location,
         clone_free,
         pe__count_common,
         pe__clone_is_filtered,
         active_node,
         pe__clone_max_per_node,
    },
    {
         pe__unpack_bundle,
         native_find_rsc,
         native_parameter,
         pe__bundle_active,
         pe__bundle_resource_state,
         native_location,
         pe__free_bundle,
         pe__count_bundle,
         pe__bundle_is_filtered,
         pe__bundle_active_node,
         pe__bundle_max_per_node,
    }
};

static enum pcmk__rsc_variant
get_resource_type(const char *name)
{
    if (pcmk__str_eq(name, PCMK_XE_PRIMITIVE, pcmk__str_casei)) {
        return pcmk__rsc_variant_primitive;

    } else if (pcmk__str_eq(name, PCMK_XE_GROUP, pcmk__str_casei)) {
        return pcmk__rsc_variant_group;

    } else if (pcmk__str_eq(name, PCMK_XE_CLONE, pcmk__str_casei)) {
        return pcmk__rsc_variant_clone;

    } else if (pcmk__str_eq(name, PCMK__XE_PROMOTABLE_LEGACY,
                            pcmk__str_casei)) {
        // @COMPAT deprecated since 2.0.0
        return pcmk__rsc_variant_clone;

    } else if (pcmk__str_eq(name, PCMK_XE_BUNDLE, pcmk__str_casei)) {
        return pcmk__rsc_variant_bundle;
    }

    return pcmk__rsc_variant_unknown;
}

/*!
 * \internal
 * \brief Insert a meta-attribute if not already present
 *
 * \param[in]     key    Meta-attribute name
 * \param[in]     value  Meta-attribute value to add if not already present
 * \param[in,out] table  Meta-attribute hash table to insert into
 *
 * \note This is like pcmk__insert_meta() except it won't overwrite existing
 *       values.
 */
static void
dup_attr(gpointer key, gpointer value, gpointer user_data)
{
    GHashTable *table = user_data;

    CRM_CHECK((key != NULL) && (table != NULL), return);
    if (pcmk__str_eq((const char *) value, "#default", pcmk__str_casei)) {
        // @COMPAT Deprecated since 2.1.8
        pcmk__config_warn("Support for setting meta-attributes (such as %s) to "
                          "the explicit value '#default' is deprecated and "
                          "will be removed in a future release",
                          (const char *) key);
    } else if ((value != NULL) && (g_hash_table_lookup(table, key) == NULL)) {
        pcmk__insert_dup(table, (const char *) key, (const char *) value);
    }
}

static void
expand_parents_fixed_nvpairs(pcmk_resource_t *rsc,
                             pe_rule_eval_data_t *rule_data,
                             GHashTable *meta_hash, pcmk_scheduler_t *scheduler)
{
    GHashTable *parent_orig_meta = pcmk__strkey_table(free, free);
    pcmk_resource_t *p = rsc->private->parent;

    if (p == NULL) {
        return ;
    }

    /* Search all parent resources, get the fixed value of
     * PCMK_XE_META_ATTRIBUTES set only in the original xml, and stack it in the
     * hash table. The fixed value of the lower parent resource takes precedence
     * and is not overwritten.
     */
    while(p != NULL) {
        /* A hash table for comparison is generated, including the id-ref. */
        pe__unpack_dataset_nvpairs(p->private->xml, PCMK_XE_META_ATTRIBUTES,
                                   rule_data, parent_orig_meta, NULL, FALSE,
                                   scheduler);
        p = p->private->parent;
    }

    if (parent_orig_meta != NULL) {
        // This will not overwrite any values already existing for child
        g_hash_table_foreach(parent_orig_meta, dup_attr, meta_hash);
    }

    if (parent_orig_meta != NULL) {
        g_hash_table_destroy(parent_orig_meta);
    }
    
    return ;

}
void
get_meta_attributes(GHashTable * meta_hash, pcmk_resource_t * rsc,
                    pcmk_node_t *node, pcmk_scheduler_t *scheduler)
{
    pe_rsc_eval_data_t rsc_rule_data = {
        .standard = crm_element_value(rsc->private->xml, PCMK_XA_CLASS),
        .provider = crm_element_value(rsc->private->xml, PCMK_XA_PROVIDER),
        .agent = crm_element_value(rsc->private->xml, PCMK_XA_TYPE)
    };

    pe_rule_eval_data_t rule_data = {
        .node_hash = NULL,
        .now = scheduler->now,
        .match_data = NULL,
        .rsc_data = &rsc_rule_data,
        .op_data = NULL
    };

    if (node) {
        /* @COMPAT Support for node attribute expressions in rules for
         * meta-attributes is deprecated. When we can break behavioral backward
         * compatibility, drop this block.
         */
        rule_data.node_hash = node->details->attrs;
    }

    for (xmlAttrPtr a = pcmk__xe_first_attr(rsc->private->xml);
         a != NULL; a = a->next) {

        if (a->children != NULL) {
            dup_attr((gpointer) a->name, (gpointer) a->children->content,
                     meta_hash);
        }
    }

    pe__unpack_dataset_nvpairs(rsc->private->xml, PCMK_XE_META_ATTRIBUTES,
                               &rule_data, meta_hash, NULL, FALSE, scheduler);

    /* Set the PCMK_XE_META_ATTRIBUTES explicitly set in the parent resource to
     * the hash table of the child resource. If it is already explicitly set as
     * a child, it will not be overwritten.
     */
    if (rsc->private->parent != NULL) {
        expand_parents_fixed_nvpairs(rsc, &rule_data, meta_hash, scheduler);
    }

    /* check the defaults */
    pe__unpack_dataset_nvpairs(scheduler->rsc_defaults, PCMK_XE_META_ATTRIBUTES,
                               &rule_data, meta_hash, NULL, FALSE, scheduler);

    /* If there is PCMK_XE_META_ATTRIBUTES that the parent resource has not
     * explicitly set, set a value that is not set from PCMK_XE_RSC_DEFAULTS
     * either. The values already set up to this point will not be overwritten.
     */
    if (rsc->private->parent != NULL) {
        g_hash_table_foreach(rsc->private->parent->meta, dup_attr, meta_hash);
    }
}

void
get_rsc_attributes(GHashTable *meta_hash, const pcmk_resource_t *rsc,
                   const pcmk_node_t *node, pcmk_scheduler_t *scheduler)
{
    pe_rule_eval_data_t rule_data = {
        .node_hash = NULL,
        .now = scheduler->now,
        .match_data = NULL,
        .rsc_data = NULL,
        .op_data = NULL
    };

    if (node) {
        rule_data.node_hash = node->details->attrs;
    }

    pe__unpack_dataset_nvpairs(rsc->private->xml, PCMK_XE_INSTANCE_ATTRIBUTES,
                               &rule_data, meta_hash, NULL, FALSE, scheduler);

    /* set anything else based on the parent */
    if (rsc->private->parent != NULL) {
        get_rsc_attributes(meta_hash, rsc->private->parent, node, scheduler);

    } else {
        if (pcmk__xe_first_child(scheduler->rsc_defaults,
                                 PCMK_XE_INSTANCE_ATTRIBUTES, NULL,
                                 NULL) != NULL) {
            /* Not possible with schema validation enabled
             *
             * @COMPAT Drop support when we can break behavioral
             * backward compatibility
             */
            pcmk__warn_once(pcmk__wo_instance_defaults,
                            "Support for " PCMK_XE_INSTANCE_ATTRIBUTES " in "
                            PCMK_XE_RSC_DEFAULTS " is deprecated and will be "
                            "removed in a future release");
        }

        /* and finally check the defaults */
        pe__unpack_dataset_nvpairs(scheduler->rsc_defaults,
                                   PCMK_XE_INSTANCE_ATTRIBUTES, &rule_data,
                                   meta_hash, NULL, FALSE, scheduler);
    }
}

static char *
template_op_key(xmlNode * op)
{
    const char *name = crm_element_value(op, PCMK_XA_NAME);
    const char *role = crm_element_value(op, PCMK_XA_ROLE);
    char *key = NULL;

    if ((role == NULL)
        || pcmk__strcase_any_of(role, PCMK_ROLE_STARTED, PCMK_ROLE_UNPROMOTED,
                                PCMK__ROLE_UNPROMOTED_LEGACY, NULL)) {
        role = PCMK__ROLE_UNKNOWN;
    }

    key = crm_strdup_printf("%s-%s", name, role);
    return key;
}

static gboolean
unpack_template(xmlNode *xml_obj, xmlNode **expanded_xml,
                pcmk_scheduler_t *scheduler)
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
        pcmk__config_err("No resource object for template unpacking");
        return FALSE;
    }

    template_ref = crm_element_value(xml_obj, PCMK_XA_TEMPLATE);
    if (template_ref == NULL) {
        return TRUE;
    }

    id = pcmk__xe_id(xml_obj);
    if (id == NULL) {
        pcmk__config_err("'%s' object must have a id", xml_obj->name);
        return FALSE;
    }

    if (pcmk__str_eq(template_ref, id, pcmk__str_none)) {
        pcmk__config_err("The resource object '%s' should not reference itself",
                         id);
        return FALSE;
    }

    cib_resources = get_xpath_object("//" PCMK_XE_RESOURCES, scheduler->input,
                                     LOG_TRACE);
    if (cib_resources == NULL) {
        pcmk__config_err("No resources configured");
        return FALSE;
    }

    template = pcmk__xe_first_child(cib_resources, PCMK_XE_TEMPLATE,
                                    PCMK_XA_ID, template_ref);
    if (template == NULL) {
        pcmk__config_err("No template named '%s'", template_ref);
        return FALSE;
    }

    new_xml = pcmk__xml_copy(NULL, template);
    xmlNodeSetName(new_xml, xml_obj->name);
    crm_xml_add(new_xml, PCMK_XA_ID, id);
    crm_xml_add(new_xml, PCMK__META_CLONE,
                crm_element_value(xml_obj, PCMK__META_CLONE));

    template_ops = pcmk__xe_first_child(new_xml, PCMK_XE_OPERATIONS, NULL,
                                        NULL);

    for (child_xml = pcmk__xe_first_child(xml_obj, NULL, NULL, NULL);
         child_xml != NULL; child_xml = pcmk__xe_next(child_xml)) {

        xmlNode *new_child = pcmk__xml_copy(new_xml, child_xml);

        if (pcmk__xe_is(new_child, PCMK_XE_OPERATIONS)) {
            rsc_ops = new_child;
        }
    }

    if (template_ops && rsc_ops) {
        xmlNode *op = NULL;
        GHashTable *rsc_ops_hash = pcmk__strkey_table(free, NULL);

        for (op = pcmk__xe_first_child(rsc_ops, NULL, NULL, NULL); op != NULL;
             op = pcmk__xe_next(op)) {

            char *key = template_op_key(op);

            g_hash_table_insert(rsc_ops_hash, key, op);
        }

        for (op = pcmk__xe_first_child(template_ops, NULL, NULL, NULL);
             op != NULL; op = pcmk__xe_next(op)) {

            char *key = template_op_key(op);

            if (g_hash_table_lookup(rsc_ops_hash, key) == NULL) {
                pcmk__xml_copy(rsc_ops, op);
            }

            free(key);
        }

        if (rsc_ops_hash) {
            g_hash_table_destroy(rsc_ops_hash);
        }

        pcmk__xml_free(template_ops);
    }

    /*pcmk__xml_free(*expanded_xml); */
    *expanded_xml = new_xml;

#if 0 /* Disable multi-level templates for now */
    if (!unpack_template(new_xml, expanded_xml, scheduler)) {
       pcmk__xml_free(*expanded_xml);
       *expanded_xml = NULL;
       return FALSE;
    }
#endif

    return TRUE;
}

static gboolean
add_template_rsc(xmlNode *xml_obj, pcmk_scheduler_t *scheduler)
{
    const char *template_ref = NULL;
    const char *id = NULL;

    if (xml_obj == NULL) {
        pcmk__config_err("No resource object for processing resource list "
                         "of template");
        return FALSE;
    }

    template_ref = crm_element_value(xml_obj, PCMK_XA_TEMPLATE);
    if (template_ref == NULL) {
        return TRUE;
    }

    id = pcmk__xe_id(xml_obj);
    if (id == NULL) {
        pcmk__config_err("'%s' object must have a id", xml_obj->name);
        return FALSE;
    }

    if (pcmk__str_eq(template_ref, id, pcmk__str_none)) {
        pcmk__config_err("The resource object '%s' should not reference itself",
                         id);
        return FALSE;
    }

    if (add_tag_ref(scheduler->template_rsc_sets, template_ref, id) == FALSE) {
        return FALSE;
    }

    return TRUE;
}

static bool
detect_promotable(pcmk_resource_t *rsc)
{
    const char *promotable = g_hash_table_lookup(rsc->meta,
                                                 PCMK_META_PROMOTABLE);

    if (crm_is_true(promotable)) {
        return TRUE;
    }

    // @COMPAT deprecated since 2.0.0
    if (pcmk__xe_is(rsc->private->xml, PCMK__XE_PROMOTABLE_LEGACY)) {
        pcmk__warn_once(pcmk__wo_master_element,
                        "Support for <" PCMK__XE_PROMOTABLE_LEGACY "> (such "
                        "as in %s) is deprecated and will be removed in a "
                        "future release. Use <" PCMK_XE_CLONE "> with a "
                        PCMK_META_PROMOTABLE " meta-attribute instead.",
                        rsc->id);
        pcmk__insert_dup(rsc->meta, PCMK_META_PROMOTABLE, PCMK_VALUE_TRUE);
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
 * \param[in,out] rsc        Resource to query
 * \param[in]     node       Node for evaluating rules (NULL for defaults)
 * \param[in,out] scheduler  Scheduler data
 *
 * \return Hash table containing resource parameter names and values
 *         (or NULL if \p rsc or \p scheduler is NULL)
 * \note The returned table will be destroyed when the resource is freed, so
 *       callers should not destroy it.
 */
GHashTable *
pe_rsc_params(pcmk_resource_t *rsc, const pcmk_node_t *node,
              pcmk_scheduler_t *scheduler)
{
    GHashTable *params_on_node = NULL;

    /* A NULL node is used to request the resource's default parameters
     * (not evaluated for node), but we always want something non-NULL
     * as a hash table key.
     */
    const char *node_name = "";

    // Sanity check
    if ((rsc == NULL) || (scheduler == NULL)) {
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
        get_rsc_attributes(params_on_node, rsc, node, scheduler);
        g_hash_table_insert(rsc->parameter_cache, strdup(node_name),
                            params_on_node);
    }
    return params_on_node;
}

/*!
 * \internal
 * \brief Unpack a resource's \c PCMK_META_REQUIRES meta-attribute
 *
 * \param[in,out] rsc         Resource being unpacked
 * \param[in]     value       Value of \c PCMK_META_REQUIRES meta-attribute
 * \param[in]     is_default  Whether \p value was selected by default
 */
static void
unpack_requires(pcmk_resource_t *rsc, const char *value, bool is_default)
{
    const pcmk_scheduler_t *scheduler = rsc->private->scheduler;

    if (pcmk__str_eq(value, PCMK_VALUE_NOTHING, pcmk__str_casei)) {

    } else if (pcmk__str_eq(value, PCMK_VALUE_QUORUM, pcmk__str_casei)) {
        pcmk__set_rsc_flags(rsc, pcmk__rsc_needs_quorum);

    } else if (pcmk__str_eq(value, PCMK_VALUE_FENCING, pcmk__str_casei)) {
        pcmk__set_rsc_flags(rsc, pcmk__rsc_needs_fencing);
        if (!pcmk_is_set(scheduler->flags, pcmk_sched_fencing_enabled)) {
            pcmk__config_warn("%s requires fencing but fencing is disabled",
                              rsc->id);
        }

    } else if (pcmk__str_eq(value, PCMK_VALUE_UNFENCING, pcmk__str_casei)) {
        if (pcmk_is_set(rsc->flags, pcmk__rsc_fence_device)) {
            pcmk__config_warn("Resetting \"" PCMK_META_REQUIRES "\" for %s "
                              "to \"" PCMK_VALUE_QUORUM "\" because fencing "
                              "devices cannot require unfencing", rsc->id);
            unpack_requires(rsc, PCMK_VALUE_QUORUM, true);
            return;

        } else if (!pcmk_is_set(scheduler->flags, pcmk_sched_fencing_enabled)) {
            pcmk__config_warn("Resetting \"" PCMK_META_REQUIRES "\" for %s "
                              "to \"" PCMK_VALUE_QUORUM "\" because fencing is "
                              "disabled", rsc->id);
            unpack_requires(rsc, PCMK_VALUE_QUORUM, true);
            return;

        } else {
            pcmk__set_rsc_flags(rsc, pcmk__rsc_needs_fencing
                                     |pcmk__rsc_needs_unfencing);
        }

    } else {
        const char *orig_value = value;

        if (pcmk_is_set(rsc->flags, pcmk__rsc_fence_device)) {
            value = PCMK_VALUE_QUORUM;

        } else if (pcmk__is_primitive(rsc)
                   && xml_contains_remote_node(rsc->private->xml)) {
            value = PCMK_VALUE_QUORUM;

        } else if (pcmk_is_set(scheduler->flags, pcmk_sched_enable_unfencing)) {
            value = PCMK_VALUE_UNFENCING;

        } else if (pcmk_is_set(scheduler->flags, pcmk_sched_fencing_enabled)) {
            value = PCMK_VALUE_FENCING;

        } else if (scheduler->no_quorum_policy == pcmk_no_quorum_ignore) {
            value = PCMK_VALUE_NOTHING;

        } else {
            value = PCMK_VALUE_QUORUM;
        }

        if (orig_value != NULL) {
            pcmk__config_err("Resetting '" PCMK_META_REQUIRES "' for %s "
                             "to '%s' because '%s' is not valid",
                              rsc->id, value, orig_value);
        }
        unpack_requires(rsc, value, true);
        return;
    }

    pcmk__rsc_trace(rsc, "\tRequired to start: %s%s", value,
                    (is_default? " (default)" : ""));
}

static void
warn_about_deprecated_classes(pcmk_resource_t *rsc)
{
    const char *std = crm_element_value(rsc->private->xml, PCMK_XA_CLASS);

    if (pcmk__str_eq(std, PCMK_RESOURCE_CLASS_UPSTART, pcmk__str_none)) {
        pcmk__warn_once(pcmk__wo_upstart,
                        "Support for Upstart resources (such as %s) is "
                        "deprecated and will be removed in a future release",
                        rsc->id);

    } else if (pcmk__str_eq(std, PCMK_RESOURCE_CLASS_NAGIOS, pcmk__str_none)) {
        pcmk__warn_once(pcmk__wo_nagios,
                        "Support for Nagios resources (such as %s) is "
                        "deprecated and will be removed in a future release",
                        rsc->id);
    }
}

/*!
 * \internal
 * \brief Unpack configuration XML for a given resource
 *
 * Unpack the XML object containing a resource's configuration into a new
 * \c pcmk_resource_t object.
 *
 * \param[in]     xml_obj    XML node containing the resource's configuration
 * \param[out]    rsc        Where to store the unpacked resource information
 * \param[in]     parent     Resource's parent, if any
 * \param[in,out] scheduler  Scheduler data
 *
 * \return Standard Pacemaker return code
 * \note If pcmk_rc_ok is returned, \p *rsc is guaranteed to be non-NULL, and
 *       the caller is responsible for freeing it using its variant-specific
 *       free() method. Otherwise, \p *rsc is guaranteed to be NULL.
 */
int
pe__unpack_resource(xmlNode *xml_obj, pcmk_resource_t **rsc,
                    pcmk_resource_t *parent, pcmk_scheduler_t *scheduler)
{
    xmlNode *expanded_xml = NULL;
    xmlNode *ops = NULL;
    const char *value = NULL;
    const char *id = NULL;
    bool guest_node = false;
    bool remote_node = false;
    pcmk__resource_private_t *rsc_private = NULL;

    pe_rule_eval_data_t rule_data = {
        .node_hash = NULL,
        .now = NULL,
        .match_data = NULL,
        .rsc_data = NULL,
        .op_data = NULL
    };

    CRM_CHECK(rsc != NULL, return EINVAL);
    CRM_CHECK((xml_obj != NULL) && (scheduler != NULL),
              *rsc = NULL;
              return EINVAL);

    rule_data.now = scheduler->now;

    crm_log_xml_trace(xml_obj, "[raw XML]");

    id = crm_element_value(xml_obj, PCMK_XA_ID);
    if (id == NULL) {
        pcmk__config_err("Ignoring <%s> configuration without " PCMK_XA_ID,
                         xml_obj->name);
        return pcmk_rc_unpack_error;
    }

    if (unpack_template(xml_obj, &expanded_xml, scheduler) == FALSE) {
        return pcmk_rc_unpack_error;
    }

    *rsc = calloc(1, sizeof(pcmk_resource_t));
    if (*rsc == NULL) {
        pcmk__sched_err("Unable to allocate memory for resource '%s'", id);
        return ENOMEM;
    }

    (*rsc)->private = calloc(1, sizeof(pcmk__resource_private_t));
    if ((*rsc)->private == NULL) {
        pcmk__sched_err("Unable to allocate memory for resource '%s'", id);
        free(*rsc);
        return ENOMEM;
    }
    rsc_private = (*rsc)->private;

    rsc_private->scheduler = scheduler;

    if (expanded_xml) {
        crm_log_xml_trace(expanded_xml, "[expanded XML]");
        rsc_private->xml = expanded_xml;
        rsc_private->orig_xml = xml_obj;

    } else {
        rsc_private->xml = xml_obj;
        rsc_private->orig_xml = NULL;
    }

    /* Do not use xml_obj from here on, use (*rsc)->xml in case templates are involved */

    rsc_private->parent = parent;

    ops = pcmk__xe_first_child(rsc_private->xml, PCMK_XE_OPERATIONS, NULL,
                               NULL);
    rsc_private->ops_xml = pcmk__xe_resolve_idref(ops, scheduler->input);

    rsc_private->variant = get_resource_type((const char *)
                                             rsc_private->xml->name);
    if (rsc_private->variant == pcmk__rsc_variant_unknown) {
        pcmk__config_err("Ignoring resource '%s' of unknown type '%s'",
                         id, rsc_private->xml->name);
        common_free(*rsc);
        *rsc = NULL;
        return pcmk_rc_unpack_error;
    }

    (*rsc)->meta = pcmk__strkey_table(free, free);
    rsc_private->probed_nodes = pcmk__strkey_table(NULL, free);
    rsc_private->allowed_nodes = pcmk__strkey_table(NULL, free);

    value = crm_element_value(rsc_private->xml, PCMK__META_CLONE);
    if (value) {
        (*rsc)->id = crm_strdup_printf("%s:%s", id, value);
        pcmk__insert_meta(*rsc, PCMK__META_CLONE, value);

    } else {
        (*rsc)->id = strdup(id);
    }

    warn_about_deprecated_classes(*rsc);

    rsc_private->fns = &resource_class_functions[rsc_private->variant];

    get_meta_attributes((*rsc)->meta, *rsc, NULL, scheduler);
    (*rsc)->parameters = pe_rsc_params(*rsc, NULL, scheduler); // \deprecated

    (*rsc)->flags = 0;
    pcmk__set_rsc_flags(*rsc, pcmk__rsc_unassigned);

    if (!pcmk_is_set(scheduler->flags, pcmk_sched_in_maintenance)) {
        pcmk__set_rsc_flags(*rsc, pcmk__rsc_managed);
    }

    rsc_private->orig_role = pcmk_role_stopped;
    rsc_private->next_role = pcmk_role_unknown;

    rsc_private->ban_after_failures = PCMK_SCORE_INFINITY;

    value = g_hash_table_lookup((*rsc)->meta, PCMK_META_PRIORITY);
    rsc_private->priority = char2score(value);

    value = g_hash_table_lookup((*rsc)->meta, PCMK_META_CRITICAL);
    if ((value == NULL) || crm_is_true(value)) {
        pcmk__set_rsc_flags(*rsc, pcmk__rsc_critical);
    }

    value = g_hash_table_lookup((*rsc)->meta, PCMK_META_NOTIFY);
    if (crm_is_true(value)) {
        pcmk__set_rsc_flags(*rsc, pcmk__rsc_notify);
    }

    if (xml_contains_remote_node(rsc_private->xml)) {
        pcmk__set_rsc_flags(*rsc, pcmk__rsc_is_remote_connection);
        if (g_hash_table_lookup((*rsc)->meta, PCMK__META_CONTAINER)) {
            guest_node = true;
        } else {
            remote_node = true;
        }
    }

    value = g_hash_table_lookup((*rsc)->meta, PCMK_META_ALLOW_MIGRATE);
    if (crm_is_true(value)) {
        pcmk__set_rsc_flags(*rsc, pcmk__rsc_migratable);
    } else if ((value == NULL) && remote_node) {
        /* By default, we want remote nodes to be able
         * to float around the cluster without having to stop all the
         * resources within the remote-node before moving. Allowing
         * migration support enables this feature. If this ever causes
         * problems, migration support can be explicitly turned off with
         * PCMK_META_ALLOW_MIGRATE=false.
         */
        pcmk__set_rsc_flags(*rsc, pcmk__rsc_migratable);
    }

    value = g_hash_table_lookup((*rsc)->meta, PCMK_META_IS_MANAGED);
    if (value != NULL) {
        if (pcmk__str_eq(PCMK_VALUE_DEFAULT, value, pcmk__str_casei)) {
            // @COMPAT Deprecated since 2.1.8
            pcmk__config_warn("Support for setting " PCMK_META_IS_MANAGED
                              " to the explicit value '" PCMK_VALUE_DEFAULT
                              "' is deprecated and will be removed in a "
                              "future release (just leave it unset)");
        } else if (crm_is_true(value)) {
            pcmk__set_rsc_flags(*rsc, pcmk__rsc_managed);
        } else {
            pcmk__clear_rsc_flags(*rsc, pcmk__rsc_managed);
        }
    }

    value = g_hash_table_lookup((*rsc)->meta, PCMK_META_MAINTENANCE);
    if (crm_is_true(value)) {
        pcmk__clear_rsc_flags(*rsc, pcmk__rsc_managed);
        pcmk__set_rsc_flags(*rsc, pcmk__rsc_maintenance);
    }
    if (pcmk_is_set(scheduler->flags, pcmk_sched_in_maintenance)) {
        pcmk__clear_rsc_flags(*rsc, pcmk__rsc_managed);
        pcmk__set_rsc_flags(*rsc, pcmk__rsc_maintenance);
    }

    if (pcmk__is_clone(pe__const_top_resource(*rsc, false))) {
        value = g_hash_table_lookup((*rsc)->meta, PCMK_META_GLOBALLY_UNIQUE);
        if (crm_is_true(value)) {
            pcmk__set_rsc_flags(*rsc, pcmk__rsc_unique);
        }
        if (detect_promotable(*rsc)) {
            pcmk__set_rsc_flags(*rsc, pcmk__rsc_promotable);
        }
    } else {
        pcmk__set_rsc_flags(*rsc, pcmk__rsc_unique);
    }

    // @COMPAT Deprecated meta-attribute
    value = g_hash_table_lookup((*rsc)->meta, PCMK__META_RESTART_TYPE);
    if (pcmk__str_eq(value, PCMK_VALUE_RESTART, pcmk__str_casei)) {
        rsc_private->restart_type = pcmk__restart_restart;
        pcmk__rsc_trace(*rsc, "%s dependency restart handling: restart",
                        (*rsc)->id);
        pcmk__warn_once(pcmk__wo_restart_type,
                        "Support for " PCMK__META_RESTART_TYPE " is deprecated "
                        "and will be removed in a future release");

    } else {
        rsc_private->restart_type = pcmk__restart_ignore;
        pcmk__rsc_trace(*rsc, "%s dependency restart handling: ignore",
                        (*rsc)->id);
    }

    value = g_hash_table_lookup((*rsc)->meta, PCMK_META_MULTIPLE_ACTIVE);
    if (pcmk__str_eq(value, PCMK_VALUE_STOP_ONLY, pcmk__str_casei)) {
        rsc_private->multiply_active_policy = pcmk__multiply_active_stop;
        pcmk__rsc_trace(*rsc, "%s multiple running resource recovery: stop only",
                        (*rsc)->id);

    } else if (pcmk__str_eq(value, PCMK_VALUE_BLOCK, pcmk__str_casei)) {
        rsc_private->multiply_active_policy = pcmk__multiply_active_block;
        pcmk__rsc_trace(*rsc, "%s multiple running resource recovery: block",
                        (*rsc)->id);

    } else if (pcmk__str_eq(value, PCMK_VALUE_STOP_UNEXPECTED,
                            pcmk__str_casei)) {
        rsc_private->multiply_active_policy = pcmk__multiply_active_unexpected;
        pcmk__rsc_trace(*rsc,
                        "%s multiple running resource recovery: "
                        "stop unexpected instances",
                        (*rsc)->id);

    } else { // PCMK_VALUE_STOP_START
        if (!pcmk__str_eq(value, PCMK_VALUE_STOP_START,
                          pcmk__str_casei|pcmk__str_null_matches)) {
            pcmk__config_warn("%s is not a valid value for "
                              PCMK_META_MULTIPLE_ACTIVE
                              ", using default of "
                              "\"" PCMK_VALUE_STOP_START "\"",
                              value);
        }
        rsc_private->multiply_active_policy = pcmk__multiply_active_restart;
        pcmk__rsc_trace(*rsc,
                        "%s multiple running resource recovery: stop/start",
                        (*rsc)->id);
    }

    value = g_hash_table_lookup((*rsc)->meta, PCMK_META_RESOURCE_STICKINESS);
    if (value != NULL) {
        if (pcmk__str_eq(PCMK_VALUE_DEFAULT, value, pcmk__str_casei)) {
            // @COMPAT Deprecated since 2.1.8
            pcmk__config_warn("Support for setting "
                              PCMK_META_RESOURCE_STICKINESS
                              " to the explicit value '" PCMK_VALUE_DEFAULT
                              "' is deprecated and will be removed in a "
                              "future release (just leave it unset)");
        } else {
            rsc_private->stickiness = char2score(value);
        }
    }

    value = g_hash_table_lookup((*rsc)->meta, PCMK_META_MIGRATION_THRESHOLD);
    if (value != NULL) {
        if (pcmk__str_eq(PCMK_VALUE_DEFAULT, value, pcmk__str_casei)) {
            // @COMPAT Deprecated since 2.1.8
            pcmk__config_warn("Support for setting "
                              PCMK_META_MIGRATION_THRESHOLD
                              " to the explicit value '" PCMK_VALUE_DEFAULT
                              "' is deprecated and will be removed in a "
                              "future release (just leave it unset)");
        } else {
            rsc_private->ban_after_failures = char2score(value);
            if (rsc_private->ban_after_failures < 0) {
                /* @COMPAT We use 1 here to preserve previous behavior, but this
                 * should probably use the default (INFINITY) or 0 (to disable)
                 * instead.
                 */
                pcmk__warn_once(pcmk__wo_neg_threshold,
                                PCMK_META_MIGRATION_THRESHOLD
                                " must be non-negative, using 1 instead");
                rsc_private->ban_after_failures = 1;
            }
        }
    }

    if (pcmk__str_eq(crm_element_value(rsc_private->xml, PCMK_XA_CLASS),
                     PCMK_RESOURCE_CLASS_STONITH, pcmk__str_casei)) {
        pcmk__set_scheduler_flags(scheduler, pcmk_sched_have_fencing);
        pcmk__set_rsc_flags(*rsc, pcmk__rsc_fence_device);
    }

    value = g_hash_table_lookup((*rsc)->meta, PCMK_META_REQUIRES);
    unpack_requires(*rsc, value, false);

    value = g_hash_table_lookup((*rsc)->meta, PCMK_META_FAILURE_TIMEOUT);
    if (value != NULL) {
        pcmk_parse_interval_spec(value, &(rsc_private->failure_expiration_ms));
    }

    if (remote_node) {
        GHashTable *params = pe_rsc_params(*rsc, NULL, scheduler);

        /* Grabbing the value now means that any rules based on node attributes
         * will evaluate to false, so such rules should not be used with
         * PCMK_REMOTE_RA_RECONNECT_INTERVAL.
         *
         * @TODO Evaluate per node before using
         */
        value = g_hash_table_lookup(params, PCMK_REMOTE_RA_RECONNECT_INTERVAL);
        if (value) {
            /* reconnect delay works by setting failure_timeout and preventing the
             * connection from starting until the failure is cleared. */
            pcmk_parse_interval_spec(value,
                                     &(rsc_private->remote_reconnect_ms));

            /* We want to override any default failure_timeout in use when remote
             * PCMK_REMOTE_RA_RECONNECT_INTERVAL is in use.
             */
            rsc_private->failure_expiration_ms =
                rsc_private->remote_reconnect_ms;
        }
    }

    get_target_role(*rsc, &(rsc_private->next_role));
    pcmk__rsc_trace(*rsc, "%s desired next state: %s", (*rsc)->id,
                    (rsc_private->next_role == pcmk_role_unknown)?
                        "default" : pcmk_role_text(rsc_private->next_role));

    if (rsc_private->fns->unpack(*rsc, scheduler) == FALSE) {
        rsc_private->fns->free(*rsc);
        *rsc = NULL;
        return pcmk_rc_unpack_error;
    }

    if (pcmk_is_set(scheduler->flags, pcmk_sched_symmetric_cluster)) {
        // This tag must stay exactly the same because it is tested elsewhere
        resource_location(*rsc, NULL, 0, "symmetric_default", scheduler);
    } else if (guest_node) {
        /* remote resources tied to a container resource must always be allowed
         * to opt-in to the cluster. Whether the connection resource is actually
         * allowed to be placed on a node is dependent on the container resource */
        resource_location(*rsc, NULL, 0, "remote_connection_default",
                          scheduler);
    }

    pcmk__rsc_trace(*rsc, "%s action notification: %s", (*rsc)->id,
                    pcmk_is_set((*rsc)->flags, pcmk__rsc_notify)? "required" : "not required");

    (*rsc)->utilization = pcmk__strkey_table(free, free);

    pe__unpack_dataset_nvpairs(rsc_private->xml, PCMK_XE_UTILIZATION,
                               &rule_data, (*rsc)->utilization, NULL, FALSE,
                               scheduler);

    if (expanded_xml) {
        if (add_template_rsc(xml_obj, scheduler) == FALSE) {
            rsc_private->fns->free(*rsc);
            *rsc = NULL;
            return pcmk_rc_unpack_error;
        }
    }
    return pcmk_rc_ok;
}

gboolean
is_parent(pcmk_resource_t *child, pcmk_resource_t *rsc)
{
    pcmk_resource_t *parent = child;

    if (parent == NULL || rsc == NULL) {
        return FALSE;
    }
    while (parent->private->parent != NULL) {
        if (parent->private->parent == rsc) {
            return TRUE;
        }
        parent = parent->private->parent;
    }
    return FALSE;
}

pcmk_resource_t *
uber_parent(pcmk_resource_t *rsc)
{
    pcmk_resource_t *parent = rsc;

    if (parent == NULL) {
        return NULL;
    }
    while ((parent->private->parent != NULL)
           && !pcmk__is_bundle(parent->private->parent)) {
        parent = parent->private->parent;
    }
    return parent;
}

/*!
 * \internal
 * \brief Get the topmost parent of a resource as a const pointer
 *
 * \param[in] rsc             Resource to check
 * \param[in] include_bundle  If true, go all the way to bundle
 *
 * \return \p NULL if \p rsc is NULL, \p rsc if \p rsc has no parent,
 *         the bundle if \p rsc is bundled and \p include_bundle is true,
 *         otherwise the topmost parent of \p rsc up to a clone
 */
const pcmk_resource_t *
pe__const_top_resource(const pcmk_resource_t *rsc, bool include_bundle)
{
    const pcmk_resource_t *parent = rsc;

    if (parent == NULL) {
        return NULL;
    }
    while (parent->private->parent != NULL) {
        if (!include_bundle && pcmk__is_bundle(parent->private->parent)) {
            break;
        }
        parent = parent->private->parent;
    }
    return parent;
}

void
common_free(pcmk_resource_t * rsc)
{
    if (rsc == NULL) {
        return;
    }

    pcmk__rsc_trace(rsc, "Freeing %s %s",
                    (const char *) rsc->private->xml->name, rsc->id);

    g_list_free(rsc->dangling_migrations);

    if (rsc->parameter_cache != NULL) {
        g_hash_table_destroy(rsc->parameter_cache);
    }
    if (rsc->meta != NULL) {
        g_hash_table_destroy(rsc->meta);
    }
    if (rsc->utilization != NULL) {
        g_hash_table_destroy(rsc->utilization);
    }

    if ((rsc->private->parent == NULL)
        && pcmk_is_set(rsc->flags, pcmk__rsc_removed)) {

        pcmk__xml_free(rsc->private->xml);
        rsc->private->xml = NULL;
        pcmk__xml_free(rsc->private->orig_xml);
        rsc->private->orig_xml = NULL;

    } else if (rsc->private->orig_xml != NULL) {
        // rsc->private->xml was expanded from a template
        pcmk__xml_free(rsc->private->xml);
        rsc->private->xml = NULL;
    }
    g_list_free(rsc->fillers);
    free(rsc->id);

    free(rsc->private->variant_opaque);
    free(rsc->private->history_id);
    free(rsc->private->pending_action);
    free(rsc->private->assigned_node);
    g_list_free(rsc->private->actions);
    g_list_free(rsc->private->active_nodes);
    g_list_free(rsc->private->with_this_colocations);
    g_list_free(rsc->private->this_with_colocations);
    g_list_free(rsc->private->location_constraints);
    g_list_free(rsc->private->ticket_constraints);
    if (rsc->private->probed_nodes != NULL) {
        g_hash_table_destroy(rsc->private->probed_nodes);
    }
    if (rsc->private->allowed_nodes != NULL) {
        g_hash_table_destroy(rsc->private->allowed_nodes);
    }
    free(rsc->private);

    free(rsc);
}

/*!
 * \internal
 * \brief Count a node and update most preferred to it as appropriate
 *
 * \param[in]     rsc          An active resource
 * \param[in]     node         A node that \p rsc is active on
 * \param[in,out] active       This will be set to \p node if \p node is more
 *                             preferred than the current value
 * \param[in,out] count_all    If not NULL, this will be incremented
 * \param[in,out] count_clean  If not NULL, this will be incremented if \p node
 *                             is online and clean
 *
 * \return true if the count should continue, or false if sufficiently known
 */
bool
pe__count_active_node(const pcmk_resource_t *rsc, pcmk_node_t *node,
                      pcmk_node_t **active, unsigned int *count_all,
                      unsigned int *count_clean)
{
    bool keep_looking = false;
    bool is_happy = false;

    CRM_CHECK((rsc != NULL) && (node != NULL) && (active != NULL),
              return false);

    is_happy = node->details->online && !node->details->unclean;

    if (count_all != NULL) {
        ++*count_all;
    }
    if ((count_clean != NULL) && is_happy) {
        ++*count_clean;
    }
    if ((count_all != NULL) || (count_clean != NULL)) {
        keep_looking = true; // We're counting, so go through entire list
    }

    if (rsc->private->partial_migration_source != NULL) {
        if (pcmk__same_node(node, rsc->private->partial_migration_source)) {
            *active = node; // This is the migration source
        } else {
            keep_looking = true;
        }
    } else if (!pcmk_is_set(rsc->flags, pcmk__rsc_needs_fencing)) {
        if (is_happy && ((*active == NULL) || !(*active)->details->online
                         || (*active)->details->unclean)) {
            *active = node; // This is the first clean node
        } else {
            keep_looking = true;
        }
    }
    if (*active == NULL) {
        *active = node; // This is the first node checked
    }
    return keep_looking;
}

// Shared implementation of pcmk__rsc_methods_t:active_node()
static pcmk_node_t *
active_node(const pcmk_resource_t *rsc, unsigned int *count_all,
            unsigned int *count_clean)
{
    pcmk_node_t *active = NULL;

    if (count_all != NULL) {
        *count_all = 0;
    }
    if (count_clean != NULL) {
        *count_clean = 0;
    }
    if (rsc == NULL) {
        return NULL;
    }
    for (GList *iter = rsc->private->active_nodes;
         iter != NULL; iter = iter->next) {

        if (!pe__count_active_node(rsc, (pcmk_node_t *) iter->data, &active,
                                   count_all, count_clean)) {
            break; // Don't waste time iterating if we don't have to
        }
    }
    return active;
}

/*!
 * \brief
 * \internal Find and count active nodes according to \c PCMK_META_REQUIRES
 *
 * \param[in]  rsc    Resource to check
 * \param[out] count  If not NULL, will be set to count of active nodes
 *
 * \return An active node (or NULL if resource is not active anywhere)
 *
 * \note This is a convenience wrapper for active_node() where the count of all
 *       active nodes or only clean active nodes is desired according to the
 *       \c PCMK_META_REQUIRES meta-attribute.
 */
pcmk_node_t *
pe__find_active_requires(const pcmk_resource_t *rsc, unsigned int *count)
{
    if (rsc == NULL) {
        if (count != NULL) {
            *count = 0;
        }
        return NULL;
    }

    if (pcmk_is_set(rsc->flags, pcmk__rsc_needs_fencing)) {
        return rsc->private->fns->active_node(rsc, count, NULL);
    } else {
        return rsc->private->fns->active_node(rsc, NULL, count);
    }
}

void
pe__count_common(pcmk_resource_t *rsc)
{
    if (rsc->children != NULL) {
        for (GList *item = rsc->children; item != NULL; item = item->next) {
            pcmk_resource_t *child = item->data;

            child->private->fns->count(item->data);
        }

    } else if (!pcmk_is_set(rsc->flags, pcmk__rsc_removed)
               || (rsc->private->orig_role > pcmk_role_stopped)) {
        rsc->private->scheduler->ninstances++;
        if (pe__resource_is_disabled(rsc)) {
            rsc->private->scheduler->disabled_resources++;
        }
        if (pcmk_is_set(rsc->flags, pcmk__rsc_blocked)) {
            rsc->private->scheduler->blocked_resources++;
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
pe__set_next_role(pcmk_resource_t *rsc, enum rsc_role_e role, const char *why)
{
    CRM_ASSERT((rsc != NULL) && (why != NULL));
    if (rsc->private->next_role != role) {
        pcmk__rsc_trace(rsc, "Resetting next role for %s from %s to %s (%s)",
                        rsc->id, pcmk_role_text(rsc->private->next_role),
                        pcmk_role_text(role), why);
        rsc->private->next_role = role;
    }
}
