/*
 * Copyright 2004-2020 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/pengine/rules.h>
#include <crm/pengine/status.h>
#include <crm/pengine/complex.h>
#include <crm/pengine/internal.h>
#include <crm/msg_xml.h>
#include <pe_status_private.h>

#define VARIANT_NATIVE 1
#include "./variant.h"

/*!
 * \internal
 * \brief Check whether a resource is active on multiple nodes
 */
static bool
is_multiply_active(pe_resource_t *rsc)
{
    unsigned int count = 0;

    if (rsc->variant == pe_native) {
        pe__find_active_requires(rsc, &count);
    }
    return count > 1;
}

static void
native_priority_to_node(pe_resource_t * rsc, pe_node_t * node)
{
    int priority = 0;

    if (rsc->priority == 0) {
        return;
    }

    if (rsc->role == RSC_ROLE_MASTER) {
        // Promoted instance takes base priority + 1
        priority = rsc->priority + 1;

    } else {
        priority = rsc->priority;
    }

    node->details->priority += priority;
    pe_rsc_trace(rsc, "Node '%s' now has priority %d with %s'%s' (priority: %d%s)",
                 node->details->uname, node->details->priority,
                 rsc->role == RSC_ROLE_MASTER ? "promoted " : "",
                 rsc->id, rsc->priority,
                 rsc->role == RSC_ROLE_MASTER ? " + 1" : "");

    /* Priority of a resource running on a guest node is added to the cluster
     * node as well. */
    if (node->details->remote_rsc
        && node->details->remote_rsc->container) {
        GListPtr gIter = node->details->remote_rsc->container->running_on;

        for (; gIter != NULL; gIter = gIter->next) {
            pe_node_t *a_node = gIter->data;

            a_node->details->priority += priority;
            pe_rsc_trace(rsc, "Node '%s' now has priority %d with %s'%s' (priority: %d%s) "
                         "from guest node '%s'",
                         a_node->details->uname, a_node->details->priority,
                         rsc->role == RSC_ROLE_MASTER ? "promoted " : "",
                         rsc->id, rsc->priority,
                         rsc->role == RSC_ROLE_MASTER ? " + 1" : "",
                         node->details->uname);
        }
    }
}

void
native_add_running(pe_resource_t * rsc, pe_node_t * node, pe_working_set_t * data_set)
{
    GListPtr gIter = rsc->running_on;

    CRM_CHECK(node != NULL, return);
    for (; gIter != NULL; gIter = gIter->next) {
        pe_node_t *a_node = (pe_node_t *) gIter->data;

        CRM_CHECK(a_node != NULL, return);
        if (safe_str_eq(a_node->details->id, node->details->id)) {
            return;
        }
    }

    pe_rsc_trace(rsc, "Adding %s to %s %s", rsc->id, node->details->uname,
                 is_set(rsc->flags, pe_rsc_managed)?"":"(unmanaged)");

    rsc->running_on = g_list_append(rsc->running_on, node);
    if (rsc->variant == pe_native) {
        node->details->running_rsc = g_list_append(node->details->running_rsc, rsc);

        native_priority_to_node(rsc, node);
    }

    if (rsc->variant == pe_native && node->details->maintenance) {
        clear_bit(rsc->flags, pe_rsc_managed);
    }

    if (is_not_set(rsc->flags, pe_rsc_managed)) {
        pe_resource_t *p = rsc->parent;

        pe_rsc_info(rsc, "resource %s isn't managed", rsc->id);
        resource_location(rsc, node, INFINITY, "not_managed_default", data_set);

        while(p && node->details->online) {
            /* add without the additional location constraint */
            p->running_on = g_list_append(p->running_on, node);
            p = p->parent;
        }
        return;
    }

    if (is_multiply_active(rsc)) {
        switch (rsc->recovery_type) {
            case recovery_stop_only:
                {
                    GHashTableIter gIter;
                    pe_node_t *local_node = NULL;

                    /* make sure it doesn't come up again */
                    if (rsc->allowed_nodes != NULL) {
                        g_hash_table_destroy(rsc->allowed_nodes);
                    }
                    rsc->allowed_nodes = pe__node_list2table(data_set->nodes);
                    g_hash_table_iter_init(&gIter, rsc->allowed_nodes);
                    while (g_hash_table_iter_next(&gIter, NULL, (void **)&local_node)) {
                        local_node->weight = -INFINITY;
                    }
                }
                break;
            case recovery_stop_start:
                break;
            case recovery_block:
                clear_bit(rsc->flags, pe_rsc_managed);
                set_bit(rsc->flags, pe_rsc_block);

                /* If the resource belongs to a group or bundle configured with
                 * multiple-active=block, block the entire entity.
                 */
                if (rsc->parent
                    && (rsc->parent->variant == pe_group || rsc->parent->variant == pe_container)
                    && rsc->parent->recovery_type == recovery_block) {
                    GListPtr gIter = rsc->parent->children;

                    for (; gIter != NULL; gIter = gIter->next) {
                        pe_resource_t *child = (pe_resource_t *) gIter->data;

                        clear_bit(child->flags, pe_rsc_managed);
                        set_bit(child->flags, pe_rsc_block);
                    }
                }
                break;
        }
        crm_debug("%s is active on multiple nodes including %s: %s",
                  rsc->id, node->details->uname,
                  recovery2text(rsc->recovery_type));

    } else {
        pe_rsc_trace(rsc, "Resource %s is active on: %s", rsc->id, node->details->uname);
    }

    if (rsc->parent != NULL) {
        native_add_running(rsc->parent, node, data_set);
    }
}

static void
recursive_clear_unique(pe_resource_t *rsc)
{
    clear_bit(rsc->flags, pe_rsc_unique);
    add_hash_param(rsc->meta, XML_RSC_ATTR_UNIQUE, XML_BOOLEAN_FALSE);

    for (GList *child = rsc->children; child != NULL; child = child->next) {
        recursive_clear_unique((pe_resource_t *) child->data);
    }
}

gboolean
native_unpack(pe_resource_t * rsc, pe_working_set_t * data_set)
{
    pe_resource_t *parent = uber_parent(rsc);
    native_variant_data_t *native_data = NULL;
    const char *standard = crm_element_value(rsc->xml, XML_AGENT_ATTR_CLASS);
    uint32_t ra_caps = pcmk_get_ra_caps(standard);

    pe_rsc_trace(rsc, "Processing resource %s...", rsc->id);

    native_data = calloc(1, sizeof(native_variant_data_t));
    rsc->variant_opaque = native_data;

    // Only some agent standards support unique and promotable clones
    if (is_not_set(ra_caps, pcmk_ra_cap_unique)
        && is_set(rsc->flags, pe_rsc_unique) && pe_rsc_is_clone(parent)) {

        /* @COMPAT We should probably reject this situation as an error (as we
         * do for promotable below) rather than warn and convert, but that would
         * be a backward-incompatible change that we should probably do with a
         * transform at a schema major version bump.
         */
        pe__force_anon(standard, parent, rsc->id, data_set);

        /* Clear globally-unique on the parent and all its descendents unpacked
         * so far (clearing the parent should make any future children unpacking
         * correct). We have to clear this resource explicitly because it isn't
         * hooked into the parent's children yet.
         */
        recursive_clear_unique(parent);
        recursive_clear_unique(rsc);
    }
    if (is_not_set(ra_caps, pcmk_ra_cap_promotable)
        && is_set(parent->flags, pe_rsc_promotable)) {

        pe_err("Resource %s is of type %s and therefore "
               "cannot be used as a promotable clone resource",
               rsc->id, standard);
        return FALSE;
    }
    return TRUE;
}

static bool
rsc_is_on_node(pe_resource_t *rsc, const pe_node_t *node, int flags)
{
    pe_rsc_trace(rsc, "Checking whether %s is on %s",
                 rsc->id, node->details->uname);

    if (is_set(flags, pe_find_current) && rsc->running_on) {

        for (GListPtr iter = rsc->running_on; iter; iter = iter->next) {
            pe_node_t *loc = (pe_node_t *) iter->data;

            if (loc->details == node->details) {
                return TRUE;
            }
        }

    } else if (is_set(flags, pe_find_inactive) && (rsc->running_on == NULL)) {
        return TRUE;

    } else if (is_not_set(flags, pe_find_current) && rsc->allocated_to
               && (rsc->allocated_to->details == node->details)) {
        return TRUE;
    }
    return FALSE;
}

pe_resource_t *
native_find_rsc(pe_resource_t * rsc, const char *id, const pe_node_t *on_node,
                int flags)
{
    bool match = FALSE;
    pe_resource_t *result = NULL;

    CRM_CHECK(id && rsc && rsc->id, return NULL);

    if (flags & pe_find_clone) {
        const char *rid = ID(rsc->xml);

        if (!pe_rsc_is_clone(uber_parent(rsc))) {
            match = FALSE;

        } else if (!strcmp(id, rsc->id) || safe_str_eq(id, rid)) {
            match = TRUE;
        }

    } else if (!strcmp(id, rsc->id)) {
        match = TRUE;

    } else if (is_set(flags, pe_find_renamed)
               && rsc->clone_name && strcmp(rsc->clone_name, id) == 0) {
        match = TRUE;

    } else if (is_set(flags, pe_find_any)
               || (is_set(flags, pe_find_anon)
                   && is_not_set(rsc->flags, pe_rsc_unique))) {
        match = pe_base_name_eq(rsc, id);
    }

    if (match && on_node) {
        bool match_node = rsc_is_on_node(rsc, on_node, flags);

        if (match_node == FALSE) {
            match = FALSE;
        }
    }

    if (match) {
        return rsc;
    }

    for (GListPtr gIter = rsc->children; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *child = (pe_resource_t *) gIter->data;

        result = rsc->fns->find_rsc(child, id, on_node, flags);
        if (result) {
            return result;
        }
    }
    return NULL;
}

char *
native_parameter(pe_resource_t * rsc, pe_node_t * node, gboolean create, const char *name,
                 pe_working_set_t * data_set)
{
    char *value_copy = NULL;
    const char *value = NULL;
    GHashTable *hash = NULL;
    GHashTable *local_hash = NULL;

    CRM_CHECK(rsc != NULL, return NULL);
    CRM_CHECK(name != NULL && strlen(name) != 0, return NULL);

    pe_rsc_trace(rsc, "Looking up %s in %s", name, rsc->id);

    if (create || g_hash_table_size(rsc->parameters) == 0) {
        if (node != NULL) {
            pe_rsc_trace(rsc, "Creating hash with node %s", node->details->uname);
        } else {
            pe_rsc_trace(rsc, "Creating default hash");
        }

        local_hash = crm_str_table_new();

        get_rsc_attributes(local_hash, rsc, node, data_set);

        hash = local_hash;
    } else {
        hash = rsc->parameters;
    }

    value = g_hash_table_lookup(hash, name);
    if (value == NULL) {
        /* try meta attributes instead */
        value = g_hash_table_lookup(rsc->meta, name);
    }

    if (value != NULL) {
        value_copy = strdup(value);
    }
    if (local_hash != NULL) {
        g_hash_table_destroy(local_hash);
    }
    return value_copy;
}

gboolean
native_active(pe_resource_t * rsc, gboolean all)
{
    for (GList *gIter = rsc->running_on; gIter != NULL; gIter = gIter->next) {
        pe_node_t *a_node = (pe_node_t *) gIter->data;

        if (a_node->details->unclean) {
            pe_rsc_trace(rsc, "Resource %s: node %s is unclean",
                         rsc->id, a_node->details->uname);
            return TRUE;
        } else if (a_node->details->online == FALSE) {
            pe_rsc_trace(rsc, "Resource %s: node %s is offline",
                         rsc->id, a_node->details->uname);
        } else {
            pe_rsc_trace(rsc, "Resource %s active on %s",
                         rsc->id, a_node->details->uname);
            return TRUE;
        }
    }
    return FALSE;
}

struct print_data_s {
    long options;
    void *print_data;
};

static void
native_print_attr(gpointer key, gpointer value, gpointer user_data)
{
    long options = ((struct print_data_s *)user_data)->options;
    void *print_data = ((struct print_data_s *)user_data)->print_data;

    status_print("Option: %s = %s\n", (char *)key, (char *)value);
}

static const char *
native_pending_state(pe_resource_t * rsc)
{
    const char *pending_state = NULL;

    if (safe_str_eq(rsc->pending_task, CRMD_ACTION_START)) {
        pending_state = "Starting";

    } else if (safe_str_eq(rsc->pending_task, CRMD_ACTION_STOP)) {
        pending_state = "Stopping";

    } else if (safe_str_eq(rsc->pending_task, CRMD_ACTION_MIGRATE)) {
        pending_state = "Migrating";

    } else if (safe_str_eq(rsc->pending_task, CRMD_ACTION_MIGRATED)) {
       /* Work might be done in here. */
        pending_state = "Migrating";

    } else if (safe_str_eq(rsc->pending_task, CRMD_ACTION_PROMOTE)) {
        pending_state = "Promoting";

    } else if (safe_str_eq(rsc->pending_task, CRMD_ACTION_DEMOTE)) {
        pending_state = "Demoting";
    }

    return pending_state;
}

static const char *
native_pending_task(pe_resource_t * rsc)
{
    const char *pending_task = NULL;

    if (safe_str_eq(rsc->pending_task, CRMD_ACTION_STATUS)) {
        pending_task = "Monitoring";

    /* Pending probes are not printed, even if pending
     * operations are requested. If someone ever requests that
     * behavior, uncomment this and the corresponding part of
     * unpack.c:unpack_rsc_op().
     */
    /*
    } else if (safe_str_eq(rsc->pending_task, "probe")) {
        pending_task = "Checking";
    */
    }

    return pending_task;
}

static enum rsc_role_e
native_displayable_role(pe_resource_t *rsc)
{
    enum rsc_role_e role = rsc->role;

    if ((role == RSC_ROLE_STARTED)
        && is_set(uber_parent(rsc)->flags, pe_rsc_promotable)) {

        role = RSC_ROLE_SLAVE;
    }
    return role;
}

static const char *
native_displayable_state(pe_resource_t *rsc, long options)
{
    const char *rsc_state = NULL;

    if (options & pe_print_pending) {
        rsc_state = native_pending_state(rsc);
    }
    if (rsc_state == NULL) {
        rsc_state = role2text(native_displayable_role(rsc));
    }
    return rsc_state;
}

static void
native_print_xml(pe_resource_t * rsc, const char *pre_text, long options, void *print_data)
{
    const char *class = crm_element_value(rsc->xml, XML_AGENT_ATTR_CLASS);
    const char *prov = crm_element_value(rsc->xml, XML_AGENT_ATTR_PROVIDER);
    const char *rsc_state = native_displayable_state(rsc, options);
    const char *target_role = NULL;

    /* resource information. */
    status_print("%s<resource ", pre_text);
    status_print("id=\"%s\" ", rsc_printable_id(rsc));
    status_print("resource_agent=\"%s%s%s:%s\" ",
                 class,
                 prov ? "::" : "", prov ? prov : "", crm_element_value(rsc->xml, XML_ATTR_TYPE));

    status_print("role=\"%s\" ", rsc_state);
    if (rsc->meta) {
        target_role = g_hash_table_lookup(rsc->meta, XML_RSC_ATTR_TARGET_ROLE);
    }
    if (target_role) {
        status_print("target_role=\"%s\" ", target_role);
    }
    status_print("active=\"%s\" ", rsc->fns->active(rsc, TRUE) ? "true" : "false");
    status_print("orphaned=\"%s\" ", is_set(rsc->flags, pe_rsc_orphan) ? "true" : "false");
    status_print("blocked=\"%s\" ", is_set(rsc->flags, pe_rsc_block) ? "true" : "false");
    status_print("managed=\"%s\" ", is_set(rsc->flags, pe_rsc_managed) ? "true" : "false");
    status_print("failed=\"%s\" ", is_set(rsc->flags, pe_rsc_failed) ? "true" : "false");
    status_print("failure_ignored=\"%s\" ",
                 is_set(rsc->flags, pe_rsc_failure_ignored) ? "true" : "false");
    status_print("nodes_running_on=\"%d\" ", g_list_length(rsc->running_on));

    if (options & pe_print_pending) {
        const char *pending_task = native_pending_task(rsc);

        if (pending_task) {
            status_print("pending=\"%s\" ", pending_task);
        }
    }

    if (options & pe_print_dev) {
        status_print("provisional=\"%s\" ",
                     is_set(rsc->flags, pe_rsc_provisional) ? "true" : "false");
        status_print("runnable=\"%s\" ", is_set(rsc->flags, pe_rsc_runnable) ? "true" : "false");
        status_print("priority=\"%f\" ", (double)rsc->priority);
        status_print("variant=\"%s\" ", crm_element_name(rsc->xml));
    }

    /* print out the nodes this resource is running on */
    if (options & pe_print_rsconly) {
        status_print("/>\n");
        /* do nothing */
    } else if (rsc->running_on != NULL) {
        GListPtr gIter = rsc->running_on;

        status_print(">\n");
        for (; gIter != NULL; gIter = gIter->next) {
            pe_node_t *node = (pe_node_t *) gIter->data;

            status_print("%s    <node name=\"%s\" id=\"%s\" cached=\"%s\"/>\n", pre_text,
                         node->details->uname, node->details->id,
                         node->details->online ? "false" : "true");
        }
        status_print("%s</resource>\n", pre_text);
    } else {
        status_print("/>\n");
    }
}

// Append a flag to resource description string's flags list
static bool
add_output_flag(GString *s, const char *flag_desc, bool have_flags)
{
    g_string_append(s, (have_flags? ", " : " ("));
    g_string_append(s, flag_desc);
    return true;
}

// Append a node name to resource description string's node list
static bool
add_output_node(GString *s, const char *node, bool have_nodes)
{
    g_string_append(s, (have_nodes? " " : " [ "));
    g_string_append(s, node);
    return true;
}

/*!
 * \internal
 * \brief Create a string description of a resource
 *
 * \param[in] rsc          Resource to describe
 * \param[in] name         Desired identifier for the resource
 * \param[in] node         If not NULL, node that resource is "on"
 * \param[in] options      Bitmask of pe_print_*
 * \param[in] target_role  Resource's target role
 * \param[in] show_nodes   Whether to display nodes when multiply active
 *
 * \return Newly allocated string description of resource
 * \note Caller must free the result with g_free().
 */
static gchar *
native_output_string(pe_resource_t *rsc, const char *name, pe_node_t *node,
                     long options, const char *target_role, bool show_nodes)
{
    const char *class = crm_element_value(rsc->xml, XML_AGENT_ATTR_CLASS);
    const char *provider = NULL;
    const char *kind = crm_element_value(rsc->xml, XML_ATTR_TYPE);
    char *retval = NULL;
    GString *outstr = NULL;
    bool have_flags = false;

    CRM_CHECK(name != NULL, name = "unknown");
    CRM_CHECK(kind != NULL, kind = "unknown");
    CRM_CHECK(class != NULL, class = "unknown");

    if (is_set(pcmk_get_ra_caps(class), pcmk_ra_cap_provider)) {
        provider = crm_element_value(rsc->xml, XML_AGENT_ATTR_PROVIDER);
    }

    if ((node == NULL) && (rsc->lock_node != NULL)) {
        node = rsc->lock_node;
    }
    if (is_set(options, pe_print_rsconly)
        || pcmk__list_of_multiple(rsc->running_on)) {
        node = NULL;
    }

    // We need a string of at least this size
    outstr = g_string_sized_new(strlen(name) + strlen(class) + strlen(kind)
                                + (provider? (strlen(provider) + 2) : 0)
                                + (node? strlen(node->details->uname) + 1 : 0)
                                + 11);

    // Resource name and agent
    g_string_printf(outstr, "%s\t(%s%s%s:%s):\t", name, class,
                    /* @COMPAT This should be a single ':' (see CLBZ#5395) but
                     * to avoid breaking anything relying on it, we're keeping
                     * it like this until the next minor version bump.
                     */
                    (provider? "::" : ""), (provider? provider : ""), kind);

    // State on node
    if (is_set(rsc->flags, pe_rsc_orphan)) {
        g_string_append(outstr, " ORPHANED");
    }
    if (is_set(rsc->flags, pe_rsc_failed)) {
        enum rsc_role_e role = native_displayable_role(rsc);

        if (role > RSC_ROLE_SLAVE) {
            g_string_append_printf(outstr, " FAILED %s", role2text(role));
        } else {
            g_string_append(outstr, " FAILED");
        }
    } else {
        g_string_append_printf(outstr, " %s", native_displayable_state(rsc, options));
    }
    if (node) {
        g_string_append_printf(outstr, " %s", node->details->uname);
    }

    // Flags, as: (<flag> [...])
    if (node && !(node->details->online) && node->details->unclean) {
        have_flags = add_output_flag(outstr, "UNCLEAN", have_flags);
    }
    if (node && (node == rsc->lock_node)) {
        have_flags = add_output_flag(outstr, "LOCKED", have_flags);
    }
    if (is_set(options, pe_print_pending)) {
        const char *pending_task = native_pending_task(rsc);

        if (pending_task) {
            have_flags = add_output_flag(outstr, pending_task, have_flags);
        }
    }
    if (target_role) {
        enum rsc_role_e target_role_e = text2role(target_role);

        /* Only show target role if it limits our abilities (i.e. ignore
         * Started, as it is the default anyways, and doesn't prevent the
         * resource from becoming Master).
         */
        if (target_role_e == RSC_ROLE_STOPPED) {
            have_flags = add_output_flag(outstr, "disabled", have_flags);

        } else if (is_set(uber_parent(rsc)->flags, pe_rsc_promotable)
                   && target_role_e == RSC_ROLE_SLAVE) {
            have_flags = add_output_flag(outstr, "target-role:", have_flags);
            g_string_append(outstr, target_role);
        }
    }
    if (is_set(rsc->flags, pe_rsc_block)) {
        have_flags = add_output_flag(outstr, "blocked", have_flags);
    } else if (is_not_set(rsc->flags, pe_rsc_managed)) {
        have_flags = add_output_flag(outstr, "unmanaged", have_flags);
    }
    if (is_set(rsc->flags, pe_rsc_failure_ignored)) {
        have_flags = add_output_flag(outstr, "failure ignored", have_flags);
    }
    if (is_set(options, pe_print_dev)) {
        if (is_set(options, pe_rsc_provisional)) {
            have_flags = add_output_flag(outstr, "provisional", have_flags);
        }
        if (is_not_set(options, pe_rsc_runnable)) {
            have_flags = add_output_flag(outstr, "non-startable", have_flags);
        }
        have_flags = add_output_flag(outstr, "variant:", have_flags);
        g_string_append_printf(outstr, "%s priority:%f",
                                       crm_element_name(rsc->xml),
                                       (double) (rsc->priority));
    }
    if (have_flags) {
        g_string_append(outstr, ")");
    }

    // User-supplied description
    if (is_set(options, pe_print_rsconly)
        || pcmk__list_of_multiple(rsc->running_on)) {
        const char *desc = crm_element_value(rsc->xml, XML_ATTR_DESC);

        if (desc) {
            g_string_append_printf(outstr, " %s", desc);
        }
    }

    if (show_nodes && is_not_set(options, pe_print_rsconly)
        && pcmk__list_of_multiple(rsc->running_on)) {
        bool have_nodes = false;

        for (GList *iter = rsc->running_on; iter != NULL; iter = iter->next) {
            pe_node_t *n = (pe_node_t *) iter->data;

            have_nodes = add_output_node(outstr, n->details->uname, have_nodes);
        }
        if (have_nodes) {
            g_string_append(outstr, " ]");
        }
    }

    retval = outstr->str;
    g_string_free(outstr, FALSE);
    return retval;
}

int
pe__common_output_html(pcmk__output_t *out, pe_resource_t * rsc,
                       const char *name, pe_node_t *node, long options)
{
    const char *kind = crm_element_value(rsc->xml, XML_ATTR_TYPE);
    const char *target_role = NULL;

    xmlNodePtr list_node = NULL;
    const char *cl = NULL;

    CRM_ASSERT(rsc->variant == pe_native);
    CRM_ASSERT(kind != NULL);

    if (rsc->meta) {
        const char *is_internal = g_hash_table_lookup(rsc->meta, XML_RSC_ATTR_INTERNAL_RSC);
        if (crm_is_true(is_internal) && is_not_set(options, pe_print_implicit)) {
            crm_trace("skipping print of internal resource %s", rsc->id);
            return pcmk_rc_no_output;
        }
        target_role = g_hash_table_lookup(rsc->meta, XML_RSC_ATTR_TARGET_ROLE);
    }

    if (is_not_set(rsc->flags, pe_rsc_managed)) {
        cl = "rsc-managed";

    } else if (is_set(rsc->flags, pe_rsc_failed)) {
        cl = "rsc-failed";

    } else if (rsc->variant == pe_native && (rsc->running_on == NULL)) {
        cl = "rsc-failed";

    } else if (pcmk__list_of_multiple(rsc->running_on)) {
        cl = "rsc-multiple";

    } else if (is_set(rsc->flags, pe_rsc_failure_ignored)) {
        cl = "rsc-failure-ignored";

    } else {
        cl = "rsc-ok";
    }

    {
        gchar *s = native_output_string(rsc, name, node, options, target_role,
                                        true);

        list_node = pcmk__output_create_html_node(out, "li", NULL, NULL, NULL);
        pcmk_create_html_node(list_node, "span", NULL, cl, s);
        g_free(s);
    }

    if (is_set(options, pe_print_details)) {
        GHashTableIter iter;
        gpointer key, value;

        out->begin_list(out, NULL, NULL, "Options");
        g_hash_table_iter_init(&iter, rsc->parameters);
        while (g_hash_table_iter_next(&iter, &key, &value)) {
            out->list_item(out, NULL, "Option: %s = %s", (char *) key, (char *) value);
        }
        out->end_list(out);
    }

    if (is_set(options, pe_print_dev)) {
        GHashTableIter iter;
        pe_node_t *n = NULL;

        out->begin_list(out, NULL, NULL, "Allowed Nodes");
        g_hash_table_iter_init(&iter, rsc->allowed_nodes);
        while (g_hash_table_iter_next(&iter, NULL, (void **)&n)) {
            out->list_item(out, NULL, "%s %d", n->details->uname, n->weight);
        }
        out->end_list(out);
    }

    if (is_set(options, pe_print_max_details)) {
        GHashTableIter iter;
        pe_node_t *n = NULL;

        out->begin_list(out, NULL, NULL, "=== Allowed Nodes");
        g_hash_table_iter_init(&iter, rsc->allowed_nodes);
        while (g_hash_table_iter_next(&iter, NULL, (void **)&n)) {
            pe__output_node(n, FALSE, out);
        }
        out->end_list(out);
    }

    return pcmk_rc_ok;
}

int
pe__common_output_text(pcmk__output_t *out, pe_resource_t * rsc,
                       const char *name, pe_node_t *node, long options)
{
    const char *target_role = NULL;

    CRM_ASSERT(rsc->variant == pe_native);

    if (rsc->meta) {
        const char *is_internal = g_hash_table_lookup(rsc->meta, XML_RSC_ATTR_INTERNAL_RSC);
        if (crm_is_true(is_internal) && is_not_set(options, pe_print_implicit)) {
            crm_trace("skipping print of internal resource %s", rsc->id);
            return pcmk_rc_no_output;
        }
        target_role = g_hash_table_lookup(rsc->meta, XML_RSC_ATTR_TARGET_ROLE);
    }

    {
        gchar *s = native_output_string(rsc, name, node, options, target_role,
                                        true);

        out->list_item(out, NULL, "%s", s);
        g_free(s);
    }

    if (is_set(options, pe_print_details)) {
        GHashTableIter iter;
        gpointer key, value;

        out->begin_list(out, NULL, NULL, "Options");
        g_hash_table_iter_init(&iter, rsc->parameters);
        while (g_hash_table_iter_next(&iter, &key, &value)) {
            out->list_item(out, NULL, "Option: %s = %s", (char *) key, (char *) value);
        }
        out->end_list(out);
    }

    if (is_set(options, pe_print_dev)) {
        GHashTableIter iter;
        pe_node_t *n = NULL;

        out->begin_list(out, NULL, NULL, "Allowed Nodes");
        g_hash_table_iter_init(&iter, rsc->allowed_nodes);
        while (g_hash_table_iter_next(&iter, NULL, (void **)&n)) {
            out->list_item(out, NULL, "%s %d", n->details->uname, n->weight);
        }
        out->end_list(out);
    }

    if (is_set(options, pe_print_max_details)) {
        GHashTableIter iter;
        pe_node_t *n = NULL;

        out->begin_list(out, NULL, NULL, "=== Allowed Nodes");
        g_hash_table_iter_init(&iter, rsc->allowed_nodes);
        while (g_hash_table_iter_next(&iter, NULL, (void **)&n)) {
            pe__output_node(n, FALSE, out);
        }
        out->end_list(out);
    }

    return pcmk_rc_ok;
}

void
common_print(pe_resource_t * rsc, const char *pre_text, const char *name, pe_node_t *node, long options, void *print_data)
{
    const char *target_role = NULL;

    CRM_ASSERT(rsc->variant == pe_native);

    if (rsc->meta) {
        const char *is_internal = g_hash_table_lookup(rsc->meta,
                                                      XML_RSC_ATTR_INTERNAL_RSC);

        if (crm_is_true(is_internal) && is_not_set(options, pe_print_implicit)) {
            crm_trace("skipping print of internal resource %s", rsc->id);
            return;
        }
        target_role = g_hash_table_lookup(rsc->meta, XML_RSC_ATTR_TARGET_ROLE);
    }

    if (options & pe_print_xml) {
        native_print_xml(rsc, pre_text, options, print_data);
        return;
    }

    if ((pre_text == NULL) && (options & pe_print_printf)) {
        pre_text = " ";
    }

    if (options & pe_print_html) {
        if (is_not_set(rsc->flags, pe_rsc_managed)) {
            status_print("<font color=\"yellow\">");

        } else if (is_set(rsc->flags, pe_rsc_failed)) {
            status_print("<font color=\"red\">");

        } else if (rsc->running_on == NULL) {
            status_print("<font color=\"red\">");

        } else if (pcmk__list_of_multiple(rsc->running_on)) {
            status_print("<font color=\"orange\">");

        } else if (is_set(rsc->flags, pe_rsc_failure_ignored)) {
            status_print("<font color=\"yellow\">");

        } else {
            status_print("<font color=\"green\">");
        }
    }

    {
        gchar *resource_s = native_output_string(rsc, name, node, options,
                                                 target_role, false);
        status_print("%s%s", (pre_text? pre_text : ""), resource_s);
        g_free(resource_s);
    }

#if CURSES_ENABLED
    if (is_set(options, pe_print_ncurses)
        && is_not_set(options, pe_print_rsconly)
        && !pcmk__list_of_multiple(rsc->running_on)) {
        /* coverity[negative_returns] False positive */
        move(-1, 0);
    }
#endif

    if (is_set(options, pe_print_html)) {
        status_print(" </font> ");
    }

    if (is_not_set(options, pe_print_rsconly)
        && pcmk__list_of_multiple(rsc->running_on)) {

        GListPtr gIter = rsc->running_on;
        int counter = 0;

        if (options & pe_print_html) {
            status_print("<ul>\n");
        } else if ((options & pe_print_printf)
                   || (options & pe_print_ncurses)) {
            status_print("[");
        }

        for (; gIter != NULL; gIter = gIter->next) {
            pe_node_t *n = (pe_node_t *) gIter->data;

            counter++;

            if (options & pe_print_html) {
                status_print("<li>\n%s", n->details->uname);

            } else if ((options & pe_print_printf)
                       || (options & pe_print_ncurses)) {
                status_print(" %s", n->details->uname);

            } else if ((options & pe_print_log)) {
                status_print("\t%d : %s", counter, n->details->uname);

            } else {
                status_print("%s", n->details->uname);
            }
            if (options & pe_print_html) {
                status_print("</li>\n");

            }
        }

        if (options & pe_print_html) {
            status_print("</ul>\n");
        } else if ((options & pe_print_printf)
                   || (options & pe_print_ncurses)) {
            status_print(" ]");
        }
    }

    if (options & pe_print_html) {
        status_print("<br/>\n");
    } else if (options & pe_print_suppres_nl) {
        /* nothing */
    } else if ((options & pe_print_printf) || (options & pe_print_ncurses)) {
        status_print("\n");
    }

    if (options & pe_print_details) {
        struct print_data_s pdata;

        pdata.options = options;
        pdata.print_data = print_data;
        g_hash_table_foreach(rsc->parameters, native_print_attr, &pdata);
    }

    if (options & pe_print_dev) {
        GHashTableIter iter;
        pe_node_t *n = NULL;

        status_print("%s\tAllowed Nodes", pre_text);
        g_hash_table_iter_init(&iter, rsc->allowed_nodes);
        while (g_hash_table_iter_next(&iter, NULL, (void **)&n)) {
            status_print("%s\t * %s %d", pre_text, n->details->uname, n->weight);
        }
    }

    if (options & pe_print_max_details) {
        GHashTableIter iter;
        pe_node_t *n = NULL;

        status_print("%s\t=== Allowed Nodes\n", pre_text);
        g_hash_table_iter_init(&iter, rsc->allowed_nodes);
        while (g_hash_table_iter_next(&iter, NULL, (void **)&n)) {
            print_node("\t", n, FALSE);
        }
    }
}

void
native_print(pe_resource_t * rsc, const char *pre_text, long options, void *print_data)
{
    pe_node_t *node = NULL;

    CRM_ASSERT(rsc->variant == pe_native);
    if (options & pe_print_xml) {
        native_print_xml(rsc, pre_text, options, print_data);
        return;
    }

    node = pe__current_node(rsc);

    if (node == NULL) {
        // This is set only if a non-probe action is pending on this node
        node = rsc->pending_node;
    }

    common_print(rsc, pre_text, rsc_printable_id(rsc), node, options, print_data);
}

PCMK__OUTPUT_ARGS("primitive", "unsigned int", "pe_resource_t *", "GListPtr")
int
pe__resource_xml(pcmk__output_t *out, va_list args)
{
    unsigned int options = va_arg(args, unsigned int);
    pe_resource_t *rsc = va_arg(args, pe_resource_t *);
    GListPtr only_node G_GNUC_UNUSED = va_arg(args, GListPtr);

    const char *class = crm_element_value(rsc->xml, XML_AGENT_ATTR_CLASS);
    const char *prov = crm_element_value(rsc->xml, XML_AGENT_ATTR_PROVIDER);
    const char *rsc_state = native_displayable_state(rsc, options);

    long is_print_pending = options & pe_print_pending;
    long is_print_dev = options & pe_print_dev;

    char ra_name[LINE_MAX];
    char *nodes_running_on = NULL;
    char *priority = NULL;
    int rc = pcmk_rc_no_output;

    CRM_ASSERT(rsc->variant == pe_native);

    /* resource information. */
    sprintf(ra_name, "%s%s%s:%s", class, prov ? "::" : "", prov ? prov : ""
           , crm_element_value(rsc->xml, XML_ATTR_TYPE));

    nodes_running_on = crm_itoa(g_list_length(rsc->running_on));
    priority = crm_ftoa(rsc->priority);

    rc = pe__name_and_nvpairs_xml(out, true, "resource", 16
                 , "id", rsc_printable_id(rsc)
                 , "resource_agent", ra_name
                 , "role", rsc_state
                 , "target_role", (rsc->meta ? g_hash_table_lookup(rsc->meta, XML_RSC_ATTR_TARGET_ROLE) : NULL)
                 , "active", BOOL2STR(rsc->fns->active(rsc, TRUE))
                 , "orphaned", BOOL2STR(is_set(rsc->flags, pe_rsc_orphan))
                 , "blocked", BOOL2STR(is_set(rsc->flags, pe_rsc_block))
                 , "managed", BOOL2STR(is_set(rsc->flags, pe_rsc_managed))
                 , "failed", BOOL2STR(is_set(rsc->flags, pe_rsc_failed))
                 , "failure_ignored", BOOL2STR(is_set(rsc->flags, pe_rsc_failure_ignored))
                 , "nodes_running_on", nodes_running_on
                 , "pending", (is_print_pending ? native_pending_task(rsc) : NULL)
                 , "provisional", (is_print_dev ? BOOL2STR(is_set(rsc->flags, pe_rsc_provisional)) : NULL)
                 , "runnable", (is_print_dev ? BOOL2STR(is_set(rsc->flags, pe_rsc_runnable)) : NULL)
                 , "priority", (is_print_dev ? priority : NULL)
                 , "variant", (is_print_dev ? crm_element_name(rsc->xml) : NULL));
    free(priority);
    free(nodes_running_on);

    CRM_ASSERT(rc == pcmk_rc_ok);

    if (rsc->running_on != NULL) {
        GListPtr gIter = rsc->running_on;

        for (; gIter != NULL; gIter = gIter->next) {
            pe_node_t *node = (pe_node_t *) gIter->data;

            rc = pe__name_and_nvpairs_xml(out, false, "node", 3
                                          , "name", node->details->uname
                                          , "id", node->details->id
                                          , "cached", BOOL2STR(node->details->online));
            CRM_ASSERT(rc == pcmk_rc_ok);
        }
    }

    pcmk__output_xml_pop_parent(out);
    return rc;
}

PCMK__OUTPUT_ARGS("primitive", "unsigned int", "pe_resource_t *", "GListPtr")
int
pe__resource_html(pcmk__output_t *out, va_list args)
{
    unsigned int options = va_arg(args, unsigned int);
    pe_resource_t *rsc = va_arg(args, pe_resource_t *);
    GListPtr only_node G_GNUC_UNUSED = va_arg(args, GListPtr);

    pe_node_t *node = pe__current_node(rsc);

    CRM_ASSERT(rsc->variant == pe_native);

    if (node == NULL) {
        // This is set only if a non-probe action is pending on this node
        node = rsc->pending_node;
    }
    return pe__common_output_html(out, rsc, rsc_printable_id(rsc), node, options);
}

PCMK__OUTPUT_ARGS("primitive", "unsigned int", "pe_resource_t *", "GListPtr")
int
pe__resource_text(pcmk__output_t *out, va_list args)
{
    unsigned int options = va_arg(args, unsigned int);
    pe_resource_t *rsc = va_arg(args, pe_resource_t *);
    GListPtr only_node G_GNUC_UNUSED = va_arg(args, GListPtr);

    pe_node_t *node = pe__current_node(rsc);

    CRM_ASSERT(rsc->variant == pe_native);

    if (node == NULL) {
        // This is set only if a non-probe action is pending on this node
        node = rsc->pending_node;
    }
    return pe__common_output_text(out, rsc, rsc_printable_id(rsc), node, options);
}

void
native_free(pe_resource_t * rsc)
{
    pe_rsc_trace(rsc, "Freeing resource action list (not the data)");
    common_free(rsc);
}

enum rsc_role_e
native_resource_state(const pe_resource_t * rsc, gboolean current)
{
    enum rsc_role_e role = rsc->next_role;

    if (current) {
        role = rsc->role;
    }
    pe_rsc_trace(rsc, "%s state: %s", rsc->id, role2text(role));
    return role;
}

/*!
 * \internal
 * \brief List nodes where a resource (or any of its children) is
 *
 * \param[in]  rsc      Resource to check
 * \param[out] list     List to add result to
 * \param[in]  current  0 = where known, 1 = running, 2 = running or pending
 *
 * \return If list contains only one node, that node
 */
pe_node_t *
native_location(const pe_resource_t *rsc, GList **list, int current)
{
    pe_node_t *one = NULL;
    GListPtr result = NULL;

    if (rsc->children) {
        GListPtr gIter = rsc->children;

        for (; gIter != NULL; gIter = gIter->next) {
            pe_resource_t *child = (pe_resource_t *) gIter->data;

            child->fns->location(child, &result, current);
        }

    } else if (current) {

        if (rsc->running_on) {
            result = g_list_copy(rsc->running_on);
        }
        if ((current == 2) && rsc->pending_node
            && !pe_find_node_id(result, rsc->pending_node->details->id)) {
                result = g_list_append(result, rsc->pending_node);
        }

    } else if (current == FALSE && rsc->allocated_to) {
        result = g_list_append(NULL, rsc->allocated_to);
    }

    if (result && (result->next == NULL)) {
        one = result->data;
    }

    if (list) {
        GListPtr gIter = result;

        for (; gIter != NULL; gIter = gIter->next) {
            pe_node_t *node = (pe_node_t *) gIter->data;

            if (*list == NULL || pe_find_node_id(*list, node->details->id) == NULL) {
                *list = g_list_append(*list, node);
            }
        }
    }

    g_list_free(result);
    return one;
}

static void
get_rscs_brief(GListPtr rsc_list, GHashTable * rsc_table, GHashTable * active_table)
{
    GListPtr gIter = rsc_list;

    for (; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *rsc = (pe_resource_t *) gIter->data;

        const char *class = crm_element_value(rsc->xml, XML_AGENT_ATTR_CLASS);
        const char *kind = crm_element_value(rsc->xml, XML_ATTR_TYPE);

        int offset = 0;
        char buffer[LINE_MAX];

        int *rsc_counter = NULL;
        int *active_counter = NULL;

        if (rsc->variant != pe_native) {
            continue;
        }

        offset += snprintf(buffer + offset, LINE_MAX - offset, "%s", class);
        if (is_set(pcmk_get_ra_caps(class), pcmk_ra_cap_provider)) {
            const char *prov = crm_element_value(rsc->xml, XML_AGENT_ATTR_PROVIDER);
            offset += snprintf(buffer + offset, LINE_MAX - offset, "::%s", prov);
        }
        offset += snprintf(buffer + offset, LINE_MAX - offset, ":%s", kind);
        CRM_LOG_ASSERT(offset > 0);

        if (rsc_table) {
            rsc_counter = g_hash_table_lookup(rsc_table, buffer);
            if (rsc_counter == NULL) {
                rsc_counter = calloc(1, sizeof(int));
                *rsc_counter = 0;
                g_hash_table_insert(rsc_table, strdup(buffer), rsc_counter);
            }
            (*rsc_counter)++;
        }

        if (active_table) {
            GListPtr gIter2 = rsc->running_on;

            for (; gIter2 != NULL; gIter2 = gIter2->next) {
                pe_node_t *node = (pe_node_t *) gIter2->data;
                GHashTable *node_table = NULL;

                if (node->details->unclean == FALSE && node->details->online == FALSE) {
                    continue;
                }

                node_table = g_hash_table_lookup(active_table, node->details->uname);
                if (node_table == NULL) {
                    node_table = crm_str_table_new();
                    g_hash_table_insert(active_table, strdup(node->details->uname), node_table);
                }

                active_counter = g_hash_table_lookup(node_table, buffer);
                if (active_counter == NULL) {
                    active_counter = calloc(1, sizeof(int));
                    *active_counter = 0;
                    g_hash_table_insert(node_table, strdup(buffer), active_counter);
                }
                (*active_counter)++;
            }
        }
    }
}

static void
destroy_node_table(gpointer data)
{
    GHashTable *node_table = data;

    if (node_table) {
        g_hash_table_destroy(node_table);
    }
}

void
print_rscs_brief(GListPtr rsc_list, const char *pre_text, long options,
                 void *print_data, gboolean print_all)
{
    GHashTable *rsc_table = crm_str_table_new();
    GHashTable *active_table = g_hash_table_new_full(crm_str_hash, g_str_equal,
                                                     free, destroy_node_table);
    GHashTableIter hash_iter;
    char *type = NULL;
    int *rsc_counter = NULL;

    get_rscs_brief(rsc_list, rsc_table, active_table);

    g_hash_table_iter_init(&hash_iter, rsc_table);
    while (g_hash_table_iter_next(&hash_iter, (gpointer *)&type, (gpointer *)&rsc_counter)) {
        GHashTableIter hash_iter2;
        char *node_name = NULL;
        GHashTable *node_table = NULL;
        int active_counter_all = 0;

        g_hash_table_iter_init(&hash_iter2, active_table);
        while (g_hash_table_iter_next(&hash_iter2, (gpointer *)&node_name, (gpointer *)&node_table)) {
            int *active_counter = g_hash_table_lookup(node_table, type);

            if (active_counter == NULL || *active_counter == 0) {
                continue;

            } else {
                active_counter_all += *active_counter;
            }

            if (options & pe_print_rsconly) {
                node_name = NULL;
            }

            if (options & pe_print_html) {
                status_print("<li>\n");
            }

            if (print_all) {
                status_print("%s%d/%d\t(%s):\tActive %s\n", pre_text ? pre_text : "",
                             active_counter ? *active_counter : 0,
                             rsc_counter ? *rsc_counter : 0, type,
                             active_counter && (*active_counter > 0) && node_name ? node_name : "");
            } else {
                status_print("%s%d\t(%s):\tActive %s\n", pre_text ? pre_text : "",
                             active_counter ? *active_counter : 0, type,
                             active_counter && (*active_counter > 0) && node_name ? node_name : "");
            }

            if (options & pe_print_html) {
                status_print("</li>\n");
            }
        }

        if (print_all && active_counter_all == 0) {
            if (options & pe_print_html) {
                status_print("<li>\n");
            }

            status_print("%s%d/%d\t(%s):\tActive\n", pre_text ? pre_text : "",
                         active_counter_all,
                         rsc_counter ? *rsc_counter : 0, type);

            if (options & pe_print_html) {
                status_print("</li>\n");
            }
        }
    }

    if (rsc_table) {
        g_hash_table_destroy(rsc_table);
        rsc_table = NULL;
    }
    if (active_table) {
        g_hash_table_destroy(active_table);
        active_table = NULL;
    }
}

int
pe__rscs_brief_output(pcmk__output_t *out, GListPtr rsc_list, long options, gboolean print_all)
{
    GHashTable *rsc_table = crm_str_table_new();
    GHashTable *active_table = g_hash_table_new_full(crm_str_hash, g_str_equal,
                                                     free, destroy_node_table);
    GListPtr sorted_rscs;
    int rc = pcmk_rc_no_output;

    get_rscs_brief(rsc_list, rsc_table, active_table);

    /* Make a list of the rsc_table keys so that it can be sorted.  This is to make sure
     * output order stays consistent between systems.
     */
    sorted_rscs = g_hash_table_get_keys(rsc_table);
    sorted_rscs = g_list_sort(sorted_rscs, (GCompareFunc) strcmp);

    for (GListPtr gIter = sorted_rscs; gIter; gIter = gIter->next) {
        char *type = (char *) gIter->data;
        int *rsc_counter = g_hash_table_lookup(rsc_table, type);

        GHashTableIter hash_iter2;
        char *node_name = NULL;
        GHashTable *node_table = NULL;
        int active_counter_all = 0;

        g_hash_table_iter_init(&hash_iter2, active_table);
        while (g_hash_table_iter_next(&hash_iter2, (gpointer *)&node_name, (gpointer *)&node_table)) {
            int *active_counter = g_hash_table_lookup(node_table, type);

            if (active_counter == NULL || *active_counter == 0) {
                continue;

            } else {
                active_counter_all += *active_counter;
            }

            if (options & pe_print_rsconly) {
                node_name = NULL;
            }

            if (print_all) {
                out->list_item(out, NULL, " %d/%d\t(%s):\tActive %s",
                               *active_counter,
                               rsc_counter ? *rsc_counter : 0, type,
                               (*active_counter > 0) && node_name ? node_name : "");
            } else {
                out->list_item(out, NULL, " %d\t(%s):\tActive %s",
                               *active_counter, type,
                               (*active_counter > 0) && node_name ? node_name : "");
            }

            rc = pcmk_rc_ok;
        }

        if (print_all && active_counter_all == 0) {
            out->list_item(out, NULL, " %d/%d\t(%s):\tActive",
                           active_counter_all,
                           rsc_counter ? *rsc_counter : 0, type);
            rc = pcmk_rc_ok;
        }
    }

    if (rsc_table) {
        g_hash_table_destroy(rsc_table);
        rsc_table = NULL;
    }
    if (active_table) {
        g_hash_table_destroy(active_table);
        active_table = NULL;
    }
    if (sorted_rscs) {
        g_list_free(sorted_rscs);
    }

    return rc;
}
