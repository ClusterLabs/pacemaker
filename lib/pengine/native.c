/*
 * Copyright 2004-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdint.h>

#include <crm/common/output.h>
#include <crm/pengine/rules.h>
#include <crm/pengine/status.h>
#include <crm/pengine/complex.h>
#include <crm/pengine/internal.h>
#include <crm/msg_xml.h>
#include <pe_status_private.h>

#ifdef PCMK__COMPAT_2_0
#define PROVIDER_SEP "::"
#else
#define PROVIDER_SEP ":"
#endif

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
native_priority_to_node(pe_resource_t * rsc, pe_node_t * node, gboolean failed)
{
    int priority = 0;

    if ((rsc->priority == 0) || (failed == TRUE)) {
        return;
    }

    if (rsc->role == RSC_ROLE_PROMOTED) {
        // Promoted instance takes base priority + 1
        priority = rsc->priority + 1;

    } else {
        priority = rsc->priority;
    }

    node->details->priority += priority;
    pe_rsc_trace(rsc, "%s now has priority %d with %s'%s' (priority: %d%s)",
                 pe__node_name(node), node->details->priority,
                 (rsc->role == RSC_ROLE_PROMOTED)? "promoted " : "",
                 rsc->id, rsc->priority,
                 (rsc->role == RSC_ROLE_PROMOTED)? " + 1" : "");

    /* Priority of a resource running on a guest node is added to the cluster
     * node as well. */
    if (node->details->remote_rsc
        && node->details->remote_rsc->container) {
        GList *gIter = node->details->remote_rsc->container->running_on;

        for (; gIter != NULL; gIter = gIter->next) {
            pe_node_t *a_node = gIter->data;

            a_node->details->priority += priority;
            pe_rsc_trace(rsc, "%s now has priority %d with %s'%s' (priority: %d%s) "
                         "from guest node %s",
                         pe__node_name(a_node), a_node->details->priority,
                         (rsc->role == RSC_ROLE_PROMOTED)? "promoted " : "",
                         rsc->id, rsc->priority,
                         (rsc->role == RSC_ROLE_PROMOTED)? " + 1" : "",
                         pe__node_name(node));
        }
    }
}

void
native_add_running(pe_resource_t * rsc, pe_node_t * node, pe_working_set_t * data_set, gboolean failed)
{
    GList *gIter = rsc->running_on;

    CRM_CHECK(node != NULL, return);
    for (; gIter != NULL; gIter = gIter->next) {
        pe_node_t *a_node = (pe_node_t *) gIter->data;

        CRM_CHECK(a_node != NULL, return);
        if (pcmk__str_eq(a_node->details->id, node->details->id, pcmk__str_casei)) {
            return;
        }
    }

    pe_rsc_trace(rsc, "Adding %s to %s %s", rsc->id, pe__node_name(node),
                 pcmk_is_set(rsc->flags, pe_rsc_managed)? "" : "(unmanaged)");

    rsc->running_on = g_list_append(rsc->running_on, node);
    if (rsc->variant == pe_native) {
        node->details->running_rsc = g_list_append(node->details->running_rsc, rsc);

        native_priority_to_node(rsc, node, failed);
    }

    if (rsc->variant == pe_native && node->details->maintenance) {
        pe__clear_resource_flags(rsc, pe_rsc_managed);
    }

    if (!pcmk_is_set(rsc->flags, pe_rsc_managed)) {
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
            case recovery_block:
                pe__clear_resource_flags(rsc, pe_rsc_managed);
                pe__set_resource_flags(rsc, pe_rsc_block);

                /* If the resource belongs to a group or bundle configured with
                 * multiple-active=block, block the entire entity.
                 */
                if (rsc->parent
                    && (rsc->parent->variant == pe_group || rsc->parent->variant == pe_container)
                    && rsc->parent->recovery_type == recovery_block) {
                    GList *gIter = rsc->parent->children;

                    for (; gIter != NULL; gIter = gIter->next) {
                        pe_resource_t *child = (pe_resource_t *) gIter->data;

                        pe__clear_resource_flags(child, pe_rsc_managed);
                        pe__set_resource_flags(child, pe_rsc_block);
                    }
                }
                break;
            default: // recovery_stop_start, recovery_stop_unexpected
                /* The scheduler will do the right thing because the relevant
                 * variables and flags are set when unpacking the history.
                 */
                break;
        }
        crm_debug("%s is active on multiple nodes including %s: %s",
                  rsc->id, pe__node_name(node),
                  recovery2text(rsc->recovery_type));

    } else {
        pe_rsc_trace(rsc, "Resource %s is active on %s",
                     rsc->id, pe__node_name(node));
    }

    if (rsc->parent != NULL) {
        native_add_running(rsc->parent, node, data_set, FALSE);
    }
}

static void
recursive_clear_unique(pe_resource_t *rsc, gpointer user_data)
{
    pe__clear_resource_flags(rsc, pe_rsc_unique);
    add_hash_param(rsc->meta, XML_RSC_ATTR_UNIQUE, XML_BOOLEAN_FALSE);
    g_list_foreach(rsc->children, (GFunc) recursive_clear_unique, NULL);
}

gboolean
native_unpack(pe_resource_t * rsc, pe_working_set_t * data_set)
{
    pe_resource_t *parent = uber_parent(rsc);
    const char *standard = crm_element_value(rsc->xml, XML_AGENT_ATTR_CLASS);
    uint32_t ra_caps = pcmk_get_ra_caps(standard);

    pe_rsc_trace(rsc, "Processing resource %s...", rsc->id);

    // Only some agent standards support unique and promotable clones
    if (!pcmk_is_set(ra_caps, pcmk_ra_cap_unique)
        && pcmk_is_set(rsc->flags, pe_rsc_unique) && pe_rsc_is_clone(parent)) {

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
        recursive_clear_unique(parent, NULL);
        recursive_clear_unique(rsc, NULL);
    }
    if (!pcmk_is_set(ra_caps, pcmk_ra_cap_promotable)
        && pcmk_is_set(parent->flags, pe_rsc_promotable)) {

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
                 rsc->id, pe__node_name(node));

    if (pcmk_is_set(flags, pe_find_current) && rsc->running_on) {

        for (GList *iter = rsc->running_on; iter; iter = iter->next) {
            pe_node_t *loc = (pe_node_t *) iter->data;

            if (loc->details == node->details) {
                return true;
            }
        }

    } else if (pcmk_is_set(flags, pe_find_inactive)
               && (rsc->running_on == NULL)) {
        return true;

    } else if (!pcmk_is_set(flags, pe_find_current) && rsc->allocated_to
               && (rsc->allocated_to->details == node->details)) {
        return true;
    }
    return false;
}

pe_resource_t *
native_find_rsc(pe_resource_t * rsc, const char *id, const pe_node_t *on_node,
                int flags)
{
    bool match = false;
    pe_resource_t *result = NULL;

    CRM_CHECK(id && rsc && rsc->id, return NULL);

    if (flags & pe_find_clone) {
        const char *rid = ID(rsc->xml);

        if (!pe_rsc_is_clone(uber_parent(rsc))) {
            match = false;

        } else if (!strcmp(id, rsc->id) || pcmk__str_eq(id, rid, pcmk__str_none)) {
            match = true;
        }

    } else if (!strcmp(id, rsc->id)) {
        match = true;

    } else if (pcmk_is_set(flags, pe_find_renamed)
               && rsc->clone_name && strcmp(rsc->clone_name, id) == 0) {
        match = true;

    } else if (pcmk_is_set(flags, pe_find_any)
               || (pcmk_is_set(flags, pe_find_anon)
                   && !pcmk_is_set(rsc->flags, pe_rsc_unique))) {
        match = pe_base_name_eq(rsc, id);
    }

    if (match && on_node) {
        if (!rsc_is_on_node(rsc, on_node, flags)) {
            match = false;
        }
    }

    if (match) {
        return rsc;
    }

    for (GList *gIter = rsc->children; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *child = (pe_resource_t *) gIter->data;

        result = rsc->fns->find_rsc(child, id, on_node, flags);
        if (result) {
            return result;
        }
    }
    return NULL;
}

// create is ignored
char *
native_parameter(pe_resource_t * rsc, pe_node_t * node, gboolean create, const char *name,
                 pe_working_set_t * data_set)
{
    char *value_copy = NULL;
    const char *value = NULL;
    GHashTable *params = NULL;

    CRM_CHECK(rsc != NULL, return NULL);
    CRM_CHECK(name != NULL && strlen(name) != 0, return NULL);

    pe_rsc_trace(rsc, "Looking up %s in %s", name, rsc->id);
    params = pe_rsc_params(rsc, node, data_set);
    value = g_hash_table_lookup(params, name);
    if (value == NULL) {
        /* try meta attributes instead */
        value = g_hash_table_lookup(rsc->meta, name);
    }
    pcmk__str_update(&value_copy, value);
    return value_copy;
}

gboolean
native_active(pe_resource_t * rsc, gboolean all)
{
    for (GList *gIter = rsc->running_on; gIter != NULL; gIter = gIter->next) {
        pe_node_t *a_node = (pe_node_t *) gIter->data;

        if (a_node->details->unclean) {
            pe_rsc_trace(rsc, "Resource %s: %s is unclean",
                         rsc->id, pe__node_name(a_node));
            return TRUE;
        } else if (a_node->details->online == FALSE && pcmk_is_set(rsc->flags, pe_rsc_managed)) {
            pe_rsc_trace(rsc, "Resource %s: %s is offline",
                         rsc->id, pe__node_name(a_node));
        } else {
            pe_rsc_trace(rsc, "Resource %s active on %s",
                         rsc->id, pe__node_name(a_node));
            return TRUE;
        }
    }
    return FALSE;
}

struct print_data_s {
    long options;
    void *print_data;
};

static const char *
native_pending_state(pe_resource_t * rsc)
{
    const char *pending_state = NULL;

    if (pcmk__str_eq(rsc->pending_task, CRMD_ACTION_START, pcmk__str_casei)) {
        pending_state = "Starting";

    } else if (pcmk__str_eq(rsc->pending_task, CRMD_ACTION_STOP, pcmk__str_casei)) {
        pending_state = "Stopping";

    } else if (pcmk__str_eq(rsc->pending_task, CRMD_ACTION_MIGRATE, pcmk__str_casei)) {
        pending_state = "Migrating";

    } else if (pcmk__str_eq(rsc->pending_task, CRMD_ACTION_MIGRATED, pcmk__str_casei)) {
       /* Work might be done in here. */
        pending_state = "Migrating";

    } else if (pcmk__str_eq(rsc->pending_task, CRMD_ACTION_PROMOTE, pcmk__str_casei)) {
        pending_state = "Promoting";

    } else if (pcmk__str_eq(rsc->pending_task, CRMD_ACTION_DEMOTE, pcmk__str_casei)) {
        pending_state = "Demoting";
    }

    return pending_state;
}

static const char *
native_pending_task(pe_resource_t * rsc)
{
    const char *pending_task = NULL;

    if (pcmk__str_eq(rsc->pending_task, CRMD_ACTION_STATUS, pcmk__str_casei)) {
        pending_task = "Monitoring";

    /* Pending probes are not printed, even if pending
     * operations are requested. If someone ever requests that
     * behavior, uncomment this and the corresponding part of
     * unpack.c:unpack_rsc_op().
     */
    /*
    } else if (pcmk__str_eq(rsc->pending_task, "probe", pcmk__str_casei)) {
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
        && pcmk_is_set(uber_parent(rsc)->flags, pe_rsc_promotable)) {

        role = RSC_ROLE_UNPROMOTED;
    }
    return role;
}

static const char *
native_displayable_state(pe_resource_t *rsc, bool print_pending)
{
    const char *rsc_state = NULL;

    if (print_pending) {
        rsc_state = native_pending_state(rsc);
    }
    if (rsc_state == NULL) {
        rsc_state = role2text(native_displayable_role(rsc));
    }
    return rsc_state;
}

/*!
 * \internal
 * \deprecated This function will be removed in a future release
 */
static void
native_print_xml(pe_resource_t *rsc, const char *pre_text, long options,
                 void *print_data)
{
    const char *class = crm_element_value(rsc->xml, XML_AGENT_ATTR_CLASS);
    const char *prov = crm_element_value(rsc->xml, XML_AGENT_ATTR_PROVIDER);
    const char *rsc_state = native_displayable_state(rsc, pcmk_is_set(options, pe_print_pending));
    const char *target_role = NULL;

    /* resource information. */
    status_print("%s<resource ", pre_text);
    status_print("id=\"%s\" ", rsc_printable_id(rsc));
    status_print("resource_agent=\"%s%s%s:%s\" ", class,
                 ((prov == NULL)? "" : PROVIDER_SEP),
                 ((prov == NULL)? "" : prov),
                 crm_element_value(rsc->xml, XML_ATTR_TYPE));

    status_print("role=\"%s\" ", rsc_state);
    if (rsc->meta) {
        target_role = g_hash_table_lookup(rsc->meta, XML_RSC_ATTR_TARGET_ROLE);
    }
    if (target_role) {
        status_print("target_role=\"%s\" ", target_role);
    }
    status_print("active=\"%s\" ", pcmk__btoa(rsc->fns->active(rsc, TRUE)));
    status_print("orphaned=\"%s\" ", pe__rsc_bool_str(rsc, pe_rsc_orphan));
    status_print("blocked=\"%s\" ", pe__rsc_bool_str(rsc, pe_rsc_block));
    status_print("managed=\"%s\" ", pe__rsc_bool_str(rsc, pe_rsc_managed));
    status_print("failed=\"%s\" ", pe__rsc_bool_str(rsc, pe_rsc_failed));
    status_print("failure_ignored=\"%s\" ",
                 pe__rsc_bool_str(rsc, pe_rsc_failure_ignored));
    status_print("nodes_running_on=\"%d\" ", g_list_length(rsc->running_on));

    if (options & pe_print_pending) {
        const char *pending_task = native_pending_task(rsc);

        if (pending_task) {
            status_print("pending=\"%s\" ", pending_task);
        }
    }

    /* print out the nodes this resource is running on */
    if (options & pe_print_rsconly) {
        status_print("/>\n");
        /* do nothing */
    } else if (rsc->running_on != NULL) {
        GList *gIter = rsc->running_on;

        status_print(">\n");
        for (; gIter != NULL; gIter = gIter->next) {
            pe_node_t *node = (pe_node_t *) gIter->data;

            status_print("%s    <node name=\"%s\" id=\"%s\" cached=\"%s\"/>\n", pre_text,
                         pcmk__s(node->details->uname, ""), node->details->id,
                         pcmk__btoa(node->details->online == FALSE));
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
 * \param[in] show_opts    Bitmask of pcmk_show_opt_e.
 * \param[in] target_role  Resource's target role
 * \param[in] show_nodes   Whether to display nodes when multiply active
 *
 * \return Newly allocated string description of resource
 * \note Caller must free the result with g_free().
 */
gchar *
pcmk__native_output_string(pe_resource_t *rsc, const char *name, pe_node_t *node,
                           uint32_t show_opts, const char *target_role, bool show_nodes)
{
    const char *class = crm_element_value(rsc->xml, XML_AGENT_ATTR_CLASS);
    const char *provider = NULL;
    const char *kind = crm_element_value(rsc->xml, XML_ATTR_TYPE);
    GString *outstr = NULL;
    bool have_flags = false;

    if (rsc->variant != pe_native) {
        return NULL;
    }

    CRM_CHECK(name != NULL, name = "unknown");
    CRM_CHECK(kind != NULL, kind = "unknown");
    CRM_CHECK(class != NULL, class = "unknown");

    if (pcmk_is_set(pcmk_get_ra_caps(class), pcmk_ra_cap_provider)) {
        provider = crm_element_value(rsc->xml, XML_AGENT_ATTR_PROVIDER);
    }

    if ((node == NULL) && (rsc->lock_node != NULL)) {
        node = rsc->lock_node;
    }
    if (pcmk_is_set(show_opts, pcmk_show_rsc_only)
        || pcmk__list_of_multiple(rsc->running_on)) {
        node = NULL;
    }

    outstr = g_string_sized_new(128);

    // Resource name and agent
    pcmk__g_strcat(outstr,
                   name, "\t(", class, ((provider == NULL)? "" : PROVIDER_SEP),
                   pcmk__s(provider, ""), ":", kind, "):\t", NULL);

    // State on node
    if (pcmk_is_set(rsc->flags, pe_rsc_orphan)) {
        g_string_append(outstr, " ORPHANED");
    }
    if (pcmk_is_set(rsc->flags, pe_rsc_failed)) {
        enum rsc_role_e role = native_displayable_role(rsc);

        g_string_append(outstr, " FAILED");
        if (role > RSC_ROLE_UNPROMOTED) {
            pcmk__add_word(&outstr, 0, role2text(role));
        }
    } else {
        bool show_pending = pcmk_is_set(show_opts, pcmk_show_pending);

        pcmk__add_word(&outstr, 0, native_displayable_state(rsc, show_pending));
    }
    if (node) {
        pcmk__add_word(&outstr, 0, pe__node_name(node));
    }

    // Failed probe operation
    if (native_displayable_role(rsc) == RSC_ROLE_STOPPED) {
        xmlNode *probe_op = pe__failed_probe_for_rsc(rsc, node ? node->details->uname : NULL);
        if (probe_op != NULL) {
            int rc;

            pcmk__scan_min_int(crm_element_value(probe_op, XML_LRM_ATTR_RC), &rc, 0);
            pcmk__g_strcat(outstr, " (", services_ocf_exitcode_str(rc), ") ",
                           NULL);
        }
    }

    // Flags, as: (<flag> [...])
    if (node && !(node->details->online) && node->details->unclean) {
        have_flags = add_output_flag(outstr, "UNCLEAN", have_flags);
    }
    if (node && (node == rsc->lock_node)) {
        have_flags = add_output_flag(outstr, "LOCKED", have_flags);
    }
    if (pcmk_is_set(show_opts, pcmk_show_pending)) {
        const char *pending_task = native_pending_task(rsc);

        if (pending_task) {
            have_flags = add_output_flag(outstr, pending_task, have_flags);
        }
    }
    if (target_role) {
        enum rsc_role_e target_role_e = text2role(target_role);

        /* Only show target role if it limits our abilities (i.e. ignore
         * Started, as it is the default anyways, and doesn't prevent the
         * resource from becoming promoted).
         */
        if (target_role_e == RSC_ROLE_STOPPED) {
            have_flags = add_output_flag(outstr, "disabled", have_flags);

        } else if (pcmk_is_set(uber_parent(rsc)->flags, pe_rsc_promotable)
                   && target_role_e == RSC_ROLE_UNPROMOTED) {
            have_flags = add_output_flag(outstr, "target-role:", have_flags);
            g_string_append(outstr, target_role);
        }
    }

    // Blocked or maintenance implies unmanaged
    if (pcmk_any_flags_set(rsc->flags, pe_rsc_block|pe_rsc_maintenance)) {
        if (pcmk_is_set(rsc->flags, pe_rsc_block)) {
            have_flags = add_output_flag(outstr, "blocked", have_flags);

        } else if (pcmk_is_set(rsc->flags, pe_rsc_maintenance)) {
            have_flags = add_output_flag(outstr, "maintenance", have_flags);
        }
    } else if (!pcmk_is_set(rsc->flags, pe_rsc_managed)) {
        have_flags = add_output_flag(outstr, "unmanaged", have_flags);
    }

    if (pcmk_is_set(rsc->flags, pe_rsc_failure_ignored)) {
        have_flags = add_output_flag(outstr, "failure ignored", have_flags);
    }
    if (have_flags) {
        g_string_append_c(outstr, ')');
    }

    // User-supplied description
    if (pcmk_is_set(show_opts, pcmk_show_rsc_only)
        || pcmk__list_of_multiple(rsc->running_on)) {
        const char *desc = crm_element_value(rsc->xml, XML_ATTR_DESC);

        if (desc) {
            pcmk__add_word(&outstr, 0, desc);
        }
    }

    if (show_nodes && !pcmk_is_set(show_opts, pcmk_show_rsc_only)
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

    return g_string_free(outstr, FALSE);
}

int
pe__common_output_html(pcmk__output_t *out, pe_resource_t * rsc,
                       const char *name, pe_node_t *node, uint32_t show_opts)
{
    const char *kind = crm_element_value(rsc->xml, XML_ATTR_TYPE);
    const char *target_role = NULL;

    xmlNodePtr list_node = NULL;
    const char *cl = NULL;

    CRM_ASSERT(rsc->variant == pe_native);
    CRM_ASSERT(kind != NULL);

    if (rsc->meta) {
        const char *is_internal = g_hash_table_lookup(rsc->meta, XML_RSC_ATTR_INTERNAL_RSC);

        if (crm_is_true(is_internal)
            && !pcmk_is_set(show_opts, pcmk_show_implicit_rscs)) {

            crm_trace("skipping print of internal resource %s", rsc->id);
            return pcmk_rc_no_output;
        }
        target_role = g_hash_table_lookup(rsc->meta, XML_RSC_ATTR_TARGET_ROLE);
    }

    if (!pcmk_is_set(rsc->flags, pe_rsc_managed)) {
        cl = "rsc-managed";

    } else if (pcmk_is_set(rsc->flags, pe_rsc_failed)) {
        cl = "rsc-failed";

    } else if (rsc->variant == pe_native && (rsc->running_on == NULL)) {
        cl = "rsc-failed";

    } else if (pcmk__list_of_multiple(rsc->running_on)) {
        cl = "rsc-multiple";

    } else if (pcmk_is_set(rsc->flags, pe_rsc_failure_ignored)) {
        cl = "rsc-failure-ignored";

    } else {
        cl = "rsc-ok";
    }

    {
        gchar *s = pcmk__native_output_string(rsc, name, node, show_opts,
                                              target_role, true);

        list_node = pcmk__output_create_html_node(out, "li", NULL, NULL, NULL);
        pcmk_create_html_node(list_node, "span", NULL, cl, s);
        g_free(s);
    }

    return pcmk_rc_ok;
}

int
pe__common_output_text(pcmk__output_t *out, pe_resource_t * rsc,
                       const char *name, pe_node_t *node, uint32_t show_opts)
{
    const char *target_role = NULL;

    CRM_ASSERT(rsc->variant == pe_native);

    if (rsc->meta) {
        const char *is_internal = g_hash_table_lookup(rsc->meta, XML_RSC_ATTR_INTERNAL_RSC);

        if (crm_is_true(is_internal)
            && !pcmk_is_set(show_opts, pcmk_show_implicit_rscs)) {

            crm_trace("skipping print of internal resource %s", rsc->id);
            return pcmk_rc_no_output;
        }
        target_role = g_hash_table_lookup(rsc->meta, XML_RSC_ATTR_TARGET_ROLE);
    }

    {
        gchar *s = pcmk__native_output_string(rsc, name, node, show_opts,
                                              target_role, true);

        out->list_item(out, NULL, "%s", s);
        g_free(s);
    }

    return pcmk_rc_ok;
}

/*!
 * \internal
 * \deprecated This function will be removed in a future release
 */
void
common_print(pe_resource_t *rsc, const char *pre_text, const char *name,
             pe_node_t *node, long options, void *print_data)
{
    const char *target_role = NULL;

    CRM_ASSERT(rsc->variant == pe_native);

    if (rsc->meta) {
        const char *is_internal = g_hash_table_lookup(rsc->meta,
                                                      XML_RSC_ATTR_INTERNAL_RSC);

        if (crm_is_true(is_internal)
            && !pcmk_is_set(options, pe_print_implicit)) {

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
        if (!pcmk_is_set(rsc->flags, pe_rsc_managed)) {
            status_print("<font color=\"yellow\">");

        } else if (pcmk_is_set(rsc->flags, pe_rsc_failed)) {
            status_print("<font color=\"red\">");

        } else if (rsc->running_on == NULL) {
            status_print("<font color=\"red\">");

        } else if (pcmk__list_of_multiple(rsc->running_on)) {
            status_print("<font color=\"orange\">");

        } else if (pcmk_is_set(rsc->flags, pe_rsc_failure_ignored)) {
            status_print("<font color=\"yellow\">");

        } else {
            status_print("<font color=\"green\">");
        }
    }

    {
        gchar *resource_s = pcmk__native_output_string(rsc, name, node, options,
                                                       target_role, false);
        status_print("%s%s", (pre_text? pre_text : ""), resource_s);
        g_free(resource_s);
    }

    if (pcmk_is_set(options, pe_print_html)) {
        status_print(" </font> ");
    }

    if (!pcmk_is_set(options, pe_print_rsconly)
        && pcmk__list_of_multiple(rsc->running_on)) {

        GList *gIter = rsc->running_on;
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
                status_print("<li>\n%s", pe__node_name(n));

            } else if ((options & pe_print_printf)
                       || (options & pe_print_ncurses)) {
                status_print(" %s", pe__node_name(n));

            } else if ((options & pe_print_log)) {
                status_print("\t%d : %s", counter, pe__node_name(n));

            } else {
                status_print("%s", pe__node_name(n));
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
}

/*!
 * \internal
 * \deprecated This function will be removed in a future release
 */
void
native_print(pe_resource_t *rsc, const char *pre_text, long options,
             void *print_data)
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

PCMK__OUTPUT_ARGS("primitive", "uint32_t", "pe_resource_t *", "GList *", "GList *")
int
pe__resource_xml(pcmk__output_t *out, va_list args)
{
    uint32_t show_opts = va_arg(args, uint32_t);
    pe_resource_t *rsc = va_arg(args, pe_resource_t *);
    GList *only_node G_GNUC_UNUSED = va_arg(args, GList *);
    GList *only_rsc = va_arg(args, GList *);

    bool print_pending = pcmk_is_set(show_opts, pcmk_show_pending);
    const char *class = crm_element_value(rsc->xml, XML_AGENT_ATTR_CLASS);
    const char *prov = crm_element_value(rsc->xml, XML_AGENT_ATTR_PROVIDER);
    const char *rsc_state = native_displayable_state(rsc, print_pending);

    char ra_name[LINE_MAX];
    char *nodes_running_on = NULL;
    const char *lock_node_name = NULL;
    int rc = pcmk_rc_no_output;
    const char *target_role = NULL;

    if (rsc->meta != NULL) {
       target_role = g_hash_table_lookup(rsc->meta, XML_RSC_ATTR_TARGET_ROLE);
    }

    CRM_ASSERT(rsc->variant == pe_native);

    if (rsc->fns->is_filtered(rsc, only_rsc, TRUE)) {
        return pcmk_rc_no_output;
    }

    /* resource information. */
    snprintf(ra_name, LINE_MAX, "%s%s%s:%s", class,
            ((prov == NULL)? "" : PROVIDER_SEP), ((prov == NULL)? "" : prov),
            crm_element_value(rsc->xml, XML_ATTR_TYPE));

    nodes_running_on = pcmk__itoa(g_list_length(rsc->running_on));

    if (rsc->lock_node != NULL) {
        lock_node_name = rsc->lock_node->details->uname;
    }

    rc = pe__name_and_nvpairs_xml(out, true, "resource", 14,
             "id", rsc_printable_id(rsc),
             "resource_agent", ra_name,
             "role", rsc_state,
             "target_role", target_role,
             "active", pcmk__btoa(rsc->fns->active(rsc, TRUE)),
             "orphaned", pe__rsc_bool_str(rsc, pe_rsc_orphan),
             "blocked", pe__rsc_bool_str(rsc, pe_rsc_block),
             "maintenance", pe__rsc_bool_str(rsc, pe_rsc_maintenance),
             "managed", pe__rsc_bool_str(rsc, pe_rsc_managed),
             "failed", pe__rsc_bool_str(rsc, pe_rsc_failed),
             "failure_ignored", pe__rsc_bool_str(rsc, pe_rsc_failure_ignored),
             "nodes_running_on", nodes_running_on,
             "pending", (print_pending? native_pending_task(rsc) : NULL),
             "locked_to", lock_node_name);
    free(nodes_running_on);

    CRM_ASSERT(rc == pcmk_rc_ok);

    if (rsc->running_on != NULL) {
        GList *gIter = rsc->running_on;

        for (; gIter != NULL; gIter = gIter->next) {
            pe_node_t *node = (pe_node_t *) gIter->data;

            rc = pe__name_and_nvpairs_xml(out, false, "node", 3,
                     "name", node->details->uname,
                     "id", node->details->id,
                     "cached", pcmk__btoa(node->details->online));
            CRM_ASSERT(rc == pcmk_rc_ok);
        }
    }

    pcmk__output_xml_pop_parent(out);
    return rc;
}

PCMK__OUTPUT_ARGS("primitive", "uint32_t", "pe_resource_t *", "GList *", "GList *")
int
pe__resource_html(pcmk__output_t *out, va_list args)
{
    uint32_t show_opts = va_arg(args, uint32_t);
    pe_resource_t *rsc = va_arg(args, pe_resource_t *);
    GList *only_node G_GNUC_UNUSED = va_arg(args, GList *);
    GList *only_rsc = va_arg(args, GList *);

    pe_node_t *node = pe__current_node(rsc);

    if (rsc->fns->is_filtered(rsc, only_rsc, TRUE)) {
        return pcmk_rc_no_output;
    }

    CRM_ASSERT(rsc->variant == pe_native);

    if (node == NULL) {
        // This is set only if a non-probe action is pending on this node
        node = rsc->pending_node;
    }
    return pe__common_output_html(out, rsc, rsc_printable_id(rsc), node, show_opts);
}

PCMK__OUTPUT_ARGS("primitive", "uint32_t", "pe_resource_t *", "GList *", "GList *")
int
pe__resource_text(pcmk__output_t *out, va_list args)
{
    uint32_t show_opts = va_arg(args, uint32_t);
    pe_resource_t *rsc = va_arg(args, pe_resource_t *);
    GList *only_node G_GNUC_UNUSED = va_arg(args, GList *);
    GList *only_rsc = va_arg(args, GList *);

    pe_node_t *node = pe__current_node(rsc);

    CRM_ASSERT(rsc->variant == pe_native);

    if (rsc->fns->is_filtered(rsc, only_rsc, TRUE)) {
        return pcmk_rc_no_output;
    }

    if (node == NULL) {
        // This is set only if a non-probe action is pending on this node
        node = rsc->pending_node;
    }
    return pe__common_output_text(out, rsc, rsc_printable_id(rsc), node, show_opts);
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
 * \param[in]  current  0 = where allocated, 1 = where running,
 *                      2 = where running or pending
 *
 * \return If list contains only one node, that node, or NULL otherwise
 */
pe_node_t *
native_location(const pe_resource_t *rsc, GList **list, int current)
{
    pe_node_t *one = NULL;
    GList *result = NULL;

    if (rsc->children) {
        GList *gIter = rsc->children;

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
        GList *gIter = result;

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
get_rscs_brief(GList *rsc_list, GHashTable * rsc_table, GHashTable * active_table)
{
    GList *gIter = rsc_list;

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
        if (pcmk_is_set(pcmk_get_ra_caps(class), pcmk_ra_cap_provider)) {
            const char *prov = crm_element_value(rsc->xml, XML_AGENT_ATTR_PROVIDER);

            if (prov != NULL) {
                offset += snprintf(buffer + offset, LINE_MAX - offset,
                                   PROVIDER_SEP "%s", prov);
            }
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
            GList *gIter2 = rsc->running_on;

            for (; gIter2 != NULL; gIter2 = gIter2->next) {
                pe_node_t *node = (pe_node_t *) gIter2->data;
                GHashTable *node_table = NULL;

                if (node->details->unclean == FALSE && node->details->online == FALSE &&
                    pcmk_is_set(rsc->flags, pe_rsc_managed)) {
                    continue;
                }

                node_table = g_hash_table_lookup(active_table, node->details->uname);
                if (node_table == NULL) {
                    node_table = pcmk__strkey_table(free, free);
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

/*!
 * \internal
 * \deprecated This function will be removed in a future release
 */
void
print_rscs_brief(GList *rsc_list, const char *pre_text, long options,
                 void *print_data, gboolean print_all)
{
    GHashTable *rsc_table = pcmk__strkey_table(free, free);
    GHashTable *active_table = pcmk__strkey_table(free, destroy_node_table);
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
pe__rscs_brief_output(pcmk__output_t *out, GList *rsc_list, uint32_t show_opts)
{
    GHashTable *rsc_table = pcmk__strkey_table(free, free);
    GHashTable *active_table = pcmk__strkey_table(free, destroy_node_table);
    GList *sorted_rscs;
    int rc = pcmk_rc_no_output;

    get_rscs_brief(rsc_list, rsc_table, active_table);

    /* Make a list of the rsc_table keys so that it can be sorted.  This is to make sure
     * output order stays consistent between systems.
     */
    sorted_rscs = g_hash_table_get_keys(rsc_table);
    sorted_rscs = g_list_sort(sorted_rscs, (GCompareFunc) strcmp);

    for (GList *gIter = sorted_rscs; gIter; gIter = gIter->next) {
        char *type = (char *) gIter->data;
        int *rsc_counter = g_hash_table_lookup(rsc_table, type);

        GList *sorted_nodes = NULL;
        int active_counter_all = 0;

        /* Also make a list of the active_table keys so it can be sorted.  If there's
         * more than one instance of a type of resource running, we need the nodes to
         * be sorted to make sure output order stays consistent between systems.
         */
        sorted_nodes = g_hash_table_get_keys(active_table);
        sorted_nodes = g_list_sort(sorted_nodes, (GCompareFunc) pcmk__numeric_strcasecmp);

        for (GList *gIter2 = sorted_nodes; gIter2; gIter2 = gIter2->next) {
            char *node_name = (char *) gIter2->data;
            GHashTable *node_table = g_hash_table_lookup(active_table, node_name);
            int *active_counter = NULL;

            if (node_table == NULL) {
                continue;
            }

            active_counter = g_hash_table_lookup(node_table, type);

            if (active_counter == NULL || *active_counter == 0) {
                continue;

            } else {
                active_counter_all += *active_counter;
            }

            if (pcmk_is_set(show_opts, pcmk_show_rsc_only)) {
                node_name = NULL;
            }

            if (pcmk_is_set(show_opts, pcmk_show_inactive_rscs)) {
                out->list_item(out, NULL, "%d/%d\t(%s):\tActive %s",
                               *active_counter,
                               rsc_counter ? *rsc_counter : 0, type,
                               (*active_counter > 0) && node_name ? node_name : "");
            } else {
                out->list_item(out, NULL, "%d\t(%s):\tActive %s",
                               *active_counter, type,
                               (*active_counter > 0) && node_name ? node_name : "");
            }

            rc = pcmk_rc_ok;
        }

        if (pcmk_is_set(show_opts, pcmk_show_inactive_rscs) && active_counter_all == 0) {
            out->list_item(out, NULL, "%d/%d\t(%s):\tActive",
                           active_counter_all,
                           rsc_counter ? *rsc_counter : 0, type);
            rc = pcmk_rc_ok;
        }

        if (sorted_nodes) {
            g_list_free(sorted_nodes);
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

gboolean
pe__native_is_filtered(pe_resource_t *rsc, GList *only_rsc, gboolean check_parent)
{
    if (pcmk__str_in_list(rsc_printable_id(rsc), only_rsc, pcmk__str_star_matches) ||
        pcmk__str_in_list(rsc->id, only_rsc, pcmk__str_star_matches)) {
        return FALSE;
    } else if (check_parent && rsc->parent) {
        pe_resource_t *up = uber_parent(rsc);

        if (pe_rsc_is_bundled(rsc)) {
            return up->parent->fns->is_filtered(up->parent, only_rsc, FALSE);
        } else {
            return up->fns->is_filtered(up, only_rsc, FALSE);
        }
    }

    return TRUE;
}
