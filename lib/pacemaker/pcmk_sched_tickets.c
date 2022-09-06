/*
 * Copyright 2004-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>
#include <glib.h>

#include <crm/crm.h>
#include <crm/pengine/status.h>
#include <pacemaker-internal.h>

#include "libpacemaker_private.h"

enum loss_ticket_policy {
    loss_ticket_stop,
    loss_ticket_demote,
    loss_ticket_fence,
    loss_ticket_freeze
};

typedef struct {
    const char *id;
    pe_resource_t *rsc;
    pe_ticket_t *ticket;
    enum loss_ticket_policy loss_policy;
    int role;
} rsc_ticket_t;

/*!
 * \brief Check whether a ticket constraint matches a resource by role
 *
 * \param[in] rsc_ticket  Ticket constraint
 * \param[in] rsc         Resource to compare with ticket
 *
 * \param[in] true if constraint has no role or resource's role matches
 *            constraint's, otherwise false
 */
static bool
ticket_role_matches(pe_resource_t *rsc, rsc_ticket_t *rsc_ticket)
{
    if ((rsc_ticket->role == RSC_ROLE_UNKNOWN)
        || (rsc_ticket->role == rsc->role)) {
        return true;
    }
    pe_rsc_trace(rsc, "Skipping constraint: \"%s\" state filter",
                 role2text(rsc_ticket->role));
    return false;
}

/*!
 * \brief Create location constraints and fencing as needed for a ticket
 *
 * \param[in] rsc         Resource affected by ticket
 * \param[in] rsc_ticket  Ticket
 * \param[in] data_set    Cluster working set
 */
static void
constraints_for_ticket(pe_resource_t *rsc, rsc_ticket_t *rsc_ticket,
                       pe_working_set_t *data_set)
{
    GList *gIter = NULL;

    CRM_CHECK((rsc != NULL) && (rsc_ticket != NULL), return);

    if (rsc_ticket->ticket->granted && !rsc_ticket->ticket->standby) {
        return;
    }

    if (rsc->children) {
        pe_rsc_trace(rsc, "Processing ticket dependencies from %s", rsc->id);
        for (gIter = rsc->children; gIter != NULL; gIter = gIter->next) {
            constraints_for_ticket((pe_resource_t *) gIter->data, rsc_ticket,
                                  data_set);
        }
        return;
    }

    pe_rsc_trace(rsc, "%s: Processing ticket dependency on %s (%s, %s)",
                 rsc->id, rsc_ticket->ticket->id, rsc_ticket->id,
                 role2text(rsc_ticket->role));

    if (!rsc_ticket->ticket->granted && (rsc->running_on != NULL)) {

        switch (rsc_ticket->loss_policy) {
            case loss_ticket_stop:
                resource_location(rsc, NULL, -INFINITY, "__loss_of_ticket__",
                                  data_set);
                break;

            case loss_ticket_demote:
                // Promotion score will be set to -INFINITY in promotion_order()
                if (rsc_ticket->role != RSC_ROLE_PROMOTED) {
                    resource_location(rsc, NULL, -INFINITY,
                                      "__loss_of_ticket__", data_set);
                }
                break;

            case loss_ticket_fence:
                if (!ticket_role_matches(rsc, rsc_ticket)) {
                    return;
                }

                resource_location(rsc, NULL, -INFINITY, "__loss_of_ticket__",
                                  data_set);

                for (gIter = rsc->running_on; gIter != NULL;
                     gIter = gIter->next) {
                    pe_fence_node(data_set, (pe_node_t *) gIter->data,
                                  "deadman ticket was lost", FALSE);
                }
                break;

            case loss_ticket_freeze:
                if (!ticket_role_matches(rsc, rsc_ticket)) {
                    return;
                }
                if (rsc->running_on != NULL) {
                    pe__clear_resource_flags(rsc, pe_rsc_managed);
                    pe__set_resource_flags(rsc, pe_rsc_block);
                }
                break;
        }

    } else if (!rsc_ticket->ticket->granted) {

        if ((rsc_ticket->role != RSC_ROLE_PROMOTED)
            || (rsc_ticket->loss_policy == loss_ticket_stop)) {
            resource_location(rsc, NULL, -INFINITY, "__no_ticket__",
                              data_set);
        }

    } else if (rsc_ticket->ticket->standby) {

        if ((rsc_ticket->role != RSC_ROLE_PROMOTED)
            || (rsc_ticket->loss_policy == loss_ticket_stop)) {
            resource_location(rsc, NULL, -INFINITY, "__ticket_standby__",
                              data_set);
        }
    }
}

static void
rsc_ticket_new(const char *id, pe_resource_t *rsc, pe_ticket_t *ticket,
               const char *state, const char *loss_policy,
               pe_working_set_t *data_set)
{
    rsc_ticket_t *new_rsc_ticket = NULL;

    if (rsc == NULL) {
        pcmk__config_err("Ignoring ticket '%s' because resource "
                         "does not exist", id);
        return;
    }

    new_rsc_ticket = calloc(1, sizeof(rsc_ticket_t));
    if (new_rsc_ticket == NULL) {
        return;
    }

    if (pcmk__str_eq(state, RSC_ROLE_STARTED_S,
                     pcmk__str_null_matches|pcmk__str_casei)) {
        state = RSC_ROLE_UNKNOWN_S;
    }

    new_rsc_ticket->id = id;
    new_rsc_ticket->ticket = ticket;
    new_rsc_ticket->rsc = rsc;
    new_rsc_ticket->role = text2role(state);

    if (pcmk__str_eq(loss_policy, "fence", pcmk__str_casei)) {
        if (pcmk_is_set(data_set->flags, pe_flag_stonith_enabled)) {
            new_rsc_ticket->loss_policy = loss_ticket_fence;
        } else {
            pcmk__config_err("Resetting '" XML_TICKET_ATTR_LOSS_POLICY
                             "' for ticket '%s' to 'stop' "
                             "because fencing is not configured", ticket->id);
            loss_policy = "stop";
        }
    }

    if (new_rsc_ticket->loss_policy == loss_ticket_fence) {
        crm_debug("On loss of ticket '%s': Fence the nodes running %s (%s)",
                  new_rsc_ticket->ticket->id, new_rsc_ticket->rsc->id,
                  role2text(new_rsc_ticket->role));

    } else if (pcmk__str_eq(loss_policy, "freeze", pcmk__str_casei)) {
        crm_debug("On loss of ticket '%s': Freeze %s (%s)",
                  new_rsc_ticket->ticket->id, new_rsc_ticket->rsc->id,
                  role2text(new_rsc_ticket->role));
        new_rsc_ticket->loss_policy = loss_ticket_freeze;

    } else if (pcmk__str_eq(loss_policy, "demote", pcmk__str_casei)) {
        crm_debug("On loss of ticket '%s': Demote %s (%s)",
                  new_rsc_ticket->ticket->id, new_rsc_ticket->rsc->id,
                  role2text(new_rsc_ticket->role));
        new_rsc_ticket->loss_policy = loss_ticket_demote;

    } else if (pcmk__str_eq(loss_policy, "stop", pcmk__str_casei)) {
        crm_debug("On loss of ticket '%s': Stop %s (%s)",
                  new_rsc_ticket->ticket->id, new_rsc_ticket->rsc->id,
                  role2text(new_rsc_ticket->role));
        new_rsc_ticket->loss_policy = loss_ticket_stop;

    } else {
        if (new_rsc_ticket->role == RSC_ROLE_PROMOTED) {
            crm_debug("On loss of ticket '%s': Default to demote %s (%s)",
                      new_rsc_ticket->ticket->id, new_rsc_ticket->rsc->id,
                      role2text(new_rsc_ticket->role));
            new_rsc_ticket->loss_policy = loss_ticket_demote;

        } else {
            crm_debug("On loss of ticket '%s': Default to stop %s (%s)",
                      new_rsc_ticket->ticket->id, new_rsc_ticket->rsc->id,
                      role2text(new_rsc_ticket->role));
            new_rsc_ticket->loss_policy = loss_ticket_stop;
        }
    }

    pe_rsc_trace(rsc, "%s (%s) ==> %s",
                 rsc->id, role2text(new_rsc_ticket->role), ticket->id);

    rsc->rsc_tickets = g_list_append(rsc->rsc_tickets, new_rsc_ticket);

    data_set->ticket_constraints = g_list_append(data_set->ticket_constraints,
                                                 new_rsc_ticket);

    if (!(new_rsc_ticket->ticket->granted) || new_rsc_ticket->ticket->standby) {
        constraints_for_ticket(rsc, new_rsc_ticket, data_set);
    }
}

// \return Standard Pacemaker return code
static int
unpack_rsc_ticket_set(xmlNode *set, pe_ticket_t *ticket,
                      const char *loss_policy, pe_working_set_t *data_set)
{
    const char *set_id = NULL;
    const char *role = NULL;

    CRM_CHECK(set != NULL, return EINVAL);
    CRM_CHECK(ticket != NULL, return EINVAL);

    set_id = ID(set);
    if (set_id == NULL) {
        pcmk__config_err("Ignoring <" XML_CONS_TAG_RSC_SET "> without "
                         XML_ATTR_ID);
        return pcmk_rc_unpack_error;
    }

    role = crm_element_value(set, "role");

    for (xmlNode *xml_rsc = first_named_child(set, XML_TAG_RESOURCE_REF);
         xml_rsc != NULL; xml_rsc = crm_next_same_xml(xml_rsc)) {

        pe_resource_t *resource = NULL;

        resource = pcmk__find_constraint_resource(data_set->resources,
                                                  ID(xml_rsc));
        if (resource == NULL) {
            pcmk__config_err("%s: No resource found for %s",
                             set_id, ID(xml_rsc));
            return pcmk_rc_unpack_error;
        }
        pe_rsc_trace(resource, "Resource '%s' depends on ticket '%s'",
                     resource->id, ticket->id);
        rsc_ticket_new(set_id, resource, ticket, role, loss_policy, data_set);
    }

    return pcmk_rc_ok;
}

static void
unpack_simple_rsc_ticket(xmlNode *xml_obj, pe_working_set_t *data_set)
{
    const char *id = NULL;
    const char *ticket_str = crm_element_value(xml_obj, XML_TICKET_ATTR_TICKET);
    const char *loss_policy = crm_element_value(xml_obj,
                                                XML_TICKET_ATTR_LOSS_POLICY);

    pe_ticket_t *ticket = NULL;

    const char *rsc_id = crm_element_value(xml_obj, XML_COLOC_ATTR_SOURCE);
    const char *state = crm_element_value(xml_obj,
                                             XML_COLOC_ATTR_SOURCE_ROLE);

    // experimental syntax from pacemaker-next (unlikely to be adopted as-is)
    const char *instance = crm_element_value(xml_obj,
                                             XML_COLOC_ATTR_SOURCE_INSTANCE);

    pe_resource_t *rsc = NULL;

    CRM_CHECK(xml_obj != NULL, return);

    id = ID(xml_obj);
    if (id == NULL) {
        pcmk__config_err("Ignoring <%s> constraint without " XML_ATTR_ID,
                         crm_element_name(xml_obj));
        return;
    }

    if (ticket_str == NULL) {
        pcmk__config_err("Ignoring constraint '%s' without ticket specified",
                         id);
        return;
    } else {
        ticket = g_hash_table_lookup(data_set->tickets, ticket_str);
    }

    if (ticket == NULL) {
        pcmk__config_err("Ignoring constraint '%s' because ticket '%s' "
                         "does not exist", id, ticket_str);
        return;
    }

    if (rsc_id == NULL) {
        pcmk__config_err("Ignoring constraint '%s' without resource", id);
        return;
    } else {
        rsc = pcmk__find_constraint_resource(data_set->resources, rsc_id);
    }

    if (rsc == NULL) {
        pcmk__config_err("Ignoring constraint '%s' because resource '%s' "
                         "does not exist", id, rsc_id);
        return;

    } else if ((instance != NULL) && !pe_rsc_is_clone(rsc)) {
        pcmk__config_err("Ignoring constraint '%s' because resource '%s' "
                         "is not a clone but instance '%s' was requested",
                         id, rsc_id, instance);
        return;
    }

    if (instance != NULL) {
        rsc = find_clone_instance(rsc, instance, data_set);
        if (rsc == NULL) {
            pcmk__config_warn("Ignoring constraint '%s' because resource '%s' "
                              "does not have an instance '%s'",
                              "'%s'", id, rsc_id, instance);
            return;
        }
    }

    rsc_ticket_new(id, rsc, ticket, state, loss_policy, data_set);
}

// \return Standard Pacemaker return code
static int
unpack_rsc_ticket_tags(xmlNode *xml_obj, xmlNode **expanded_xml,
                       pe_working_set_t *data_set)
{
    const char *id = NULL;
    const char *rsc_id = NULL;
    const char *state = NULL;

    pe_resource_t *rsc = NULL;
    pe_tag_t *tag = NULL;

    xmlNode *rsc_set = NULL;

    *expanded_xml = NULL;

    CRM_CHECK(xml_obj != NULL, return EINVAL);

    id = ID(xml_obj);
    if (id == NULL) {
        pcmk__config_err("Ignoring <%s> constraint without " XML_ATTR_ID,
                         crm_element_name(xml_obj));
        return pcmk_rc_unpack_error;
    }

    // Check whether there are any resource sets with template or tag references
    *expanded_xml = pcmk__expand_tags_in_sets(xml_obj, data_set);
    if (*expanded_xml != NULL) {
        crm_log_xml_trace(*expanded_xml, "Expanded rsc_ticket");
        return pcmk_rc_ok;
    }

    rsc_id = crm_element_value(xml_obj, XML_COLOC_ATTR_SOURCE);
    if (rsc_id == NULL) {
        return pcmk_rc_ok;
    }

    if (!pcmk__valid_resource_or_tag(data_set, rsc_id, &rsc, &tag)) {
        pcmk__config_err("Ignoring constraint '%s' because '%s' is not a "
                         "valid resource or tag", id, rsc_id);
        return pcmk_rc_unpack_error;

    } else if (rsc != NULL) {
        // No template or tag is referenced
        return pcmk_rc_ok;
    }

    state = crm_element_value(xml_obj, XML_COLOC_ATTR_SOURCE_ROLE);

    *expanded_xml = copy_xml(xml_obj);

    // Convert template/tag reference in "rsc" into resource_set under rsc_ticket
    if (!pcmk__tag_to_set(*expanded_xml, &rsc_set, XML_COLOC_ATTR_SOURCE,
                          false, data_set)) {
        free_xml(*expanded_xml);
        *expanded_xml = NULL;
        return pcmk_rc_unpack_error;
    }

    if (rsc_set != NULL) {
        if (state != NULL) {
            // Move "rsc-role" into converted resource_set as a "role" attribute
            crm_xml_add(rsc_set, "role", state);
            xml_remove_prop(*expanded_xml, XML_COLOC_ATTR_SOURCE_ROLE);
        }

    } else {
        free_xml(*expanded_xml);
        *expanded_xml = NULL;
    }

    return pcmk_rc_ok;
}

void
pcmk__unpack_rsc_ticket(xmlNode *xml_obj, pe_working_set_t *data_set)
{
    xmlNode *set = NULL;
    bool any_sets = false;

    const char *id = NULL;
    const char *ticket_str = crm_element_value(xml_obj, XML_TICKET_ATTR_TICKET);
    const char *loss_policy = crm_element_value(xml_obj, XML_TICKET_ATTR_LOSS_POLICY);

    pe_ticket_t *ticket = NULL;

    xmlNode *orig_xml = NULL;
    xmlNode *expanded_xml = NULL;

    CRM_CHECK(xml_obj != NULL, return);

    id = ID(xml_obj);
    if (id == NULL) {
        pcmk__config_err("Ignoring <%s> constraint without " XML_ATTR_ID,
                         crm_element_name(xml_obj));
        return;
    }

    if (data_set->tickets == NULL) {
        data_set->tickets = pcmk__strkey_table(free, destroy_ticket);
    }

    if (ticket_str == NULL) {
        pcmk__config_err("Ignoring constraint '%s' without ticket", id);
        return;
    } else {
        ticket = g_hash_table_lookup(data_set->tickets, ticket_str);
    }

    if (ticket == NULL) {
        ticket = ticket_new(ticket_str, data_set);
        if (ticket == NULL) {
            return;
        }
    }

    if (unpack_rsc_ticket_tags(xml_obj, &expanded_xml,
                               data_set) != pcmk_rc_ok) {
        return;
    }
    if (expanded_xml != NULL) {
        orig_xml = xml_obj;
        xml_obj = expanded_xml;
    }

    for (set = first_named_child(xml_obj, XML_CONS_TAG_RSC_SET); set != NULL;
         set = crm_next_same_xml(set)) {

        any_sets = true;
        set = expand_idref(set, data_set->input);
        if ((set == NULL) // Configuration error, message already logged
            || (unpack_rsc_ticket_set(set, ticket, loss_policy,
                                      data_set) != pcmk_rc_ok)) {
            if (expanded_xml != NULL) {
                free_xml(expanded_xml);
            }
            return;
        }
    }

    if (expanded_xml) {
        free_xml(expanded_xml);
        xml_obj = orig_xml;
    }

    if (!any_sets) {
        unpack_simple_rsc_ticket(xml_obj, data_set);
    }
}

/*!
 * \internal
 * \brief Ban resource from a node if it doesn't have a promotion ticket
 *
 * If a resource has tickets for the promoted role, and the ticket is either not
 * granted or set to standby, then ban the resource from all nodes.
 *
 * \param[in] rsc  Resource to check
 */
void
pcmk__require_promotion_tickets(pe_resource_t *rsc)
{
    for (GList *item = rsc->rsc_tickets; item != NULL; item = item->next) {
        rsc_ticket_t *rsc_ticket = (rsc_ticket_t *) item->data;

        if ((rsc_ticket->role == RSC_ROLE_PROMOTED)
            && (!rsc_ticket->ticket->granted || rsc_ticket->ticket->standby)) {
            resource_location(rsc, NULL, -INFINITY,
                              "__stateful_without_ticket__", rsc->cluster);
        }
    }
}
