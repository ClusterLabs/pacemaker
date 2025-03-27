/*
 * Copyright 2004-2025 the Pacemaker project contributors
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
#include <crm/common/scheduler.h>
#include <crm/common/scheduler_internal.h>
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
    pcmk_resource_t *rsc;
    pcmk__ticket_t *ticket;
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
ticket_role_matches(const pcmk_resource_t *rsc, const rsc_ticket_t *rsc_ticket)
{
    if ((rsc_ticket->role == pcmk_role_unknown)
        || (rsc_ticket->role == rsc->priv->orig_role)) {
        return true;
    }
    pcmk__rsc_trace(rsc, "Skipping constraint: \"%s\" state filter",
                    pcmk_role_text(rsc_ticket->role));
    return false;
}

/*!
 * \brief Create location constraints and fencing as needed for a ticket
 *
 * \param[in,out] rsc         Resource affected by ticket
 * \param[in]     rsc_ticket  Ticket
 */
static void
constraints_for_ticket(pcmk_resource_t *rsc, const rsc_ticket_t *rsc_ticket)
{
    GList *iter = NULL;

    CRM_CHECK((rsc != NULL) && (rsc_ticket != NULL), return);

    if (pcmk_is_set(rsc_ticket->ticket->flags, pcmk__ticket_granted)
        && !pcmk_is_set(rsc_ticket->ticket->flags, pcmk__ticket_standby)) {
        return;
    }

    if (rsc->priv->children != NULL) {
        pcmk__rsc_trace(rsc, "Processing ticket dependencies from %s", rsc->id);
        for (iter = rsc->priv->children; iter != NULL; iter = iter->next) {
            constraints_for_ticket((pcmk_resource_t *) iter->data, rsc_ticket);
        }
        return;
    }

    pcmk__rsc_trace(rsc, "%s: Processing ticket dependency on %s (%s, %s)",
                    rsc->id, rsc_ticket->ticket->id, rsc_ticket->id,
                    pcmk_role_text(rsc_ticket->role));

    if (!pcmk_is_set(rsc_ticket->ticket->flags, pcmk__ticket_granted)
        && (rsc->priv->active_nodes != NULL)) {

        switch (rsc_ticket->loss_policy) {
            case loss_ticket_stop:
                resource_location(rsc, NULL, -PCMK_SCORE_INFINITY,
                                  "__loss_of_ticket__",
                                  rsc->priv->scheduler);
                break;

            case loss_ticket_demote:
                // Promotion score will be set to -INFINITY in promotion_order()
                if (rsc_ticket->role != pcmk_role_promoted) {
                    resource_location(rsc, NULL, -PCMK_SCORE_INFINITY,
                                      "__loss_of_ticket__",
                                      rsc->priv->scheduler);
                }
                break;

            case loss_ticket_fence:
                if (!ticket_role_matches(rsc, rsc_ticket)) {
                    return;
                }

                resource_location(rsc, NULL, -PCMK_SCORE_INFINITY,
                                  "__loss_of_ticket__",
                                  rsc->priv->scheduler);

                for (iter = rsc->priv->active_nodes;
                     iter != NULL; iter = iter->next) {

                    pe_fence_node(rsc->priv->scheduler,
                                  (pcmk_node_t *) iter->data,
                                  "deadman ticket was lost", FALSE);
                }
                break;

            case loss_ticket_freeze:
                if (!ticket_role_matches(rsc, rsc_ticket)) {
                    return;
                }
                if (rsc->priv->active_nodes != NULL) {
                    pcmk__clear_rsc_flags(rsc, pcmk__rsc_managed);
                    pcmk__set_rsc_flags(rsc, pcmk__rsc_blocked);
                }
                break;
        }

    } else if (!pcmk_is_set(rsc_ticket->ticket->flags, pcmk__ticket_granted)) {

        if ((rsc_ticket->role != pcmk_role_promoted)
            || (rsc_ticket->loss_policy == loss_ticket_stop)) {
            resource_location(rsc, NULL, -PCMK_SCORE_INFINITY,
                              "__no_ticket__", rsc->priv->scheduler);
        }

    } else if (pcmk_is_set(rsc_ticket->ticket->flags, pcmk__ticket_standby)) {

        if ((rsc_ticket->role != pcmk_role_promoted)
            || (rsc_ticket->loss_policy == loss_ticket_stop)) {
            resource_location(rsc, NULL, -PCMK_SCORE_INFINITY,
                              "__ticket_standby__", rsc->priv->scheduler);
        }
    }
}

static void
rsc_ticket_new(const char *id, pcmk_resource_t *rsc, pcmk__ticket_t *ticket,
               const char *role_spec, const char *loss_policy)
{
    rsc_ticket_t *new_rsc_ticket = NULL;
    enum rsc_role_e role = pcmk_role_unknown;

    if (rsc == NULL) {
        pcmk__config_err("Ignoring ticket '%s' because resource "
                         "does not exist", id);
        return;
    }
    if (pcmk__parse_constraint_role(id, role_spec, &role) != pcmk_rc_ok) {
        // Not possible with schema validation enabled (error already logged)
        return;
    }

    new_rsc_ticket = pcmk__assert_alloc(1, sizeof(rsc_ticket_t));
    new_rsc_ticket->id = id;
    new_rsc_ticket->ticket = ticket;
    new_rsc_ticket->rsc = rsc;
    new_rsc_ticket->role = role;

    if (pcmk__str_eq(loss_policy, PCMK_VALUE_FENCE, pcmk__str_casei)) {
        if (pcmk_is_set(rsc->priv->scheduler->flags,
                        pcmk__sched_fencing_enabled)) {
            new_rsc_ticket->loss_policy = loss_ticket_fence;
        } else {
            pcmk__config_err("Resetting '" PCMK_XA_LOSS_POLICY "' "
                             "for ticket '%s' to '" PCMK_VALUE_STOP "' "
                             "because fencing is not configured", ticket->id);
            loss_policy = PCMK_VALUE_STOP;
        }
    }

    if (new_rsc_ticket->loss_policy == loss_ticket_fence) {
        crm_debug("On loss of ticket '%s': Fence the nodes running %s (%s)",
                  new_rsc_ticket->ticket->id, new_rsc_ticket->rsc->id,
                  pcmk_role_text(new_rsc_ticket->role));

    } else if (pcmk__str_eq(loss_policy, PCMK_VALUE_FREEZE, pcmk__str_casei)) {
        crm_debug("On loss of ticket '%s': Freeze %s (%s)",
                  new_rsc_ticket->ticket->id, new_rsc_ticket->rsc->id,
                  pcmk_role_text(new_rsc_ticket->role));
        new_rsc_ticket->loss_policy = loss_ticket_freeze;

    } else if (pcmk__str_eq(loss_policy, PCMK_VALUE_DEMOTE, pcmk__str_casei)) {
        crm_debug("On loss of ticket '%s': Demote %s (%s)",
                  new_rsc_ticket->ticket->id, new_rsc_ticket->rsc->id,
                  pcmk_role_text(new_rsc_ticket->role));
        new_rsc_ticket->loss_policy = loss_ticket_demote;

    } else if (pcmk__str_eq(loss_policy, PCMK_VALUE_STOP, pcmk__str_casei)) {
        crm_debug("On loss of ticket '%s': Stop %s (%s)",
                  new_rsc_ticket->ticket->id, new_rsc_ticket->rsc->id,
                  pcmk_role_text(new_rsc_ticket->role));
        new_rsc_ticket->loss_policy = loss_ticket_stop;

    } else {
        if (new_rsc_ticket->role == pcmk_role_promoted) {
            crm_debug("On loss of ticket '%s': Default to demote %s (%s)",
                      new_rsc_ticket->ticket->id, new_rsc_ticket->rsc->id,
                      pcmk_role_text(new_rsc_ticket->role));
            new_rsc_ticket->loss_policy = loss_ticket_demote;

        } else {
            crm_debug("On loss of ticket '%s': Default to stop %s (%s)",
                      new_rsc_ticket->ticket->id, new_rsc_ticket->rsc->id,
                      pcmk_role_text(new_rsc_ticket->role));
            new_rsc_ticket->loss_policy = loss_ticket_stop;
        }
    }

    pcmk__rsc_trace(rsc, "%s (%s) ==> %s",
                    rsc->id, pcmk_role_text(new_rsc_ticket->role), ticket->id);

    rsc->priv->ticket_constraints =
        g_list_append(rsc->priv->ticket_constraints, new_rsc_ticket);

    if (!pcmk_is_set(new_rsc_ticket->ticket->flags, pcmk__ticket_granted)
        || pcmk_is_set(new_rsc_ticket->ticket->flags, pcmk__ticket_standby)) {
        constraints_for_ticket(rsc, new_rsc_ticket);
    }
}

// \return Standard Pacemaker return code
static int
unpack_rsc_ticket_set(xmlNode *set, pcmk__ticket_t *ticket,
                      const char *loss_policy, pcmk_scheduler_t *scheduler)
{
    const char *set_id = NULL;
    const char *role = NULL;

    CRM_CHECK(set != NULL, return EINVAL);
    CRM_CHECK(ticket != NULL, return EINVAL);

    set_id = pcmk__xe_id(set);
    if (set_id == NULL) {
        pcmk__config_err("Ignoring <" PCMK_XE_RESOURCE_SET "> without "
                         PCMK_XA_ID);
        return pcmk_rc_unpack_error;
    }

    role = pcmk__xe_get(set, PCMK_XA_ROLE);

    for (xmlNode *xml_rsc = pcmk__xe_first_child(set, PCMK_XE_RESOURCE_REF,
                                                 NULL, NULL);
         xml_rsc != NULL;
         xml_rsc = pcmk__xe_next(xml_rsc, PCMK_XE_RESOURCE_REF)) {

        pcmk_resource_t *resource = NULL;

        resource = pcmk__find_constraint_resource(scheduler->priv->resources,
                                                  pcmk__xe_id(xml_rsc));
        if (resource == NULL) {
            pcmk__config_err("%s: No resource found for %s",
                             set_id, pcmk__xe_id(xml_rsc));
            return pcmk_rc_unpack_error;
        }
        pcmk__rsc_trace(resource, "Resource '%s' depends on ticket '%s'",
                        resource->id, ticket->id);
        rsc_ticket_new(set_id, resource, ticket, role, loss_policy);
    }

    return pcmk_rc_ok;
}

static void
unpack_simple_rsc_ticket(xmlNode *xml_obj, pcmk_scheduler_t *scheduler)
{
    const char *id = NULL;
    const char *ticket_str = pcmk__xe_get(xml_obj, PCMK_XA_TICKET);
    const char *loss_policy = pcmk__xe_get(xml_obj, PCMK_XA_LOSS_POLICY);

    pcmk__ticket_t *ticket = NULL;

    const char *rsc_id = pcmk__xe_get(xml_obj, PCMK_XA_RSC);
    const char *state = pcmk__xe_get(xml_obj, PCMK_XA_RSC_ROLE);

    pcmk_resource_t *rsc = NULL;

    CRM_CHECK(xml_obj != NULL, return);

    id = pcmk__xe_id(xml_obj);
    if (id == NULL) {
        pcmk__config_err("Ignoring <%s> constraint without " PCMK_XA_ID,
                         xml_obj->name);
        return;
    }

    if (ticket_str == NULL) {
        pcmk__config_err("Ignoring constraint '%s' without ticket specified",
                         id);
        return;
    } else {
        ticket = g_hash_table_lookup(scheduler->priv->ticket_constraints,
                                     ticket_str);
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
        rsc = pcmk__find_constraint_resource(scheduler->priv->resources,
                                             rsc_id);
    }

    if (rsc == NULL) {
        pcmk__config_err("Ignoring constraint '%s' because resource '%s' "
                         "does not exist", id, rsc_id);
        return;
    }

    rsc_ticket_new(id, rsc, ticket, state, loss_policy);
}

// \return Standard Pacemaker return code
static int
unpack_rsc_ticket_tags(xmlNode *xml_obj, xmlNode **expanded_xml,
                       pcmk_scheduler_t *scheduler)
{
    const char *id = NULL;
    const char *rsc_id = NULL;
    const char *state = NULL;

    pcmk_resource_t *rsc = NULL;
    pcmk__idref_t *tag = NULL;

    xmlNode *rsc_set = NULL;

    *expanded_xml = NULL;

    CRM_CHECK(xml_obj != NULL, return EINVAL);

    id = pcmk__xe_id(xml_obj);
    if (id == NULL) {
        pcmk__config_err("Ignoring <%s> constraint without " PCMK_XA_ID,
                         xml_obj->name);
        return pcmk_rc_unpack_error;
    }

    // Check whether there are any resource sets with template or tag references
    *expanded_xml = pcmk__expand_tags_in_sets(xml_obj, scheduler);
    if (*expanded_xml != NULL) {
        crm_log_xml_trace(*expanded_xml, "Expanded rsc_ticket");
        return pcmk_rc_ok;
    }

    rsc_id = pcmk__xe_get(xml_obj, PCMK_XA_RSC);
    if (rsc_id == NULL) {
        return pcmk_rc_ok;
    }

    if (!pcmk__valid_resource_or_tag(scheduler, rsc_id, &rsc, &tag)) {
        pcmk__config_err("Ignoring constraint '%s' because '%s' is not a "
                         "valid resource or tag", id, rsc_id);
        return pcmk_rc_unpack_error;

    } else if (rsc != NULL) {
        // No template or tag is referenced
        return pcmk_rc_ok;
    }

    state = pcmk__xe_get(xml_obj, PCMK_XA_RSC_ROLE);

    *expanded_xml = pcmk__xml_copy(NULL, xml_obj);

    /* Convert any template or tag reference in "rsc" into ticket
     * PCMK_XE_RESOURCE_SET
     */
    if (!pcmk__tag_to_set(*expanded_xml, &rsc_set, PCMK_XA_RSC, false,
                          scheduler)) {
        pcmk__xml_free(*expanded_xml);
        *expanded_xml = NULL;
        return pcmk_rc_unpack_error;
    }

    if (rsc_set != NULL) {
        if (state != NULL) {
            /* Move PCMK_XA_RSC_ROLE into converted PCMK_XE_RESOURCE_SET as a
             * PCMK_XA_ROLE attribute
             */
            pcmk__xe_set(rsc_set, PCMK_XA_ROLE, state);
            pcmk__xe_remove_attr(*expanded_xml, PCMK_XA_RSC_ROLE);
        }

    } else {
        pcmk__xml_free(*expanded_xml);
        *expanded_xml = NULL;
    }

    return pcmk_rc_ok;
}

void
pcmk__unpack_rsc_ticket(xmlNode *xml_obj, pcmk_scheduler_t *scheduler)
{
    xmlNode *set = NULL;
    bool any_sets = false;

    const char *id = NULL;
    const char *ticket_str = NULL;

    pcmk__ticket_t *ticket = NULL;

    xmlNode *orig_xml = NULL;
    xmlNode *expanded_xml = NULL;

    CRM_CHECK(xml_obj != NULL, return);

    id = pcmk__xe_id(xml_obj);
    if (id == NULL) {
        pcmk__config_err("Ignoring <%s> constraint without " PCMK_XA_ID,
                         xml_obj->name);
        return;
    }

    if (scheduler->priv->ticket_constraints == NULL) {
        scheduler->priv->ticket_constraints =
            pcmk__strkey_table(free, destroy_ticket);
    }

    ticket_str = pcmk__xe_get(xml_obj, PCMK_XA_TICKET);
    if (ticket_str == NULL) {
        pcmk__config_err("Ignoring constraint '%s' without ticket", id);
        return;
    } else {
        ticket = g_hash_table_lookup(scheduler->priv->ticket_constraints,
                                     ticket_str);
    }

    if (ticket == NULL) {
        ticket = ticket_new(ticket_str, scheduler);
        if (ticket == NULL) {
            return;
        }
    }

    if (unpack_rsc_ticket_tags(xml_obj, &expanded_xml,
                               scheduler) != pcmk_rc_ok) {
        return;
    }
    if (expanded_xml != NULL) {
        orig_xml = xml_obj;
        xml_obj = expanded_xml;
    }

    for (set = pcmk__xe_first_child(xml_obj, PCMK_XE_RESOURCE_SET, NULL, NULL);
         set != NULL; set = pcmk__xe_next(set, PCMK_XE_RESOURCE_SET)) {

        const char *loss_policy = NULL;

        any_sets = true;
        set = pcmk__xe_resolve_idref(set, scheduler->input);
        loss_policy = pcmk__xe_get(xml_obj, PCMK_XA_LOSS_POLICY);

        if ((set == NULL) // Configuration error, message already logged
            || (unpack_rsc_ticket_set(set, ticket, loss_policy,
                                      scheduler) != pcmk_rc_ok)) {
            if (expanded_xml != NULL) {
                pcmk__xml_free(expanded_xml);
            }
            return;
        }
    }

    if (expanded_xml) {
        pcmk__xml_free(expanded_xml);
        xml_obj = orig_xml;
    }

    if (!any_sets) {
        unpack_simple_rsc_ticket(xml_obj, scheduler);
    }
}

/*!
 * \internal
 * \brief Ban resource from a node if it doesn't have a promotion ticket
 *
 * If a resource has tickets for the promoted role, and the ticket is either not
 * granted or set to standby, then ban the resource from all nodes.
 *
 * \param[in,out] rsc  Resource to check
 */
void
pcmk__require_promotion_tickets(pcmk_resource_t *rsc)
{
    for (GList *item = rsc->priv->ticket_constraints;
         item != NULL; item = item->next) {

        rsc_ticket_t *rsc_ticket = (rsc_ticket_t *) item->data;

        if ((rsc_ticket->role == pcmk_role_promoted)
            && (!pcmk_is_set(rsc_ticket->ticket->flags, pcmk__ticket_granted)
                || pcmk_is_set(rsc_ticket->ticket->flags,
                               pcmk__ticket_standby))) {
            resource_location(rsc, NULL, -PCMK_SCORE_INFINITY,
                              "__stateful_without_ticket__",
                              rsc->priv->scheduler);
        }
    }
}
