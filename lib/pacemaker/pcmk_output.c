/*
 * Copyright 2019-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <crm/common/results.h>
#include <crm/msg_xml.h>
#include <crm/stonith-ng.h>
#include <crm/fencing/internal.h>
#include <crm/pengine/internal.h>
#include <libxml/tree.h>
#include <pacemaker-internal.h>

static char *
colocations_header(pe_resource_t *rsc, pcmk__colocation_t *cons,
                   gboolean dependents) {
    char *score = NULL;
    char *retval = NULL;

    score = score2char(cons->score);
    if (cons->role_rh > RSC_ROLE_STARTED) {
            retval = crm_strdup_printf("%s (score=%s, %s role=%s, id=%s)",
                                       rsc->id, score, dependents ? "needs" : "with",
                                       role2text(cons->role_rh), cons->id);
    } else {
        retval = crm_strdup_printf("%s (score=%s, id=%s)",
                                   rsc->id, score, cons->id);
    }

    free(score);
    return retval;
}

static void
colocations_xml_node(pcmk__output_t *out, pe_resource_t *rsc,
                     pcmk__colocation_t *cons) {
    char *score = NULL;
    xmlNodePtr node = NULL;

    score = score2char(cons->score);
    node = pcmk__output_create_xml_node(out, XML_CONS_TAG_RSC_DEPEND,
                                        "id", cons->id,
                                        "rsc", cons->rsc_lh->id,
                                        "with-rsc", cons->rsc_rh->id,
                                        "score", score,
                                        NULL);

    if (cons->node_attribute) {
        xmlSetProp(node, (pcmkXmlStr) "node-attribute", (pcmkXmlStr) cons->node_attribute);
    }

    if (cons->role_lh != RSC_ROLE_UNKNOWN) {
        xmlSetProp(node, (pcmkXmlStr) "rsc-role", (pcmkXmlStr) role2text(cons->role_lh));
    }

    if (cons->role_rh != RSC_ROLE_UNKNOWN) {
        xmlSetProp(node, (pcmkXmlStr) "with-rsc-role", (pcmkXmlStr) role2text(cons->role_rh));
    }

    free(score);
}

static int
do_locations_list_xml(pcmk__output_t *out, pe_resource_t *rsc, bool add_header)
{
    GList *lpc = NULL;
    GList *list = rsc->rsc_location;
    int rc = pcmk_rc_no_output;

    for (lpc = list; lpc != NULL; lpc = lpc->next) {
        pe__location_t *cons = lpc->data;

        GList *lpc2 = NULL;

        for (lpc2 = cons->node_list_rh; lpc2 != NULL; lpc2 = lpc2->next) {
            pe_node_t *node = (pe_node_t *) lpc2->data;
            char *score = score2char(node->weight);

            if (add_header) {
                PCMK__OUTPUT_LIST_HEADER(out, FALSE, rc, "locations");
            }

            pcmk__output_create_xml_node(out, XML_CONS_TAG_RSC_LOCATION,
                                         "node", node->details->uname,
                                         "rsc", rsc->id,
                                         "id", cons->id,
                                         "score", score,
                                         NULL);
            free(score);
        }
    }

    if (add_header) {
        PCMK__OUTPUT_LIST_FOOTER(out, rc);
    }

    return rc;
}

PCMK__OUTPUT_ARGS("rsc-action-item", "const char *", "pe_resource_t *",
                  "pe_node_t *", "pe_node_t *", "pe_action_t *",
                  "pe_action_t *")
static int
rsc_action_item(pcmk__output_t *out, va_list args)
{
    const char *change = va_arg(args, const char *);
    pe_resource_t *rsc = va_arg(args, pe_resource_t *);
    pe_node_t *origin = va_arg(args, pe_node_t *);
    pe_node_t *destination = va_arg(args, pe_node_t *);
    pe_action_t *action = va_arg(args, pe_action_t *);
    pe_action_t *source = va_arg(args, pe_action_t *);

    int len = 0;
    char *reason = NULL;
    char *details = NULL;
    bool same_host = FALSE;
    bool same_role = FALSE;
    bool need_role = FALSE;

    static int rsc_width = 5;
    static int detail_width = 5;

    CRM_ASSERT(action);
    CRM_ASSERT(destination != NULL || origin != NULL);

    if(source == NULL) {
        source = action;
    }

    len = strlen(rsc->id);
    if(len > rsc_width) {
        rsc_width = len + 2;
    }

    if(rsc->role > RSC_ROLE_STARTED || rsc->next_role > RSC_ROLE_SLAVE) {
        need_role = TRUE;
    }

    if(origin != NULL && destination != NULL && origin->details == destination->details) {
        same_host = TRUE;
    }

    if(rsc->role == rsc->next_role) {
        same_role = TRUE;
    }

    if (need_role && (origin == NULL)) {
        /* Starting and promoting a promotable clone instance */
        details = crm_strdup_printf("%s -> %s %s", role2text(rsc->role), role2text(rsc->next_role), destination->details->uname);

    } else if (origin == NULL) {
        /* Starting a resource */
        details = crm_strdup_printf("%s", destination->details->uname);

    } else if (need_role && (destination == NULL)) {
        /* Stopping a promotable clone instance */
        details = crm_strdup_printf("%s %s", role2text(rsc->role), origin->details->uname);

    } else if (destination == NULL) {
        /* Stopping a resource */
        details = crm_strdup_printf("%s", origin->details->uname);

    } else if (need_role && same_role && same_host) {
        /* Recovering, restarting or re-promoting a promotable clone instance */
        details = crm_strdup_printf("%s %s", role2text(rsc->role), origin->details->uname);

    } else if (same_role && same_host) {
        /* Recovering or Restarting a normal resource */
        details = crm_strdup_printf("%s", origin->details->uname);

    } else if (need_role && same_role) {
        /* Moving a promotable clone instance */
        details = crm_strdup_printf("%s -> %s %s", origin->details->uname, destination->details->uname, role2text(rsc->role));

    } else if (same_role) {
        /* Moving a normal resource */
        details = crm_strdup_printf("%s -> %s", origin->details->uname, destination->details->uname);

    } else if (same_host) {
        /* Promoting or demoting a promotable clone instance */
        details = crm_strdup_printf("%s -> %s %s", role2text(rsc->role), role2text(rsc->next_role), origin->details->uname);

    } else {
        /* Moving and promoting/demoting */
        details = crm_strdup_printf("%s %s -> %s %s", role2text(rsc->role), origin->details->uname, role2text(rsc->next_role), destination->details->uname);
    }

    len = strlen(details);
    if(len > detail_width) {
        detail_width = len;
    }

    if(source->reason && !pcmk_is_set(action->flags, pe_action_runnable)) {
        reason = crm_strdup_printf("due to %s (blocked)", source->reason);

    } else if(source->reason) {
        reason = crm_strdup_printf("due to %s", source->reason);

    } else if (!pcmk_is_set(action->flags, pe_action_runnable)) {
        reason = strdup("blocked");

    }

    out->list_item(out, NULL, "%-8s   %-*s   ( %*s )%s%s", change, rsc_width,
                   rsc->id, detail_width, details, reason ? "  " : "", reason ? reason : "");

    free(details);
    free(reason);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("rsc-action-item", "const char *", "pe_resource_t *",
                  "pe_node_t *", "pe_node_t *", "pe_action_t *",
                  "pe_action_t *")
static int
rsc_action_item_xml(pcmk__output_t *out, va_list args)
{
    const char *change = va_arg(args, const char *);
    pe_resource_t *rsc = va_arg(args, pe_resource_t *);
    pe_node_t *origin = va_arg(args, pe_node_t *);
    pe_node_t *destination = va_arg(args, pe_node_t *);
    pe_action_t *action = va_arg(args, pe_action_t *);
    pe_action_t *source = va_arg(args, pe_action_t *);

    char *change_str = NULL;

    bool same_host = FALSE;
    bool same_role = FALSE;
    bool need_role = FALSE;
    xmlNode *xml = NULL;

    CRM_ASSERT(action);
    CRM_ASSERT(destination != NULL || origin != NULL);

    if (source == NULL) {
        source = action;
    }

    if(rsc->role > RSC_ROLE_STARTED || rsc->next_role > RSC_ROLE_SLAVE) {
        need_role = TRUE;
    }

    if(origin != NULL && destination != NULL && origin->details == destination->details) {
        same_host = TRUE;
    }

    if(rsc->role == rsc->next_role) {
        same_role = TRUE;
    }

    change_str = g_ascii_strdown(change, -1);
    xml = pcmk__output_create_xml_node(out, "rsc_action",
                                       "action", change_str,
                                       "resource", rsc->id,
                                       NULL);
    g_free(change_str);

    if (need_role && (origin == NULL)) {
        /* Starting and promoting a promotable clone instance */
        pcmk__xe_set_props(xml,
                           "role", role2text(rsc->role),
                           "next-role", role2text(rsc->next_role),
                           "dest", destination->details->uname,
                           NULL);

    } else if (origin == NULL) {
        /* Starting a resource */
        crm_xml_add(xml, "node", destination->details->uname);

    } else if (need_role && (destination == NULL)) {
        /* Stopping a promotable clone instance */
        pcmk__xe_set_props(xml,
                           "role", role2text(rsc->role),
                           "node", origin->details->uname,
                           NULL);

    } else if (destination == NULL) {
        /* Stopping a resource */
        crm_xml_add(xml, "node", origin->details->uname);

    } else if (need_role && same_role && same_host) {
        /* Recovering, restarting or re-promoting a promotable clone instance */
        pcmk__xe_set_props(xml,
                           "role", role2text(rsc->role),
                           "source", origin->details->uname,
                           NULL);

    } else if (same_role && same_host) {
        /* Recovering or Restarting a normal resource */
        crm_xml_add(xml, "source", origin->details->uname);

    } else if (need_role && same_role) {
        /* Moving a promotable clone instance */
        pcmk__xe_set_props(xml,
                           "source", origin->details->uname,
                           "dest", destination->details->uname,
                           "role", role2text(rsc->role),
                           NULL);

    } else if (same_role) {
        /* Moving a normal resource */
        pcmk__xe_set_props(xml,
                           "source", origin->details->uname,
                           "dest", destination->details->uname,
                           NULL);

    } else if (same_host) {
        /* Promoting or demoting a promotable clone instance */
        pcmk__xe_set_props(xml,
                           "role", role2text(rsc->role),
                           "next-role", role2text(rsc->next_role),
                           "source", origin->details->uname,
                           NULL);

    } else {
        /* Moving and promoting/demoting */
        pcmk__xe_set_props(xml,
                           "role", role2text(rsc->role),
                           "source", origin->details->uname,
                           "next-role", role2text(rsc->next_role),
                           "dest", destination->details->uname,
                           NULL);
    }

    if (source->reason && !pcmk_is_set(action->flags, pe_action_runnable)) {
        pcmk__xe_set_props(xml,
                           "reason", source->reason,
                           "blocked", "true",
                           NULL);

    } else if(source->reason) {
        crm_xml_add(xml, "reason", source->reason);

    } else if (!pcmk_is_set(action->flags, pe_action_runnable)) {
        crm_xml_add(xml, "blocked", "true");

    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("rsc-is-colocated-with-list", "pe_resource_t *", "gboolean")
static int
rsc_is_colocated_with_list(pcmk__output_t *out, va_list args) {
    pe_resource_t *rsc = va_arg(args, pe_resource_t *);
    gboolean recursive = va_arg(args, gboolean);

    int rc = pcmk_rc_no_output;

    if (pcmk_is_set(rsc->flags, pe_rsc_allocating)) {
        return rc;
    }

    pe__set_resource_flags(rsc, pe_rsc_allocating);
    for (GList *lpc = rsc->rsc_cons; lpc != NULL; lpc = lpc->next) {
        pcmk__colocation_t *cons = (pcmk__colocation_t *) lpc->data;
        char *hdr = NULL;

        PCMK__OUTPUT_LIST_HEADER(out, FALSE, rc, "Resources %s is colocated with", rsc->id);

        if (pcmk_is_set(cons->rsc_rh->flags, pe_rsc_allocating)) {
            out->list_item(out, NULL, "%s (id=%s - loop)", cons->rsc_rh->id, cons->id);
            continue;
        }

        hdr = colocations_header(cons->rsc_rh, cons, FALSE);
        out->list_item(out, NULL, "%s", hdr);
        free(hdr);

        /* Empty list header just for indentation of information about this resource. */
        out->begin_list(out, NULL, NULL, NULL);

        out->message(out, "locations-list", cons->rsc_rh);
        if (recursive) {
            out->message(out, "rsc-is-colocated-with-list", cons->rsc_rh, recursive);
        }

        out->end_list(out);
    }

    PCMK__OUTPUT_LIST_FOOTER(out, rc);
    return rc;
}

PCMK__OUTPUT_ARGS("rsc-is-colocated-with-list", "pe_resource_t *", "gboolean")
static int
rsc_is_colocated_with_list_xml(pcmk__output_t *out, va_list args) {
    pe_resource_t *rsc = va_arg(args, pe_resource_t *);
    gboolean recursive = va_arg(args, gboolean);

    int rc = pcmk_rc_no_output;

    if (pcmk_is_set(rsc->flags, pe_rsc_allocating)) {
        return rc;
    }

    pe__set_resource_flags(rsc, pe_rsc_allocating);
    for (GList *lpc = rsc->rsc_cons; lpc != NULL; lpc = lpc->next) {
        pcmk__colocation_t *cons = (pcmk__colocation_t *) lpc->data;

        if (pcmk_is_set(cons->rsc_rh->flags, pe_rsc_allocating)) {
            colocations_xml_node(out, cons->rsc_rh, cons);
            continue;
        }

        colocations_xml_node(out, cons->rsc_rh, cons);
        do_locations_list_xml(out, cons->rsc_rh, false);

        if (recursive) {
            out->message(out, "rsc-is-colocated-with-list", cons->rsc_rh, recursive);
        }
    }

    return rc;
}

PCMK__OUTPUT_ARGS("rscs-colocated-with-list", "pe_resource_t *", "gboolean")
static int
rscs_colocated_with_list(pcmk__output_t *out, va_list args) {
    pe_resource_t *rsc = va_arg(args, pe_resource_t *);
    gboolean recursive = va_arg(args, gboolean);

    int rc = pcmk_rc_no_output;

    if (pcmk_is_set(rsc->flags, pe_rsc_allocating)) {
        return rc;
    }

    pe__set_resource_flags(rsc, pe_rsc_allocating);
    for (GList *lpc = rsc->rsc_cons_lhs; lpc != NULL; lpc = lpc->next) {
        pcmk__colocation_t *cons = (pcmk__colocation_t *) lpc->data;
        char *hdr = NULL;

        PCMK__OUTPUT_LIST_HEADER(out, FALSE, rc, "Resources colocated with %s", rsc->id);

        if (pcmk_is_set(cons->rsc_lh->flags, pe_rsc_allocating)) {
            out->list_item(out, NULL, "%s (id=%s - loop)", cons->rsc_lh->id, cons->id);
            continue;
        }

        hdr = colocations_header(cons->rsc_lh, cons, TRUE);
        out->list_item(out, NULL, "%s", hdr);
        free(hdr);

        /* Empty list header just for indentation of information about this resource. */
        out->begin_list(out, NULL, NULL, NULL);

        out->message(out, "locations-list", cons->rsc_lh);
        if (recursive) {
            out->message(out, "rscs-colocated-with-list", cons->rsc_lh, recursive);
        }

        out->end_list(out);
    }

    PCMK__OUTPUT_LIST_FOOTER(out, rc);
    return rc;
}

PCMK__OUTPUT_ARGS("rscs-colocated-with-list", "pe_resource_t *", "gboolean")
static int
rscs_colocated_with_list_xml(pcmk__output_t *out, va_list args) {
    pe_resource_t *rsc = va_arg(args, pe_resource_t *);
    gboolean recursive = va_arg(args, gboolean);

    int rc = pcmk_rc_no_output;

    if (pcmk_is_set(rsc->flags, pe_rsc_allocating)) {
        return rc;
    }

    pe__set_resource_flags(rsc, pe_rsc_allocating);
    for (GList *lpc = rsc->rsc_cons_lhs; lpc != NULL; lpc = lpc->next) {
        pcmk__colocation_t *cons = (pcmk__colocation_t *) lpc->data;

        if (pcmk_is_set(cons->rsc_lh->flags, pe_rsc_allocating)) {
            colocations_xml_node(out, cons->rsc_lh, cons);
            continue;
        }

        colocations_xml_node(out, cons->rsc_lh, cons);
        do_locations_list_xml(out, cons->rsc_lh, false);

        if (recursive) {
            out->message(out, "rscs-colocated-with-list", cons->rsc_lh, recursive);
        }
    }

    return rc;
}

PCMK__OUTPUT_ARGS("locations-list", "pe_resource_t *")
static int
locations_list(pcmk__output_t *out, va_list args) {
    pe_resource_t *rsc = va_arg(args, pe_resource_t *);

    GList *lpc = NULL;
    GList *list = rsc->rsc_location;
    int rc = pcmk_rc_no_output;

    for (lpc = list; lpc != NULL; lpc = lpc->next) {
        pe__location_t *cons = lpc->data;

        GList *lpc2 = NULL;

        for (lpc2 = cons->node_list_rh; lpc2 != NULL; lpc2 = lpc2->next) {
            pe_node_t *node = (pe_node_t *) lpc2->data;
            char *score = score2char(node->weight);

            PCMK__OUTPUT_LIST_HEADER(out, FALSE, rc, "Locations");
            out->list_item(out, NULL, "Node %s (score=%s, id=%s, rsc=%s)",
                           node->details->uname, score, cons->id, rsc->id);
            free(score);
        }
    }

    PCMK__OUTPUT_LIST_FOOTER(out, rc);
    return rc;
}

PCMK__OUTPUT_ARGS("locations-list", "pe_resource_t *")
static int
locations_list_xml(pcmk__output_t *out, va_list args) {
    pe_resource_t *rsc = va_arg(args, pe_resource_t *);
    return do_locations_list_xml(out, rsc, true);
}

PCMK__OUTPUT_ARGS("stacks-constraints", "pe_resource_t *", "pe_working_set_t *", "gboolean")
static int
stacks_and_constraints(pcmk__output_t *out, va_list args) {
    pe_resource_t *rsc = va_arg(args, pe_resource_t *);
    pe_working_set_t *data_set = va_arg(args, pe_working_set_t *);
    gboolean recursive = va_arg(args, gboolean);

    xmlNodePtr cib_constraints = get_object_root(XML_CIB_TAG_CONSTRAINTS,
                                                 data_set->input);

    unpack_constraints(cib_constraints, data_set);

    // Constraints apply to group/clone, not member/instance
    rsc = uber_parent(rsc);

    out->message(out, "locations-list", rsc);

    pe__clear_resource_flags_on_all(data_set, pe_rsc_allocating);
    out->message(out, "rscs-colocated-with-list", rsc, recursive);

    pe__clear_resource_flags_on_all(data_set, pe_rsc_allocating);
    out->message(out, "rsc-is-colocated-with-list", rsc, recursive);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("stacks-constraints", "pe_resource_t *", "pe_working_set_t *", "gboolean")
static int
stacks_and_constraints_xml(pcmk__output_t *out, va_list args) {
    pe_resource_t *rsc = va_arg(args, pe_resource_t *);
    pe_working_set_t *data_set = va_arg(args, pe_working_set_t *);
    gboolean recursive = va_arg(args, gboolean);

    xmlNodePtr cib_constraints = get_object_root(XML_CIB_TAG_CONSTRAINTS,
                                                 data_set->input);

    unpack_constraints(cib_constraints, data_set);

    // Constraints apply to group/clone, not member/instance
    rsc = uber_parent(rsc);

    pcmk__output_xml_create_parent(out, "constraints", NULL);
    do_locations_list_xml(out, rsc, false);

    pe__clear_resource_flags_on_all(data_set, pe_rsc_allocating);
    out->message(out, "rscs-colocated-with-list", rsc, recursive);

    pe__clear_resource_flags_on_all(data_set, pe_rsc_allocating);
    out->message(out, "rsc-is-colocated-with-list", rsc, recursive);

    pcmk__output_xml_pop_parent(out);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("health", "const char *", "const char *", "const char *", "const char *")
static int
health_text(pcmk__output_t *out, va_list args)
{
    const char *sys_from G_GNUC_UNUSED = va_arg(args, const char *);
    const char *host_from = va_arg(args, const char *);
    const char *fsa_state = va_arg(args, const char *);
    const char *result = va_arg(args, const char *);

    if (!out->is_quiet(out)) {
        return out->info(out, "Controller on %s in state %s: %s", crm_str(host_from),
                         crm_str(fsa_state), crm_str(result));
    } else if (fsa_state != NULL) {
        pcmk__formatted_printf(out, "%s\n", fsa_state);
        return pcmk_rc_ok;
    }

    return pcmk_rc_no_output;
}

PCMK__OUTPUT_ARGS("health", "const char *", "const char *", "const char *", "const char *")
static int
health_xml(pcmk__output_t *out, va_list args)
{
    const char *sys_from = va_arg(args, const char *);
    const char *host_from = va_arg(args, const char *);
    const char *fsa_state = va_arg(args, const char *);
    const char *result = va_arg(args, const char *);

    pcmk__output_create_xml_node(out, crm_str(sys_from),
                                 "node_name", crm_str(host_from),
                                 "state", crm_str(fsa_state),
                                 "result", crm_str(result),
                                 NULL);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("pacemakerd-health", "const char *", "const char *", "const char *")
static int
pacemakerd_health_text(pcmk__output_t *out, va_list args)
{
    const char *sys_from = va_arg(args, const char *);
    const char *state = va_arg(args, const char *);
    const char *last_updated = va_arg(args, const char *);

    if (!out->is_quiet(out)) {
        return out->info(out, "Status of %s: '%s' %s %s", crm_str(sys_from),
                         crm_str(state), (!pcmk__str_empty(last_updated))?
                         "last updated":"", crm_str(last_updated));
    } else {
        pcmk__formatted_printf(out, "%s\n", crm_str(state));
        return pcmk_rc_ok;
    }

    return pcmk_rc_no_output;
}

PCMK__OUTPUT_ARGS("pacemakerd-health", "const char *", "const char *", "const char *")
static int
pacemakerd_health_xml(pcmk__output_t *out, va_list args)
{
    const char *sys_from = va_arg(args, const char *);
    const char *state = va_arg(args, const char *);
    const char *last_updated = va_arg(args, const char *);

    pcmk__output_create_xml_node(out, crm_str(sys_from),
                                 "state", crm_str(state),
                                 "last_updated", crm_str(last_updated),
                                 NULL);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("dc", "const char *")
static int
dc_text(pcmk__output_t *out, va_list args)
{
    const char *dc = va_arg(args, const char *);

    if (!out->is_quiet(out)) {
        return out->info(out, "Designated Controller is: %s", crm_str(dc));
    } else if (dc != NULL) {
        pcmk__formatted_printf(out, "%s\n", dc);
        return pcmk_rc_ok;
    }

    return pcmk_rc_no_output;
}

PCMK__OUTPUT_ARGS("dc", "const char *")
static int
dc_xml(pcmk__output_t *out, va_list args)
{
    const char *dc = va_arg(args, const char *);

    pcmk__output_create_xml_node(out, "dc",
                                 "node_name", crm_str(dc),
                                 NULL);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("crmadmin-node", "const char *", "const char *", "const char *", "gboolean")
static int
crmadmin_node_text(pcmk__output_t *out, va_list args)
{
    const char *type = va_arg(args, const char *);
    const char *name = va_arg(args, const char *);
    const char *id = va_arg(args, const char *);
    gboolean BASH_EXPORT = va_arg(args, gboolean);

    if (out->is_quiet(out)) {
        pcmk__formatted_printf(out, "%s\n", crm_str(name));
        return pcmk_rc_ok;
    } else if (BASH_EXPORT) {
        return out->info(out, "export %s=%s", crm_str(name), crm_str(id));
    } else {
        return out->info(out, "%s node: %s (%s)", type ? type : "cluster",
                         crm_str(name), crm_str(id));
    }
}

PCMK__OUTPUT_ARGS("crmadmin-node", "const char *", "const char *", "const char *", "gboolean")
static int
crmadmin_node_xml(pcmk__output_t *out, va_list args)
{
    const char *type = va_arg(args, const char *);
    const char *name = va_arg(args, const char *);
    const char *id = va_arg(args, const char *);

    pcmk__output_create_xml_node(out, "node",
                                 "type", type ? type : "cluster",
                                 "name", crm_str(name),
                                 "id", crm_str(id),
                                 NULL);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("digests", "pe_resource_t *", "pe_node_t *", "const char *",
                  "guint", "op_digest_cache_t *")
static int
digests_text(pcmk__output_t *out, va_list args)
{
    pe_resource_t *rsc = va_arg(args, pe_resource_t *);
    pe_node_t *node = va_arg(args, pe_node_t *);
    const char *task = va_arg(args, const char *);
    guint interval_ms = va_arg(args, guint);
    op_digest_cache_t *digests = va_arg(args, op_digest_cache_t *);

    char *action_desc = NULL;
    const char *rsc_desc = "unknown resource";
    const char *node_desc = "unknown node";

    if (interval_ms != 0) {
        action_desc = crm_strdup_printf("%ums-interval %s action", interval_ms,
                                        ((task == NULL)? "unknown" : task));
    } else if (pcmk__str_eq(task, "monitor", pcmk__str_none)) {
        action_desc = strdup("probe action");
    } else {
        action_desc = crm_strdup_printf("%s action",
                                        ((task == NULL)? "unknown" : task));
    }
    if ((rsc != NULL) && (rsc->id != NULL)) {
        rsc_desc = rsc->id;
    }
    if ((node != NULL) && (node->details->uname != NULL)) {
        node_desc = node->details->uname;
    }
    out->begin_list(out, NULL, NULL, "Digests for %s %s on %s",
                    rsc_desc, action_desc, node_desc);
    free(action_desc);

    if (digests == NULL) {
        out->list_item(out, NULL, "none");
        out->end_list(out);
        return pcmk_rc_ok;
    }
    if (digests->digest_all_calc != NULL) {
        out->list_item(out, NULL, "%s (all parameters)",
                       digests->digest_all_calc);
    }
    if (digests->digest_secure_calc != NULL) {
        out->list_item(out, NULL, "%s (non-private parameters)",
                       digests->digest_secure_calc);
    }
    if (digests->digest_restart_calc != NULL) {
        out->list_item(out, NULL, "%s (non-reloadable parameters)",
                       digests->digest_restart_calc);
    }
    out->end_list(out);
    return pcmk_rc_ok;
}

static void
add_digest_xml(xmlNode *parent, const char *type, const char *digest,
               xmlNode *digest_source)
{
    if (digest != NULL) {
        xmlNodePtr digest_xml = create_xml_node(parent, "digest");

        crm_xml_add(digest_xml, "type", ((type == NULL)? "unspecified" : type));
        crm_xml_add(digest_xml, "hash", digest);
        if (digest_source != NULL) {
            add_node_copy(digest_xml, digest_source);
        }
    }
}

PCMK__OUTPUT_ARGS("digests", "pe_resource_t *", "pe_node_t *", "const char *",
                  "guint", "op_digest_cache_t *")
static int
digests_xml(pcmk__output_t *out, va_list args)
{
    pe_resource_t *rsc = va_arg(args, pe_resource_t *);
    pe_node_t *node = va_arg(args, pe_node_t *);
    const char *task = va_arg(args, const char *);
    guint interval_ms = va_arg(args, guint);
    op_digest_cache_t *digests = va_arg(args, op_digest_cache_t *);

    char *interval_s = crm_strdup_printf("%ums", interval_ms);
    xmlNode *xml = NULL;

    xml = pcmk__output_create_xml_node(out, "digests",
                                       "resource", crm_str(rsc->id),
                                       "node", crm_str(node->details->uname),
                                       "task", crm_str(task),
                                       "interval", interval_s,
                                       NULL);
    free(interval_s);
    if (digests != NULL) {
        add_digest_xml(xml, "all", digests->digest_all_calc,
                       digests->params_all);
        add_digest_xml(xml, "nonprivate", digests->digest_secure_calc,
                       digests->params_secure);
        add_digest_xml(xml, "nonreloadable", digests->digest_restart_calc,
                       digests->params_restart);
    }
    return pcmk_rc_ok;
}

#define STOP_SANITY_ASSERT(lineno) do {                                 \
        if(current && current->details->unclean) {                      \
            /* It will be a pseudo op */                                \
        } else if(stop == NULL) {                                       \
            crm_err("%s:%d: No stop action exists for %s",              \
                    __func__, lineno, rsc->id);                         \
            CRM_ASSERT(stop != NULL);                                   \
        } else if (pcmk_is_set(stop->flags, pe_action_optional)) {      \
            crm_err("%s:%d: Action %s is still optional",               \
                    __func__, lineno, stop->uuid);                      \
            CRM_ASSERT(!pcmk_is_set(stop->flags, pe_action_optional));  \
        }                                                               \
    } while(0)

PCMK__OUTPUT_ARGS("rsc-action", "pe_resource_t *", "pe_node_t *", "pe_node_t *",
                  "gboolean")
static int
rsc_action_default(pcmk__output_t *out, va_list args)
{
    pe_resource_t *rsc = va_arg(args, pe_resource_t *);
    pe_node_t *current = va_arg(args, pe_node_t *);
    pe_node_t *next = va_arg(args, pe_node_t *);
    gboolean moving = va_arg(args, gboolean);

    GList *possible_matches = NULL;
    char *key = NULL;
    int rc = pcmk_rc_no_output;

    pe_node_t *start_node = NULL;
    pe_action_t *start = NULL;
    pe_action_t *stop = NULL;
    pe_action_t *promote = NULL;
    pe_action_t *demote = NULL;

    if (!pcmk_is_set(rsc->flags, pe_rsc_managed)
        || (current == NULL && next == NULL)) {
        pe_rsc_info(rsc, "Leave   %s\t(%s%s)",
                    rsc->id, role2text(rsc->role),
                    !pcmk_is_set(rsc->flags, pe_rsc_managed)? " unmanaged" : "");
        return rc;
    }

    if (current != NULL && next != NULL && !pcmk__str_eq(current->details->id, next->details->id, pcmk__str_casei)) {
        moving = TRUE;
    }

    possible_matches = pe__resource_actions(rsc, next, RSC_START, FALSE);
    if (possible_matches) {
        start = possible_matches->data;
        g_list_free(possible_matches);
    }

    if ((start == NULL) || !pcmk_is_set(start->flags, pe_action_runnable)) {
        start_node = NULL;
    } else {
        start_node = current;
    }
    possible_matches = pe__resource_actions(rsc, start_node, RSC_STOP, FALSE);
    if (possible_matches) {
        stop = possible_matches->data;
        g_list_free(possible_matches);
    }

    possible_matches = pe__resource_actions(rsc, next, RSC_PROMOTE, FALSE);
    if (possible_matches) {
        promote = possible_matches->data;
        g_list_free(possible_matches);
    }

    possible_matches = pe__resource_actions(rsc, next, RSC_DEMOTE, FALSE);
    if (possible_matches) {
        demote = possible_matches->data;
        g_list_free(possible_matches);
    }

    if (rsc->role == rsc->next_role) {
        pe_action_t *migrate_op = NULL;

        possible_matches = pe__resource_actions(rsc, next, RSC_MIGRATED, FALSE);
        if (possible_matches) {
            migrate_op = possible_matches->data;
        }

        CRM_CHECK(next != NULL,);
        if (next == NULL) {
        } else if ((migrate_op != NULL) && (current != NULL)
                   && pcmk_is_set(migrate_op->flags, pe_action_runnable)) {
            rc = out->message(out, "rsc-action-item", "Migrate", rsc, current,
                              next, start, NULL);

        } else if (pcmk_is_set(rsc->flags, pe_rsc_reload)) {
            rc = out->message(out, "rsc-action-item", "Reload", rsc, current,
                              next, start, NULL);

        } else if (start == NULL || pcmk_is_set(start->flags, pe_action_optional)) {
            if ((demote != NULL) && (promote != NULL)
                && !pcmk_is_set(demote->flags, pe_action_optional)
                && !pcmk_is_set(promote->flags, pe_action_optional)) {
                rc = out->message(out, "rsc-action-item", "Re-promote", rsc,
                                  current, next, promote, demote);
            } else {
                pe_rsc_info(rsc, "Leave   %s\t(%s %s)", rsc->id,
                            role2text(rsc->role), next->details->uname);
            }

        } else if (!pcmk_is_set(start->flags, pe_action_runnable)) {
            rc = out->message(out, "rsc-action-item", "Stop", rsc, current,
                              NULL, stop, (stop && stop->reason)? stop : start);
            STOP_SANITY_ASSERT(__LINE__);

        } else if (moving && current) {
            rc = out->message(out, "rsc-action-item", pcmk_is_set(rsc->flags, pe_rsc_failed)? "Recover" : "Move",
                              rsc, current, next, stop, NULL);

        } else if (pcmk_is_set(rsc->flags, pe_rsc_failed)) {
            rc = out->message(out, "rsc-action-item", "Recover", rsc, current,
                              NULL, stop, NULL);
            STOP_SANITY_ASSERT(__LINE__);

        } else {
            rc = out->message(out, "rsc-action-item", "Restart", rsc, current,
                              next, start, NULL);
            /* STOP_SANITY_ASSERT(__LINE__); False positive for migrate-fail-7 */
        }

        g_list_free(possible_matches);
        return rc;
    }

    if(stop
       && (rsc->next_role == RSC_ROLE_STOPPED
           || (start && !pcmk_is_set(start->flags, pe_action_runnable)))) {

        GList *gIter = NULL;

        key = stop_key(rsc);
        for (gIter = rsc->running_on; gIter != NULL; gIter = gIter->next) {
            pe_node_t *node = (pe_node_t *) gIter->data;
            pe_action_t *stop_op = NULL;

            possible_matches = find_actions(rsc->actions, key, node);
            if (possible_matches) {
                stop_op = possible_matches->data;
                g_list_free(possible_matches);
            }

            if (stop_op && (stop_op->flags & pe_action_runnable)) {
                STOP_SANITY_ASSERT(__LINE__);
            }

            if (out->message(out, "rsc-action-item", "Stop", rsc, node, NULL,
                             stop_op, (stop_op && stop_op->reason)? stop_op : start) == pcmk_rc_ok) {
                rc = pcmk_rc_ok;
            }
        }

        free(key);

    } else if ((stop != NULL)
               && pcmk_all_flags_set(rsc->flags, pe_rsc_failed|pe_rsc_stop)) {
        /* 'stop' may be NULL if the failure was ignored */
        rc = out->message(out, "rsc-action-item", "Recover", rsc, current,
                          next, stop, start);
        STOP_SANITY_ASSERT(__LINE__);

    } else if (moving) {
        rc = out->message(out, "rsc-action-item", "Move", rsc, current, next,
                          stop, NULL);
        STOP_SANITY_ASSERT(__LINE__);

    } else if (pcmk_is_set(rsc->flags, pe_rsc_reload)) {
        rc = out->message(out, "rsc-action-item", "Reload", rsc, current, next,
                          start, NULL);

    } else if (stop != NULL && !pcmk_is_set(stop->flags, pe_action_optional)) {
        rc = out->message(out, "rsc-action-item", "Restart", rsc, current,
                          next, start, NULL);
        STOP_SANITY_ASSERT(__LINE__);

    } else if (rsc->role == RSC_ROLE_MASTER) {
        CRM_LOG_ASSERT(current != NULL);
        rc = out->message(out, "rsc-action-item", "Demote", rsc, current,
                          next, demote, NULL);

    } else if(rsc->next_role == RSC_ROLE_MASTER) {
        CRM_LOG_ASSERT(next);
        rc = out->message(out, "rsc-action-item", "Promote", rsc, current,
                          next, promote, NULL);

    } else if (rsc->role == RSC_ROLE_STOPPED && rsc->next_role > RSC_ROLE_STOPPED) {
        rc = out->message(out, "rsc-action-item", "Start", rsc, current, next,
                          start, NULL);
    }

    return rc;
}

PCMK__OUTPUT_ARGS("node-action", "char *", "char *", "char *")
static int
node_action(pcmk__output_t *out, va_list args)
{
    char *task = va_arg(args, char *);
    char *node_name = va_arg(args, char *);
    char *reason = va_arg(args, char *);

    if (task == NULL) {
        return pcmk_rc_no_output;
    } else if (reason) {
        out->list_item(out, NULL, "%s %s '%s'", task, node_name, reason);
    } else {
        crm_notice(" * %s %s\n", task, node_name);
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("node-action", "char *", "char *", "char *")
static int
node_action_xml(pcmk__output_t *out, va_list args)
{
    char *task = va_arg(args, char *);
    char *node_name = va_arg(args, char *);
    char *reason = va_arg(args, char *);

    if (task == NULL) {
        return pcmk_rc_no_output;
    } else if (reason) {
        pcmk__output_create_xml_node(out, "node_action",
                                     "task", task,
                                     "node", node_name,
                                     "reason", reason,
                                     NULL);
    } else {
        crm_notice(" * %s %s\n", task, node_name);
    }

    return pcmk_rc_ok;
}

static pcmk__message_entry_t fmt_functions[] = {
    { "crmadmin-node", "default", crmadmin_node_text },
    { "crmadmin-node", "xml", crmadmin_node_xml },
    { "dc", "default", dc_text },
    { "dc", "xml", dc_xml },
    { "digests", "default", digests_text },
    { "digests", "xml", digests_xml },
    { "health", "default", health_text },
    { "health", "xml", health_xml },
    { "locations-list", "default", locations_list },
    { "locations-list", "xml", locations_list_xml },
    { "node-action", "default", node_action },
    { "node-action", "xml", node_action_xml },
    { "pacemakerd-health", "default", pacemakerd_health_text },
    { "pacemakerd-health", "xml", pacemakerd_health_xml },
    { "rsc-action", "default", rsc_action_default },
    { "rsc-action-item", "default", rsc_action_item },
    { "rsc-action-item", "xml", rsc_action_item_xml },
    { "rsc-is-colocated-with-list", "default", rsc_is_colocated_with_list },
    { "rsc-is-colocated-with-list", "xml", rsc_is_colocated_with_list_xml },
    { "rscs-colocated-with-list", "default", rscs_colocated_with_list },
    { "rscs-colocated-with-list", "xml", rscs_colocated_with_list_xml },
    { "stacks-constraints", "default", stacks_and_constraints },
    { "stacks-constraints", "xml", stacks_and_constraints_xml },

    { NULL, NULL, NULL }
};

void
pcmk__register_lib_messages(pcmk__output_t *out) {
    pcmk__register_messages(out, fmt_functions);
}
