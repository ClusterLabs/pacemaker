/*
 * Copyright 2019-2020 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <crm/common/results.h>
#include <crm/common/output_internal.h>
#include <crm/stonith-ng.h>
#include <crm/fencing/internal.h>
#include <libxml/tree.h>
#include <pacemaker-internal.h>

pcmk__supported_format_t pcmk__out_formats[] = {
    PCMK__SUPPORTED_FORMAT_XML,
    { NULL, NULL, NULL }
};

int
pcmk__out_prologue(pcmk__output_t **out, xmlNodePtr *xml) {
    int rc = pcmk_rc_ok;

    if (*xml != NULL) {
        xmlFreeNode(*xml);
    }

    pcmk__register_formats(NULL, pcmk__out_formats);
    rc = pcmk__output_new(out, "xml", NULL, NULL);
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    stonith__register_messages(*out);
    return rc;
}

void
pcmk__out_epilogue(pcmk__output_t *out, xmlNodePtr *xml, int retval) {
    if (retval == pcmk_rc_ok) {
        out->finish(out, 0, FALSE, (void **) xml);
    }

    pcmk__output_free(out);
}

PCMK__OUTPUT_ARGS("colocations-list", "pe_resource_t *", "gboolean", "gboolean")
static int colocations_list(pcmk__output_t *out, va_list args) {
    pe_resource_t *rsc = va_arg(args, pe_resource_t *);
    gboolean dependents = va_arg(args, gboolean);
    gboolean recursive = va_arg(args, gboolean);

    GListPtr lpc = NULL;
    GListPtr list = rsc->rsc_cons;
    bool printed_header = false;

    if (dependents) {
        list = rsc->rsc_cons_lhs;
    }

    if (pcmk_is_set(rsc->flags, pe_rsc_allocating)) {
        return pcmk_rc_no_output;
    }

    pe__set_resource_flags(rsc, pe_rsc_allocating);
    for (lpc = list; lpc != NULL; lpc = lpc->next) {
        rsc_colocation_t *cons = (rsc_colocation_t *) lpc->data;

        char *score = NULL;
        pe_resource_t *peer = cons->rsc_rh;

        if (dependents) {
            peer = cons->rsc_lh;
        }

        if (pcmk_is_set(peer->flags, pe_rsc_allocating)) {
            if (dependents == FALSE) {
                if (!printed_header) {
                    out->begin_list(out, NULL, NULL, "Colocations");
                    printed_header = true;
                }

                out->list_item(out, NULL, "%s (id=%s - loop)", peer->id, cons->id);
            }
            continue;
        }

        if (dependents && recursive) {
            if (!printed_header) {
                out->begin_list(out, NULL, NULL, "Colocations");
                printed_header = true;
            }

            out->message(out, "colocations-list", rsc, dependents, recursive);
        }

        if (!printed_header) {
            out->begin_list(out, NULL, NULL, "Colocations");
            printed_header = true;
        }

        score = score2char(cons->score);
        if (cons->role_rh > RSC_ROLE_STARTED) {
            out->list_item(out, NULL, "%s (score=%s, %s role=%s, id=%s",
                           peer->id, score, dependents ? "needs" : "with",
                           role2text(cons->role_rh), cons->id);
        } else {
            out->list_item(out, NULL, "%s (score=%s, id=%s",
                           peer->id, score, cons->id);
        }

        free(score);
        out->message(out, "locations-list", peer);

        if (!dependents && recursive) {
            out->message(out, "colocations-list", rsc, dependents, recursive);
        }
    }

    if (printed_header) {
        out->end_list(out);
    }

    return pcmk_rc_no_output;
}

PCMK__OUTPUT_ARGS("colocations-list", "pe_resource_t *", "gboolean", "gboolean")
static int colocations_list_xml(pcmk__output_t *out, va_list args) {
    pe_resource_t *rsc = va_arg(args, pe_resource_t *);
    gboolean dependents = va_arg(args, gboolean);
    gboolean recursive = va_arg(args, gboolean);

    GListPtr lpc = NULL;
    GListPtr list = rsc->rsc_cons;
    bool printed_header = false;

    if (dependents) {
        list = rsc->rsc_cons_lhs;
    }

    if (pcmk_is_set(rsc->flags, pe_rsc_allocating)) {
        return pcmk_rc_ok;
    }

    pe__set_resource_flags(rsc, pe_rsc_allocating);
    for (lpc = list; lpc != NULL; lpc = lpc->next) {
        rsc_colocation_t *cons = (rsc_colocation_t *) lpc->data;
        pe_resource_t *peer = cons->rsc_rh;
        char *score = NULL;

        if (dependents) {
            peer = cons->rsc_lh;
        }

        if (pcmk_is_set(peer->flags, pe_rsc_allocating)) {
            if (dependents == FALSE) {
                xmlNodePtr node;

                if (!printed_header) {
                    pcmk__output_xml_create_parent(out, "colocations");
                    printed_header = true;
                }

                node = pcmk__output_create_xml_node(out, "colocation");
                xmlSetProp(node, (pcmkXmlStr) "peer", (pcmkXmlStr) peer->id);
                xmlSetProp(node, (pcmkXmlStr) "id", (pcmkXmlStr) cons->id);
            }
            continue;
        }

        if (dependents && recursive) {
            if (!printed_header) {
                pcmk__output_xml_create_parent(out, "colocations");
                printed_header = true;
            }

            out->message(out, "colocations-list", rsc, dependents, recursive);
        }

        if (!printed_header) {
            pcmk__output_xml_create_parent(out, "colocations");
            printed_header = true;
        }

        score = score2char(cons->score);
        if (cons->role_rh > RSC_ROLE_STARTED) {
            xmlNodePtr node = pcmk__output_create_xml_node(out, "colocation");
            xmlSetProp(node, (pcmkXmlStr) "peer", (pcmkXmlStr) peer->id);
            xmlSetProp(node, (pcmkXmlStr) "id", (pcmkXmlStr) cons->id);
            xmlSetProp(node, (pcmkXmlStr) "score", (pcmkXmlStr) score);
            xmlSetProp(node, (pcmkXmlStr) "dependents",
                       (pcmkXmlStr) (dependents ? "needs" : "with"));
            xmlSetProp(node, (pcmkXmlStr) "role", (pcmkXmlStr) role2text(cons->role_rh));
        } else {
            xmlNodePtr node = pcmk__output_create_xml_node(out, "colocation");
            xmlSetProp(node, (pcmkXmlStr) "peer", (pcmkXmlStr) peer->id);
            xmlSetProp(node, (pcmkXmlStr) "id", (pcmkXmlStr) cons->id);
            xmlSetProp(node, (pcmkXmlStr) "score", (pcmkXmlStr) score);
        }

        free(score);
        out->message(out, "locations-list", peer);

        if (!dependents && recursive) {
            out->message(out, "colocations-list", rsc, dependents, recursive);
        }
    }

    if (printed_header) {
        pcmk__output_xml_pop_parent(out);
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("locations-list", "pe_resource_t *")
static int locations_list(pcmk__output_t *out, va_list args) {
    pe_resource_t *rsc G_GNUC_UNUSED = va_arg(args, pe_resource_t *);

    GListPtr lpc = NULL;
    GListPtr list = rsc->rsc_location;

    out->begin_list(out, NULL, NULL, "Locations");

    for (lpc = list; lpc != NULL; lpc = lpc->next) {
        pe__location_t *cons = lpc->data;

        GListPtr lpc2 = NULL;

        for (lpc2 = cons->node_list_rh; lpc2 != NULL; lpc2 = lpc2->next) {
            pe_node_t *node = (pe_node_t *) lpc2->data;
            char *score = score2char(node->weight);

            out->list_item(out, NULL, "Node %s (score=%s, id=%s)",
                           node->details->uname, score, cons->id);
            free(score);
        }
    }

    out->end_list(out);

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("locations-list", "pe_resource_t *")
static int locations_list_xml(pcmk__output_t *out, va_list args) {
    pe_resource_t *rsc = va_arg(args, pe_resource_t *);

    GListPtr lpc = NULL;
    GListPtr list = rsc->rsc_location;

    pcmk__output_xml_create_parent(out, "locations");

    for (lpc = list; lpc != NULL; lpc = lpc->next) {
        pe__location_t *cons = lpc->data;

        GListPtr lpc2 = NULL;

        for (lpc2 = cons->node_list_rh; lpc2 != NULL; lpc2 = lpc2->next) {
            pe_node_t *node = (pe_node_t *) lpc2->data;
            char *score = score2char(node->weight);

            xmlNodePtr xml_node = pcmk__output_create_xml_node(out, "location");
            xmlSetProp(xml_node, (pcmkXmlStr) "host", (pcmkXmlStr) node->details->uname);
            xmlSetProp(xml_node, (pcmkXmlStr) "id", (pcmkXmlStr) cons->id);
            xmlSetProp(xml_node, (pcmkXmlStr) "score", (pcmkXmlStr) score);

            free(score);
        }
    }

    pcmk__output_xml_pop_parent(out);

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("stacks-constraints", "pe_resource_t *", "pe_working_set_t *", "gboolean")
static int
stacks_and_constraints(pcmk__output_t *out, va_list args) {
    pe_resource_t *rsc G_GNUC_UNUSED = va_arg(args, pe_resource_t *);
    pe_working_set_t *data_set G_GNUC_UNUSED = va_arg(args, pe_working_set_t *);
    gboolean recursive G_GNUC_UNUSED = va_arg(args, gboolean);

    GListPtr lpc = NULL;
    xmlNode *cib_constraints = get_object_root(XML_CIB_TAG_CONSTRAINTS,
                                               data_set->input);

    unpack_constraints(cib_constraints, data_set);

    // Constraints apply to group/clone, not member/instance
    rsc = uber_parent(rsc);

    for (lpc = data_set->resources; lpc != NULL; lpc = lpc->next) {
        pe_resource_t *r = (pe_resource_t *) lpc->data;

        pe__clear_resource_flags(r, pe_rsc_allocating);
    }

    out->message(out, "colocations-list", rsc, TRUE, recursive);

    out->begin_list(out, NULL, NULL, "%s", rsc->id);
    out->message(out, "locations-list", rsc);
    out->end_list(out);

    for (lpc = data_set->resources; lpc != NULL; lpc = lpc->next) {
        pe_resource_t *r = (pe_resource_t *) lpc->data;

        pe__clear_resource_flags(r, pe_rsc_allocating);
    }

    out->message(out, "colocations-list", rsc, FALSE, recursive);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("stacks-constraints", "pe_resource_t *", "pe_working_set_t *", "gboolean")
static int
stacks_and_constraints_xml(pcmk__output_t *out, va_list args) {
    pe_resource_t *rsc = va_arg(args, pe_resource_t *);
    pe_working_set_t *data_set = va_arg(args, pe_working_set_t *);
    gboolean recursive = va_arg(args, gboolean);

    GListPtr lpc = NULL;
    xmlNodePtr node = NULL;
    xmlNode *cib_constraints = get_object_root(XML_CIB_TAG_CONSTRAINTS,
                                               data_set->input);

    unpack_constraints(cib_constraints, data_set);

    // Constraints apply to group/clone, not member/instance
    rsc = uber_parent(rsc);

    for (lpc = data_set->resources; lpc != NULL; lpc = lpc->next) {
        pe_resource_t *r = (pe_resource_t *) lpc->data;

        pe__clear_resource_flags(r, pe_rsc_allocating);
    }

    pcmk__output_xml_create_parent(out, "constraints");

    out->message(out, "colocations-list", rsc, TRUE, recursive);

    node = pcmk__output_xml_create_parent(out, "resource");
    xmlSetProp(node, (pcmkXmlStr) "id", (pcmkXmlStr) rsc->id);
    out->message(out, "locations-list", rsc);
    pcmk__output_xml_pop_parent(out);

    for (lpc = data_set->resources; lpc != NULL; lpc = lpc->next) {
        pe_resource_t *r = (pe_resource_t *) lpc->data;

        pe__clear_resource_flags(r, pe_rsc_allocating);
    }

    out->message(out, "colocations-list", rsc, FALSE, recursive);
    return pcmk_rc_ok;
}

static pcmk__message_entry_t fmt_functions[] = {
    { "colocations-list", "default", colocations_list },
    { "colocations-list", "xml", colocations_list_xml },
    { "locations-list", "default", locations_list },
    { "locations-list", "xml", locations_list_xml },
    { "stacks-constraints", "default", stacks_and_constraints },
    { "stacks-constraints", "xml", stacks_and_constraints_xml },

    { NULL, NULL, NULL }
};

void
pcmk__register_lib_messages(pcmk__output_t *out) {
    pcmk__register_messages(out, fmt_functions);
}
