/*
 * Copyright 2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/cib/internal.h>
#include <crm/pengine/internal.h>

#include <pacemaker.h>
#include <pacemaker-internal.h>

#include "libpacemaker_private.h"

int
pcmk__get_ticket_state(cib_t *cib, const char *ticket_id, xmlNode **state)
{
    int rc = pcmk_rc_ok;
    xmlNode *xml_search = NULL;
    char *xpath = NULL;

    CRM_ASSERT(cib!= NULL && state != NULL);
    *state = NULL;

    if (ticket_id != NULL) {
        xpath = crm_strdup_printf("/" PCMK_XE_CIB "/" PCMK_XE_STATUS "/" PCMK_XE_TICKETS
                                  "/" PCMK__XE_TICKET_STATE "[@" PCMK_XA_ID "=\"%s\"]",
                                  ticket_id);
    } else {
        xpath = crm_strdup_printf("/" PCMK_XE_CIB "/" PCMK_XE_STATUS "/" PCMK_XE_TICKETS);
    }

    rc = cib->cmds->query(cib, xpath, &xml_search,
                          cib_sync_call | cib_scope_local | cib_xpath);
    rc = pcmk_legacy2rc(rc);

    if (rc == pcmk_rc_ok) {
        crm_log_xml_debug(xml_search, "Match");

        if (xml_search->children != NULL && ticket_id != NULL) {
            rc = pcmk_rc_duplicate_id;
        }
    }

    free(xpath);

    *state = xml_search;
    return rc;
}

int
pcmk__ticket_constraints(pcmk__output_t *out, cib_t *cib, const char *ticket_id)
{
    int rc = pcmk_rc_ok;
    xmlNode *result = NULL;
    const char *xpath_base = NULL;
    char *xpath = NULL;

    CRM_ASSERT(out != NULL && cib != NULL);

    xpath_base = pcmk_cib_xpath_for(PCMK_XE_CONSTRAINTS);
    CRM_ASSERT(xpath_base != NULL);

    if (ticket_id != NULL) {
        xpath = crm_strdup_printf("%s/" PCMK_XE_RSC_TICKET "[@" PCMK_XA_TICKET "=\"%s\"]",
                                  xpath_base, ticket_id);
    } else {
        xpath = crm_strdup_printf("%s/" PCMK_XE_RSC_TICKET, xpath_base);
    }

    rc = cib->cmds->query(cib, (const char *) xpath, &result,
                          cib_sync_call | cib_scope_local | cib_xpath);
    rc = pcmk_legacy2rc(rc);

    if (result != NULL) {
        out->message(out, "ticket-constraints", result);
        free_xml(result);
    }

    free(xpath);
    return rc;
}

int
pcmk_ticket_constraints(xmlNodePtr *xml, const char *ticket_id)
{
    pcmk__output_t *out = NULL;
    int rc = pcmk_rc_ok;
    cib_t *cib = NULL;

    rc = pcmk__setup_output_cib_sched(&out, &cib, NULL, xml);
    if (rc != pcmk_rc_ok) {
        goto done;
    }

    rc = pcmk__ticket_constraints(out, cib, ticket_id);

done:
    if (cib != NULL) {
        cib__clean_up_connection(&cib);
    }

    pcmk__xml_output_finish(out, pcmk_rc2exitc(rc), xml);
    return rc;
}

int
pcmk__ticket_get_attr(pcmk__output_t *out, pcmk_scheduler_t *scheduler,
                      const char *ticket_id, const char *attr_name,
                      const char *attr_default)
{
    int rc = pcmk_rc_ok;
    const char *attr_value = NULL;
    pcmk_ticket_t *ticket = NULL;

    CRM_ASSERT(out != NULL && scheduler != NULL);

    if (ticket_id == NULL || attr_name == NULL) {
        return EINVAL;
    }

    ticket = g_hash_table_lookup(scheduler->tickets, ticket_id);

    if (ticket != NULL) {
        attr_value = g_hash_table_lookup(ticket->state, attr_name);
    }

    if (attr_value != NULL) {
        out->message(out, "ticket-attribute", ticket_id, attr_name, attr_value);
    } else if (attr_default != NULL) {
        out->message(out, "ticket-attribute", ticket_id, attr_name, attr_default);
    } else {
        rc = ENXIO;
    }

    return rc;
}

int
pcmk_ticket_get_attr(xmlNodePtr *xml, const char *ticket_id,
                     const char *attr_name, const char *attr_default)
{
    pcmk_scheduler_t *scheduler = NULL;
    pcmk__output_t *out = NULL;
    int rc = pcmk_rc_ok;

    rc = pcmk__setup_output_cib_sched(&out, NULL, &scheduler, xml);
    if (rc != pcmk_rc_ok) {
        goto done;
    }

    rc = pcmk__ticket_get_attr(out, scheduler, ticket_id, attr_name, attr_default);

done:
    pcmk__xml_output_finish(out, pcmk_rc2exitc(rc), xml);
    pe_free_working_set(scheduler);
    return rc;
}

int
pcmk__ticket_info(pcmk__output_t *out, pcmk_scheduler_t *scheduler,
                  const char *ticket_id, bool details, bool raw)
{
    int rc = pcmk_rc_ok;

    CRM_ASSERT(out != NULL && scheduler != NULL);

    if (ticket_id != NULL) {
        GHashTable *tickets = NULL;
        pcmk_ticket_t *ticket = g_hash_table_lookup(scheduler->tickets, ticket_id);

        if (ticket == NULL) {
            return ENXIO;
        }

        /* The ticket-list message expects a GHashTable, so we'll construct
         * one with just this single item.
         */
        tickets = pcmk__strkey_table(free, NULL);
        g_hash_table_insert(tickets, strdup(ticket->id), ticket);
        out->message(out, "ticket-list", tickets, false, raw, details);
        g_hash_table_destroy(tickets);

    } else {
        out->message(out, "ticket-list", scheduler->tickets, false, raw, details);
    }

    return rc;
}

int
pcmk_ticket_info(xmlNodePtr *xml, const char *ticket_id)
{
    pcmk_scheduler_t *scheduler = NULL;
    pcmk__output_t *out = NULL;
    int rc = pcmk_rc_ok;

    rc = pcmk__setup_output_cib_sched(&out, NULL, &scheduler, xml);
    if (rc != pcmk_rc_ok) {
        goto done;
    }

    pe__register_messages(out);

    /* XML output (which is the only format supported by public API functions
     * due to the use of pcmk__xml_output_new above) always prints all details,
     * so just pass false for the last two arguments.
     */
    rc = pcmk__ticket_info(out, scheduler, ticket_id, false, false);

done:
    pcmk__xml_output_finish(out, pcmk_rc2exitc(rc), xml);
    pe_free_working_set(scheduler);
    return rc;
}
