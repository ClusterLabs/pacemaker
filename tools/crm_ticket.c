
/* 
 * Copyright (C) 2012 Gao,Yan <ygao@suse.com>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <crm_internal.h>

#include <sys/param.h>

#include <crm/crm.h>

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>

#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/ipc.h>

#include <crm/cib.h>
#include <crm/pengine/rules.h>
#include <crm/pengine/status.h>

#include <../pengine/pengine.h>

gboolean do_force = FALSE;
gboolean BE_QUIET = FALSE;
const char *ticket_id = NULL;
const char *attr_name = "granted";
const char *attr_value = NULL;
const char *attr_id = NULL;
const char *set_name = NULL;
const char *attr_default = NULL;
char ticket_cmd = 'S';
char *xml_file = NULL;
int cib_options = cib_sync_call;

extern void cleanup_alloc_calculations(pe_working_set_t * data_set);

#define CMD_ERR(fmt, args...) do {		\
	crm_warn(fmt, ##args);			\
	fprintf(stderr, fmt, ##args);		\
    } while(0)

static ticket_t *
find_ticket(const char *ticket_id , pe_working_set_t * data_set)
{
    ticket_t *ticket = NULL;
    ticket = g_hash_table_lookup(data_set->tickets, ticket_id);

    return ticket;
}

static void
print_date(time_t time)
{
    int lpc = 0;
    char date_str[26];

    asctime_r(localtime(&time), date_str);
    for (; lpc < 26; lpc++) {
        if (date_str[lpc] == '\n') {
            date_str[lpc] = 0;
        }
    }
    fprintf(stdout,"'%s'", date_str);
}

static int
print_ticket(ticket_t *ticket, gboolean raw, gboolean details)
{
    if (raw) {
        fprintf(stdout, "%s\n", ticket->id); 
        return pcmk_ok;
    }

    fprintf(stdout, "%s\t%s %s",
            ticket->id, ticket->granted?"granted":"revoked", 
            ticket->standby?"[standby]":"         ");

    if (details && g_hash_table_size(ticket->state) > 0) {
        GHashTableIter iter;
        const char *name = NULL;
        const char *value = NULL;
        int lpc = 0;

        fprintf(stdout, " (");

        g_hash_table_iter_init(&iter, ticket->state);
        while (g_hash_table_iter_next(&iter, (void **)&name, (void **)&value)) {
            if (lpc > 0) {
                fprintf(stdout, ", ");
            }
            fprintf(stdout, "%s=", name);
            if (crm_str_eq(name, "last-granted", TRUE)
                || crm_str_eq(name, "expires", TRUE)) {
                print_date(crm_parse_int(value, 0));
            } else {
                fprintf(stdout, "%s", value);
            }
            lpc++;
        }

        fprintf(stdout, ")\n");

    } else {
        if (ticket->last_granted > -1) {
             fprintf(stdout, " last-granted=");
             print_date(ticket->last_granted);
        }
        fprintf(stdout, "\n");
    }

    return pcmk_ok;
}

static int
print_ticket_list(pe_working_set_t * data_set, gboolean raw, gboolean details)
{
    GHashTableIter iter;
    ticket_t *ticket = NULL;

    g_hash_table_iter_init(&iter, data_set->tickets);

    while (g_hash_table_iter_next(&iter, NULL, (void **)&ticket)) {
        print_ticket(ticket, raw, details);
    }

    return pcmk_ok;
}

static int
find_ticket_state(cib_t * the_cib, const char * ticket_id, xmlNode ** ticket_state_xml)
{
    int offset = 0;
    static int xpath_max = 1024;
    int rc = pcmk_ok;
    xmlNode *xml_search = NULL;

    char *xpath_string = NULL;

    CRM_ASSERT(ticket_state_xml != NULL);
    *ticket_state_xml = NULL;

    xpath_string = calloc(1, xpath_max);
    offset +=
        snprintf(xpath_string + offset, xpath_max - offset, "%s", "/cib/status/tickets");

    if (ticket_id) {
        offset += snprintf(xpath_string + offset, xpath_max - offset, "/%s[@id=\"%s\"]",
                       XML_CIB_TAG_TICKET_STATE, ticket_id);
    }

    rc = the_cib->cmds->query(the_cib, xpath_string, &xml_search,
                              cib_sync_call | cib_scope_local | cib_xpath);

    if (rc != pcmk_ok) {
        goto bail;
    }

    crm_log_xml_debug(xml_search, "Match");
    if (xml_has_children(xml_search)) {
        if (ticket_id) {
            fprintf(stdout, "Multiple ticket_states match ticket_id=%s\n", ticket_id);
        }
        *ticket_state_xml = xml_search;
    } else {
        *ticket_state_xml = xml_search;
    }

  bail:
    free(xpath_string);
    return rc;
}

static int
find_ticket_constraints(cib_t * the_cib, const char * ticket_id, xmlNode ** ticket_cons_xml)
{
    int offset = 0;
    static int xpath_max = 1024;
    int rc = pcmk_ok;
    xmlNode *xml_search = NULL;

    char *xpath_string = NULL;

    CRM_ASSERT(ticket_cons_xml != NULL);
    *ticket_cons_xml = NULL;

    xpath_string = calloc(1, xpath_max);
    offset +=
        snprintf(xpath_string + offset, xpath_max - offset, "%s/%s",
                 get_object_path(XML_CIB_TAG_CONSTRAINTS), XML_CONS_TAG_RSC_TICKET);

    if (ticket_id) {
        offset += snprintf(xpath_string + offset, xpath_max - offset, "[@ticket=\"%s\"]",
                       ticket_id);
    }

    rc = the_cib->cmds->query(the_cib, xpath_string, &xml_search,
                              cib_sync_call | cib_scope_local | cib_xpath);

    if (rc != pcmk_ok) {
        goto bail;
    }

    crm_log_xml_debug(xml_search, "Match");
    *ticket_cons_xml = xml_search;

  bail:
    free(xpath_string);
    return rc;
}

static int
dump_ticket_xml(cib_t * the_cib, const char *ticket_id)
{
    int rc = pcmk_ok;
    xmlNode * state_xml = NULL;

    rc = find_ticket_state(the_cib, ticket_id, &state_xml);

    if (state_xml == NULL) {
        return rc;
    }

    fprintf(stdout, "State XML:\n");
    if (state_xml) {
        char *state_xml_str = NULL;

        state_xml_str = dump_xml_formatted(state_xml);
        fprintf(stdout, "\n%s\n", crm_str(state_xml_str));
        free_xml(state_xml);
        free(state_xml_str);
    }

    return pcmk_ok;
}

static int
dump_constraints(cib_t * the_cib, const char * ticket_id)
{
    int rc = pcmk_ok;
    xmlNode * cons_xml = NULL;
    char *cons_xml_str = NULL;

    rc = find_ticket_constraints(the_cib, ticket_id, &cons_xml);

    if (cons_xml == NULL) {
        return rc;
    }

    cons_xml_str = dump_xml_formatted(cons_xml);
    fprintf(stdout, "Constraints XML:\n\n%s\n", crm_str(cons_xml_str));
    free_xml(cons_xml);
    free(cons_xml_str);

    return pcmk_ok;
}

static int
find_ticket_state_attr_legacy(cib_t * the_cib, const char *attr, const char *ticket_id, const char *set_type,
                   const char *set_name, const char *attr_id, const char *attr_name, char **value)
{
    int offset = 0;
    static int xpath_max = 1024;
    int rc = pcmk_ok;
    xmlNode *xml_search = NULL;

    char *xpath_string = NULL;

    CRM_ASSERT(value != NULL);
    *value = NULL;

    xpath_string = calloc(1, xpath_max);
    offset +=
        snprintf(xpath_string + offset, xpath_max - offset, "%s", "/cib/status/tickets");

    if (set_type) {
        offset += snprintf(xpath_string + offset, xpath_max - offset, "/%s", set_type);
        if (set_name) {
            offset += snprintf(xpath_string + offset, xpath_max - offset, "[@id=\"%s\"]", set_name);
        }
    }

    offset += snprintf(xpath_string + offset, xpath_max - offset, "//nvpair[");
    if (attr_id) {
        offset += snprintf(xpath_string + offset, xpath_max - offset, "@id=\"%s\"", attr_id);
    }

    if (attr_name) {
        const char *attr_prefix = NULL;
        char *long_key = NULL;

        if (crm_str_eq(attr_name, "granted", TRUE)) {
            attr_prefix = "granted-ticket";
        } else {
            attr_prefix = attr_name;
        }
        long_key = crm_concat(attr_prefix, ticket_id, '-');

        if (attr_id) {
            offset += snprintf(xpath_string + offset, xpath_max - offset, " and ");
        }
        offset += snprintf(xpath_string + offset, xpath_max - offset, "@name=\"%s\"", long_key);

        free(long_key);
    }
    offset += snprintf(xpath_string + offset, xpath_max - offset, "]");

    rc = the_cib->cmds->query(the_cib, xpath_string, &xml_search,
                              cib_sync_call | cib_scope_local | cib_xpath);

    if (rc != pcmk_ok) {
        goto bail;
    }

    crm_log_xml_debug(xml_search, "Match");
    if (xml_has_children(xml_search)) {
        xmlNode *child = NULL;

        rc = -EINVAL;
        fprintf(stdout, "Multiple attributes match name=%s\n", attr_name);

        for (child = __xml_first_child(xml_search); child != NULL; child = __xml_next(child)) {
            fprintf(stdout, "  Value: %s \t(id=%s)\n",
                   crm_element_value(child, XML_NVPAIR_ATTR_VALUE), ID(child));
        }

    } else {
        const char *tmp = crm_element_value(xml_search, attr);

        if (tmp) {
            *value = strdup(tmp);
        }
    }

  bail:
    free(xpath_string);
    free_xml(xml_search);
    return rc;
}

static int
delete_ticket_state_attr_legacy(const char *ticket_id, const char *set_name, const char *attr_id,
                     const char *attr_name, cib_t * cib)
{
    xmlNode *xml_obj = NULL;

    int rc = pcmk_ok;
    char *local_attr_id = NULL;

    rc = find_ticket_state_attr_legacy(cib, XML_ATTR_ID, ticket_id, XML_TAG_ATTR_SETS, set_name, attr_id, attr_name,
                            &local_attr_id);

    if (rc == -ENXIO) {
        return pcmk_ok;

    } else if (rc != pcmk_ok) {
        return rc;
    }

    if (attr_id == NULL) {
        attr_id = local_attr_id;
    }

    xml_obj = create_xml_node(NULL, XML_CIB_TAG_NVPAIR);
    crm_xml_add(xml_obj, XML_ATTR_ID, attr_id);
    /*crm_xml_add(xml_obj, XML_NVPAIR_ATTR_NAME, attr_name);*/

    crm_log_xml_debug(xml_obj, "Delete");

    rc = cib->cmds->delete(cib, XML_CIB_TAG_STATUS, xml_obj, cib_options);

    if (rc == pcmk_ok) {
        fprintf(stdout, "Deleted legacy %s state attribute: id=%s%s%s%s%s\n", ticket_id, local_attr_id,
               set_name ? " set=" : "", set_name ? set_name : "",
               attr_name ? " name=" : "", attr_name ? attr_name : "");
    }

    free_xml(xml_obj);
    free(local_attr_id);
    return rc;
}

static int
get_ticket_state_attr(const char *ticket_id, const char *attr_name, const char **attr_value, pe_working_set_t * data_set)
{
    ticket_t *ticket = NULL;

    CRM_ASSERT(attr_value != NULL);
    *attr_value = NULL;

    ticket = g_hash_table_lookup(data_set->tickets, ticket_id);
    if (ticket == NULL) {
        return -ENXIO;
    }

    *attr_value = g_hash_table_lookup(ticket->state, attr_name);
    if (*attr_value == NULL) {
        return -ENXIO;
    }

    return pcmk_ok;
}

static int
delete_ticket_state_attr(const char *ticket_id, const char *attr_name, cib_t * cib)
{
    xmlNode *ticket_state_xml = NULL;

    int rc = pcmk_ok;

    rc = find_ticket_state(cib, ticket_id, &ticket_state_xml);

    if (rc == -ENXIO) {
        return pcmk_ok;

    } else if (rc != pcmk_ok) {
        return rc;
    }

    xml_remove_prop(ticket_state_xml, attr_name);
    rc = cib->cmds->replace(cib, XML_CIB_TAG_STATUS, ticket_state_xml, cib_options);

    if (rc == pcmk_ok) {
        fprintf(stdout, "Deleted %s state attribute: %s%s\n", ticket_id,
               attr_name ? " name=" : "", attr_name ? attr_name : "");
    }

    free_xml(ticket_state_xml);
    return rc;
}

static int
set_ticket_state_attr(const char *ticket_id, const char *attr_name,
                      const char *attr_value, cib_t * cib)
{
    int rc = pcmk_ok;
    xmlNode *xml_top = NULL;
    xmlNode *ticket_state_xml = NULL;

    rc = find_ticket_state(cib, ticket_id, &ticket_state_xml);
    if (rc == pcmk_ok) {
        crm_debug("Found a match state for ticket: id=%s", ticket_id);
        xml_top = ticket_state_xml;

    } else if (rc != -ENXIO) {
        return rc;

    } else {
        xmlNode *xml_obj = NULL;

        xml_top = create_xml_node(NULL, XML_CIB_TAG_STATUS);
        xml_obj = create_xml_node(xml_top, XML_CIB_TAG_TICKETS);
        ticket_state_xml = create_xml_node(xml_obj, XML_CIB_TAG_TICKET_STATE);
        crm_xml_add(ticket_state_xml, XML_ATTR_ID, ticket_id);
    }

    crm_xml_add(ticket_state_xml, attr_name, attr_value);

    crm_log_xml_debug(xml_top, "Update");

    rc = cib->cmds->modify(cib, XML_CIB_TAG_STATUS, xml_top, cib_options);

    free_xml(xml_top);

    return rc;
}

static int
delete_ticket_state(const char *ticket_id, cib_t * cib)
{
    xmlNode *ticket_state_xml = NULL;

    int rc = pcmk_ok;

    rc = find_ticket_state(cib, ticket_id, &ticket_state_xml);

    if (rc == -ENXIO) {
        return pcmk_ok;

    } else if (rc != pcmk_ok) {
        return rc;
    }

    crm_log_xml_debug(ticket_state_xml, "Delete");

    rc = cib->cmds->delete(cib, XML_CIB_TAG_STATUS, ticket_state_xml, cib_options);

    if (rc == pcmk_ok) {
        fprintf(stdout, "Cleaned up %s\n", ticket_id);
    }

    free_xml(ticket_state_xml);
    return rc;
}

static gboolean
confirm(const char *ticket_id, const char *action)
{
    gboolean rc = FALSE;
    int offset = 0;
    static int text_max = 1024;

    char *warning = NULL;
    const char * word = NULL;

    warning = calloc(1, text_max);
    if (safe_str_eq(action, "grant")) {
        offset += snprintf(warning + offset, text_max - offset,
                "The command cannot help you verify if '%s' is already granted elsewhere.\n",
                ticket_id);
        word = "to";

    } else {
        offset += snprintf(warning + offset, text_max - offset,
                "Revoking '%s' can trigger the specified 'loss-policy'(s) relating to '%s'.\n\n",
                ticket_id, ticket_id);

        offset += snprintf(warning + offset, text_max - offset,
                "You can check that with:\ncrm_ticket --ticket %s --constraints\n\n",
                ticket_id);

        offset += snprintf(warning + offset, text_max - offset,
                "Otherwise before revoking '%s', you may want to make '%s' standby with:\ncrm_ticket --ticket %s --standby\n",
                ticket_id, ticket_id, ticket_id);
        word = "from";
    }

    fprintf(stdout, "%s\n", warning);

    while (TRUE) {
        char *answer = NULL;

        answer = calloc(1, text_max);
        fprintf(stdout, "Are you sure you want to %s '%s' %s this site now? (y/n)",
                action, ticket_id, word);

        rc = scanf("%s", answer);

        if (strchr(answer, 'y') == answer || strchr(answer, 'Y') == answer) {
            rc = TRUE;
            free(answer);
            goto bail;

        } else if (strchr(answer, 'n') == answer || strchr(answer, 'N') == answer) {
            rc = FALSE;
            free(answer);
            goto bail;

        } else {
            free(answer);
            fprintf(stdout, "Please answer with y or n\n");
        }
    }

bail:
    free(warning);
    return rc;
}

/* *INDENT-OFF* */
static struct crm_option long_options[] = {
    /* Top-level Options */
    {"help",    0, 0, '?', "\t\tThis text"},
    {"version", 0, 0, '$', "\t\tVersion information"  },
    {"verbose", 0, 0, 'V', "\t\tIncrease debug output"},
    {"quiet",   0, 0, 'Q', "\t\tPrint only the value on stdout\n"},

    {"ticket",  1, 0, 't', "\tTicket ID" },

    {"-spacer-",   1, 0, '-', "\nQueries:"},
    {"info",       0, 0, 'l', "\t\tDisplay the information of ticket(s)"},
    {"details",    0, 0, 'L', "\t\tDisplay the details of ticket(s)"},
    {"raw",        0, 0, 'w', "\t\tDisplay the IDs of ticket(s)"},
    {"query-xml",  0, 0, 'q', "\tQuery the XML of ticket(s)"},
    {"constraints",0, 0, 'c', "\tDisplay the rsc_ticket constraints that apply to ticket(s)"},

    {"-spacer-",   1, 0, '-', "\nCommands:"},
    {"grant",      0, 0, 'g', "\t\tGrant a ticket to this cluster site"},
    {"revoke",     0, 0, 'r', "\t\tRevoke a ticket from this cluster site"},
    {"standby",    0, 0, 's', "\t\tTell this cluster site this ticket is standby"},
    {"activate",   0, 0, 'a', "\tTell this cluster site this ticket is active"},
    
    {"-spacer-",   1, 0, '-', "\nAdvanced Commands:"},
    {"get-attr",   1, 0, 'G', "\tDisplay the named attribute for a ticket"},
    {"set-attr",   1, 0, 'S', "\tSet the named attribtue for a ticket"},
    {"delete-attr",1, 0, 'D', "\tDelete the named attribute for a ticket"},
    {"cleanup",    0, 0, 'C', "\t\tDelete all state of a ticket at this cluster site"},
    
    {"-spacer-",   1, 0, '-', "\nAdditional Options:"},
    {"attr-value", 1, 0, 'v', "\tAttribute value to use with -S"},
    {"default",    1, 0, 'd', "\t(Advanced) The default attribute value to display if none is found. For use with -G"},
    {"force",      0, 0, 'f', "\t\t(Advanced) Force the action to be performed"},
    {"xml-file",   1, 0, 'x', NULL, 1},\

    /* legacy options */
    {"set-name",   1, 0, 'n', "\t(Advanced) ID of the instance_attributes object to change"},
    {"nvpair",     1, 0, 'i', "\t(Advanced) ID of the nvpair object to change/delete"},
    
    {"-spacer-",	1, 0, '-', "\nExamples:", pcmk_option_paragraph},
    {"-spacer-",	1, 0, '-', "Display the info of tickets:", pcmk_option_paragraph},
    {"-spacer-",	1, 0, '-', " crm_ticket --info", pcmk_option_example},
    {"-spacer-",	1, 0, '-', "Display the detailed info of tickets:", pcmk_option_paragraph},
    {"-spacer-",	1, 0, '-', " crm_ticket --details", pcmk_option_example},
    {"-spacer-",	1, 0, '-', "Display the XML of 'ticketA':", pcmk_option_paragraph},
    {"-spacer-",	1, 0, '-', " crm_ticket --ticket ticketA --query-xml", pcmk_option_example},
    {"-spacer-",	1, 0, '-', "Display the rsc_ticket constraints that apply to 'ticketA':", pcmk_option_paragraph},
    {"-spacer-",	1, 0, '-', " crm_ticket --ticket ticketA --constraints", pcmk_option_example},

    {"-spacer-",	1, 0, '-', "Grant 'ticketA' to this cluster site:", pcmk_option_paragraph},
    {"-spacer-",	1, 0, '-', " crm_ticket --ticket ticketA --grant", pcmk_option_example},
    {"-spacer-",	1, 0, '-', "Revoke 'ticketA' from this cluster site:", pcmk_option_paragraph},
    {"-spacer-",	1, 0, '-', " crm_ticket --ticket ticketA --revoke", pcmk_option_example},
    {"-spacer-",	1, 0, '-', "Make 'ticketA' standby:", pcmk_option_paragraph},
    {"-spacer-",	1, 0, '-', "The cluster site will treat a granted 'ticketA' as 'standby'."},
    {"-spacer-",	1, 0, '-', "The dependent resources will be stopped or demoted gracefully without triggering loss-policies", pcmk_option_paragraph},
    {"-spacer-",	1, 0, '-', " crm_ticket --ticket ticketA --standby", pcmk_option_example},
    {"-spacer-",	1, 0, '-', "Activate 'ticketA' from being standby:", pcmk_option_paragraph},
    {"-spacer-",	1, 0, '-', " crm_ticket --ticket ticketA --activate", pcmk_option_example},

    {"-spacer-",	1, 0, '-', "Get the value of the 'granted' attribute for 'ticketA':", pcmk_option_paragraph},
    {"-spacer-",	1, 0, '-', " crm_ticket --ticket ticketA --get-attr granted", pcmk_option_example},
    {"-spacer-",	1, 0, '-', "Set the value of the 'standby' attribute for 'ticketA':", pcmk_option_paragraph},
    {"-spacer-",	1, 0, '-', " crm_ticket --ticket ticketA --set-attr standby --attr-value true", pcmk_option_example},
    {"-spacer-",	1, 0, '-', "Delete the 'granted' attribute for 'ticketA':", pcmk_option_paragraph},
    {"-spacer-",	1, 0, '-', " crm_ticket --ticket ticketA --delete-attr granted", pcmk_option_example},
    {"-spacer-",	1, 0, '-', "Erase the operation history of 'ticketA' at this cluster site:", pcmk_option_paragraph},
    {"-spacer-",	1, 0, '-', "The cluster site will 'forget' the existing ticket state.", pcmk_option_paragraph},
    {"-spacer-",	1, 0, '-', " crm_ticket --ticket ticketA --cleanup", pcmk_option_example},
    
    {0, 0, 0, 0}
};
/* *INDENT-ON* */

int
main(int argc, char **argv)
{
    pe_working_set_t data_set;
    xmlNode *cib_xml_copy = NULL;
    xmlNode *cib_constraints = NULL;

    cib_t *cib_conn = NULL;
    int rc = pcmk_ok;

    int option_index = 0;
    int argerr = 0;
    int flag;

    crm_log_init(NULL, LOG_CRIT, FALSE, FALSE, argc, argv, FALSE);
    crm_set_options(NULL, "(query|command) [options]", long_options,
                    "Perform tasks related to cluster tickets.\nAllows ticket attributes to be queried, modified and deleted.\n");

    if (argc < 2) {
        crm_help('?', EX_USAGE);
    }

    while (1) {
        flag = crm_get_option(argc, argv, &option_index);
        if (flag == -1)
            break;

        switch (flag) {
            case 'V':
                crm_bump_log_level(argc, argv);
                break;
            case '$':
            case '?':
                crm_help(flag, EX_OK);
                break;
            case 'Q':
                BE_QUIET = TRUE;
                break;
            case 't':
                ticket_id = optarg;
                break;
            case 'l':
            case 'L':
            case 'w':
            case 'q':
            case 'c':
                ticket_cmd = flag;
                break;
            case 'g':
            case 'r':
            case 's':
            case 'a':
                ticket_cmd = flag;
                break;
            case 'G':
            case 'S':
            case 'D':
                attr_name = optarg;
                ticket_cmd = flag;
                break;
            case 'C':
                ticket_cmd = flag;
                break;
            case 'v':
                attr_value = optarg;
                break;
            case 'd':
                attr_default = optarg;
                break;
            case 'f':
                do_force = TRUE;
                break;
            case 'x':
                xml_file = strdup(optarg);
                break;
            case 'n':
                set_name = optarg;
                break;
            case 'i':
                attr_id = optarg;
                break;

            default:
                CMD_ERR("Argument code 0%o (%c) is not (?yet?) supported\n", flag, flag);
                ++argerr;
                break;
        }
    }

    if (optind < argc && argv[optind] != NULL) {
        CMD_ERR("non-option ARGV-elements: ");
        while (optind < argc && argv[optind] != NULL) {
            CMD_ERR("%s ", argv[optind++]);
            ++argerr;
        }
        CMD_ERR("\n");
    }

    if (optind > argc) {
        ++argerr;
    }

    if (argerr) {
        crm_help('?', EX_USAGE);
    }

    set_working_set_defaults(&data_set);

    cib_conn = cib_new();
    if (cib_conn == NULL) {
        rc = -ENOTCONN;
        CMD_ERR("Error initiating the connection to the CIB service: %s\n",
                pcmk_strerror(rc));
        return rc;
    }

    rc = cib_conn->cmds->signon(cib_conn, crm_system_name, cib_command);
    if (rc != pcmk_ok) {
        CMD_ERR("Error signing on to the CIB service: %s\n", pcmk_strerror(rc));
        return rc;
    }

    if (xml_file != NULL) {
        cib_xml_copy = filename2xml(xml_file);

    } else {
        cib_xml_copy = get_cib_copy(cib_conn);
    }

    if (cli_config_update(&cib_xml_copy, NULL, FALSE) == FALSE) {
        rc = -ENOKEY;
        goto bail;
    }

    data_set.input = cib_xml_copy;
    data_set.now = crm_time_new(NULL);

    cluster_status(&data_set);

    /* For recording the tickets that are referenced in rsc_ticket constraints
     * but have never been granted yet. */
    cib_constraints = get_object_root(XML_CIB_TAG_CONSTRAINTS, data_set.input);
    unpack_constraints(cib_constraints, &data_set);

    if (ticket_cmd == 'l' || ticket_cmd == 'L' || ticket_cmd == 'w') {
        gboolean raw = FALSE;
        gboolean details = FALSE;
        rc = pcmk_ok;

        if (ticket_cmd == 'L') {
            details = TRUE;
        } else if (ticket_cmd == 'w') {
            raw = TRUE;
        }

        if (ticket_id) {
            ticket_t *ticket = find_ticket(ticket_id, &data_set);
            if (ticket == NULL) {
                rc = -ENXIO;
                goto bail;
            }
            rc = print_ticket(ticket, raw, details);

        } else {
            rc = print_ticket_list(&data_set, raw, details);
        }

    } else if (ticket_cmd == 'q') {
        rc = dump_ticket_xml(cib_conn, ticket_id);

    } else if (ticket_cmd == 'c') {
        rc = dump_constraints(cib_conn, ticket_id);

    } else if (ticket_cmd == 'G') {
        const char *value = NULL;

        if (ticket_id == NULL) {
            CMD_ERR("Must supply a ticket id with -t\n");
            rc = -ENXIO;
            goto bail;
        }

        rc = get_ticket_state_attr(ticket_id, attr_name, &value, &data_set);
        if (rc == pcmk_ok) {
            fprintf(stdout, "%s\n", value);
        } else if (rc == -ENXIO && attr_default) {
            fprintf(stdout, "%s\n", attr_default);
            rc = pcmk_ok;
        }

    } else if (ticket_cmd == 'S' 
               || ticket_cmd == 'g' || ticket_cmd == 'r'
               || ticket_cmd == 's' || ticket_cmd == 'a') {
        gboolean is_granting = FALSE;

        if (ticket_id == NULL) {
            CMD_ERR("Must supply a ticket id with -t\n");
            rc = -ENXIO;
            goto bail;
        }

        if (ticket_cmd == 'g') {
            attr_name = "granted";
            attr_value = "true";

        } else if (ticket_cmd == 'r') {
            attr_name = "granted";
            attr_value = "false";

        } else if (ticket_cmd == 's') {
            attr_name = "standby";
            attr_value = "true";

        } else if (ticket_cmd == 'a') {
            attr_name = "standby";
            attr_value = "false";
        }

        if (attr_value == NULL || strlen(attr_value) == 0) {
            CMD_ERR("You need to supply a value with the -v option\n");
            rc = -EINVAL;
            goto bail;
        }

        if (safe_str_eq(attr_name, "granted") && do_force == FALSE) {
            if (crm_is_true(attr_value) && confirm(ticket_id, "grant") == FALSE) {
                CMD_ERR("Cancelled\n");
                rc = pcmk_ok;
                goto bail;

            } else if (crm_is_true(attr_value) == FALSE && confirm(ticket_id, "revoke") == FALSE) {
                CMD_ERR("Cancelled\n");
                rc = pcmk_ok;
                goto bail;
            }
        }

        if (safe_str_eq(attr_name, "granted") && crm_is_true(attr_value)) {
            ticket_t *ticket = find_ticket(ticket_id, &data_set);

            if (ticket == NULL || ticket->granted == FALSE) {
                is_granting = TRUE;
            }
        }

        rc = set_ticket_state_attr(ticket_id, attr_name, attr_value, cib_conn);
        delete_ticket_state_attr_legacy(ticket_id, set_name, attr_id, attr_name, cib_conn);

        if(rc != pcmk_ok) {
            goto bail;
        }

        if (is_granting == TRUE) {
            set_ticket_state_attr(ticket_id, "last-granted", crm_itoa(time(NULL)), cib_conn);
            delete_ticket_state_attr_legacy(ticket_id, set_name, attr_id, "last-granted", cib_conn);
        }

    } else if (ticket_cmd == 'D') {
        if (ticket_id == NULL) {
            CMD_ERR("Must supply a ticket id with -t\n");
            rc = -ENXIO;
            goto bail;
        }

        if (safe_str_eq(attr_name, "granted") && do_force == FALSE
            && confirm(ticket_id, "revoke") == FALSE) {
            CMD_ERR("Cancelled\n");
            rc = pcmk_ok;
            goto bail;
        }

        delete_ticket_state_attr_legacy(ticket_id, set_name, attr_id, attr_name, cib_conn);
        rc = delete_ticket_state_attr(ticket_id, attr_name, cib_conn);

    } else if (ticket_cmd == 'C') {
        if (ticket_id == NULL) {
            CMD_ERR("Must supply a ticket id with -t\n");
            rc = -ENXIO;
            goto bail;
        }
        
        if (do_force == FALSE) {
            ticket_t *ticket = NULL;

            ticket = find_ticket(ticket_id, &data_set);
            if (ticket == NULL) {
                rc = -ENXIO;
                goto bail;
            }

            if (ticket->granted && confirm(ticket_id, "revoke") == FALSE) {
                CMD_ERR("Cancelled\n");
                rc = pcmk_ok;
                goto bail;
            }
        }

        rc = delete_ticket_state(ticket_id, cib_conn);

    } else {
        CMD_ERR("Unknown command: %c\n", ticket_cmd);
    }

  bail:

    if (cib_conn != NULL) {
        cleanup_alloc_calculations(&data_set);
        cib_conn->cmds->signoff(cib_conn);
        cib_delete(cib_conn);
    }

    if (rc == -pcmk_err_no_quorum) {
        CMD_ERR("Error performing operation: %s\n", pcmk_strerror(rc));
        CMD_ERR("Try using -f\n");

    } else if (rc != pcmk_ok) {
        CMD_ERR("Error performing operation: %s\n", pcmk_strerror(rc));
    }

    return crm_exit(rc);
}
