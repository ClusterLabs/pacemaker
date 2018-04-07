
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
const char *get_attr_name = NULL;
const char *attr_name = NULL;
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
find_ticket(const char *ticket_id, pe_working_set_t * data_set)
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
    fprintf(stdout, "'%s'", date_str);
}

static int
print_ticket(ticket_t * ticket, gboolean raw, gboolean details)
{
    if (raw) {
        fprintf(stdout, "%s\n", ticket->id);
        return pcmk_ok;
    }

    fprintf(stdout, "%s\t%s %s",
            ticket->id, ticket->granted ? "granted" : "revoked",
            ticket->standby ? "[standby]" : "         ");

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

#define XPATH_MAX 1024

static int
find_ticket_state(cib_t * the_cib, const char *ticket_id, xmlNode ** ticket_state_xml)
{
    int offset = 0;
    int rc = pcmk_ok;
    xmlNode *xml_search = NULL;

    char *xpath_string = NULL;

    CRM_ASSERT(ticket_state_xml != NULL);
    *ticket_state_xml = NULL;

    xpath_string = calloc(1, XPATH_MAX);
    offset += snprintf(xpath_string + offset, XPATH_MAX - offset, "%s", "/cib/status/tickets");

    if (ticket_id) {
        offset += snprintf(xpath_string + offset, XPATH_MAX - offset, "/%s[@id=\"%s\"]",
                           XML_CIB_TAG_TICKET_STATE, ticket_id);
    }

    CRM_LOG_ASSERT(offset > 0);
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
find_ticket_constraints(cib_t * the_cib, const char *ticket_id, xmlNode ** ticket_cons_xml)
{
    int offset = 0;
    int rc = pcmk_ok;
    xmlNode *xml_search = NULL;

    char *xpath_string = NULL;

    CRM_ASSERT(ticket_cons_xml != NULL);
    *ticket_cons_xml = NULL;

    xpath_string = calloc(1, XPATH_MAX);
    offset +=
        snprintf(xpath_string + offset, XPATH_MAX - offset, "%s/%s",
                 get_object_path(XML_CIB_TAG_CONSTRAINTS), XML_CONS_TAG_RSC_TICKET);

    if (ticket_id) {
        offset += snprintf(xpath_string + offset, XPATH_MAX - offset, "[@ticket=\"%s\"]",
                           ticket_id);
    }

    CRM_LOG_ASSERT(offset > 0);
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
    xmlNode *state_xml = NULL;

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
dump_constraints(cib_t * the_cib, const char *ticket_id)
{
    int rc = pcmk_ok;
    xmlNode *cons_xml = NULL;
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
get_ticket_state_attr(const char *ticket_id, const char *attr_name, const char **attr_value,
                      pe_working_set_t * data_set)
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

static gboolean
ticket_warning(const char *ticket_id, const char *action)
{
    gboolean rc = FALSE;
    int offset = 0;
    static int text_max = 1024;

    char *warning = NULL;
    const char *word = NULL;

    warning = calloc(1, text_max);
    if (safe_str_eq(action, "grant")) {
        offset += snprintf(warning + offset, text_max - offset,
                           "This command cannot help you verify whether '%s' has been already granted elsewhere.\n",
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
                           "Otherwise before revoking '%s', you may want to make '%s' standby with:\ncrm_ticket --ticket %s --standby\n\n",
                           ticket_id, ticket_id, ticket_id);
        word = "from";
    }

    offset += snprintf(warning + offset, text_max - offset,
                       "If you really want to %s '%s' %s this site now, and you know what you are doing,\n",
                       action, ticket_id, word);

    offset += snprintf(warning + offset, text_max - offset, 
                       "please specify --force.");

    CRM_LOG_ASSERT(offset > 0);
    fprintf(stdout, "%s\n", warning);

    free(warning);
    return rc;
}

static gboolean
allow_modification(const char *ticket_id, GListPtr attr_delete,
                   GHashTable *attr_set)
{
    const char *value = NULL;
    GListPtr list_iter = NULL;

    if (do_force) {
        return TRUE;
    }

    if (g_hash_table_lookup_extended(attr_set, "granted", NULL, (gpointer *) & value)) {
        if (crm_is_true(value)) {
            ticket_warning(ticket_id, "grant");
            return FALSE;

        } else {
            ticket_warning(ticket_id, "revoke");
            return FALSE;
        }
    }

    for(list_iter = attr_delete; list_iter; list_iter = list_iter->next) {
        const char *key = (const char *)list_iter->data;

        if (safe_str_eq(key, "granted")) {
            ticket_warning(ticket_id, "revoke");
            return FALSE;
        }
    }

    return TRUE;
}

static int
modify_ticket_state(const char * ticket_id, GListPtr attr_delete, GHashTable * attr_set,
                    cib_t * cib, pe_working_set_t * data_set)
{
    int rc = pcmk_ok;
    xmlNode *xml_top = NULL;
    xmlNode *ticket_state_xml = NULL;
    gboolean found = FALSE;

    GListPtr list_iter = NULL;
    GHashTableIter hash_iter;

    char *key = NULL;
    char *value = NULL;

    ticket_t *ticket = NULL;

    rc = find_ticket_state(cib, ticket_id, &ticket_state_xml);
    if (rc == pcmk_ok) {
        crm_debug("Found a match state for ticket: id=%s", ticket_id);
        xml_top = ticket_state_xml;
        found = TRUE;

    } else if (rc != -ENXIO) {
        return rc;

    } else if (g_hash_table_size(attr_set) == 0){
        return pcmk_ok;

    } else {
        xmlNode *xml_obj = NULL;

        xml_top = create_xml_node(NULL, XML_CIB_TAG_STATUS);
        xml_obj = create_xml_node(xml_top, XML_CIB_TAG_TICKETS);
        ticket_state_xml = create_xml_node(xml_obj, XML_CIB_TAG_TICKET_STATE);
        crm_xml_add(ticket_state_xml, XML_ATTR_ID, ticket_id);
    }

    for(list_iter = attr_delete; list_iter; list_iter = list_iter->next) {
        const char *key = (const char *)list_iter->data;
        xml_remove_prop(ticket_state_xml, key);
    }

    ticket = find_ticket(ticket_id, data_set);

    g_hash_table_iter_init(&hash_iter, attr_set);
    while (g_hash_table_iter_next(&hash_iter, (gpointer *) & key, (gpointer *) & value)) {
        crm_xml_add(ticket_state_xml, key, value);

        if (safe_str_eq(key, "granted")
            && (ticket == NULL || ticket->granted == FALSE)
            && crm_is_true(value)) {

            char *now = crm_itoa(time(NULL));

            crm_xml_add(ticket_state_xml, "last-granted", now);
            free(now);
        }
    }

    if (found && g_list_length(attr_delete)) {
        crm_log_xml_debug(xml_top, "Replace");
        rc = cib->cmds->replace(cib, XML_CIB_TAG_STATUS, ticket_state_xml, cib_options);

    } else {
        crm_log_xml_debug(xml_top, "Update");
        rc = cib->cmds->modify(cib, XML_CIB_TAG_STATUS, xml_top, cib_options);
    }

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

    rc = cib->cmds->remove(cib, XML_CIB_TAG_STATUS, ticket_state_xml, cib_options);

    if (rc == pcmk_ok) {
        fprintf(stdout, "Cleaned up %s\n", ticket_id);
    }

    free_xml(ticket_state_xml);
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
    crm_exit_t exit_code = CRM_EX_OK;
    int rc = pcmk_ok;

    int option_index = 0;
    int argerr = 0;
    int flag;
    guint modified = 0;

    GListPtr attr_delete = NULL;
    GHashTable *attr_set = crm_str_table_new();

    crm_log_init(NULL, LOG_CRIT, FALSE, FALSE, argc, argv, FALSE);
    crm_set_options(NULL, "(query|command) [options]", long_options,
                    "Perform tasks related to cluster tickets.\nAllows ticket attributes to be queried, modified and deleted.\n");

    if (argc < 2) {
        crm_help('?', CRM_EX_USAGE);
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
                crm_help(flag, CRM_EX_OK);
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
                g_hash_table_insert(attr_set, strdup("granted"), strdup("true"));
                modified++;
                break;
            case 'r':
                g_hash_table_insert(attr_set, strdup("granted"), strdup("false"));
                modified++;
                break;
            case 's':
                g_hash_table_insert(attr_set, strdup("standby"), strdup("true"));
                modified++;
                break;
            case 'a':
                g_hash_table_insert(attr_set, strdup("standby"), strdup("false"));
                modified++;
                break;
            case 'G':
                get_attr_name = optarg;
                ticket_cmd = flag;
                break;
            case 'S':
                attr_name = optarg;
                if (attr_name && attr_value) {
                    g_hash_table_insert(attr_set, strdup(attr_name), strdup(attr_value));
                    attr_name = NULL;
                    attr_value = NULL;
                    modified++;
                }
                break;
            case 'D':
                attr_delete = g_list_append(attr_delete, optarg);
                modified++;
                break;
            case 'C':
                ticket_cmd = flag;
                break;
            case 'v':
                attr_value = optarg;
                if (attr_name && attr_value) {
                    g_hash_table_insert(attr_set, strdup(attr_name), strdup(attr_value));
                    attr_name = NULL;
                    attr_value = NULL;
                    modified++;
                }
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
                CMD_ERR("Argument code 0%o (%c) is not (?yet?) supported", flag, flag);
                ++argerr;
                break;
        }
    }

    if (optind < argc && argv[optind] != NULL) {
        CMD_ERR("non-option ARGV-elements:");
        while (optind < argc && argv[optind] != NULL) {
            CMD_ERR("%s", argv[optind++]);
            ++argerr;
        }
    }

    if (optind > argc) {
        ++argerr;
    }

    if (argerr) {
        crm_help('?', CRM_EX_USAGE);
    }

    set_working_set_defaults(&data_set);

    cib_conn = cib_new();
    if (cib_conn == NULL) {
        CMD_ERR("Could not connect to CIB");
        return CRM_EX_DISCONNECT;
    }

    rc = cib_conn->cmds->signon(cib_conn, crm_system_name, cib_command);
    if (rc != pcmk_ok) {
        CMD_ERR("Could not connect to CIB: %s", pcmk_strerror(rc));
        exit_code = crm_errno2exit(rc);
        goto bail;
    }

    if (xml_file != NULL) {
        cib_xml_copy = filename2xml(xml_file);

    } else {
        rc = cib_conn->cmds->query(cib_conn, NULL, &cib_xml_copy, cib_scope_local | cib_sync_call);
        if (rc != pcmk_ok) {
            CMD_ERR("Could not get local CIB: %s", pcmk_strerror(rc));
            exit_code = crm_errno2exit(rc);
            goto bail;
        }
    }

    if (cli_config_update(&cib_xml_copy, NULL, FALSE) == FALSE) {
        CMD_ERR("Could not update local CIB to latest schema version");
        exit_code = CRM_EX_CONFIG;
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

        if (ticket_cmd == 'L') {
            details = TRUE;
        } else if (ticket_cmd == 'w') {
            raw = TRUE;
        }

        if (ticket_id) {
            ticket_t *ticket = find_ticket(ticket_id, &data_set);

            if (ticket == NULL) {
                CMD_ERR("No such ticket '%s'", ticket_id);
                exit_code = CRM_EX_NOSUCH;
                goto bail;
            }
            rc = print_ticket(ticket, raw, details);

        } else {
            rc = print_ticket_list(&data_set, raw, details);
        }
        if (rc != pcmk_ok) {
            CMD_ERR("Could not print ticket: %s", pcmk_strerror(rc));
        }
        exit_code = crm_errno2exit(rc);

    } else if (ticket_cmd == 'q') {
        rc = dump_ticket_xml(cib_conn, ticket_id);
        if (rc != pcmk_ok) {
            CMD_ERR("Could not query ticket XML: %s", pcmk_strerror(rc));
        }
        exit_code = crm_errno2exit(rc);

    } else if (ticket_cmd == 'c') {
        rc = dump_constraints(cib_conn, ticket_id);
        if (rc != pcmk_ok) {
            CMD_ERR("Could not show ticket constraints: %s", pcmk_strerror(rc));
        }
        exit_code = crm_errno2exit(rc);

    } else if (ticket_cmd == 'G') {
        const char *value = NULL;

        if (ticket_id == NULL) {
            CMD_ERR("Must supply ticket ID with -t");
            exit_code = CRM_EX_NOSUCH;
            goto bail;
        }

        rc = get_ticket_state_attr(ticket_id, get_attr_name, &value, &data_set);
        if (rc == pcmk_ok) {
            fprintf(stdout, "%s\n", value);
        } else if (rc == -ENXIO && attr_default) {
            fprintf(stdout, "%s\n", attr_default);
            rc = pcmk_ok;
        }
        exit_code = crm_errno2exit(rc);

    } else if (ticket_cmd == 'C') {
        if (ticket_id == NULL) {
            CMD_ERR("Must supply ticket ID with -t");
            exit_code = CRM_EX_USAGE;
            goto bail;
        }

        if (do_force == FALSE) {
            ticket_t *ticket = NULL;

            ticket = find_ticket(ticket_id, &data_set);
            if (ticket == NULL) {
                CMD_ERR("No such ticket '%s'", ticket_id);
                exit_code = CRM_EX_NOSUCH;
                goto bail;
            }

            if (ticket->granted) {
                ticket_warning(ticket_id, "revoke");
                exit_code = CRM_EX_INSUFFICIENT_PRIV;
                goto bail;
            }
        }

        rc = delete_ticket_state(ticket_id, cib_conn);
        if (rc != pcmk_ok) {
            CMD_ERR("Could not clean up ticket: %s", pcmk_strerror(rc));
        }
        exit_code = crm_errno2exit(rc);

    } else if (modified) {
        if (ticket_id == NULL) {
            CMD_ERR("Must supply ticket ID with -t");
            exit_code = CRM_EX_USAGE;
            goto bail;
        }

        if (attr_value
            && (attr_name == NULL || strlen(attr_name) == 0)) {
            CMD_ERR("Must supply attribute name with -S for -v %s", attr_value);
            exit_code = CRM_EX_USAGE;
            goto bail;
        }

        if (attr_name
            && (attr_value == NULL || strlen(attr_value) == 0)) {
            CMD_ERR("Must supply attribute value with -v for -S %s", attr_name);
            exit_code = CRM_EX_USAGE;
            goto bail;
        }

        if (allow_modification(ticket_id, attr_delete, attr_set) == FALSE) {
            CMD_ERR("Ticket modification not allowed");
            exit_code = CRM_EX_INSUFFICIENT_PRIV;
            goto bail;
        }

        rc = modify_ticket_state(ticket_id, attr_delete, attr_set, cib_conn, &data_set);
        if (rc != pcmk_ok) {
            CMD_ERR("Could not modify ticket: %s", pcmk_strerror(rc));
        }
        exit_code = crm_errno2exit(rc);

    } else if (ticket_cmd == 'S') {
        /* Correct usage was handled in the "if (modified)" block above, so
         * this is just for reporting usage errors
         */

        if (attr_name == NULL || strlen(attr_name) == 0) {
            // We only get here if ticket_cmd was left as default
            CMD_ERR("Must supply a command");
            exit_code = CRM_EX_USAGE;
            goto bail;
        }

        if (ticket_id == NULL) {
            CMD_ERR("Must supply ticket ID with -t");
            exit_code = CRM_EX_USAGE;
            goto bail;
        }

        if (attr_value == NULL || strlen(attr_value) == 0) {
            CMD_ERR("Must supply value with -v for -S %s", attr_name);
            exit_code = CRM_EX_USAGE;
            goto bail;
        }

    } else {
        CMD_ERR("Unknown command: %c", ticket_cmd);
        exit_code = CRM_EX_USAGE;
    }

  bail:
    if (attr_set) {
        g_hash_table_destroy(attr_set);
    }
    attr_set = NULL;

    if (attr_delete) {
        g_list_free(attr_delete);
    }
    attr_delete = NULL;

    if (cib_conn != NULL) {
        cleanup_alloc_calculations(&data_set);
        cib_conn->cmds->signoff(cib_conn);
        cib_delete(cib_conn);
    }

    if (rc == -pcmk_err_no_quorum) {
        CMD_ERR("Use --force to ignore quorum");
    }

    return crm_exit(exit_code);
}
