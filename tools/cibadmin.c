
/* 
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
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

#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/ipc.h>
#include <crm/cib/internal.h>

int exit_code = pcmk_ok;
int message_timer_id = -1;
int message_timeout_ms = 30;

GMainLoop *mainloop = NULL;

const char *host = NULL;
void usage(const char *cmd, int exit_status);
int do_init(void);
int do_work(xmlNode * input, int command_options, xmlNode ** output);

gboolean admin_message_timeout(gpointer data);
void cib_connection_destroy(gpointer user_data);
void cibadmin_op_callback(xmlNode * msg, int call_id, int rc, xmlNode * output, void *user_data);

int command_options = 0;
const char *cib_action = NULL;

typedef struct str_list_s {
    int num_items;
    char *value;
    struct str_list_s *next;
} str_list_t;

char *obj_type = NULL;
char *status = NULL;
char *migrate_from = NULL;
char *migrate_res = NULL;
char *subtype = NULL;
char *reset = NULL;

int request_id = 0;
int operation_status = 0;
cib_t *the_cib = NULL;
gboolean force_flag = FALSE;

/* *INDENT-OFF* */
static struct crm_option long_options[] = {
    {"help",    0, 0, '?', "\tThis text"},
    {"version", 0, 0, '$', "\tVersion information"  },
    {"verbose", 0, 0, 'V', "\tIncrease debug output\n"},
    
    {"-spacer-",    0, 0, '-', "Commands:"},
    {"upgrade",     0, 0, 'u', "\tUpgrade the configuration to the latest syntax"},
    {"query",       0, 0, 'Q', "\tQuery the contents of the CIB"},
    {"erase",       0, 0, 'E', "\tErase the contents of the whole CIB"},
    {"bump",        0, 0, 'B', "\tIncrease the CIB's epoch value by 1"},
    {"create",      0, 0, 'C', "\tCreate an object in the CIB.  Will fail if the object already exists."},
    {"modify",      0, 0, 'M', "\tFind the object somewhere in the CIB's XML tree and update it.  Fails if the object does not exist unless -c is specified"},
    {"patch",	    0, 0, 'P', "\tSupply an update in the form of an xml diff (See also: crm_diff)"},
    {"replace",     0, 0, 'R', "\tRecursivly replace an object in the CIB"},
    {"delete",      0, 0, 'D', "\tDelete the first object matching the supplied criteria, Eg. <op id=\"rsc1_op1\" name=\"monitor\"/>"},
    {"-spacer-",    0, 0, '-', "\n\t\t\tThe tagname and all attributes must match in order for the element to be deleted"},
    {"delete-all",  0, 0, 'd', "\tWhen used with --xpath, remove all matching objects in the configuration instead of just the first one"},
    {"md5-sum",	    0, 0, '5', "\tCalculate the on-disk CIB digest"},    
    {"md5-sum-versioned",  0, 0, '6', "\tCalculate an on-the-wire versioned CIB digest"},    
    {"sync",        0, 0, 'S', "\t(Advanced) Force a refresh of the CIB to all nodes\n"},
    {"make-slave",  0, 0, 'r', NULL, 1},
    {"make-master", 0, 0, 'w', NULL, 1},
    {"is-master",   0, 0, 'm', NULL, 1},
    {"empty",       0, 0, 'a', "\tOutput an empty CIB"},
    {"blank",       0, 0, 'a', NULL, 1},

    {"-spacer-",1, 0, '-', "\nAdditional options:"},
    {"force",	    0, 0, 'f'},
    {"timeout",	    1, 0, 't', "Time (in seconds) to wait before declaring the operation failed"},
    {"sync-call",   0, 0, 's', "Wait for call to complete before returning"},
    {"local",	    0, 0, 'l', "\tCommand takes effect locally.  Should only be used for queries"},
    {"allow-create",0, 0, 'c', "(Advanced) Allow the target of a -M operation to be created if they do not exist"},
    {"no-children", 0, 0, 'n', "(Advanced) When querying an object, do not return include its children in the result\n"},
    {"no-bcast",    0, 0, 'b', NULL, 1},
    
    {"-spacer-",    0, 0, '-', "Data:"},
    {"xml-text",    1, 0, 'X', "Retrieve XML from the supplied string"},
    {"xml-file",    1, 0, 'x', "Retrieve XML from the named file"},
    {"xml-pipe",    0, 0, 'p', "Retrieve XML from stdin\n"},

    {"xpath",       1, 0, 'A', "A valid XPath to use instead of -o"},
    {"scope",       1, 0, 'o', "Limit the scope of the operation to a specific section of the CIB."},
    {"-spacer-",    0, 0, '-', "\t\t\tValid values are: nodes, resources, constraints, crm_config, rsc_defaults, op_defaults, status"},
    {"node",	    1, 0, 'N', "(Advanced) Send command to the specified host\n"},
    {"-space-",	    0, 0, '!', NULL, 1},

    {"-spacer-",    0, 0, '-', "\nExamples:\n"},
    {"-spacer-",    0, 0, '-', "Query the configuration from the local node:", pcmk_option_paragraph},
    {"-spacer-",    0, 0, '-', " cibadmin --query --local", pcmk_option_example},
    
    {"-spacer-",    0, 0, '-', "Query the just the cluster options configuration:", pcmk_option_paragraph},
    {"-spacer-",    0, 0, '-', " cibadmin --query --scope crm_config", pcmk_option_example},

    {"-spacer-",    0, 0, '-', "Query all 'target-role' settings:", pcmk_option_paragraph},
    {"-spacer-",    0, 0, '-', " cibadmin --query --xpath \"//nvpair[@name='target-role']\"", pcmk_option_example},

    {"-spacer-",    0, 0, '-', "Remove all 'is-managed' settings:", pcmk_option_paragraph},
    {"-spacer-",    0, 0, '-', " cibadmin --delete-all --xpath \"//nvpair[@name='is-managed']\"", pcmk_option_example},

    {"-spacer-",    0, 0, '-', "Remove the resource named 'old':", pcmk_option_paragraph},
    {"-spacer-",    0, 0, '-', " cibadmin --delete --xml-text '<primitive id=\"old\"/>'", pcmk_option_example},

    {"-spacer-",    0, 0, '-', "Remove all resources from the configuration:", pcmk_option_paragraph},
    {"-spacer-",    0, 0, '-', " cibadmin --replace --scope resources --xml-text '<resources/>'", pcmk_option_example},

    {"-spacer-",    0, 0, '-', "Replace the complete configuration with the contents of $HOME/pacemaker.xml:", pcmk_option_paragraph},
    {"-spacer-",    0, 0, '-', " cibadmin --replace --xml-file $HOME/pacemaker.xml", pcmk_option_example},

    {"-spacer-",    0, 0, '-', "Replace the constraints section of the configuration with the contents of $HOME/constraints.xml:", pcmk_option_paragraph},
    {"-spacer-",    0, 0, '-', " cibadmin --replace --scope constraints --xml-file $HOME/constraints.xml", pcmk_option_example},

    {"-spacer-",    0, 0, '-', "Increase the configuration version to prevent old configurations from being loaded accidentally:", pcmk_option_paragraph},
    {"-spacer-",    0, 0, '-', " cibadmin --modify --xml-text '<cib admin_epoch=\"admin_epoch++\"/>'", pcmk_option_example},

    {"-spacer-",    0, 0, '-', "Edit the configuration with your favorite $EDITOR:", pcmk_option_paragraph},
    {"-spacer-",    0, 0, '-', " cibadmin --query > $HOME/local.xml", pcmk_option_example},
    {"-spacer-",    0, 0, '-', " $EDITOR $HOME/local.xml", pcmk_option_example},
    {"-spacer-",    0, 0, '-', " cibadmin --replace --xml-file $HOME/local.xml", pcmk_option_example},

    {"-spacer-",    0, 0, '-', "SEE ALSO:"},
    {"-spacer-",    0, 0, '-', " CRM shell, crm(8), crm_shadow(8)"},

    /* Legacy options */
    {"host",	     1, 0, 'h', NULL, 1},
    {"force-quorum", 0, 0, 'f', NULL, 1},
    {"obj_type",     1, 0, 'o', NULL, 1},
    {F_CRM_DATA,     1, 0, 'X', NULL, 1},
    {CIB_OP_ERASE,   0, 0, 'E', NULL, 1},
    {CIB_OP_QUERY,   0, 0, 'Q', NULL, 1},
    {CIB_OP_CREATE,  0, 0, 'C', NULL, 1},
    {CIB_OP_REPLACE, 0, 0, 'R', NULL, 1},
    {CIB_OP_UPDATE,  0, 0, 'U', NULL, 1},
    {CIB_OP_MODIFY,  0, 0, 'M', NULL, 1},
    {CIB_OP_DELETE,  0, 0, 'D', NULL, 1},
    {CIB_OP_BUMP,    0, 0, 'B', NULL, 1},
    {CIB_OP_SYNC,    0, 0, 'S', NULL, 1},
    {CIB_OP_SLAVE,   0, 0, 'r', NULL, 1},
    {CIB_OP_MASTER,  0, 0, 'w', NULL, 1},
    {CIB_OP_ISMASTER,0, 0, 'm', NULL, 1},
    
    {0, 0, 0, 0}
};
/* *INDENT-ON* */

int
main(int argc, char **argv)
{
    int argerr = 0;
    int flag;
    const char *source = NULL;
    char *admin_input_xml = NULL;
    char *admin_input_file = NULL;
    gboolean dangerous_cmd = FALSE;
    gboolean admin_input_stdin = FALSE;
    xmlNode *output = NULL;
    xmlNode *input = NULL;

    int option_index = 0;

    crm_log_init(NULL, LOG_CRIT, FALSE, FALSE, argc, argv, FALSE);
    crm_set_options(NULL, "command [options] [data]", long_options,
                    "Provides direct access to the cluster configuration."
                    "\n\nAllows the configuration, or sections of it, to be queried, modified, replaced and deleted."
                    "\n\nWhere necessary, XML data will be obtained using the -X, -x, or -p options\n");

    if (argc < 2) {
        crm_help('?', EX_USAGE);
    }

    while (1) {
        flag = crm_get_option(argc, argv, &option_index);
        if (flag == -1)
            break;

        switch (flag) {
            case 't':
                message_timeout_ms = atoi(optarg);
                if (message_timeout_ms < 1) {
                    message_timeout_ms = 30;
                }
                break;
            case 'A':
                obj_type = strdup(optarg);
                command_options |= cib_xpath;
                break;
            case 'u':
                cib_action = CIB_OP_UPGRADE;
                dangerous_cmd = TRUE;
                break;
            case 'E':
                cib_action = CIB_OP_ERASE;
                dangerous_cmd = TRUE;
                break;
            case 'Q':
                cib_action = CIB_OP_QUERY;
                break;
            case 'P':
                cib_action = CIB_OP_APPLY_DIFF;
                break;
            case 'S':
                cib_action = CIB_OP_SYNC;
                break;
            case 'U':
            case 'M':
                cib_action = CIB_OP_MODIFY;
                break;
            case 'R':
                cib_action = CIB_OP_REPLACE;
                break;
            case 'C':
                cib_action = CIB_OP_CREATE;
                break;
            case 'D':
                cib_action = CIB_OP_DELETE;
                break;
            case '5':
                cib_action = "md5-sum";
                break;
            case '6':
                cib_action = "md5-sum-versioned";
                break;
            case 'c':
                command_options |= cib_can_create;
                break;
            case 'n':
                command_options |= cib_no_children;
                break;
            case 'm':
                cib_action = CIB_OP_ISMASTER;
                command_options |= cib_scope_local;
                break;
            case 'B':
                cib_action = CIB_OP_BUMP;
                break;
            case 'r':
                dangerous_cmd = TRUE;
                cib_action = CIB_OP_SLAVE;
                break;
            case 'w':
                dangerous_cmd = TRUE;
                cib_action = CIB_OP_MASTER;
                command_options |= cib_scope_local;
                break;
            case 'V':
                command_options = command_options | cib_verbose;
                crm_bump_log_level(argc, argv);
                break;
            case '?':
            case '$':
            case '!':
                crm_help(flag, EX_OK);
                break;
            case 'o':
                crm_trace("Option %c => %s", flag, optarg);
                obj_type = strdup(optarg);
                break;
            case 'X':
                crm_trace("Option %c => %s", flag, optarg);
                admin_input_xml = strdup(optarg);
                break;
            case 'x':
                crm_trace("Option %c => %s", flag, optarg);
                admin_input_file = strdup(optarg);
                break;
            case 'p':
                admin_input_stdin = TRUE;
                break;
            case 'N':
            case 'h':
                host = strdup(optarg);
                break;
            case 'l':
                command_options |= cib_scope_local;
                break;
            case 'd':
                cib_action = CIB_OP_DELETE;
                command_options |= cib_multiple;
                dangerous_cmd = TRUE;
                break;
            case 'b':
                dangerous_cmd = TRUE;
                command_options |= cib_inhibit_bcast;
                command_options |= cib_scope_local;
                break;
            case 's':
                command_options |= cib_sync_call;
                break;
            case 'f':
                force_flag = TRUE;
                command_options |= cib_quorum_override;
                break;
            case 'a':
                output = createEmptyCib();
                crm_xml_add(output, XML_ATTR_CRM_VERSION, CRM_FEATURE_SET);
                if (optind >= argc) {
                    crm_xml_add(output, XML_ATTR_VALIDATION, LATEST_SCHEMA_VERSION);
                } else {
                    crm_xml_add(output, XML_ATTR_VALIDATION, argv[optind]);
                }
                crm_xml_add_int(output, XML_ATTR_GENERATION_ADMIN, 1);
                crm_xml_add_int(output, XML_ATTR_GENERATION, 0);
                crm_xml_add_int(output, XML_ATTR_NUMUPDATES, 0);

                admin_input_xml = dump_xml_formatted(output);
                fprintf(stdout, "%s\n", crm_str(admin_input_xml));
                goto bail;
                break;
            default:
                printf("Argument code 0%o (%c)" " is not (?yet?) supported\n", flag, flag);
                ++argerr;
                break;
        }
    }

    if (optind < argc) {
        printf("non-option ARGV-elements: ");
        while (optind < argc)
            printf("%s ", argv[optind++]);
        printf("\n");
        crm_help('?', EX_USAGE);
    }

    if (optind > argc || cib_action == NULL) {
        ++argerr;
    }

    if (argerr) {
        crm_help('?', EX_USAGE);
    }

    if (dangerous_cmd && force_flag == FALSE) {
        fprintf(stderr, "The supplied command is considered dangerous."
                "  To prevent accidental destruction of the cluster,"
                " the --force flag is required in order to proceed.\n");
        fflush(stderr);
        exit_code = -EINVAL;
        goto bail;
    }

    if (admin_input_file != NULL) {
        input = filename2xml(admin_input_file);
        source = admin_input_file;

    } else if (admin_input_xml != NULL) {
        source = "input string";
        input = string2xml(admin_input_xml);

    } else if (admin_input_stdin) {
        source = "STDIN";
        input = stdin2xml();
    }

    if (input != NULL) {
        crm_log_xml_debug(input, "[admin input]");

    } else if (source) {
        fprintf(stderr, "Couldn't parse input from %s.\n", source);
        exit_code = -EINVAL;
        goto bail;
    }

    if (safe_str_eq(cib_action, "md5-sum")) {
        char *digest = NULL;

        if (input == NULL) {
            fprintf(stderr, "Please supply XML to process with -X, -x or -p\n");
            exit_code = -EINVAL;
            goto bail;
        }

        digest = calculate_on_disk_digest(input);
        fprintf(stderr, "Digest: ");
        fprintf(stdout, "%s\n", crm_str(digest));
        free(digest);
        goto bail;

    } else if (safe_str_eq(cib_action, "md5-sum-versioned")) {
        char *digest = NULL;
        const char *version = NULL;

        if (input == NULL) {
            fprintf(stderr, "Please supply XML to process with -X, -x or -p\n");
            exit_code = -EINVAL;
            goto bail;
        }

        version = crm_element_value(input, XML_ATTR_CRM_VERSION);
        digest = calculate_xml_versioned_digest(input, FALSE, TRUE, version);
        fprintf(stderr, "Versioned (%s) digest: ", version);
        fprintf(stdout, "%s\n", crm_str(digest));
        free(digest);
        goto bail;
    }
    
    exit_code = do_init();
    if (exit_code != pcmk_ok) {
        crm_err("Init failed, could not perform requested operations");
        fprintf(stderr, "Init failed, could not perform requested operations\n");
        return -exit_code;
    }

    exit_code = do_work(input, command_options, &output);
    if (exit_code > 0) {
        /* wait for the reply by creating a mainloop and running it until
         * the callbacks are invoked...
         */
        request_id = exit_code;

        the_cib->cmds->register_callback(the_cib, request_id, message_timeout_ms, FALSE, NULL,
                                         "cibadmin_op_callback", cibadmin_op_callback);

        mainloop = g_main_new(FALSE);

        crm_trace("%s waiting for reply from the local CIB", crm_system_name);

        crm_info("Starting mainloop");
        g_main_run(mainloop);

    } else if (exit_code < 0) {
        crm_err("Call failed: %s", pcmk_strerror(exit_code));
        fprintf(stderr, "Call failed: %s\n", pcmk_strerror(exit_code));
        operation_status = exit_code;

        if (exit_code == -pcmk_err_dtd_validation) {
            if (crm_str_eq(cib_action, CIB_OP_UPGRADE, TRUE)) {
                xmlNode *obj = NULL;
                int version = 0, rc = 0;

                rc = the_cib->cmds->query(the_cib, NULL, &obj, command_options);
                if (rc == pcmk_ok) {
                    update_validation(&obj, &version, TRUE, FALSE);
                }

            } else if (output) {
                validate_xml_verbose(output);
            }
        }
    }

    if (output != NULL) {
        char *buffer = dump_xml_formatted(output);

        fprintf(stdout, "%s\n", crm_str(buffer));
        free(buffer);
        free_xml(output);
    }

    crm_trace("%s exiting normally", crm_system_name);

    free_xml(input);
    free(admin_input_xml);
    free(admin_input_file);
    the_cib->cmds->signoff(the_cib);
    cib_delete(the_cib);
  bail:
    return crm_exit(-exit_code);
}

int
do_work(xmlNode * input, int call_options, xmlNode ** output)
{
    /* construct the request */
    the_cib->call_timeout = message_timeout_ms;
    if (strcasecmp(CIB_OP_REPLACE, cib_action) == 0
        && safe_str_eq(crm_element_name(input), XML_TAG_CIB)) {
        xmlNode *status = get_object_root(XML_CIB_TAG_STATUS, input);

        if (status == NULL) {
            create_xml_node(input, XML_CIB_TAG_STATUS);
        }
    }

    if (strcasecmp(CIB_OP_SYNC, cib_action) == 0) {
        crm_trace("Performing %s op...", cib_action);
        return the_cib->cmds->sync_from(the_cib, host, obj_type, call_options);

    } else if (strcasecmp(CIB_OP_SLAVE, cib_action) == 0 && (call_options ^ cib_scope_local)) {
        crm_trace("Performing %s op on all nodes...", cib_action);
        return the_cib->cmds->set_slave_all(the_cib, call_options);

    } else if (strcasecmp(CIB_OP_MASTER, cib_action) == 0) {
        crm_trace("Performing %s op on all nodes...", cib_action);
        return the_cib->cmds->set_master(the_cib, call_options);

    } else if (cib_action != NULL) {
        crm_trace("Passing \"%s\" to variant_op...", cib_action);
        return cib_internal_op(the_cib, cib_action, host, obj_type, input, output, call_options, NULL);

    } else {
        crm_err("You must specify an operation");
    }
    return -EINVAL;
}

int
do_init(void)
{
    int rc = pcmk_ok;

    the_cib = cib_new();
    rc = the_cib->cmds->signon(the_cib, crm_system_name, cib_command);
    if (rc != pcmk_ok) {
        crm_err("Signon to CIB failed: %s", pcmk_strerror(rc));
        fprintf(stderr, "Signon to CIB failed: %s\n", pcmk_strerror(rc));
    }

    return rc;
}

void
cib_connection_destroy(gpointer user_data)
{
    crm_err("Connection to the CIB terminated... exiting");
    g_main_quit(mainloop);
    return;
}

void
cibadmin_op_callback(xmlNode * msg, int call_id, int rc, xmlNode * output, void *user_data)
{
    char *admin_input_xml = NULL;

    exit_code = rc;

    if (output != NULL) {
        admin_input_xml = dump_xml_formatted(output);
    }

    if (safe_str_eq(cib_action, CIB_OP_ISMASTER) && rc != pcmk_ok) {
        crm_info("CIB on %s is _not_ the master instance", host ? host : "localhost");
        fprintf(stderr, "CIB on %s is _not_ the master instance\n", host ? host : "localhost");

    } else if (safe_str_eq(cib_action, CIB_OP_ISMASTER)) {
        crm_info("CIB on %s _is_ the master instance", host ? host : "localhost");
        fprintf(stderr, "CIB on %s _is_ the master instance\n", host ? host : "localhost");

    } else if (rc != 0) {
        crm_warn("Call %s failed (%d): %s", cib_action, rc, pcmk_strerror(rc));
        fprintf(stderr, "Call %s failed (%d): %s\n", cib_action, rc, pcmk_strerror(rc));
        fprintf(stdout, "%s\n", crm_str(admin_input_xml));

    } else if (safe_str_eq(cib_action, CIB_OP_QUERY) && output == NULL) {
        crm_err("Output expected in query response");
        crm_log_xml_err(msg, "no output");

    } else if (output == NULL) {
        crm_info("Call passed");

    } else {
        crm_info("Call passed");
        fprintf(stdout, "%s\n", crm_str(admin_input_xml));
    }
    free(admin_input_xml);

    if (call_id == request_id) {
        g_main_quit(mainloop);

    } else {
        crm_info("Message was not the response we were looking for (%d vs. %d", call_id,
                 request_id);
    }
}
