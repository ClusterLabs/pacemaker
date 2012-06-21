
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
#include <crm/crm.h>

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <glib.h>

#include <crm/common/xml.h>
#include <crm/common/util.h>
#include <crm/msg_xml.h>
#include <crm/cib.h>
#include <crm/pengine/status.h>

gboolean USE_LIVE_CIB = FALSE;
char *cib_save = NULL;
void usage(const char *cmd, int exit_status);
extern gboolean stage0(pe_working_set_t * data_set);
extern void cleanup_alloc_calculations(pe_working_set_t * data_set);
extern xmlNode *do_calculations(pe_working_set_t * data_set, xmlNode * xml_input, ha_time_t * now);

/* *INDENT-OFF* */
static struct crm_option long_options[] = {
    /* Top-level Options */
    {"help",           0, 0, '?', "\tThis text"},
    {"version",        0, 0, '$', "\tVersion information"  },
    {"verbose",        0, 0, 'V', "\tIncrease debug output\n"},
    
    {"-spacer-",	1, 0, '-', "\nData sources:"},
    {"live-check",  0, 0, 'L', "Check the configuration used by the running cluster\n"},
    {"xml-file",    1, 0, 'x', "Check the configuration in the named file"},
    {"xml-text",    1, 0, 'X', "Check the configuration in the supplied string"},
    {"xml-pipe",    0, 0, 'p', "Check the configuration piped in via stdin"},

    {"-spacer-",    1, 0, '-', "\nAdditional Options:"},
    {"save-xml",    1, 0, 'S', "Save the verified XML to the named file.  Most useful with -L"},

    {"-spacer-",    1, 0, '-', "\nExamples:", pcmk_option_paragraph},
    {"-spacer-",    1, 0, '-', "Check the consistency of the configuration in the running cluster:", pcmk_option_paragraph},
    {"-spacer-",    1, 0, '-', " crm_verify --live-check", pcmk_option_example},
    {"-spacer-",    1, 0, '-', "Check the consistency of the configuration in a given file and produce verbose output:", pcmk_option_paragraph},
    {"-spacer-",    1, 0, '-', " crm_verify --xml-file file.xml --verbose", pcmk_option_example},
  
    {F_CRM_DATA,    1, 0, 'X', NULL, 1}, /* legacy */
    {0, 0, 0, 0}
};
/* *INDENT-ON* */

int
main(int argc, char **argv)
{
    xmlNode *cib_object = NULL;
    xmlNode *status = NULL;
    int argerr = 0;
    int flag;
    int option_index = 0;

    pe_working_set_t data_set;
    cib_t *cib_conn = NULL;
    int rc = cib_ok;

    gboolean xml_stdin = FALSE;
    const char *xml_tag = NULL;
    const char *xml_file = NULL;
    const char *xml_string = NULL;

    crm_log_cli_init("crm_verify");
    crm_set_options(NULL, "[modifiers] data_source", long_options,
                    "Check a (complete) confiuration for syntax and common conceptual errors."
                    "\n\nChecks the well-formedness of an XML configuration, its conformance to the configured DTD/schema and for the presence of common misconfigurations."
                    "\n\nIt reports two classes of problems, errors and warnings."
                    " Errors must be fixed before the cluster will work properly."
                    " However, it is left up to the administrator to decide if the warnings should also be fixed.");

    while (1) {
        flag = crm_get_option(argc, argv, &option_index);
        if (flag == -1)
            break;

        switch (flag) {
#ifdef HAVE_GETOPT_H
            case 0:
                printf("option %s", long_options[option_index].name);
                if (optarg)
                    printf(" with arg %s", optarg);
                printf("\n");

                break;
#endif

            case 'X':
                crm_trace("Option %c => %s", flag, optarg);
                xml_string = crm_strdup(optarg);
                break;
            case 'x':
                crm_trace("Option %c => %s", flag, optarg);
                xml_file = crm_strdup(optarg);
                break;
            case 'p':
                xml_stdin = TRUE;
                break;
            case 'S':
                cib_save = crm_strdup(optarg);
                break;
            case 'V':
                crm_bump_log_level();
                break;
            case 'L':
                USE_LIVE_CIB = TRUE;
                break;
            case '$':
            case '?':
                crm_help(flag, EX_OK);
                break;
            default:
                fprintf(stderr, "Option -%c is not yet supported\n", flag);
                ++argerr;
                break;
        }
    }

    if (optind < argc) {
        printf("non-option ARGV-elements: ");
        while (optind < argc) {
            printf("%s ", argv[optind++]);
        }
        printf("\n");
    }

    if (optind > argc) {
        ++argerr;
    }

    if (argerr) {
        crm_err("%d errors in option parsing", argerr);
        crm_help(flag, EX_USAGE);
    }

    crm_info("=#=#=#=#= Getting XML =#=#=#=#=");

    if (USE_LIVE_CIB) {
        cib_conn = cib_new();
        rc = cib_conn->cmds->signon(cib_conn, crm_system_name, cib_command);
    }

    if (USE_LIVE_CIB) {
        if (rc == cib_ok) {
            int options = cib_scope_local | cib_sync_call;

            crm_info("Reading XML from: live cluster");
            rc = cib_conn->cmds->query(cib_conn, NULL, &cib_object, options);
        }

        if (rc != cib_ok) {
            fprintf(stderr, "Live CIB query failed: %s\n", cib_error2string(rc));
            return 3;
        }
        if (cib_object == NULL) {
            fprintf(stderr, "Live CIB query failed: empty result\n");
            return 3;
        }

    } else if (xml_file != NULL) {
        cib_object = filename2xml(xml_file);
        if (cib_object == NULL) {
            fprintf(stderr, "Couldn't parse input file: %s\n", xml_file);
            return 4;
        }

    } else if (xml_string != NULL) {
        cib_object = string2xml(xml_string);
        if (cib_object == NULL) {
            fprintf(stderr, "Couldn't parse input string: %s\n", xml_string);
            return 4;
        }
    } else if (xml_stdin) {
        cib_object = stdin2xml();
        if (cib_object == NULL) {
            fprintf(stderr, "Couldn't parse input from STDIN.\n");
            return 4;
        }

    } else {
        fprintf(stderr, "No configuration source specified."
                "  Use --help for usage information.\n");
        return 5;
    }

    xml_tag = crm_element_name(cib_object);
    if (safe_str_neq(xml_tag, XML_TAG_CIB)) {
        fprintf(stderr,
                "This tool can only check complete configurations (ie. those starting with <cib>).\n");
        return 6;
    }

    if (cib_save != NULL) {
        write_xml_file(cib_object, cib_save, FALSE);
    }

    status = get_object_root(XML_CIB_TAG_STATUS, cib_object);
    if (status == NULL) {
        create_xml_node(cib_object, XML_CIB_TAG_STATUS);
    }

    if (validate_xml(cib_object, NULL, FALSE) == FALSE) {
        crm_config_err("CIB did not pass DTD/schema validation");
        free_xml(cib_object);
        cib_object = NULL;

    } else if (cli_config_update(&cib_object, NULL, FALSE) == FALSE) {
        crm_config_error = TRUE;
        free_xml(cib_object);
        cib_object = NULL;
        fprintf(stderr, "The cluster will NOT be able to use this configuration.\n");
        fprintf(stderr, "Please manually update the configuration to conform to the %s syntax.\n",
                LATEST_SCHEMA_VERSION);
    }

    set_working_set_defaults(&data_set);
    if (cib_object == NULL) {
    } else if (USE_LIVE_CIB) {
        /* we will always have a status section and can do a full simulation */
        do_calculations(&data_set, cib_object, NULL);
        cleanup_alloc_calculations(&data_set);

    } else {
        data_set.now = new_ha_date(TRUE);
        data_set.input = cib_object;
        stage0(&data_set);
        cleanup_alloc_calculations(&data_set);
    }

    if (crm_config_error) {
        fprintf(stderr, "Errors found during check: config not valid\n");
        if (get_crm_log_level() < LOG_WARNING) {
            fprintf(stderr, "  -V may provide more details\n");
        }
        rc = 2;

    } else if (crm_config_warning) {
        fprintf(stderr, "Warnings found during check: config may not be valid\n");
        if (get_crm_log_level() < LOG_WARNING) {
            fprintf(stderr, "  Use -V for more details\n");
        }
        rc = 1;
    }

    if (USE_LIVE_CIB) {
        cib_conn->cmds->signoff(cib_conn);
        cib_delete(cib_conn);
    }

    return rc;
}
