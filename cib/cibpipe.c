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
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>

#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/msg_xml.h>

#include <crm/common/xml.h>

#include "common.h"

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif

void usage(const char *cmd, int exit_status);

struct cib_func_entry {
    const char *op;
    gboolean read_only;
    cib_op_t fn;
};

/* *INDENT-OFF* */
static struct cib_func_entry cib_pipe_ops[] = {
    {CIB_OP_QUERY,      TRUE,  cib_process_query},
    {CIB_OP_MODIFY,     FALSE, cib_process_modify},
    {CIB_OP_APPLY_DIFF, FALSE, cib_process_diff},
    {CIB_OP_BUMP,       FALSE, cib_process_bump},
    {CIB_OP_REPLACE,    FALSE, cib_process_replace},
    {CIB_OP_CREATE,     FALSE, cib_process_create},
    {CIB_OP_DELETE,     FALSE, cib_process_delete},
    {CIB_OP_ERASE,      FALSE, cib_process_erase},
};
/* *INDENT-ON* */

#define OPTARGS	"V?o:QDUCEX:t:MBfRx:P5S$"

int
main(int argc, char **argv)
{
    int lpc;
    int flag;
    int rc = 0;
    int argerr = 0;
    int max_msg_types = DIMOF(cib_pipe_ops);

    int command_options = 0;
    gboolean changed = FALSE;
    gboolean force_flag = FALSE;
    gboolean dangerous_cmd = FALSE;

    char *buffer = NULL;
    const char *section = NULL;
    const char *input_xml = NULL;
    const char *input_file = NULL;
    const char *cib_action = NULL;

    xmlNode *input = NULL;
    xmlNode *output = NULL;
    xmlNode *result_cib = NULL;
    xmlNode *current_cib = NULL;

    gboolean query = FALSE;
    cib_op_t *fn = NULL;

#ifdef HAVE_GETOPT_H
    int option_index = 0;

    static struct option long_options[] = {
        {CIB_OP_ERASE, 0, 0, 'E'},
        {CIB_OP_QUERY, 0, 0, 'Q'},
        {CIB_OP_CREATE, 0, 0, 'C'},
        {CIB_OP_REPLACE, 0, 0, 'R'},
        {CIB_OP_UPDATE, 0, 0, 'U'},
        {CIB_OP_MODIFY, 0, 0, 'M'},
        {"patch", 0, 0, 'P'},
        {CIB_OP_DELETE, 0, 0, 'D'},
        {CIB_OP_BUMP, 0, 0, 'B'},
        {"md5-sum", 0, 0, '5'},

        {"force", 0, 0, 'f'},
        {"xml-file", 1, 0, 'x'},
        {"xml-text", 1, 0, 'X'},
        {"xml-save", 1, 0, 'S'},
        {"obj_type", 1, 0, 'o'},

        {"version", 0, 0, '$'},
        {"verbose", 0, 0, 'V'},
        {"help", 0, 0, '?'},

        {0, 0, 0, 0}
    };
#endif

    crm_log_cli_init("cib_pipe");

    while (1) {
#ifdef HAVE_GETOPT_H
        flag = getopt_long(argc, argv, OPTARGS, long_options, &option_index);
#else
        flag = getopt(argc, argv, OPTARGS);
#endif
        if (flag == -1)
            break;

        switch (flag) {
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
            case 'd':
                cib_action = CIB_OP_DELETE_ALT;
                break;
            case 'm':
                cib_action = CIB_OP_ISMASTER;
                command_options |= cib_scope_local;
                break;
            case 'B':
                cib_action = CIB_OP_BUMP;
                break;
            case 'o':
                crm_trace("Option %c => %s", flag, optarg);
                section = crm_strdup(optarg);
                break;
            case 'x':
                crm_trace("Option %c => %s", flag, optarg);
                input_file = crm_strdup(optarg);
                break;
            case 'X':
                crm_trace("Option %c => %s", flag, optarg);
                input_xml = crm_strdup(optarg);
                break;
            case 'f':
                force_flag = TRUE;
                command_options |= cib_quorum_override;
                break;
            case 'V':
                crm_bump_log_level();
                break;
            case '?':          /* Help message */
                usage(crm_system_name, LSB_EXIT_OK);
                break;
            case '$':          /* Version message */
                crm_help(flag, LSB_EXIT_OK);
                break;
            default:
                ++argerr;
                break;
        }
    }

    if (cib_action == NULL) {
        ++argerr;
    }

    if (optind > argc) {
        ++argerr;
    }

    if (argerr) {
        usage(crm_system_name, LSB_EXIT_GENERIC);
    }

    if (dangerous_cmd && force_flag == FALSE) {
        fprintf(stderr, "The supplied command is considered dangerous."
                "  To prevent accidental destruction of the cluster,"
                " the --force flag is required in order to proceed.\n");
        fflush(stderr);
        usage(crm_system_name, LSB_EXIT_GENERIC);
    }

    if (input_file != NULL) {
        input = filename2xml(input_file);
        if (input == NULL) {
            fprintf(stderr, "Couldn't parse input file: %s\n", input_file);
            return 1;
        }

    } else if (input_xml != NULL) {
        input = string2xml(input_xml);
        if (input == NULL) {
            fprintf(stderr, "Couldn't parse input string: %s\n", input_xml);
            return 1;
        }
    }

    if (input && safe_str_eq(cib_action, CIB_OP_QUERY)) {
        current_cib = copy_xml(input);

    } else {
        current_cib = stdin2xml();
        if (current_cib == NULL && safe_str_neq(cib_action, CIB_OP_ERASE)) {
            fprintf(stderr, "Couldn't parse existing CIB from STDIN.\n");
            return 1;
        }
    }

    if (current_cib == NULL) {
        current_cib = createEmptyCib();
    }
    result_cib = copy_xml(current_cib);

    if (safe_str_eq(cib_action, "md5-sum")) {
        char *digest = NULL;

        digest = calculate_on_disk_digest(current_cib);
        fprintf(stdout, "%s\n", crm_str(digest));
        crm_free(digest);
        return 0;
    }

    /* read local config file */
    if (cib_action == NULL) {
        crm_err("No operation specified");
        return cib_operation;
    }

    for (lpc = 0; lpc < max_msg_types; lpc++) {
        if (safe_str_eq(cib_action, cib_pipe_ops[lpc].op)) {
            fn = &(cib_pipe_ops[lpc].fn);
            query = cib_pipe_ops[lpc].read_only;
            break;
        }
    }

    if (fn == NULL) {
        rc = cib_NOTSUPPORTED;
    } else {
        rc = cib_perform_op(cib_action, command_options, fn, query,
                            section, NULL, input, TRUE, &changed,
                            current_cib, &result_cib, NULL, &output);
    }

    if (rc != cib_ok) {
        fprintf(stderr, "Call failed: %s\n", cib_error2string(rc));
        fprintf(stdout, "%c", 0);
        return -rc;
    }

    crm_log_args(argc, argv);

    if (output) {
        buffer = dump_xml_formatted(output);
    } else {
        buffer = dump_xml_formatted(result_cib);
    }

    fprintf(stdout, "%s\n", buffer);
    fflush(stdout);

    crm_info("Done");
    return 0;
}

void
usage(const char *cmd, int exit_status)
{
    FILE *stream;

    stream = exit_status ? stderr : stdout;

    fprintf(stream, "usage: %s -Q -(x|X)\n", cmd);
    fprintf(stream, "usage: %s -Q -(x|X) | %s [-%s] | %s [-%s] | ...\n",
            cmd, cmd, OPTARGS, cmd, OPTARGS);
    fprintf(stream, "usage: cibadmin -Q  | %s [-%s] | %s [-%s] | ...\n",
            cmd, OPTARGS, cmd, OPTARGS);

    fprintf(stream, "\nOptions\n");
    fprintf(stream, "\t--%s (-%c) <type>\tobject type being operated on\n", "obj_type", 'o');
    fprintf(stream, "\t\tValid values are:" " nodes, resources, constraints, crm_config, status\n");
    fprintf(stream, "\t--%s (-%c)\tturn on debug info."
            "  additional instance increase verbosity\n", "verbose", 'V');
    fprintf(stream, "\t--%s (-%c)\tthis help message\n", "help", '?');

    fprintf(stream, "\nCommands\n");
    fprintf(stream, "\t--%s (-%c)\tErase the contents of the whole CIB\n", CIB_OP_ERASE, 'E');
    fprintf(stream, "\t--%s (-%c)\t\n", CIB_OP_QUERY, 'Q');
    fprintf(stream, "\t--%s (-%c)\tCreate an object that does not yet exist\n", CIB_OP_CREATE, 'C');
    fprintf(stream, "\t--%s (-%c)\tRecursivly update an object in the CIB\n", CIB_OP_UPDATE, 'U');
    fprintf(stream,
            "\t--%s (-%c)\tFind the object somewhere in the CIB's XML tree and update it as --"
            CIB_OP_UPDATE " would\n", CIB_OP_MODIFY, 'M');
    fprintf(stream, "\t--%s (-%c)\tRecursivly replace an object in the CIB\n", CIB_OP_REPLACE, 'R');
    fprintf(stream, "\t--%s (-%c)\t\n", CIB_OP_DELETE, 'D');
    fprintf(stream, "\t\t\tDelete the first object matching the supplied criteria\n");
    fprintf(stream, "\t\t\tEg. <op id=\"rsc1_op1\" name=\"monitor\"/>\n");
    fprintf(stream,
            "\t\t\tThe tagname and all attributes must match in order for the element to be deleted\n");

    fprintf(stream, "\t--%s (-%c)\t\n", CIB_OP_BUMP, 'B');
    fprintf(stream, "\t--%s (-%c)\t\tCalculate the configuration's digest.\n", "md5-sum", '5');
    fprintf(stream, "\nXML data\n");
    fprintf(stream, "\t--%s (-%c) <filename>\tRetrieve XML from the named file\n", "xml-file", 'x');
    fprintf(stream, "\t--%s (-%c) <string>\tRetrieve XML from the supplied string\n",
            "xml-text", 'X');
    fprintf(stream, "\t--%s (-%c) <filename>\tSave the XML output to the named file\n",
            "xml-save", 'S');
    fprintf(stream, "\nNOTE: The current CIB is assumed to be passed in via stdin,"
            " unless -Q is used in which case -x or -X are also acceptable\n");
    fflush(stream);

    exit(exit_status);
}
