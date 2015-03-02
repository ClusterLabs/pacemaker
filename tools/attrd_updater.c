
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

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <libgen.h>

#include <sys/param.h>
#include <sys/types.h>

#include <crm/crm.h>
#include <crm/common/ipc.h>

#include <crm/attrd.h>

const char *attr_node = NULL;
const char *attr_name = NULL;
const char *attr_value = NULL;
const char *attr_set = NULL;
const char *attr_section = NULL;
const char *attr_dampen = NULL;
char command = 'q';

/* *INDENT-OFF* */
static struct crm_option long_options[] = {
    /* Top-level Options */
    {"help",    0, 0, '?', "\tThis text"},
    {"version", 0, 0, '$', "\tVersion information"  },
    {"verbose", 0, 0, 'V', "\tIncrease debug output\n"},
    {"quiet",   0, 0, 'q', "\tPrint only the value on stdout\n"},

    {"name",    1, 0, 'n', "The attribute's name"},

    {"-spacer-",1, 0, '-', "\nCommands:"},
    {"update",  1, 0, 'U', "Update the attribute's value in attrd.  If this causes the value to change, it will also be updated in the cluster configuration"},
    {"query",   0, 0, 'Q', "\tQuery the attribute's value from attrd"},
    {"delete",  0, 0, 'D', "\tDelete the attribute in attrd.  If a value was previously set, it will also be removed from the cluster configuration"},
    {"refresh", 0, 0, 'R', "\t(Advanced) Force the attrd daemon to resend all current values to the CIB\n"},    
    
    {"-spacer-",1, 0, '-', "\nAdditional options:"},
    {"delay",   1, 0, 'd', "The time to wait (dampening) in seconds for further changes before writing"},
    {"set",     1, 0, 's', "(Advanced) The attribute set in which to place the value"},
    {"node",    1, 0, 'N', "Set the attribute for the named node (instead of the local one)"},
#ifdef HAVE_ATOMIC_ATTRD
    /* lifetime could be implemented for atomic attrd if there is sufficient user demand */
    {"lifetime",1, 0, 'l', "(Deprecated) Lifetime of the node attribute (silently ignored by cluster)"},
    {"private", 0, 0, 'p', "\tNever write attribute to CIB (but it can be updated and queried as usual)"},
#else
    {"lifetime",1, 0, 'l', "Lifetime of the node attribute.  Allowed values: forever, reboot"},
#endif

    /* Legacy options */
    {"update",  1, 0, 'v', NULL, 1},
    {"section", 1, 0, 'S', NULL, 1},
    {0, 0, 0, 0}
};
/* *INDENT-ON* */

int
main(int argc, char **argv)
{
    int index = 0;
    int argerr = 0;
    int attr_options = attrd_opt_none;
    int flag;

    crm_log_cli_init("attrd_updater");
    crm_set_options(NULL, "command -n attribute [options]", long_options,
                    "Tool for updating cluster node attributes");

    if (argc < 2) {
        crm_help('?', EX_USAGE);
    }

    while (1) {
        flag = crm_get_option(argc, argv, &index);
        if (flag == -1)
            break;

        switch (flag) {
            case 'V':
                crm_bump_log_level(argc, argv);
                break;
            case '?':
            case '$':
                crm_help(flag, EX_OK);
                break;
            case 'n':
                attr_name = strdup(optarg);
                break;
            case 's':
                attr_set = strdup(optarg);
                break;
            case 'd':
                attr_dampen = strdup(optarg);
                break;
            case 'l':
            case 'S':
                attr_section = strdup(optarg);
                break;
            case 'N':
                attr_node = strdup(optarg);
                break;
#ifdef HAVE_ATOMIC_ATTRD
            case 'p':
                set_bit(attr_options, attrd_opt_private);
                break;
#endif
            case 'q':
                break;
            case 'Q':
            case 'R':
            case 'D':
            case 'U':
            case 'v':
                command = flag;
                attr_value = optarg;
                break;
            default:
                ++argerr;
                break;
        }
    }

    if (optind > argc) {
        ++argerr;
    }

    if (command != 'R' && attr_name == NULL) {
        ++argerr;
    }

    if (argerr) {
        crm_help('?', EX_USAGE);
    }

    if (command == 'Q') {
        fprintf(stderr, "-Q,--query is not yet implemented, use -D to delete existing values\n\n");
        crm_help('?', EX_USAGE);

    } else {
        int rc = attrd_update_delegate(NULL, command, attr_node, attr_name, attr_value, attr_section,
                                       attr_set, attr_dampen, NULL, attr_options);
        if (rc != pcmk_ok) {
            fprintf(stderr, "Could not update %s=%s: %s (%d)\n", attr_name, attr_value, pcmk_strerror(rc), rc);
        }
        crm_exit(rc);
    }

    return crm_exit(pcmk_ok);
}
