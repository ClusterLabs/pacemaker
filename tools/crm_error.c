/* 
 * Copyright (C) 2012 Andrew Beekhof <andrew@beekhof.net>
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

/* *INDENT-OFF* */
static struct crm_option long_options[] = {
    /* Top-level Options */
    {"help",       0, 0, '?', "\tThis text"},
    {"version",    0, 0, '$', "\tVersion information"  },
    {"verbose",    0, 0, 'V', "\tIncrease debug output"},

    {"name",    0, 0, 'n', "\tShow the error's name with its description."
     "\n\t\t\tUseful for looking for sources of the error in source code"},

    {"list",    0, 0, 'l', "\tShow all known errors."},
    {"exit",    0, 0, 'X', "\tInterpret as exit code rather than function return value"},

    {0, 0, 0, 0}
};
/* *INDENT-ON* */

int
main(int argc, char **argv)
{
    int rc = 0;
    int lpc = 0;
    int flag = 0;
    int option_index = 0;

    bool do_list = FALSE;
    bool with_name = FALSE;
    bool as_exit_code = FALSE;

    crm_log_cli_init("crm_error");
    crm_set_options(NULL, "[options] -- rc", long_options,
                    "Tool for displaying the textual name or description of a reported error code");

    while (flag >= 0) {
        flag = crm_get_option(argc, argv, &option_index);
        switch (flag) {
            case -1:
                break;
            case 'V':
                crm_bump_log_level(argc, argv);
                break;
            case '$':
            case '?':
                crm_help(flag, CRM_EX_OK);
                break;
            case 'n':
                with_name = TRUE;
                break;
            case 'l':
                do_list = TRUE;
                break;
            case 'X':
                as_exit_code = TRUE;
                break;
            default:
                crm_help(flag, CRM_EX_OK);
                break;
        }
    }

    if(do_list) {
        for (rc = 0; rc < 256; rc++) {
            const char *name = as_exit_code? crm_exit_name(rc) : pcmk_errorname(rc);
            const char *desc = as_exit_code? crm_exit_str(rc) : pcmk_strerror(rc);
            if (!name || !strcmp(name, "Unknown") || !strcmp(name, "CRM_EX_UNKNOWN")) {
                /* Unknown */
            } else if(with_name) {
                printf("%.3d: %-26s  %s\n", rc, name, desc);
            } else {
                printf("%.3d: %s\n", rc, desc);
            }
        }
        return CRM_EX_OK;
    }

    for (lpc = optind; lpc < argc; lpc++) {
        const char *str, *name;

        rc = crm_atoi(argv[lpc], NULL);
        str = as_exit_code? crm_exit_str(rc) : pcmk_strerror(rc);
        if(with_name) {
            name = as_exit_code? crm_exit_name(rc) : pcmk_errorname(rc);
            printf("%s - %s\n", name, str);
        } else {
            printf("%s\n", str);
        }
    }
    return CRM_EX_OK;
}
