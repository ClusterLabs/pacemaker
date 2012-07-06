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

    crm_log_cli_init("crm_error");
    crm_set_options(NULL, "[options] -- rc", long_options,
                    "Tool for displaying the textual description of a reported error code");
    
    while (flag >= 0) {
        flag = crm_get_option(argc, argv, &option_index);
        switch (flag) {
            case -1:
                break;
            case 'V':
                crm_bump_log_level();
                break;
            case '$':
            case '?':
                crm_help(flag, EX_OK);
                break;
            default:
                crm_help(flag, EX_OK);
                break;
        }
    }

    for(lpc = optind; lpc < argc; lpc++) {
        rc = crm_atoi(argv[lpc], NULL);
        printf("%s\n", pcmk_strerror(rc));
    }
    return 0;
}
