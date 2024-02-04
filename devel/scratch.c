/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <sys/param.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <crm/crm.h>
#include <crm/cib.h>

#define OPTARGS	"X:"

int
main(int argc, char **argv)
{
    int flag;
    xmlNode *top = NULL;
    const char *xml_file = NULL;

    crm_log_init(NULL, LOG_TRACE, FALSE, TRUE, argc, argv, FALSE);
    while (1) {
        flag = getopt(argc, argv, OPTARGS);
        if (flag == -1)
            break;

        switch (flag) {
            case 'X':
                xml_file = optarg;
                break;
            default:
                printf("Unknown option: -%c\n", flag);
                break;
        }
    }

    top = pcmk__xml_parse_file(xml_file);
    free_xml(top);
    return 0;
}
