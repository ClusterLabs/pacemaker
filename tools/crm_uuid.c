
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

#include <config.h>
#include <crm_internal.h>

#include <sys/param.h>

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#ifdef HAVE_STRING_H
#  include <string.h>
#endif

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <crm/crm.h>
#include <crm/common/util.h>
#include <clplumbing/cl_uuid.h>

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif

#define UUID_LEN 16

#define OPTARGS	"?rw:"

int read_local_hb_uuid(void);
int write_local_hb_uuid(const char *buffer);

/* *INDENT-OFF* */
static struct crm_option long_options[] = {
    /* Top-level Options */
    {"help",    0, 0, '?', "\tThis text"},
    {"version", 0, 0, '$', "\tRead the machine's Heartbeat UUID"  },
    {"read",    0, 0, 'r', "\tChange the machine's Heartbeat UUID to a new value"  },
    
    {0, 0, 0, 0}
};
/* *INDENT-ON* */

int
main(int argc, char **argv)
{
    int flag;
    int rc = 0;
    int index = 0;

    if (argc == 1) {
        /* no arguments specified, default to read */
        rc = read_local_hb_uuid();
        return rc;
    }

    crm_log_cli_init("crm_uuid");
    crm_set_options(NULL, " [-r|-w new_ascii_value]",
                    long_options, "A tool for manipulating Heartbeat's UUID file");

    while (1) {
        flag = crm_get_option(argc, argv, &index);
        if (flag == -1)
            break;

        switch (flag) {
            case '?':
            case '$':
                crm_help(flag, EX_OK);
                break;
            case 'r':
                rc = read_local_hb_uuid();
                break;
            case 'w':
                rc = write_local_hb_uuid(optarg);
                break;
            default:
                crm_help('?', EX_USAGE);
                break;
        }
    }
    return rc;
}

int
read_local_hb_uuid(void)
{
    int rc = 0;
    cl_uuid_t uuid;
    char *buffer = NULL;
    long start = 0, read_len = 0;

    FILE *input = fopen(UUID_FILE, "r");

    if (input == NULL) {
        crm_perror(LOG_ERR, "Could not open UUID file %s\n", UUID_FILE);
        return 1;
    }

    /* see how big the file is */
    start = ftell(input);
    fseek(input, 0L, SEEK_END);
    if (UUID_LEN != ftell(input)) {
        fprintf(stderr, "%s must contain exactly %d bytes\n", UUID_FILE, UUID_LEN);
        abort();
    }

    fseek(input, 0L, start);

    if (start != ftell(input)) {
        fprintf(stderr, "fseek not behaving: %ld vs. %ld\n", start, ftell(input));
        rc = 2;
        goto bail;
    }

/* 	fprintf(stderr, "Reading %d bytes from: %s\n", UUID_LEN, UUID_FILE); */

    buffer = malloc(50);
    read_len = fread(uuid.uuid, 1, UUID_LEN, input);
    if (read_len != UUID_LEN) {
        fprintf(stderr, "Expected and read bytes differ: %d vs. %ld\n", UUID_LEN, read_len);
        rc = 3;
        goto bail;

    } else if (buffer != NULL) {
        cl_uuid_unparse(&uuid, buffer);
        fprintf(stdout, "%s\n", buffer);

    } else {
        fprintf(stderr, "No buffer to unparse\n");
        rc = 4;
    }

  bail:
    free(buffer);
    fclose(input);

    return rc;
}

int
write_local_hb_uuid(const char *new_value)
{
    int fd;
    int rc = 0;
    cl_uuid_t uuid;
    char *buffer = strdup(new_value);

    rc = cl_uuid_parse(buffer, &uuid);
    if (rc != 0) {
        fprintf(stderr, "Invalid ASCII UUID supplied: [%s]\n", new_value);
        fprintf(stderr, "ASCII UUIDs must be of the form"
                " XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX" " and contain only letters and digits\n");
        return 5;
    }

    if ((fd = open(UUID_FILE, O_WRONLY | O_SYNC | O_CREAT, 0644)) < 0) {
        crm_perror(LOG_ERR, "Could not open %s", UUID_FILE);
        return 6;
    }

    if (write(fd, uuid.uuid, UUID_LEN) != UUID_LEN) {
        crm_perror(LOG_ERR, "Could not write UUID to %s", UUID_FILE);
        rc = 7;
    }

    if (close(fd) < 0) {
        crm_perror(LOG_ERR, "Could not close %s", UUID_FILE);
        rc = 8;
    }
    return rc;
}
