/* $Id: crm_uuid.c,v 1.1 2005/10/25 13:55:51 andrew Exp $ */

/* 
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <portability.h>

#include <sys/param.h>

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <hb_api.h>
#include <clplumbing/cl_malloc.h>
#include <clplumbing/uids.h>
#include <clplumbing/Gmain_timeout.h>

#define UUID_LEN 16
#define UUID_FILE HA_VARLIBDIR"/"PACKAGE"/hb_uuid"
int
main(int argc, char **argv)
{
	cl_uuid_t uuid;
	char *buffer = NULL;
	long start = 0, read_len = 0;

	FILE *input = fopen(UUID_FILE, "r");
	
	if(input == NULL) {
		fprintf(stderr, "UUID File not found: %s\n", UUID_FILE);
		return 1;
	}
	
	/* see how big the file is */
	start  = ftell(input);
	fseek(input, 0L, SEEK_END);
	if(UUID_LEN != ftell(input)) {
		fprintf(stderr, "%s must contain exactly %d bytes\n",
			UUID_FILE, UUID_LEN);
		abort();
	}
	
	fseek(input, 0L, start);
	
	if(start != ftell(input)) {
		fprintf(stderr, "fseek not behaving: %ld vs. %ld\n",
			start, ftell(input));
		return 2;
	}

/* 	fprintf(stderr, "Reading %d bytes from: %s\n", UUID_LEN, UUID_FILE); */

	buffer = cl_malloc(sizeof(char) * 50);
	read_len = fread(uuid.uuid, sizeof(char), UUID_LEN, input);
	if(read_len != UUID_LEN) {
		fprintf(stderr, "Calculated and read bytes differ: %d vs. %ld\n",
			UUID_LEN, read_len);
		return 3;
		
	} else {
		cl_uuid_unparse(&uuid, buffer);
		fprintf(stdout, "%s\n", buffer);
	}
	
	cl_free(buffer);

	return 0;
}
